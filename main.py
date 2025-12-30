import argparse
import os
import shutil
import json
import subprocess
import sys
import threading
import time
import logging
import http.client
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

#!/usr/bin/env python3
"""
Simple HTTP server for Let's Encrypt ACME challenges.

Designed to work behind an OCI Load Balancer which listens on port 80 and
forwards traffic to a backend port (default 8000). Run the server on the
backend port and use certbot with the `--webroot` plugin so the LB can
deliver /.well-known/acme-challenge requests to this process.
"""


class ACMEHandler(SimpleHTTPRequestHandler):
    """Handle ACME challenges from Let's Encrypt."""
    # populated at runtime from CLI args
    allowed_lb_ips = set()

    def do_GET(self):
        """Serve challenge files from .well-known/acme-challenge/"""
        start = time.time()
        # Deny any request that looks like it is trying to access private files
        deny_patterns = ('/certs', '/letsencrypt', '.pem', '/.git')
        for p in deny_patterns:
            if p in self.path:
                self.send_response(404)
                self.end_headers()
                logging.getLogger('oci_lb_certbot').warning(
                    "Denied access to %s from %s (pattern %s)", self.path, self.client_address[0], p
                )
                return

        client_ip = self.client_address[0]
        # If request comes from a configured load balancer IP, respond 200 for health checks
        if client_ip in self.allowed_lb_ips:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
            elapsed = time.time() - start
            logging.getLogger('oci_lb_certbot').info(
                "%s %s %s -> %d (LB probe) %.3fs UA=%s",
                client_ip, self.command, self.path, 200, elapsed, self.headers.get('User-Agent')
            )
            return
        if self.path.startswith('/.well-known/acme-challenge/'):
            file_path = Path('.') / self.path.lstrip('/')
            if file_path.exists():
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
                return

        self.send_response(404)
        self.end_headers()
        elapsed = time.time() - start
        logging.getLogger('oci_lb_certbot').info(
            "%s %s %s -> %d %.3fs UA=%s",
            self.client_address[0], self.command, self.path, 404, elapsed, self.headers.get('User-Agent')
        )

    def log_message(self, format, *args):
        """Log via logging module for compatibility with structured logging."""
        logging.getLogger('oci_lb_certbot').info(f"[{self.log_date_time_string()}] {format % args}")


def _ensure_challenge_dir(path: Path = Path('.')):
    (path / '.well-known' / 'acme-challenge').mkdir(parents=True, exist_ok=True)


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child_res = child.resolve()
        parent_res = parent.resolve()
    except Exception:
        return False
    return parent_res == child_res or parent_res in child_res.parents


def ensure_output_dir_safe(webroot: str, output_dir: str, allow_in_webroot: bool = True) -> Path:
    """Ensure output_dir exists and has secure perms.

    By default we allow the output_dir to live inside the webroot (working
    directory) because you asked for the certs to be placed in the working
    directory. If creating the directory at the requested path fails due to
    permissions, fall back to a per-user location in the home directory.
    The function also attempts to set ownership to the running user (best
    effort).
    """
    webroot_p = Path(webroot).resolve()
    out_p = Path(output_dir).resolve()

    # If the requested output dir is inside the webroot and that's allowed,
    # keep it (user requested that behavior). Otherwise, the caller may pass
    # allow_in_webroot=False to force moving it out.
    if _is_within(out_p, webroot_p) and not allow_in_webroot:
        new_out = webroot_p.parent / 'certs'
        print(f"Warning: requested output dir {out_p} is inside webroot {webroot_p}. Using {new_out} instead.")
        out_p = new_out

    try:
        out_p.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        # Fallback to a user-writable location under the user's home directory
        fallback = Path.home() / '.oci_lb_certbot' / 'certs'
        print(f"Permission denied creating {out_p}; falling back to {fallback}")
        fallback.mkdir(parents=True, exist_ok=True)
        out_p = fallback

    # Lock down directory permissions (best-effort)
    try:
        os.chmod(out_p, 0o700)
    except Exception:
        pass

    # Ensure ownership is the running user (best-effort)
    try:
        uid = os.getuid()
        gid = os.getgid()
        os.chown(out_p, uid, gid)
    except Exception:
        pass

    print(f"Using output directory: {out_p}")
    return out_p


def _secure_cert_files(dest: Path):
    """Apply secure permissions to cert files and directories in dest."""
    try:
        os.chmod(dest, 0o700)
    except Exception:
        pass

    for fname in ('privkey.pem', 'fullchain.pem', 'cert.pem', 'chain.pem'):
        p = dest / fname
        if p.exists():
            try:
                if fname == 'privkey.pem':
                    os.chmod(p, 0o600)
                else:
                    os.chmod(p, 0o644)
            except Exception:
                pass


def run_server_in_thread(port: int = 8000):
    """Start HTTPServer on a background thread and return (server, thread)."""
    _ensure_challenge_dir()
    server = HTTPServer(('0.0.0.0', port), ACMEHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # give server time to start
    time.sleep(0.2)
    return server, thread


def wait_for_server(port: int = 8000, timeout: int = 120, interval: float = 2.0) -> bool:
    """Wait up to `timeout` seconds for localhost:port to accept HTTP connections.

    Returns True if the server became reachable within timeout, False otherwise.
    """
    deadline = time.time() + timeout
    logger = logging.getLogger('oci_lb_certbot')
    logger.info("Waiting up to %ds for server on port %d to become reachable...", timeout, port)
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        elapsed = int(time.time() - (deadline - timeout))
        try:
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            conn.request('GET', '/')
            resp = conn.getresponse()
            # Any response (200/404/etc.) indicates the server is up
            logger.info("Server responded with status %d on attempt %d after %ds; continuing...", resp.status, attempt, elapsed)
            try:
                conn.close()
            except Exception:
                pass
            # small grace period to let load balancer mark backend healthy
            grace = min(5, timeout)
            if grace > 0:
                logger.debug("Waiting an additional %ds to allow load balancer to pick up the backend...", grace)
                time.sleep(grace)
            logger.info("Server ready after %ds", elapsed)
            return True
        except Exception:
            # Not yet reachable; sleep and retry
            logger.debug("Attempt %d: server not reachable yet (elapsed %ds)", attempt, int(time.time() - (deadline - timeout)))
            time.sleep(interval)

    logger.warning("Timed out after %ds waiting for server on port %d; proceeding anyway.", timeout, port)
    return False


def create_cert(domain: str, email: str, webroot: str = '.', port: int = 8000,
                output_dir: str = './certs', dry_run: bool = False, wait_seconds: int = 120):
    """Request certificate from Let's Encrypt using certbot's webroot plugin.

    This function will start a temporary HTTP server on `port` to serve
    `/.well-known/acme-challenge/` while certbot performs validation. It's the
    recommended flow when an OCI load balancer listens on port 80 and forwards
    to a backend port (e.g., 8000).
    """
    os.makedirs(webroot, exist_ok=True)
    _ensure_challenge_dir(Path(webroot))

    print(f"Starting temporary HTTP server on port {port} to serve challenges...")
    server, thread = run_server_in_thread(port=port)

    # Wait for the server/load balancer to become ready (user-configurable)
    if wait_seconds and wait_seconds > 0:
        wait_for_server(port=port, timeout=wait_seconds)

    cmd = [
        'certbot', 'certonly',
        '--webroot',
        '--webroot-path', webroot,
        '--domain', domain,
        '--email', email,
        '--agree-tos',
        '--non-interactive',
    ]
    if dry_run:
        cmd.append('--dry-run')
    # Ensure certbot writes to writable directories under output_dir instead of /etc or /var
    # ensure output dir is safe (outside webroot by default) and exists
    out = ensure_output_dir_safe(webroot=webroot, output_dir=output_dir)
    config_dir = out / 'letsencrypt'
    work_dir = out / 'letsencrypt-work'
    logs_dir = out / 'letsencrypt-logs'
    config_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    cmd.extend([
        '--config-dir', str(config_dir),
        '--work-dir', str(work_dir),
        '--logs-dir', str(logs_dir),
    ])

    try:
        subprocess.run(cmd, check=True)
        print(f"✓ Certificate obtained for {domain}")
        # copy generated certs from certbot's config_dir live directory to output_dir
        live_dir = config_dir / 'live' / domain
        dest = out / domain
        dest.mkdir(parents=True, exist_ok=True)

        copied = []
        for fname in ('fullchain.pem', 'privkey.pem', 'chain.pem', 'cert.pem'):
            src = live_dir / fname
            if src.exists():
                shutil.copy2(src, dest / fname)
                copied.append(fname)

        if copied:
            print(f"Copied {', '.join(copied)} to {dest}")
            # Write a small JSON snippet for LB upload or reference
            cfg = {
                'domain': domain,
                'certificate': str((dest / 'fullchain.pem').resolve()) if (dest / 'fullchain.pem').exists() else None,
                'private_key': str((dest / 'privkey.pem').resolve()) if (dest / 'privkey.pem').exists() else None,
                'source_live_dir': str(live_dir),
            }
            cfg_path = dest / 'lb-config.json'
            with open(cfg_path, 'w') as f:
                json.dump(cfg, f, indent=2)
            print(f"Wrote LB config to {cfg_path}")
            # secure files
            _secure_cert_files(dest)
        else:
            print(f"Warning: no cert files found in {live_dir}. They may be in a custom certbot directory or certbot failed to place them.")

        # add .gitignore entries to avoid committing certs
        gitignore = Path('.gitignore')
        gi_entries = ['# certbot / generated certs', str(out) + '/', '*.pem', 'letsencrypt/', 'letsencrypt-work/', 'letsencrypt-logs/']
        if gitignore.exists():
            existing = gitignore.read_text()
        else:
            existing = ''

        to_append = []
        for e in gi_entries:
            if e not in existing:
                to_append.append(e)

        if to_append:
            with open(gitignore, 'a') as f:
                f.write('\n' + '\n'.join(to_append) + '\n')
            print(f"Updated .gitignore with {to_append}")
    finally:
        print("Shutting down temporary HTTP server...")
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def start_server(port: int = 8000):
    """Start HTTP server for ACME challenges (blocking)."""
    _ensure_challenge_dir()

    server = HTTPServer(('0.0.0.0', port), ACMEHandler)
    print(f"Starting HTTP server on port {port} (press Ctrl-C to stop)...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()


def parse_args(argv=None):
    p = argparse.ArgumentParser(description='Simple ACME webroot server for OCI LB')
    sub = p.add_subparsers(dest='command')

    srv = sub.add_parser('server', help='Run HTTP server to serve /.well-known')
    srv.add_argument('--port', '-p', type=int, default=8000, help='Port to listen on (default: 8000)')
    srv.add_argument('--lb-ip', '-l', action='append', help='Load balancer IP addresses (can be repeated)')
    srv.add_argument('--verbose', '-v', action='store_true', help='Enable debug logging')

    cert = sub.add_parser('cert', help='Obtain certificate with certbot (webroot)')
    cert.add_argument('--domain', '-d', required=True, help='Domain name')
    cert.add_argument('--email', '-m', required=True, help="Email address for Let's Encrypt")
    cert.add_argument('--webroot', default='.', help='Webroot path where .well-known is served (default: .)')
    cert.add_argument('--port', type=int, default=8000, help='Backend port the LB forwards to (default: 8000)')
    cert.add_argument('--output-dir', '-o', default='./certs', help='Directory to copy certs and store certbot config (default: ./certs)')
    cert.add_argument('--dry-run', action='store_true', help='Pass --dry-run to certbot (test)')
    cert.add_argument('--wait-seconds', type=int, default=120, help='Seconds to wait for server & LB to become ready before running certbot (default: 120)')
    cert.add_argument('--lb-ip', '-l', action='append', help='Load balancer IP addresses (can be repeated)')
    cert.add_argument('--verbose', '-v', action='store_true', help='Enable debug logging')

    return p.parse_args(argv)


if __name__ == '__main__':
    args = parse_args()

    # Configure logging
    level = logging.DEBUG if getattr(args, 'verbose', False) else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)s %(message)s')
    logger = logging.getLogger('oci_lb_certbot')

    # Set allowed LB IPs on the handler class
    lb_ips = set((args.lb_ip or []) if hasattr(args, 'lb_ip') else [])
    if lb_ips:
        logger.info('Configured load balancer IPs: %s', ','.join(lb_ips))
    ACMEHandler.allowed_lb_ips = lb_ips

    if args.command == 'server':
        start_server(port=args.port)
    elif args.command == 'cert':
        create_cert(domain=args.domain, email=args.email, webroot=args.webroot, port=args.port,
                    output_dir=args.output_dir, dry_run=bool(args.dry_run), wait_seconds=int(args.wait_seconds))
    else:
        print('No command provided. Use "server" to run the challenge server or "cert" to obtain a certificate.')
        print('Examples:')
        print('  python main.py server --port 8000')
        print('  python main.py cert --domain example.com --email you@example.com --port 8000 --output-dir ./certs')