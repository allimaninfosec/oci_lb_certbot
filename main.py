import argparse
import os
import shutil
import json
import subprocess
import sys
import threading
import time
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

    def do_GET(self):
        """Serve challenge files from .well-known/acme-challenge/"""
        # Deny any request that looks like it is trying to access private files
        deny_patterns = ('/certs', '/letsencrypt', '.pem', '/.git')
        for p in deny_patterns:
            if p in self.path:
                self.send_response(404)
                self.end_headers()
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

    def log_message(self, format, *args):
        """Log to stdout with timestamp."""
        print(f"[{self.log_date_time_string()}] {format % args}")


def _ensure_challenge_dir(path: Path = Path('.')):
    (path / '.well-known' / 'acme-challenge').mkdir(parents=True, exist_ok=True)


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child_res = child.resolve()
        parent_res = parent.resolve()
    except Exception:
        return False
    return parent_res == child_res or parent_res in child_res.parents


def ensure_output_dir_safe(webroot: str, output_dir: str, allow_in_webroot: bool = False) -> Path:
    """Ensure output_dir exists, is outside of webroot unless allowed, and has secure perms."""
    webroot_p = Path(webroot).resolve()
    out_p = Path(output_dir).resolve()

    if _is_within(out_p, webroot_p) and not allow_in_webroot:
        # Move to parent of webroot to keep it out of public files
        new_out = webroot_p.parent / 'certs'
        print(f"Warning: requested output dir {out_p} is inside webroot {webroot_p}. Using {new_out} instead.")
        out_p = new_out

    out_p.mkdir(parents=True, exist_ok=True)
    # Lock down directory permissions
    try:
        os.chmod(out_p, 0o700)
    except Exception:
        # best-effort; continue if OS disallows
        pass

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


def create_cert(domain: str, email: str, webroot: str = '.', port: int = 8000,
                output_dir: str = './certs', dry_run: bool = False):
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

    cert = sub.add_parser('cert', help='Obtain certificate with certbot (webroot)')
    cert.add_argument('--domain', '-d', required=True, help='Domain name')
    cert.add_argument('--email', '-m', required=True, help="Email address for Let's Encrypt")
    cert.add_argument('--webroot', default='.', help='Webroot path where .well-known is served (default: .)')
    cert.add_argument('--port', type=int, default=8000, help='Backend port the LB forwards to (default: 8000)')
    cert.add_argument('--output-dir', '-o', default='./certs', help='Directory to copy certs and store certbot config (default: ./certs)')
    cert.add_argument('--dry-run', action='store_true', help='Pass --dry-run to certbot (test)')

    return p.parse_args(argv)


if __name__ == '__main__':
    args = parse_args()

    if args.command == 'server':
        start_server(port=args.port)
    elif args.command == 'cert':
        create_cert(domain=args.domain, email=args.email, webroot=args.webroot, port=args.port,
                    output_dir=args.output_dir, dry_run=bool(args.dry_run))
    else:
        print('No command provided. Use "server" to run the challenge server or "cert" to obtain a certificate.')
        print('Examples:')
        print('  python main.py server --port 8000')
        print('  python main.py cert --domain example.com --email you@example.com --port 8000 --output-dir ./certs')