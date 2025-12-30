import argparse
import os
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


def run_server_in_thread(port: int = 8000):
    """Start HTTPServer on a background thread and return (server, thread)."""
    _ensure_challenge_dir()
    server = HTTPServer(('0.0.0.0', port), ACMEHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # give server time to start
    time.sleep(0.2)
    return server, thread


def create_cert(domain: str, email: str, webroot: str = '.', port: int = 8000):
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

    try:
        subprocess.run(cmd, check=True)
        print(f"✓ Certificate obtained for {domain}")
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

    return p.parse_args(argv)


if __name__ == '__main__':
    args = parse_args()

    if args.command == 'server':
        start_server(port=args.port)
    elif args.command == 'cert':
        create_cert(domain=args.domain, email=args.email, webroot=args.webroot, port=args.port)
    else:
        print('No command provided. Use "server" to run the challenge server or "cert" to obtain a certificate.')
        print('Examples:')
        print('  python main.py server --port 8000')
        print('  python main.py cert --domain example.com --email you@example.com --port 8000')