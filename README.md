# oci_lb_certbot 🔧

Simple helper to obtain Let's Encrypt certificates when running behind an OCI Load Balancer
that listens on port 80 and forwards HTTP requests to a backend port (default: 8000).

This repo provides:
- A small HTTP server that serves `/.well-known/acme-challenge/` on a configurable backend port
  (default 8000) so the load balancer can forward ACME HTTP-01 requests to it.
- A `cert` workflow that starts a temporary server, waits for the backend/LB to become healthy,
  runs `certbot --webroot` to obtain certificates, copies the generated certs to an output
  directory, writes a minimal LB config JSON, and secures the files.

---

## Quick start ✅

1. Make sure `certbot` is installed on the host.
2. Configure OCI Load Balancer to listen on port **80** and forward to backend port **8000** (or another
   port you prefer).
3. Run the long-running server (as a service or manually):

```bash
python3 main.py server --port 8000 --lb-ip 203.0.113.5
```

4. Obtain a certificate (the command starts a temporary server on the backend port, waits for the
   LB to find the backend, then runs `certbot --webroot`):

```bash
python3 main.py cert --domain example.com --email you@example.com --port 8000 --output-dir ./certs
```

- Use `--dry-run` to test (`--dry-run` is passed to certbot).
- Use `--wait-seconds N` to adjust how long the script waits (default 120s) for the backend to become reachable.
- Add `--lb-ip` flags (repeatable) to declare trusted load balancer IPs that should get an immediate 200 response
  (useful for LB health checks that probe the backend).

---

## CLI reference

- `server` — run an HTTP server that serves `/.well-known/acme-challenge/`
  - `--port, -p` (default 8000)
  - `--lb-ip, -l` (repeatable) set LB IP(s) treated as probes
  - `--verbose, -v` enable debug logging

- `cert` — obtain a certificate using certbot's `--webroot`
  - `--domain, -d` (required)
  - `--email, -m` (required)
  - `--webroot` (default `.`)
  - `--port` (default 8000)
  - `--output-dir, -o` (default `./certs`) — where certs and certbot config/work/logs are stored
  - `--dry-run` pass `--dry-run` to certbot
  - `--wait-seconds` (default 120) wait up to this many seconds for the backend to become reachable
  - `--lb-ip, -l` (repeatable) declare LB IP(s)
  - `--verbose, -v` enable debug logging

---

## Behavior & file layout

- By default, the script will place cert-related files under the requested `--output-dir`.
- If it cannot create the requested directory (permission error), it falls back to:
  `~/.oci_lb_certbot/certs` (user-local, writable by the running user).
- Certbot is run using `--config-dir`, `--work-dir`, and `--logs-dir` inside the chosen output dir so the system
  `/etc/letsencrypt` and `/var/log/letsencrypt` are not written (no root required).
- After cert issuance the script copies files from the certbot config `live/<domain>/` into:
  `<output-dir>/<domain>/` and writes `<output-dir>/<domain>/lb-config.json` containing paths the LB can use.
- The script attempts to set secure filesystem permissions:
  - directories: `0700`
  - `privkey.pem`: `0600`
  - cert files (`fullchain.pem`, `cert.pem`, `chain.pem`): `0644` (adjust if needed)
- The script also appends ignore rules to `.gitignore` to avoid committing certs or certbot directories.

---

## Security recommendations 🔐

- Keep `privkey.pem` owner-only readable (chmod 600).
- Use a dedicated service user or `root` ownership for certs depending on how you manage the LB.
- Do not commit private keys or certs to version control — `.gitignore` includes entries to help.
- Consider storing certs in encrypted storage or a secrets manager for long-term keep.

---

## Load Balancer health checks & probes

- Add the LB source IP(s) with `--lb-ip` so the server will respond `200 OK` immediately to probes from those IPs.
- If your LB uses a range (CIDR) for health checks, consider enumerating the addresses or open an issue to add CIDR support.

---

## Logging & troubleshooting

- Use `--verbose`/`-v` for debug logs (includes wait prober attempts and HTTP access logs).
- The server logs each request with source IP, method, path, status, latency and the `User-Agent` header to help debugging.
- If certbot reports permissions issues (writing `/var/log/letsencrypt`), re-run using `--output-dir` that is writable by
  the calling user or run the command as a user with write access.

---

## Example systemd unit (suggested)

Create `/etc/systemd/system/oci-lb-acme.service` (adjust `User` and paths):

```ini
[Unit]
Description=ACME challenge HTTP server for OCI Load Balancer
After=network.target

[Service]
Type=simple
User=someuser
WorkingDirectory=/opt/oci_lb_certbot
ExecStart=/usr/bin/python3 /opt/oci_lb_certbot/main.py server --port 8000 --lb-ip 203.0.113.5
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now oci-lb-acme.service
```

---

## Renewal automation ideas

- Option A: Keep the long-running server and schedule a cron/ systemd timer to run:
  ```bash
  python3 /opt/oci_lb_certbot/main.py cert --domain example.com --email you@example.com --port 8000 --output-dir /opt/oci_lb_certbot/certs
  ```
- Option B: Use certbot's renewal hooks (`--deploy-hook`) to copy certs into a place the LB can access and reload the LB configuration.

---

## Troubleshooting tips

- If the script cannot create `--output-dir`, check permissions or let it fallback to `~/.oci_lb_certbot/certs`.
- If LB health checks still fail: verify the LB's source address and add it with `--lb-ip`.
- Use `--dry-run` for safe testing against Let's Encrypt staging.

---

## Contributing

Open issues/PRs for feature requests (CIDR LB support, OCI API upload integration, or other improvements).

---

If you'd like, I can:
- Add CIDR support for load balancer ranges ✅
- Add an example renewal systemd timer or a deployment hook that uploads certs to OCI LB via API ✅
- Add CI lint/test checks and packaging for a more robust deployable service ✅

Tell me which of those you'd like next and I'll add it.
