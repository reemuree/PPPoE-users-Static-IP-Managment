# MikroTik PPPoE IP Allocation Manager

A lightweight, **read-only** web dashboard for ISP administrators. It reads `/ip/route`, `/ppp/secret`
and `/ppp/active` from a MikroTik router over the RouterOS API and shows which IPs in your customer
networks are assigned, free, reserved, in conflict, or used by sessions that have no matching secret.

Stack: Flask · librouteros · SQLite (settings + admin login only) · Chart.js (bundled) · vanilla JS.

```
app.py            Flask app: auth, CSRF, API, CSV export, cached snapshot
router_client.py  RouterOS API access (read-only) + connectivity test
ip_analyzer.py    IP classification logic (pure Python, no I/O)
templates/        index.html (app), login.html
static/           css/style.css, js/app.js, js/vendor/chart.umd.js
```

## How IPs are classified

| Status | Meaning |
|---|---|
| **Assigned** | Exactly one *enabled* PPP secret has this `remote-address`. |
| **Free** | No enabled secret, active session, conflict or reservation uses it. |
| **Reserved** | Excluded by you on the Networks page. |
| **Conflict** | Two or more enabled secrets share the IP, or a session by a different user holds a secret's IP. |
| **Active unconfigured** | An active PPP session uses the IP but no enabled secret has it. |
| **Unknown** | Router data is stale or incomplete, so Free cannot be verified. |
| Out of range | Not a row status: secrets outside all monitored networks are listed under **Reports**. |

> **“Free” means free from known PPPoE assignments and monitored conflicts.** It does not guarantee the
> address is unused by other services (static hosts, DHCP, servers, NAT pools…). Use **Reserved** for those.

**Route / table column:** each IP shows the matching `/ip route` entry: the per-user host route
(`10.10.0.16/32 → <pppoe-user015>`) when the router has one, otherwise the network route that covers it
(`10.10.0.0/24 → bridge1`), plus its routing table (`routing-table` on RouterOS v7, `routing-mark` on v6; `main` if unset).

**User traffic:** click a username to open a side panel with the session's **Download** (router → user, interface `tx`)
and **Upload** (user → router, interface `rx`): current rate and totals since the session started, refreshed every 5 s
while the panel is open. It reads the dynamic interface `<pppoe-USERNAME>` and runs `/interface/monitor-traffic once`
(read-only). If your PPPoE server uses different interface names, traffic will show "No PPPoE interface found".

Other rules: disabled secrets never claim an IP and are listed separately; default routes and `/32`
host routes are never offered as networks; overlapping networks never produce duplicate rows; secrets whose
`remote-address` is a pool name are counted as *dynamic* and not shown as assignments.

**Stale data:** if the router becomes unreachable, the last good snapshot is kept and clearly marked stale.
Would-be Free IPs turn Unknown, and the Free list and Free CSV export are refused until the router responds.

---

## 1. Prepare the MikroTik router (read-only access)

Run in RouterOS (replace `<server-ip>` with the address of the machine running this app):

```
/user group add name=api-ro policy=read,api,!local,!telnet,!ssh,!ftp,!reboot,!write,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon
/user add name=ipmgr group=api-ro password=<strong-password> address=<server-ip>/32
/ip service set api disabled=no address=<server-ip>/32
```

The `ipmgr` user cannot change configuration. For encrypted API, enable `api-ssl` (port 8729) with a
certificate and set `ROUTER_USE_SSL=true` below.

## 2. Install on Ubuntu Server

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
sudo mkdir -p /opt/pppoe-ip-manager && sudo chown $USER: /opt/pppoe-ip-manager
cp -r . /opt/pppoe-ip-manager/ && cd /opt/pppoe-ip-manager   # or git clone your repository here

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
chmod 600 .env
nano .env            # set ROUTER_HOST, ROUTER_USER, ROUTER_PASSWORD, ADMIN_PASSWORD (10+ chars)
```

### Test the router connection

```bash
python router_client.py
# OK  192.168.88.1:8728  (45 ms)
#   routes:         23
#   ppp secrets:    412
#   active sessions:389
```

Failures are reported by type: `connection` (unreachable/timeout), `auth` (wrong user or password),
`permission` (user lacks `read`/`api`), `config` (missing `.env` values).

### Run (development)

```bash
python app.py                 # http://127.0.0.1:5000
```

Open the page, sign in with `ADMIN_USER` / `ADMIN_PASSWORD`, go to **Networks**, tick the customer
networks to monitor, and press **Save and apply**. Afterwards remove `ADMIN_PASSWORD` from `.env`
(the account lives hashed in `instance/app.db`). Add or reset an admin any time with
`python app.py create-admin`.

To reach it from another machine during testing set `HOST=0.0.0.0` in `.env`, and allow the port in your
firewall. For anything beyond testing, use the production setup below.

## 3. Production deployment (Ubuntu)

Use **one** gunicorn worker with threads: the router snapshot cache and login throttling live in process memory,
so multiple workers would each query the router separately.

`/etc/systemd/system/pppoe-ip-manager.service`

```ini
[Unit]
Description=PPPoE IP Manager
After=network-online.target

[Service]
User=ipmgr
Group=ipmgr
WorkingDirectory=/opt/pppoe-ip-manager
EnvironmentFile=/opt/pppoe-ip-manager/.env
ExecStart=/opt/pppoe-ip-manager/.venv/bin/gunicorn -w 1 --threads 4 -b 127.0.0.1:8000 --timeout 60 app:app
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/opt/pppoe-ip-manager/instance

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --home /opt/pppoe-ip-manager --shell /usr/sbin/nologin ipmgr
sudo chown -R ipmgr:ipmgr /opt/pppoe-ip-manager
sudo chmod 600 /opt/pppoe-ip-manager/.env
sudo systemctl daemon-reload && sudo systemctl enable --now pppoe-ip-manager
sudo journalctl -u pppoe-ip-manager -f
```

Put nginx in front for HTTPS (`sudo apt install -y nginx certbot python3-certbot-nginx`):

```nginx
server {
    listen 80;
    server_name ipmgr.example.com;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }
}
```

```bash
sudo certbot --nginx -d ipmgr.example.com
```

Then set `BEHIND_PROXY=true` and `SESSION_COOKIE_SECURE=true` in `.env` and `sudo systemctl restart pppoe-ip-manager`.
If the app is only reachable on a private LAN without HTTPS, leave `SESSION_COOKIE_SECURE=false`.

Hardening checklist: restrict the app port to admin networks with `ufw`; keep the MikroTik API service limited to
the server's IP; keep `.env` and `instance/` readable only by the service user; back up `instance/app.db`.

## 4. Windows setup (brief)

```powershell
cd C:\pppoe-ip-manager
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
notepad .env
python router_client.py
python app.py
```

For a long-running service use `waitress` (installed automatically on Windows):
`waitress-serve --listen=127.0.0.1:8000 app:app`, run it with NSSM or Task Scheduler, and put IIS or nginx in
front if you need HTTPS.

## Configuration reference (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `ROUTER_HOST`, `ROUTER_USER`, `ROUTER_PASSWORD` | required | Read-only RouterOS API login |
| `ROUTER_PORT` | 8728 (8729 with SSL) | API port |
| `ROUTER_TIMEOUT` | 10 | Seconds before a router call fails |
| `ROUTER_USE_SSL`, `ROUTER_SSL_VERIFY` | false | Use api-ssl; verify its certificate |
| `HOST`, `PORT` | 127.0.0.1, 5000 | Dev server bind address |
| `SECRET_KEY` | auto | Session signing key (auto-generated into `instance/secret_key`) |
| `SESSION_COOKIE_SECURE` | false | Set true behind HTTPS |
| `BEHIND_PROXY` | false | Trust one reverse proxy for client IP/scheme |
| `ADMIN_USER`, `ADMIN_PASSWORD` | admin, empty | First-run admin (10+ chars) |
| `DATABASE_PATH` | instance/app.db | SQLite file (keep outside any public directory) |
| `MAX_ADDRESSES` | 65536 | Default cap on monitored addresses (editable in the UI) |
| `CACHE_TTL` | 15 | Seconds a router snapshot is reused before re-reading |

## API (all require login; POST/PUT require the CSRF token)

`GET /api/status` · `POST /api/sync` · `GET /api/dashboard` · `GET /api/inventory` ·
`GET /api/assigned` · `GET /api/free` · `GET /api/user/<username>` · `GET /api/reports` · `GET|PUT /api/networks` ·
`GET /api/export.csv?scope=all|assigned|free`

Inventory accepts `q`, `status`, `network`, `sort`, `dir`, `page`, `page_size`. Credentials are never included in any response.

## Security notes

- Router credentials are only read from the server environment; they are never sent to the browser or logged.
- Admin passwords are stored with salted scrypt hashes; login is rate limited; sessions are HttpOnly, SameSite=Lax.
- Every state-changing request needs a CSRF token. A strict Content-Security-Policy allows only same-origin scripts and styles.
- Router-supplied text is rendered with DOM text nodes, never as HTML. CSV cells starting with `= + - @` are neutralised.
- The app only calls `print`-style reads on the router. It never adds, edits or removes router configuration.
- `localStorage` holds only UI preferences (theme, network filter, page size, search, status filter, auto-refresh).

## Troubleshooting

| Symptom | Check |
|---|---|
| “Cannot reach router” | `ROUTER_HOST`/port, `/ip service` API enabled, its `address=` list includes the server, firewall |
| “rejected the username or password” | `ROUTER_USER`/`ROUTER_PASSWORD`; user's `address=` must include the server IP |
| “lacks permission” | The router group needs `read` and `api` policies |
| Traffic panel says “cannot read /interface” | The API user's group needs the `read` policy (the sample group has it) |
| TLS handshake error | Use the `api-ssl` port 8729 with a certificate, or set `ROUTER_USE_SSL=false` for port 8728 |
| Dashboard asks to select networks | Open **Networks**, tick the ranges, **Save and apply** |
| “above the limit” on save | Choose smaller networks or raise the address limit on the Networks page |
| Cannot log in | Run `python app.py create-admin` |
