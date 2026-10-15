# 🚀 Spiritus - Quick Installation Guide

## One-Command Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/v74all/Spiritus/main/install.sh)"
```

This provisions PostgreSQL + Redis, a Python virtualenv, Xray/sing-box/Mieru
binaries, a self-signed (or Let's Encrypt, if you give it a domain) TLS cert,
runs the database migrations, and installs/starts four systemd units:
`spiritus`, `spiritus-worker`, `spiritus-beat`, `v7lthronyx-helper`.

Useful flags:

```bash
sudo bash install.sh --port 8080         # custom web port (default 38471)
sudo bash install.sh --help              # all options
sudo bash install.sh uninstall           # remove (keeps the DB)
sudo bash install.sh uninstall --purge   # remove everything, including the DB
```

## Manual Install

Prefer this only for development or when you need full control over each
step — the one-command installer above does all of this for you, including
generating strong secrets.

### Step 1: System packages, clone, and Python env

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv \
    postgresql postgresql-contrib redis-server fail2ban curl wget

sudo git clone https://github.com/v74all/Spiritus.git /opt/v7lthronyx
cd /opt/v7lthronyx
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2: Database and cache

```bash
sudo -u postgres psql -c "CREATE USER vpnadmin WITH PASSWORD 'change-me';"
sudo -u postgres psql -c "CREATE DATABASE vpnpanel OWNER vpnadmin;"
sudo systemctl enable --now postgresql redis-server
```

### Step 3: Install Xray (and, optionally, sing-box for Hysteria2/TUIC/ShadowTLS/Naive)

```bash
bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) @ install
```

### Step 4: Configure

```bash
cp .env.example .env
# Edit .env and set at minimum:
#   SECRET_KEY               — python3 -c "import secrets; print(secrets.token_urlsafe(48))"
#   DATABASE_URL              — postgresql+asyncpg://vpnadmin:change-me@127.0.0.1:5432/vpnpanel
#   ADMIN_BOOTSTRAP_PASSWORD  — the password for the first login (consumed after first use)
#   VPN_SERVER_IP             — your server's public IP (or leave blank to auto-detect)
#   TLS_CERT_FILE / TLS_KEY_FILE — point at a real cert, or generate a self-signed one:
#     openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout tls/spiritus.key \
#       -out tls/spiritus.crt -subj "/CN=$(hostname)"
chmod 600 .env
```

`SECRET_KEY` must be ≥32 chars and not a known placeholder — the app refuses
to start otherwise (fail-closed by design; see `app/config.py`).

### Step 5: Migrate and start

```bash
alembic upgrade head

# Direct (foreground, for development)
uvicorn app.main:app --host 0.0.0.0 --port 38471

# Or as a systemd service — install.sh's generated unit is the reference;
# see "Systemd Service" below for the full, hardened version it writes.
```

## Auto-Update

The one-command installer sets up a daily cron job (`/etc/cron.d/spiritus-update`,
4:00 AM) that pulls `main`, reinstalls dependencies, and restarts the service.

To manually update:
```bash
cd /opt/v7lthronyx
git pull origin main
source venv/bin/activate
pip install -r requirements.txt -c constraints.txt
alembic upgrade head
sudo systemctl restart spiritus spiritus-worker spiritus-beat
```

## Access

```
URL: http://your-server-ip:38471          (or https://your-domain if you set one up)
API docs: only reachable when DEBUG=true — disabled by default in production
```

The very first login uses `admin` / the `ADMIN_BOOTSTRAP_PASSWORD` from `.env`
(the one-command installer generates and prints this for you). **Change it
immediately** via the panel's Settings page or:

```bash
curl -s -c /tmp/ck.txt -X POST http://localhost:38471/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"<bootstrap password>"}'
# then use the returned access_token / CSRF cookie to call /api/change-password
```

Then remove `ADMIN_BOOTSTRAP_PASSWORD` from `.env` and restart — it is only
consumed once, but leaving it set is unnecessary exposure.

## 🔧 Systemd Service

The installer writes four units: `spiritus` (the panel), `spiritus-worker`
and `spiritus-beat` (Celery), and `v7lthronyx-helper` (a restricted,
root-capability-scoped daemon for cert issuance / fail2ban / iptables ops
that the unprivileged panel process can't do itself). To inspect or edit
them directly:

```bash
sudo systemctl cat spiritus              # see the generated unit
sudo systemctl daemon-reload             # after any manual edit
sudo systemctl enable --now spiritus spiritus-worker spiritus-beat v7lthronyx-helper
```

The panel process itself runs as the unprivileged `vpnpanel` system user, not
root — do not run it manually as root outside of a quick dev test.

## 📊 Monitor Logs

```bash
journalctl -u spiritus -f               # panel
journalctl -u spiritus-worker -f        # Celery worker
journalctl -u v7lthronyx-helper -f      # privileged helper
tail -f /opt/v7lthronyx/vpn-panel.log   # file log (if LOG_TO_FILE is set)
```

## 🔒 Firewall Configuration

The installer opens the panel port automatically (best-effort, via
`ufw`/`firewalld` if present). To do it by hand:

```bash
sudo ufw allow 38471/tcp   # panel
sudo ufw allow 443/tcp     # TLS-bearing protocols (REALITY, WS+TLS, Trojan, ...)
sudo ufw enable
```

## ✅ Verification

```bash
# Health check (no auth required)
curl http://localhost:38471/api/health
# {"status":"healthy","service":"v7lthronyx-vpn-panel","version":"2.1.0"}

# Readiness (checks the Xray config has actually synced)
curl http://localhost:38471/api/ready

# Xray status
systemctl status xray
xray version
```

## 🎯 First Steps After Installation

1. **Log in** at `http://your-server-ip:38471` with `admin` / the bootstrap
   password, then change the password and remove `ADMIN_BOOTSTRAP_PASSWORD`
   from `.env` (see "Access" above).
2. **Create your first user** — "+ Add User", set a traffic limit and
   expiry.
3. **Get the config** — click the user's "Config" button, or share the
   subscription link (`/sub/{uuid}`) directly with the client.
4. **Point a domain at it** (optional but recommended) — the Domain tab
   issues a real Let's Encrypt certificate and updates every TLS-bearing
   protocol's SNI automatically.

## 📱 Client Configuration

Each user gets a subscription link (`/sub/{uuid}`) that most clients can
import directly, plus a base64 share-link format (`/sub-api/{uuid}`) and a
JSON profile (`/sub-json/{uuid}`) for clients that want the raw config.

### Supported Clients
- **Windows**: v2rayN, NekoRay, Clash Verge
- **macOS**: V2RayXS, ClashX
- **Linux**: v2rayN (Linux build), NekoRay
- **Android**: v2rayNG, NekoBox, the bundled V7L mobile app
- **iOS**: Shadowrocket, Streisand

## 🆘 Troubleshooting

### Panel not accessible
```bash
systemctl status spiritus
journalctl -u spiritus -n 100 --no-pager
ss -tlnp | grep 38471
sudo systemctl restart spiritus
```

### Database errors
```bash
# Back up the PostgreSQL database
sudo -u postgres pg_dump vpnpanel > vpnpanel-backup.sql

# Restore
sudo -u postgres psql vpnpanel < vpnpanel-backup.sql
```
The panel also has its own encrypted backup/restore under the Settings tab
(Fernet-encrypted, `0600` files) — prefer that for routine backups.

### Xray connection issues
```bash
systemctl status xray
journalctl -u xray -n 50 --no-pager
sudo xray run -test -config /usr/local/etc/xray/config.json   # validate the config
systemctl restart xray
```

### Privileged helper not starting
```bash
systemctl status v7lthronyx-helper
journalctl -u v7lthronyx-helper -n 50 --no-pager
```
Cert issuance, fail2ban jail management, and other root-only operations go
through this daemon — the panel itself keeps running without it, but those
specific features degrade until it's healthy.

## 📞 Support

- Documentation: [README.md](README.md), [docs/](docs/)
- Issues: https://github.com/v74all/Spiritus/issues

---

**Happy VPN Management! 🎉**
