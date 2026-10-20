# Spiritus: Installation Guide

## نصب در ۳ قدم (فارسی)

**پیش‌نیاز:** یک سرور خارج از ایران با Ubuntu 22.04 به بالا یا Debian 12، دسترسی root، و حداقل ۱ گیگ رم. **دامنه لازم نیست.**

**۱. نصب.** با SSH به سرور وصل شو و این را اجرا کن:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/v74all/Spiritus/main/install.sh)"
```

اگر پرسید دامنه داری، اگر نداری فقط Enter بزن.

**۲. ورود.** آخر نصب، آدرس پنل، نام کاربری و رمز نمایش داده می‌شود؛ آدرس را در مرورگر باز کن و وارد شو. بعد از اولین ورود رمز را عوض کن.

**۳. اولین کاربر.** در بخش Users روی Add user بزن، بعد لینک اشتراک کاربر را برایش بفرست. کاربر لینک را در v2rayNG، Hiddify، Streisand یا v2rayN وارد می‌کند و وصل می‌شود.

### بدون دامنه هم کار می‌کند

- پروتکل‌های **REALITY** (VLESS REALITY، Vision، XHTTP) اصلاً گواهی و دامنه نمی‌خواهند و کلیدهایشان خودکار ساخته می‌شود.
- نصب‌کننده برای **IP سرور** یک گواهی واقعی Let's Encrypt می‌گیرد و خودش تمدیدش می‌کند (پورت ۸۰ باید آزاد باشد).
- اگر گرفتن گواهی ممکن نبود، لینک‌ها اثر انگشت گواهی سرور را با خودشان دارند. در هیچ حالتی لازم نیست در کلاینت **allow insecure** را روشن کنی؛ نسخه‌های جدید Xray این گزینه را کلاً حذف کرده‌اند.

### مشکلات رایج

| مشکل | راه حل |
|------|--------|
| پنل در مرورگر باز نمی‌شود | پورت پنل (پیش‌فرض 38471) را در فایروال سرویس‌دهندهٔ سرور باز کن. |
| کاربر وصل نمی‌شود | اپ کلاینت را به‌روز کن، در اپ «Update subscription» بزن، و اول یک کانفیگ REALITY را امتحان کن. |
| رمز پنل را فراموش کردی | `sudo bash /opt/v7lthronyx/install.sh reset-password` |
| آدرس لینک‌ها اشتباه است | در فایل `/opt/v7lthronyx/.env` مقدار `VPN_SERVER_IP` را IP عمومی سرور بگذار و `sudo systemctl restart spiritus` را اجرا کن. |

## Install in 3 steps (English)

**You need:** a server outside the censored network running Ubuntu 22.04+ or Debian 12, root access, and at least 1 GB of RAM. **No domain needed.**

1. **Install.** Over SSH, run:
   ```bash
   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/v74all/Spiritus/main/install.sh)"
   ```
   When it asks for a domain, press Enter if you don't have one.
2. **Sign in.** The installer ends by printing the panel address, the username and the password. Open the address and sign in, then change the password.
3. **First user.** Users › Add user, then send the user their subscription link. They paste it into v2rayNG, Hiddify, Streisand or v2rayN.

### No domain? It still works

- **REALITY** protocols (VLESS REALITY, Vision, XHTTP) need no certificate and no domain; their keys are generated on first start.
- The installer requests a real **Let's Encrypt certificate for the server's IP** and renews it automatically (port 80 must be free).
- If that is not possible, every link carries the server certificate's fingerprint (`pcs`). Clients never need **allow insecure**, which current Xray versions have removed.

### Common problems

| Problem | Fix |
|---------|-----|
| The panel does not open | Open the panel port (default 38471) in your provider's firewall. |
| A user cannot connect | Update the client app, press "Update subscription", and try a REALITY config first. |
| Forgot the admin password | `sudo bash /opt/v7lthronyx/install.sh reset-password` |
| Links show the wrong address | Set `VPN_SERVER_IP` in `/opt/v7lthronyx/.env` to the server's public IP, then `sudo systemctl restart spiritus`. |

### Installer options

```bash
sudo bash install.sh --port 8080         # custom web port (default 38471)
sudo bash install.sh --help              # all options
sudo bash install.sh uninstall           # remove (keeps the DB)
sudo bash install.sh uninstall --purge   # remove everything, including the DB
sudo bash install.sh reset-password      # forgot the admin password: print a new one
                                         #   (--username NAME, --disable-2fa)
```

What it sets up: PostgreSQL and Redis, a Python virtualenv, the Xray, sing-box
and Mieru binaries, a TLS certificate (Let's Encrypt for your domain or IP,
self-signed as the fallback), the database migrations, and the systemd units
`spiritus`, `spiritus-worker`, `spiritus-beat` and `v7lthronyx-helper`.

## Manual Install

Prefer this only for development or when you need full control over each
step — the one-command installer above does all of this for you, including
generating strong secrets.

### Step 1: System packages, clone, and Python env

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv \
    postgresql postgresql-contrib redis-server fail2ban curl wget nftables iproute2

# Speed limits and per-user byte counts use tc and nftables. The helper
# service cannot load kernel modules itself, so load them now and at boot:
for m in ifb sch_htb sch_fq_codel sch_ingress cls_fw cls_matchall act_connmark act_mirred nf_tables nft_ct nf_nat; do
    sudo modprobe "$m" && echo "$m" | sudo tee -a /etc/modules-load.d/spiritus.conf >/dev/null
done

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
