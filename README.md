<p align="center">
  <img src="static/logo.png" alt="Spiritus Logo" width="200">
</p>

<h1 align="center">Spiritus — VPN Management Panel</h1>

<p align="center">
  <strong>Advanced VPN management panel for Xray-core with comprehensive DPI evasion</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/FastAPI-0.115-green.svg" alt="FastAPI">
  <img src="https://img.shields.io/badge/Xray--core-1.8+-orange.svg" alt="Xray-core 1.8+">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
</p>

[🇬🇧 English](#english) | [🇮🇷 فارسی](#فارسی)

---

<a id="english"></a>

## ✨ Features

### User Management
- 🔍 **Search** — Find users by name, UUID, or notes
- 📦 **Bulk Operations** — Update multiple users at once
- 📊 **User Statistics** — Detailed per-user stats and activity history
- 👥 **Groups** — Organize users into groups
- 🤖 **Agent System** — Multi-agent support with traffic quotas and commission
- 💰 **Payments** — Integrated payment tracking with reseller system

### Reporting & Analytics
- 📈 **Statistics Report** — Overview of all users and traffic
- 📉 **Traffic Analytics** — Daily traffic usage trends
- 🏆 **Top Users** — Identify high-traffic users
- ⚠️ **Expiring Soon** — Users expiring within 7 days

### Backup & Export
- 💾 **Backup/Restore** — Create and restore database backups
- 📄 **CSV Export** — Export user data to CSV
- 📋 **JSON Export** — Export user data to JSON

### System Monitoring
- 💻 **CPU** — Real-time CPU utilization
- 🧠 **Memory** — RAM usage tracking
- 💾 **Disk** — Storage space monitoring
- 🌐 **Network** — Active connection count
- 📡 **Xray Status** — Live Xray-core process monitoring

### Multi-Protocol Support (14+ protocols)
| Protocol | Transport | TLS | CDN-Ready |
|----------|-----------|-----|-----------|
| **VMess** | WebSocket, gRPC, HTTPUpgrade, XHTTP | ✅ | ✅ |
| **VLESS Reality** | Vision flow | ✅ | — |
| **VLESS** | WebSocket, XHTTP, Vision, Reverse | ✅ | ✅ |
| **Trojan** | WebSocket, TLS | ✅ | ✅ |
| **Trojan-CDN** | WebSocket + CDN host | ✅ | ✅ |
| **gRPC** | gRPC streaming | ✅ | ✅ |
| **HTTPUpgrade** | HTTP/1.1 upgrade | ✅ | ✅ |
| **ShadowSocks 2022** | TCP, WebSocket | ✅ | ✅ |
| **Hysteria2** | QUIC/UDP | ✅ | — |
| **TUIC** | QUIC/UDP | ✅ | — |
| **ShadowTLS** | TCP + TLS handshake spoof | ✅ | — |
| **Mieru** | TCP + protocol obfuscation | ✅ | — |
| **NaiveProxy** | HTTP/2 CONNECT | ✅ | ✅ |
| **WireGuard** | UDP | — | — |
| **OpenVPN** | TCP/UDP | ✅ | — |
| **AmneziaWG** | UDP (obfuscated WireGuard) | — | — |

### DPI Evasion (Deep Packet Inspection Bypass)

#### Host Header Spoofing (4 techniques)
- **HTTP Host Spoof** — Replaces the `Host` header on WebSocket/HTTPUpgrade connections with a legitimate domain (e.g., `chat.deepseek.com`). The DPI sees a connection to a whitelisted service instead of your VPN server.
- **WS Host Front** — Fronts WebSocket connections through a CDN-friendly host (`rubika.ir`), making traffic appear as a popular Iranian platform.
- **CDN Host Front** — Routes through ArvanCloud/CDN edge nodes (`web.splus.ir`), leveraging CDN infrastructure as a shield.
- **Bug Host Injection** — Injects additional headers (`X-Forwarded-Host`, `X-Host`) mimicking legitimate traffic patterns, confusing stateful DPI systems.

#### Network-Layer Evasion
- **TCP/IP/TLS Fragmentation** — Splits packets into fragments that bypass pattern-matching DPI rules. Configurable fragment size, count, and interval.
- **Noise Packets** — Injects random padding packets into the stream to break traffic signature analysis. Configurable packet size and delay.
- **TLS Fingerprint Spoofing** — Masquerades as Chrome, Firefox, Safari, or random TLS fingerprints to avoid JA3/JA4 fingerprinting.
- **TCP Keepalive** — Maintains persistent connections to prevent state table timeouts on restrictive firewalls.
- **MUX (Multiplexing)** — Combines multiple connections into a single TCP stream, reducing connection overhead and hiding traffic patterns.

#### Advanced Evasion
- **DNS Tunneling** — Encapsulates traffic within DNS queries/responses (Iodine-style), bypassing firewalls that allow DNS but block VPN protocols.
- **ICMP Tunneling** — Carries data inside ICMP echo packets (ping tunneling), escaping detection by firewalls that don't inspect ICMP payloads.
- **Domain Fronting** — Uses a CDN's edge certificate while connecting to a different backend, making DPI see only the CDN domain.
- **CDN Fronting** — Routes traffic through major CDN providers, hiding the true destination behind trusted infrastructure.
- **Advanced Network Resilience** — Packet reordering, dynamic port hopping, fake HTTP traffic generation, traffic shaping, multi-path routing, and protocol hopping for maximum network resilience.

### Security
- 🔒 **2FA/TOTP** — Two-factor authentication with authenticator apps
- 🛡️ **CSRF & XSS Protection** — Security headers on all responses
- 🚫 **Rate Limiting** — Brute force protection with progressive lockout
- 🚷 **Fail2Ban Integration** — Automatic IP banning after repeated failures
- 📝 **Audit Logging** — Comprehensive security event logging
- 🔑 **JWT Tokens** — Stateless authentication with configurable expiry

### UI/UX
- 🎨 **Shadow Ops Design** — Terminal Brutalism × Persian Geometry aesthetic
- 🌐 **RTL/LTR Auto-Detection** — Detects browser language and applies proper direction
- 🔄 **Direction Toggle** — One-click LTR/RTL switching with cookie persistence
- ⚡ **Real-Time Updates** — Live system stats, connection monitoring
- 📱 **Responsive Design** — Full mobile and tablet support
- 🔔 **Toast Notifications** — Non-intrusive status feedback
- 📋 **Config Generator** — Automatic Xray client config generation with QR codes

---

## 📦 Installation

### One-Command Install (Recommended)

```bash
bash <(curl -sL https://raw.githubusercontent.com/v74all/Spiritus/main/install.sh)
```

This automatically:
- Installs all dependencies (Python 3.10+, Xray-core, Redis)
- Sets up a Python virtual environment
- Configures systemd service
- Sets up daily auto-update cron job

### Manual Install

```bash
# Clone repository
git clone https://github.com/v74all/Spiritus.git
cd Spiritus

# Install dependencies
pip install -r requirements.txt

# (Optional) DPI evasion dependencies
pip install -r requirements-dpi.txt

# (Optional) Network resilience dependencies
pip install -r requirements-firewall.txt
```

### Configuration

Configure via environment variables or `.env` file:

```bash
# Server
export VPN_SERVER_IP="your-server-ip"
export VPN_SERVER_PORT="443"
export VPN_SNI_HOST="www.google.com"
export VPN_WEB_PORT="38471"
export VPN_API_PORT="10085"

# Security
export VPN_SESSION_LIFETIME_HOURS="72"
export VPN_MAX_LOGIN_ATTEMPTS="5"
export VPN_LOCKOUT_SECONDS="600"

# Redis (optional, for production)
export REDIS_URL="redis://localhost:6379/0"
```

### Run

```bash
# Development
uvicorn app.main:app --host 0.0.0.0 --port 38471 --reload

# Production (via systemd)
sudo cp vpn-panel.service /etc/systemd/system/
sudo systemctl enable vpn-panel
sudo systemctl start vpn-panel
```

### Access

```
URL: http://your-server-ip:38471
Default Password: Found in vpn-panel-password file after first run
```

### Auto-Update

The installer sets up a daily cron job at 4:00 AM:

```bash
# Check auto-update
crontab -l | grep spiritus

# Manual update
cd /opt/spiritus && git pull && sudo systemctl restart vpn-panel
```

---

## 📁 Project Structure

```
Spiritus/
├── app/                         # FastAPI application
│   ├── main.py                  # App entry point, template routes, subscription config
│   ├── auth.py                  # Authentication, JWT, TOTP/2FA, password hashing
│   ├── config.py                # Settings from env vars with defaults
│   ├── database.py              # Async SQLAlchemy + SQLite/PostgreSQL
│   ├── models.py                # SQLAlchemy ORM models (Admin, User, Agent, etc.)
│   ├── dpi_evasion.py           # DPI evasion engine (fragmentation, noise, tunneling)
│   ├── protocol_engine.py       # Multi-protocol config generator
│   ├── security.py              # Fail2ban, rate limiting, audit logging
│   ├── redis_client.py          # Redis caching layer
│   ├── payments.py              # Payment tracking system
│   ├── reseller.py              # Reseller management
│   ├── abuse_prevention.py      # Abuse detection and prevention
│   ├── telegram_bot.py          # Telegram bot integration
│   ├── orchestrator.py          # Service orchestration
│   ├── observability.py         # Metrics and monitoring
│   ├── celery_tasks.py          # Async task queue
│   └── api/                     # API route modules
│       ├── auth.py              # POST /auth/login, /auth/login/2fa, /auth/setup-2fa
│       ├── users.py             # CRUD /api/users, search, toggle
│       ├── agents.py            # Agent management endpoints
│       ├── compat.py            # Legacy settings API, server info
│       ├── dpi.py               # DPI technique control endpoints
│       ├── protocols.py         # Protocol listing and status
│       ├── system.py            # System health, stats, monitoring
│       ├── security.py          # Security settings and audit logs
│       ├── payments.py          # Payment endpoints
│       ├── resellers.py         # Reseller API
│       └── abuse.py             # Abuse reporting endpoints
├── static/
│   ├── css/panel.css            # Complete dark theme (Shadow Ops aesthetic)
│   ├── js/
│   │   ├── panel.js             # Full admin panel frontend (3271 lines)
│   │   └── qrcode.js            # QR code generation library
│   └── logo.png                 # Spiritus brand logo
├── templates/
│   ├── panel.html               # Main admin panel (dashboard, users, configs, settings)
│   ├── agent-panel.html         # Agent management interface
│   └── sub.html                 # End-user subscription page with QR codes
├── requirements.txt             # Core Python dependencies
├── requirements-dpi.txt         # DPI evasion Python dependencies
├── requirements-firewall.txt    # Network resilience testing dependencies
├── install.sh                   # Automated installation script
├── vpn-panel.service            # systemd service unit file
└── .gitignore
```

**Total**: ~24,000 lines across 37 source files

---

## 🔧 API Reference

| Category | Endpoint | Method | Auth | Description |
|----------|----------|--------|------|-------------|
| **Auth** | `/auth/login` | POST | — | Login with username/password |
| **Auth** | `/auth/login/2fa` | POST | — | Login with 2FA/TOTP |
| **Auth** | `/auth/setup-2fa` | POST | JWT | Set up 2FA for current user |
| **Auth** | `/auth/verify-2fa` | POST | JWT | Verify TOTP code |
| **Auth** | `/auth/logout` | POST | JWT | Logout (client-side token drop) |
| **Auth** | `/auth/me` | GET | JWT | Current user info |
| **Users** | `/api/users` | GET | JWT | List all users |
| **Users** | `/api/users` | POST | JWT | Create new user |
| **Users** | `/api/users/<name>` | DELETE | JWT | Delete user |
| **Users** | `/api/users/<name>/toggle` | POST | JWT | Toggle user active/inactive |
| **Users** | `/api/users/bulk` | POST | JWT | Bulk update users |
| **Search** | `/api/search?q=<query>` | GET | JWT | Search users by name/UUID/notes |
| **Analytics** | `/api/analytics?days=<n>` | GET | JWT | Traffic analytics |
| **Backup** | `/api/backup/create` | POST | JWT | Create database backup |
| **Export** | `/api/export/<format>` | GET | JWT | Export data (csv/json) |
| **System** | `/api/health` | GET | JWT | System health and resource usage |
| **System** | `/api/server/info` | GET | — | Server info for QR/subscription |
| **Settings** | `/api/settings` | GET | JWT | Get all panel settings |
| **Settings** | `/api/settings` | POST | JWT | Save settings |
| **Settings** | `/api/settings/reset` | POST | JWT | Reset to defaults |
| **DPI** | `/api/dpi/status` | GET | JWT | DPI evasion technique status |
| **DPI** | `/api/dpi/test` | POST | JWT | Test DPI techniques |
| **Direction** | `/api/direction` | POST | — | Set LTR/RTL direction cookie |
| **Payments** | `/api/payments` | GET/POST | JWT | Payment tracking |
| **Resellers** | `/api/resellers` | GET/POST | JWT | Reseller management |
| **Agents** | `/api/agents` | GET/POST | JWT | Agent management |

---

## 🎛️ Settings

The settings modal has **5 tabs** for complete panel configuration:

### 1. Protocols
Enable/disable individual protocols, configure Reality/XHTTP/Vision settings, manage gRPC/HTTPUpgrade services.

### 2. DPI & Security
- Host Header Spoofing: HTTP Host Spoof, WS Host Front, CDN Host Front, Bug Host Injection
- Custom domains for each spoofing technique
- TLS Fingerprint selection (Chrome, Firefox, Safari, Random, None)
- Noise Packets: toggle, size, delay
- Fragmentation: toggle, size, count, interval
- TCP Keepalive, MUX

### 3. Network & CDN
- DNS/ICMP Tunneling with custom domain
- Domain Fronting and CDN Fronting
- Advanced Network Resilience: packet reorder, dynamic port hopping, fake HTTP, traffic shaping, multi-path routing, protocol hopping
- Aggression level (low/medium/high)

### 4. Notifications & Backup
Telegram bot token and chat ID, backup schedule and retention settings.

### 5. System
Server IP, port, SNI host, panel/web ports. Session lifetime, lockout settings.

---

## 🌐 RTL/LTR System

The panel auto-detects language direction from your browser's `Accept-Language` header:

- **Persian (`fa`) or Arabic (`ar`)** → RTL mode with `lang="fa"` on `<html>`
- **All other languages** → LTR mode with `lang="en"`

A **direction toggle button** in the header lets you switch instantly. The choice persists via a `vpn_dir` cookie (1 year expiry).

The entire CSS uses **logical properties** (`margin-inline-start`, `inset-inline-start`, `border-inline-end`) so direction flipping works without duplicating stylesheets.

---

## 🔒 Security Features

- **JWT Authentication** — Stateless tokens with configurable session lifetime
- **2FA/TOTP** — Time-based one-time passwords via authenticator apps (Google Authenticator, Authy)
- **Password Hashing** — bcrypt password storage
- **Account Lockout** — Progressive lockout after N failed attempts (configurable)
- **Fail2Ban** — IP-level banning with database persistence
- **Rate Limiting** — Per-endpoint rate limiting on authentication routes
- **Security Headers** — `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Content-Security-Policy`
- **CSRF Protection** — SameSite cookie enforcement
- **Audit Logging** — All security events logged with timestamps and IP addresses

---

## 🧪 DPI Evasion: How It Works

### Architecture
```
Client App (v2rayNG/Nekobox/etc.)
    ↓ TLS encrypted connection
Stateful DPI Firewall (analyzes traffic patterns)
    ↓
Xray-core Inbound (on your server)
    ↓
App (main.py) generates configs with evasion parameters
```

### Technique Details

**Fragmentation** — TCP packets split into small fragments (configurable: 1-100 fragments, 0-30ms interval). Because DPI systems reassemble fragments to inspect content, high fragment counts and delays can exhaust their buffers or cause timeouts, forcing them to pass traffic uninspected.

**Noise Packets** — Random-sized padding packets (64-1500 bytes) injected at configurable intervals. These break the statistical fingerprint of VPN traffic. Real traffic has a distinct packet size distribution; noise packets flatten that distribution, making VPN traffic resemble generic HTTPS.

**TLS Fingerprint Spoofing** — Xray's `utls` module mimics specific browser TLS handshakes. Since Chrome's JA3 fingerprint differs from Firefox's, matching a common browser fingerprint makes DPI classify the connection as "browser traffic" rather than "VPN traffic."

**Host Header Spoofing** — For WebSocket/HTTPUpgrade transports, the HTTP `Host` header is what DPI uses to determine the destination. Replacing it with `chat.deepseek.com` makes the connection appear to be going to DeepSeek's chat service rather than your VPN server.

**Domain Fronting** — Routes traffic through a CDN's edge node. The TLS SNI matches the CDN's certificate, but the actual backend destination is your VPN server. The DPI only sees the CDN connection.

**DNS Tunneling** — Encapsulates data in DNS queries to a controlled domain. DNS is rarely blocked even on restrictive networks. The technique works by encoding data as subdomain queries (e.g., `base64data.yourdomain.com`) and decoding responses.

---

## ❓ Troubleshooting

### Panel won't start
```bash
# Check if port is in use
netstat -tlnp | grep 38471

# Check logs
journalctl -u vpn-panel -f
```

### Xray connection issues
```bash
# Check Xray status
systemctl status xray

# Restart Xray
systemctl restart xray

# View Xray logs
journalctl -u xray -f
```

### Database issues
```bash
# Backup current database
cp /root/vpn_users.db /root/vpn_users.db.backup

# Repair SQLite database
sqlite3 /root/vpn_users.db "VACUUM;"
```

### "Settings are still loading" error
This means the settings API call failed. Check:
1. You are authenticated (not logged out)
2. The panel server is running: `systemctl status vpn-panel`
3. The database is accessible: `ls -la /root/vpn_users.db`

---

## ⚠️ Disclaimer

**This project is for educational purposes and authorized privacy protection only.**

- Use these techniques **ONLY** on systems you own or have explicit permission to configure
- Unauthorized circumvention of network controls may violate local laws
- Always comply with local regulations regarding encryption and network traffic
- DPI evasion features are designed for protecting privacy in restrictive network environments where users face disproportionate surveillance

---

## 📄 License

MIT License — see [LICENSE](LICENSE).

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 🎉 Credits

- **Xray-core**: https://github.com/XTLS/Xray-core
- **V2Fly**: https://www.v2fly.org/
- **FastAPI**: https://fastapi.tiangolo.com/

---

**Version**: 2.0.0 · **Updated**: May 2026 · **Stack**: FastAPI + Xray-core · **Status**: Production Ready ✅

---

---

<a id="فارسی"></a>

## 🇮🇷 راهنمای کامل فارسی

### معرفی

**Spiritus** یک پنل مدیریت VPN پیشرفته برای Xray-core با قابلیت‌های جامع دور زدن DPI است. این پنل جایگزین کامل پنل‌های سنتی مانند X-UI و 3X-UI با تمرکز بر عبور از فیلترینگ هوشمند.

**تفاوت‌های کلیدی با X-UI:**
- ۱۴+ پروتکل با تنظیمات تخصصی ضد فیلتر
- موتور DPI Evasion با ۱۹ تکنیک مختلف
- پشتیبانی کامل از راست‌به‌چپ (RTL) فارسی
- احراز هویت دو مرحله‌ای (2FA)
- معماری FastAPI مدرن به جای Flask قدیمی

---

### ✨ امکانات

#### مدیریت کاربران
- 🔍 **جستجو** — پیدا کردن کاربران بر اساس نام، UUID یا یادداشت
- 📦 **عملیات گروهی** — آپدیت همزمان چند کاربر
- 📊 **آمار کاربر** — آمار تفصیلی و تاریخچه فعالیت هر کاربر
- 👥 **گروه‌ها** — دسته‌بندی کاربران در گروه‌های مختلف
- 🤖 **سیستم نماینده (Agent)** — پشتیبانی از چند نماینده با سهمیه ترافیک و کمیسیون
- 💰 **پرداخت‌ها** — ردیابی پرداخت با سیستم فروشنده

#### گزارش و تحلیل
- 📈 **گزارش آماری** — نمای کلی کاربران و ترافیک
- 📉 **تحلیل ترافیک** — روند مصرف ترافیک روزانه
- 🏆 **کاربران برتر** — شناسایی کاربران پرترافیک
- ⚠️ **در حال انقضا** — کاربرانی که ظرف ۷ روز منقضی می‌شن

#### پشتیبان‌گیری و خروجی
- 💾 **پشتیبان‌گیری/بازیابی** — ساخت و بازیابی نسخه پشتیبان دیتابیس
- 📄 **خروجی CSV** — خروجی اطلاعات کاربران به فرمت CSV
- 📋 **خروجی JSON** — خروجی اطلاعات کاربران به فرمت JSON

#### نظارت بر سیستم
- 💻 **CPU** — نظارت لحظه‌ای پردازنده
- 🧠 **حافظه** — ردیابی مصرف RAM
- 💾 **دیسک** — نظارت فضای ذخیره‌سازی
- 🌐 **شبکه** — تعداد اتصال‌های فعال
- 📡 **وضعیت Xray** — نظارت زنده روی پروسه Xray-core

#### پروتکل‌های پشتیبانی‌شده (۱۴+ پروتکل)

| پروتکل | انتقال | TLS | سازگار با CDN |
|--------|--------|-----|---------------|
| **VMess** | WebSocket, gRPC, HTTPUpgrade, XHTTP | ✅ | ✅ |
| **VLESS Reality** | Vision flow | ✅ | — |
| **VLESS** | WebSocket, XHTTP, Vision, Reverse | ✅ | ✅ |
| **Trojan** | WebSocket, TLS | ✅ | ✅ |
| **Trojan-CDN** | WebSocket + CDN host | ✅ | ✅ |
| **gRPC** | gRPC streaming | ✅ | ✅ |
| **HTTPUpgrade** | HTTP/1.1 upgrade | ✅ | ✅ |
| **ShadowSocks 2022** | TCP, WebSocket | ✅ | ✅ |
| **Hysteria2** | QUIC/UDP | ✅ | — |
| **TUIC** | QUIC/UDP | ✅ | — |
| **ShadowTLS** | TCP + TLS handshake spoof | ✅ | — |
| **Mieru** | TCP + protocol obfuscation | ✅ | — |
| **NaiveProxy** | HTTP/2 CONNECT | ✅ | ✅ |
| **WireGuard** | UDP | — | — |
| **OpenVPN** | TCP/UDP | ✅ | — |
| **AmneziaWG** | UDP (WireGuard مخفی‌شده) | — | — |

---

### 🛡️ دور زدن DPI (۱۹ تکنیک)

#### جعل هدر هاست (۴ تکنیک — Host Header Spoofing)

**این مهم‌ترین و جدیدترین قابلیت پنل است.**

- **HTTP Host Spoof** — جایگزینی هدر `Host` در اتصالات WebSocket/HTTPUpgrade با یک دامنه معتبر (مثلاً `chat.deepseek.com`). DPI فکر می‌کند به یک سرویس قانونی متصل می‌شوید.
- **WS Host Front** — اتصال از طریق هاست‌های CDN-friendly مانند `rubika.ir` که ترافیک را شبیه پلتفرم‌های ایرانی می‌کند.
- **CDN Host Front** — مسیردهی از طریق CDN (ابر آروان) با دامنه `web.splus.ir` برای مخفی‌سازی پشت CDNهای داخلی.
- **Bug Host Injection** — تزریق هدرهای اضافی (`X-Forwarded-Host`, `X-Host`) برای گیج کردن سیستم‌های DPI stateful با تقلید الگوهای قانونی.

#### فرار در لایه شبکه
- **قطعه‌قطعه‌سازی (Fragmentation)** — تقسیم بسته‌ها به قطعات کوچک با اندازه، تعداد و فاصله قابل تنظیم. بافر DPI رو پر می‌کنه.
- **بسته‌های نویز (Noise Packets)** — تزریق بسته‌های تصادفی برای شکستن الگوی آماری VPN. قابل تنظیم: سایز و تأخیر.
- **جعل اثر انگشت TLS** — تقلید اثر انگشت TLS مرورگرهای Chrome، Firefox، Safari یا تصادفی برای دور زدن JA3/JA4 fingerprinting.
- **TCP Keepalive** — نگه‌داشتن اتصال دائم برای جلوگیری از پاک شدن از جدول state فایروال.
- **MUX (مالتی‌پلکس)** — ترکیب چند اتصال در یک جریان TCP برای کاهش سربار و مخفی‌سازی.

#### فرار پیشرفته
- **تونل‌زنی DNS** — کپسوله کردن داده در کوئری‌های DNS. فایروال‌ها معمولاً DNS رو بلاک نمی‌کنند حتی در شبکه‌های محدود.
- **تونل‌زنی ICMP** — انتقال داده در بسته‌های ICMP (ping). فایروال‌ها معمولاً ICMP رو بازرسی نمی‌کنند.
- **Domain Fronting** — استفاده از گواهی CDN معتبر برای اتصال به سرور VPN. DPI فقط دامنه CDN رو می‌بینه.
- **CDN Fronting** — مسیردهی ترافیک از طریق CDNهای معتبر برای مخفی‌سازی مقصد واقعی.
- **تاب‌آوری پیشرفته شبکه** — بازچینی بسته‌ها، پرش پورت پویا، تولید ترافیک جعلی HTTP، شکل‌دهی ترافیک، مسیریابی چندمسیره و پرش پروتکل.

---

#### امنیت
- 🔒 **احراز هویت ۲ مرحله‌ای (2FA)** — کد TOTP با Google Authenticator/Authy
- 🛡️ **محافظت CSRF و XSS** — هدرهای امنیتی روی تمام پاسخ‌ها
- 🚫 **محدودیت نرخ** — محافظت در برابر Brute Force با قفل تصاعدی
- 🚷 **Fail2Ban** — مسدودسازی خودکار IP بعد از تلاش‌های مکرر
- 📝 **لاگ حسابرسی** — ثبت همه رویدادهای امنیتی
- 🔑 **توکن JWT** — احراز هویت بدون حالت با طول عمر قابل تنظیم

#### رابط کاربری
- 🎨 **طراحی Shadow Ops** — ترمینال بروتالیسم × المان‌های ایرانی
- 🌐 **RTL/LTR خودکار** — تشخیص زبان مرورگر و اعمال جهت مناسب
- 🔄 **تغییر جهت** — دکمه تعویض LTR/RTL با ذخیره در کوکی
- ⚡ **به‌روزرسانی لحظه‌ای** — آمار سیستم زنده
- 📱 **واکنش‌گرا** — پشتیبانی کامل موبایل و تبلت
- 🔔 **اعلان‌ها** — Toast notification برای بازخورد
- 📋 **تولید خودکار کانفیگ** — ساخت کانفیگ کلاینت Xray با QR کد

---

### 📦 نصب

#### نصب با یک دستور (پیشنهادی)

```bash
bash <(curl -sL https://raw.githubusercontent.com/v74all/Spiritus/main/install.sh)
```

این دستور به‌صورت خودکار:
- وابستگی‌ها (Python 3.10+، Xray-core، Redis) رو نصب می‌کنه
- محیط مجازی Python راه‌اندازی می‌کنه
- سرویس systemd رو تنظیم می‌کنه
- کرون‌جاب آپدیت خودکار روزانه تنظیم می‌کنه

#### نصب دستی

```bash
git clone https://github.com/v74all/Spiritus.git
cd Spiritus
pip install -r requirements.txt

# (اختیاری) DPI evasion
pip install -r requirements-dpi.txt

# (اختیاری) Network resilience
pip install -r requirements-firewall.txt
```

---

### ⚙️ تنظیمات

پیکربندی با متغیرهای محیطی یا فایل `.env`:

```bash
# سرور
export VPN_SERVER_IP="آی‌پی-سرور"
export VPN_SERVER_PORT="443"
export VPN_SNI_HOST="www.google.com"
export VPN_WEB_PORT="38471"
export VPN_API_PORT="10085"

# امنیت
export VPN_SESSION_LIFETIME_HOURS="72"
export VPN_MAX_LOGIN_ATTEMPTS="5"
export VPN_LOCKOUT_SECONDS="600"
```

---

### 🚀 اجرا

```bash
# توسعه
uvicorn app.main:app --host 0.0.0.0 --port 38471 --reload

# تولید (systemd)
sudo cp vpn-panel.service /etc/systemd/system/
sudo systemctl enable vpn-panel
sudo systemctl start vpn-panel
```

### دسترسی

```
آدرس: http://آی‌پی-سرور:38471
رمز پیش‌فرض: داخل فایل vpn-panel-password بعد از اولین اجرا
```

---

### 🔄 آپدیت خودکار

```bash
# وضعیت آپدیت خودکار
crontab -l | grep spiritus

# آپدیت دستی
cd /opt/spiritus && git pull && sudo systemctl restart vpn-panel
```

---

### 📁 ساختار پروژه

```
Spiritus/
├── app/                         # اپلیکیشن FastAPI
│   ├── main.py                  # نقطه ورود، روت‌های قالب، کانفیگ اشتراک
│   ├── auth.py                  # احراز هویت، JWT، TOTP/2FA
│   ├── config.py                # تنظیمات از متغیرهای محیطی
│   ├── database.py              # SQLAlchemy غیرهمگام + SQLite/PostgreSQL
│   ├── models.py                # مدل‌های ORM (Admin, User, Agent, ...)
│   ├── dpi_evasion.py           # موتور DPI Evasion (قطعه‌قطعه‌سازی، نویز، تونل‌زنی)
│   ├── protocol_engine.py       # تولید کانفیگ چند-پروتکلی
│   ├── security.py              # Fail2Ban، محدودیت نرخ، لاگ حسابرسی
│   ├── redis_client.py          # لایه کش Redis
│   ├── payments.py              # سیستم ردیابی پرداخت
│   ├── reseller.py             # مدیریت فروشندگان
│   ├── telegram_bot.py          # ادغام ربات تلگرام
│   ├── orchestrator.py          # هماهنگی سرویس
│   ├── observability.py         # نظارت و متریک
│   ├── celery_tasks.py          # صف وظایف غیرهمگام
│   └── api/                     # ماژول‌های API
│       ├── auth.py              # ورود، 2FA، تنظیمات 2FA
│       ├── users.py             # CRUD کاربران، جستجو
│       ├── agents.py            # مدیریت نماینده‌ها
│       ├── compat.py            # API تنظیمات قدیمی، info سرور
│       ├── dpi.py               # کنترل تکنیک‌های DPI
│       ├── protocols.py         # لیست و وضعیت پروتکل‌ها
│       ├── system.py            # سلامت سیستم، آمار
│       ├── security.py          # تنظیمات امنیتی و لاگ
│       ├── payments.py          # پرداخت‌ها
│       ├── resellers.py         # فروشندگان
│       └── abuse.py             # گزارش تخلفات
├── static/
│   ├── css/panel.css            # تم تیره Shadow Ops
│   ├── js/
│   │   ├── panel.js             # فرانت‌اند کامل پنل (۳۲۷۱ خط)
│   │   └── qrcode.js            # کتابخانه QR
│   └── logo.png                 # لوگوی Spiritus
├── templates/
│   ├── panel.html               # پنل مدیریت اصلی
│   ├── agent-panel.html         # پنل نماینده
│   └── sub.html                 # صفحه اشتراک کاربر با QR کد
└── ...
```

**مجموع**: ~۲۴,۰۰۰ خط کد در ۳۷ فایل

---

### 🎛️ تنظیمات پنل

تنظیمات در یک مودال **۵ تب** سازماندهی شده:

1. **پروتکل‌ها** — فعال/غیرفعال کردن پروتکل‌ها، تنظیمات Reality/XHTTP/Vision
2. **DPI و امنیت** — جعل هدر هاست (۴ روش)، دامنه‌ها، Fingerprint TLS، نویز، قطعه‌قطعه‌سازی، Keepalive، MUX
3. **شبکه و CDN** — تونل‌زنی DNS/ICMP، Domain/CDN Fronting، تاب‌آوری شبکه
4. **اعلان‌ها و پشتیبان** — توکن تلگرام، زمان‌بندی پشتیبان
5. **سیستم** — IP سرور، پورت، SNI، طول عمر نشست، تنظیمات قفل

---

### 🔧 مرجع API

| دسته | آدرس | متد | احراز | توضیح |
|------|-------|-----|-------|-------|
| **ورود** | `/auth/login` | POST | — | ورود با نام کاربری و رمز |
| **ورود** | `/auth/login/2fa` | POST | — | ورود با 2FA |
| **ورود** | `/auth/setup-2fa` | POST | JWT | تنظیم 2FA |
| **ورود** | `/auth/me` | GET | JWT | اطلاعات کاربر فعلی |
| **کاربران** | `/api/users` | GET/POST | JWT | لیست/ساخت کاربر |
| **کاربران** | `/api/users/<name>` | DELETE | JWT | حذف کاربر |
| **کاربران** | `/api/users/<name>/toggle` | POST | JWT | فعال/غیرفعال |
| **جستجو** | `/api/search?q=<query>` | GET | JWT | جستجوی کاربران |
| **تحلیل** | `/api/analytics?days=<n>` | GET | JWT | تحلیل ترافیک |
| **پشتیبان** | `/api/backup/create` | POST | JWT | پشتیبان‌گیری |
| **سیستم** | `/api/health` | GET | JWT | سلامت سیستم |
| **تنظیمات** | `/api/settings` | GET/POST | JWT | دریافت/ذخیره تنظیمات |
| **تنظیمات** | `/api/settings/reset` | POST | JWT | بازنشانی به پیش‌فرض |
| **DPI** | `/api/dpi/status` | GET | JWT | وضعیت تکنیک‌های DPI |
| **جهت** | `/api/direction` | POST | — | تنظیم کوکی LTR/RTL |

---

### 🔒 نکات امنیتی

1. **حتماً 2FA رو فعال کنید**
   - از مسیر: Settings → DPI & Security → Setup 2FA
   - با Google Authenticator یا Authy اسکن کنید

2. **رمز پیش‌فرض رو عوض کنید**
   - بعد از اولین لاگین پسورد رو تغییر بدید

3. **پشتیبان‌گیری منظم**
   - تنظیم پشتیبان‌گیری خودکار از تب Notifications & Backup

---

### 🐛 رفع مشکلات

#### پنل اجرا نمیشه
```bash
# پورت اشغال شده؟
netstat -tlnp | grep 38471

# لاگ‌ها
journalctl -u vpn-panel -f
```

#### خطای "Settings are still loading"
این یعنی API تنظیمات فراخوانی نشده. بررسی کنید:
1. هنوز لاگین هستید (خارج نشده باشید)
2. سرور پنل در حال اجراست: `systemctl status vpn-panel`
3. دیتابیس قابل دسترسه: `ls -la /root/vpn_users.db`

#### مشکلات Xray
```bash
# وضعیت Xray
systemctl status xray

# ری‌استارت
systemctl restart xray

# لاگ‌های Xray
journalctl -u xray -f
```

---

### 🧪 مکانیزم دور زدن DPI

#### معماری
```
کلاینت (v2rayNG/Nekobox/...)
    ↓ اتصال رمزگذاری شده TLS
DPI فایروال Stateful (تحلیل الگوی ترافیک)
    ↓
Xray-core Inbound (روی سرور شما)
    ↓
App (main.py) با پارامترهای DPI Evasion کانفیگ می‌سازه
```

#### توضیح تکنیک‌ها

**قطعه‌قطعه‌سازی (Fragmentation)** — بسته‌های TCP به قطعات کوچک تقسیم می‌شن (قابل تنظیم: ۱-۱۰۰ قطعه، تأخیر ۰-۳۰ms). سیستم‌های DPI باید قطعات رو سرهم کنند تا محتوا رو بازرسی کنند. قطعات زیاد بافر DPI رو پر کرده یا timeout می‌ده.

**بسته‌های نویز (Noise Packets)** — بسته‌های تصادفی (۶۴-۱۵۰۰ بایت) در فواصل قابل تنظیم تزریق می‌شن. این کار الگوی آماری VPN رو می‌شکنده — ترافیک واقعی یه توزیع اندازه بسته مشخص داره؛ نویز این توزیع رو صاف می‌کنه.

**جعل Fingerprint TLS** — ماژول `utls` در Xray دست‌دادن TLS مرورگرهای معروف رو تقلید می‌کنه. DPI فکر می‌کنه این ترافیک یه مرورگره، نه VPN.

**جعل Host Header** — برای پروتکل‌های WS/HTTPUpgrade، هدر `Host` جایی هست که DPI مقصد رو تشخیص میده. جایگزینی با `chat.deepseek.com` باعث می‌شه DPI فکر کنه به سرور DeepSeek وصل می‌شید.

**Domain Fronting** — ترافیک از طریق CDN مسیردهی می‌شه. SNI با گواهی CDN مطابقت داره اما مقصد واقعی بک‌اند سرور VPN شماست.

**تونل‌زنی DNS** — داده‌ها در کوئری‌های DNS به یه دامنه تحت کنترل کپسوله می‌شن. DNS تقریباً هیچوقت حتی در محدودترین شبکه‌ها بلاک نمی‌شه.

---

### ⚠️ هشدار

**این پروژه فقط برای مقاصد آموزشی و محافظت از حریم خصوصی مجاز است.**

- از این تکنیک‌ها **فقط** روی سیستم‌هایی استفاده کنید که مالک آن هستید یا اجازه صریح دارید
- استفاده غیرمجاز از قابلیت‌های تست شبکه **غیرقانونی** است
- همیشه قوانین محلی را رعایت کنید
- تکنیک‌های DPI Evasion برای حفظ حریم خصوصی در محیط‌های شبکه محدودکننده طراحی شده‌اند

---

### 📄 مجوز

MIT License — [LICENSE](LICENSE).

---

### 🎉 تشکر

- **Xray-core**: https://github.com/XTLS/Xray-core
- **V2Fly**: https://www.v2fly.org/
- **FastAPI**: https://fastapi.tiangolo.com/

---

**نسخه**: 2.0.0 · **آخرین بروزرسانی**: می ۲۰۲۶ · **تکنولوژی**: FastAPI + Xray-core · **وضعیت**: آماده تولید ✅
