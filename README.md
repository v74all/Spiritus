<p align="center">
  <img src="static/logo.png" alt="Spiritus" width="160">
</p>

<h1 align="center">Spiritus</h1>

<p align="center">
  <strong>A modern, security-hardened VPN management panel for Xray-core &amp; sing-box —<br>built for censorship-heavy networks, multi-tenant resellers, and a native mobile client.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.13-3776AB.svg?logo=python&logoColor=white" alt="Python 3.13">
  <img src="https://img.shields.io/badge/FastAPI-0.136-009688.svg?logo=fastapi&logoColor=white" alt="FastAPI 0.136">
  <img src="https://img.shields.io/badge/Xray--core-%E2%9C%93-orange.svg" alt="Xray-core">
  <img src="https://img.shields.io/badge/sing--box-1.14-blueviolet.svg" alt="sing-box 1.14">
  <img src="https://img.shields.io/badge/protocols-13-success.svg" alt="13 protocols">
  <img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="MIT License">
</p>

<p align="center">
  <a href="#-highlights">Highlights</a> ·
  <a href="#-screenshots">Screenshots</a> ·
  <a href="#-protocols">Protocols</a> ·
  <a href="#-security">Security</a> ·
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-mobile-client">Mobile Client</a> ·
  <a href="#فارسی">فارسی</a>
</p>

---

## ✨ Highlights

- **13 transport protocols** on Xray-core, sing-box and mita — REALITY, XHTTP, Vision, CDN-fronting, Hysteria2, TUIC, ShadowTLS, NaiveProxy, WireGuard and Mieru — each tested end to end with real clients.
- **Users take effect live** — create, renew, disable or delete a user and Xray picks it up through its API in about a second: no restart, nobody else disconnected.
- **Quotas, expiry and speed limits that are enforced** — traffic is counted per user (and per day), users are cut off at their quota or date and come back on renewal; per-user speed limits run in the kernel (tc + nftables).
- **A profile for every client** — Base64 links, Xray JSON, a sing-box profile (Hiddify, NekoBox) and a Clash Meta profile (Clash Verge, FlClash), plus a bilingual subscription page with one-tap import.
- **Built-in DPI evasion** — TLS fragmentation, noise padding, REALITY camouflage, Hysteria2 port hopping, SNI rotation, and an emergency cloak driven by in-country probes.
- **Multi-tenant by design** — admins, traffic-quota agents with their own panel, and resellers with commission tracking.
- **Security-first** — CSP with per-request nonces, HSTS preload, double-submit CSRF, pinned-algorithm JWT, TOTP 2FA, host-header allowlisting, rate-limiting + fail2ban, and a root helper that only runs allowlisted operations.
- **Operable** — one-command installer, systemd units, Prometheus metrics, Telegram alerts, automated backups, and three themes.

---

## 📸 Screenshots

<p align="center">
  <img src="docs/screenshots/users-live.png" alt="Users and subscriptions: live speed, quota, validity and status per user" width="900">
</p>
<p align="center"><em>Users &amp; subscriptions: live speed, quota, validity and status (active, expired, quota used) for every account.</em></p>

### Three themes

<table>
  <tr>
    <th>Obsidian</th><th>CyberOps</th><th>Midnight</th>
  </tr>
  <tr>
    <td><img src="docs/screenshots/theme-obsidian-dashboard.png" alt="Mission control, Obsidian theme"></td>
    <td><img src="docs/screenshots/theme-cyberops-dashboard.png" alt="Mission control, CyberOps theme"></td>
    <td><img src="docs/screenshots/theme-midnight-dashboard.png" alt="Mission control, Midnight theme"></td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/theme-obsidian-users.png" alt="Users, Obsidian theme"></td>
    <td><img src="docs/screenshots/theme-cyberops-users.png" alt="Users, CyberOps theme"></td>
    <td><img src="docs/screenshots/theme-midnight-users.png" alt="Users, Midnight theme"></td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/theme-obsidian-login.png" alt="Sign-in, Obsidian theme"></td>
    <td><img src="docs/screenshots/theme-cyberops-login.png" alt="Sign-in, CyberOps theme"></td>
    <td><img src="docs/screenshots/theme-midnight-login.png" alt="Sign-in, Midnight theme"></td>
  </tr>
</table>

### Configs and subscriptions

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/config-sheet.png" alt="Config sheet with every protocol and a QR code"><br><sub>Per-user config: every protocol the server runs, with QR</sub></td>
    <td width="50%"><img src="docs/screenshots/config-subscriptions.png" alt="Subscription page, sing-box and Clash profile links"><br><sub>Subscription page, sing-box and Clash Meta profiles</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/config-hysteria2.png" alt="Hysteria2 config"><br><sub>Hysteria2 with Salamander and a pinned certificate</sub></td>
    <td width="50%"><img src="docs/screenshots/config-wireguard.png" alt="WireGuard config"><br><sub>WireGuard: per-user keys, scan the QR in the WireGuard app</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/subscription-page.png" alt="Customer subscription page"><br><sub>What each customer sees: status, usage, one-tap import</sub></td>
    <td width="50%"><img src="docs/screenshots/subscription-mobile-fa.png" alt="Customer page on a phone, Persian"><br><sub>The same page on a phone, in Persian (RTL)</sub></td>
  </tr>
</table>

### Operations

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/protocol-engine.png" alt="Protocol engine and DPI"><br><sub>Protocol engine: listening ports, REALITY dest checks, success from Iran</sub></td>
    <td width="50%"><img src="docs/screenshots/war-room.png" alt="Cyber war-room"><br><sub>War-room: attacks, DPI posture, automatic emergency cloak</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/sentinel-probes.png" alt="Sentinel probes"><br><sub>Sentinel probes inside Iran report what each carrier lets through</sub></td>
    <td width="50%"><img src="docs/screenshots/carrier-steering.png" alt="Carrier steering"><br><sub>Carrier steering: best protocol per carrier</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/online-users.png" alt="Online users with connected IPs"><br><sub>Who is online, from which IPs</sub></td>
    <td width="50%"><img src="docs/screenshots/system-details.png" alt="System details with daily traffic"><br><sub>System details and real daily traffic</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/financials.png" alt="Financials and billing"><br><sub>Payments (Zarinpal, IDPay, USDT) and reseller wallets</sub></td>
    <td width="50%"><img src="docs/screenshots/agents.png" alt="Agents"><br><sub>Agents: quota sold and used, one-click mobile login</sub></td>
  </tr>
</table>

<details>
<summary><b>More screens</b>: agent panel, settings, edge nodes, security, add-user sheet, phone, website</summary>

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/agent-panel.png" alt="Agent panel"><br><sub>Agent panel: an agent sees and sells only their own users</sub></td>
    <td width="50%"><img src="docs/screenshots/agent-groups.png" alt="Agent groups"><br><sub>Agent panel: bulk-created groups</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/settings.png" alt="Settings"><br><sub>Settings: one row per option, sections fold</sub></td>
    <td width="50%"><img src="docs/screenshots/add-user-sheet.png" alt="Add user side sheet"><br><sub>Add user: side sheet, presets, speed limit</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/edge-nodes.png" alt="Edge nodes"><br><sub>Edge nodes and their reachability</sub></td>
    <td width="50%"><img src="docs/screenshots/carrier-diagnostics.png" alt="Carrier diagnostics"><br><sub>Carrier diagnostics</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/security-audit.png" alt="Security and audit"><br><sub>Security &amp; audit log</sub></td>
    <td width="50%"><img src="docs/screenshots/confirm-bar.png" alt="Confirm bar"><br><sub>No browser pop-ups: confirmations slide in at the bottom</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/backup.png" alt="Backup"><br><sub>Encrypted backups</sub></td>
    <td width="50%"><img src="docs/screenshots/help.png" alt="Help"><br><sub>Built-in help (English / Persian)</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/mobile-panel.png" alt="Admin panel on a phone"><br><sub>The admin panel on a phone (CyberOps)</sub></td>
    <td width="50%"><img src="docs/screenshots/landing.png" alt="Project website"><br><sub>Project website</sub></td>
  </tr>
</table>

</details>

<sub>Screenshots use demo data on a test server: addresses are from the 203.0.113.0/24 documentation range, and the "online" users are real clients connected over loopback.</sub>

---

## 🔌 Protocols

| Engine | Protocol | Transport / Flow | TLS | CDN |
|--------|----------|------------------|:---:|:---:|
| Xray | **VLESS + XHTTP + REALITY** | XHTTP | REALITY | — |
| Xray | **VLESS + REALITY + Vision** | XTLS-Vision | REALITY | — |
| Xray | **VLESS-Reverse-REALITY** | TCP | REALITY | — |
| Xray | **VLESS + WS** | WebSocket | ✅ | ✅ |
| Xray | **VMess + WS / gRPC / HTTPUpgrade** | WebSocket, gRPC, HTTPUpgrade | ✅ | ✅ |
| Xray | **Trojan** (TCP, or WS behind a CDN) | TCP / WebSocket | ✅ | ✅ |
| Xray | **Shadowsocks-2022** | TCP + UDP, one key per user | — | — |
| sing-box | **Hysteria2** | QUIC + Salamander + port hopping | ✅ | — |
| sing-box | **TUIC v5** | QUIC | ✅ | — |
| sing-box | **ShadowTLS v3** | TLS camouflage + Shadowsocks-2022 | borrowed | — |
| sing-box | **NaiveProxy** | HTTP/2 CONNECT | ✅ | — |
| sing-box | **WireGuard** | UDP | — | — |
| mita | **Mieru** | obfuscated TCP or UDP | — | — |

Every protocol in this table was run end to end with real clients (Xray 26, sing-box 1.14, mihomo 1.19, mieru 3.38): each user has their own credentials, is added and removed live (no restart, no dropped connections for others), counted, and cut off at their quota or expiry date. Per-user speed limits apply to all of them except Mieru (tc + nftables per user, through the root helper).

AmneziaWG and OpenVPN are not available yet: they need server components the installer does not set up, so the panel does not offer them.

Subscriptions:

- `/sub-api/{uuid}`: Base64 share links (V2RayNG, Hiddify, Streisand, v2rayN)
- `/sub-json/{uuid}`: Xray JSON (V2RayNG, Streisand), with Fragment / MUX
- `/sub-singbox/{uuid}`: sing-box profile (Hiddify, NekoBox, sing-box apps), the only one with ShadowTLS and WireGuard
- `/sub-clash/{uuid}`: Clash Meta / mihomo profile (Clash Verge, FlClash), with ShadowTLS and Mieru
- `/sub/{uuid}`: the styled page each customer sees

All carry `Subscription-Userinfo` traffic / expiry headers.

---

## 🔒 Security

Spiritus is built to be exposed to hostile networks. Defenses are layered:

**Transport & headers**
- Content-Security-Policy with **per-request nonces** (no `unsafe-inline`)
- HSTS `max-age=2y; includeSubDomains; preload`
- `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP/CORP
- **Host-header allowlist** (`ALLOWED_HOSTS`) — neutralizes Host / BadHost poisoning
- **Request body-size cap** (`MAX_REQUEST_BODY_BYTES`) — anti-DoS

**Authentication & sessions**
- Argon2 password hashing with a configurable strength policy
- **TOTP 2FA** with one-time challenge tokens
- JWT pinned to **HS256** — `alg:none` and algorithm-confusion rejected; JTI revocation list
- Cookies are `HttpOnly` + `Secure` + `SameSite=Strict`
- **Double-submit-cookie CSRF** on every unsafe method
- Brute-force lockout + global rate-limiting + fail2ban integration
- **Mobile refresh tokens** — single-use rotation with reuse detection (a replayed token revokes the whole session family)
- Optional **admin IP allowlist** (`ADMIN_IP_ALLOWLIST`)

**Data & auditing**
- **Tamper-evident audit log** — HMAC hash-chain, verifiable via `GET /api/security/audit/verify`
- **Encrypted backups** (Fernet) with `0600` permissions
- Honeypot endpoints that feed the audit log and fail2ban

**Supply chain & code**
- Dependencies **audited with `pip-audit` (0 known CVEs)** and pinned to patched floors
- `bandit` static analysis; SSRF-safe resolver; mTLS for the privileged helper
- Optional Prometheus alert rules for failed logins, honey-tokens, and pool exhaustion

> See [SECURITY.md](SECURITY.md) for the threat model and responsible-disclosure policy.

---

## 🚀 Quick Start

**Requirements:** a fresh Ubuntu 22.04+ or Debian 12 server, root access and 1 GB of RAM. **No domain needed:** REALITY protocols need no certificate, and the installer gets a Let's Encrypt certificate for the server's IP (clients never need "allow insecure").

**One-line install** — downloads and runs the installer, which clones the repo into `/opt/v7lthronyx`:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/v74all/Spiritus/main/install.sh)"
```

It ends by printing the panel address, username and password. Step-by-step guide with common problems (Persian and English): [INSTALL.md](INSTALL.md).

Useful flags:

```bash
sudo ./install.sh --port 8080         # custom web port
sudo ./install.sh --help              # all options
sudo ./install.sh uninstall           # remove (keep data)
sudo ./install.sh uninstall --purge   # remove everything
sudo ./install.sh reset-password      # forgot the admin password: print a new one
```

The installer provisions PostgreSQL + Redis, a Python virtualenv, Xray/sing-box binaries, TLS certificates (acme.sh), and the systemd services.

**Manual / development run:**

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then edit the secrets (see below)
uvicorn app.main:app --host 127.0.0.1 --port 38471
```

---

## ⚙️ Configuration

All settings come from environment variables (`.env`). The essentials:

| Variable | Purpose |
|----------|---------|
| `SECRET_KEY`, `JWT_SECRET_KEY` | **Required.** Unique high-entropy secrets. |
| `DATABASE_URL` | PostgreSQL DSN (SQLite for local dev). |
| `REDIS_URL` | Rate-limit / session store. |
| `ALLOWED_HOSTS` | **Recommended.** Comma-separated panel domain(s). |
| `MAX_REQUEST_BODY_BYTES` | Max request body in bytes (default 2 MiB). |
| `ADMIN_BOOTSTRAP_PASSWORD` | One-shot first-admin password (auto-cleared). |
| `CORS_ORIGINS` | Off by default; set an explicit allowlist if needed. |
| `ADMIN_IP_ALLOWLIST` | Optional IPs/CIDRs allowed to reach the admin API (loopback always allowed). |
| `BACKUP_ENCRYPTION_KEY` | Dedicated key for encrypted backups (else derived from `SECRET_KEY`). |
| `TELEGRAM_WEBHOOK_SECRET` | Enables `POST /api/telegram/webhook` (≥16 chars; pass as `secret_token` to `setWebhook`). |
| `MOBILE_REFRESH_LIFETIME_DAYS` | Mobile refresh-token lifetime (default 30). |

> ⚠️ Never commit a real `.env`. It is git-ignored by default — keep it that way.

---

## 📱 Mobile Client

A native **Android** app (Kotlin + Jetpack Compose) ships alongside the panel:

- Imports subscriptions or individual `vless / vmess / trojan / ss / hysteria2 / tuic / wireguard` links — works with **any** panel, not just Spiritus.
- Bundles **Xray**, **sing-box**, and **tun2socks** engines (arm64-v8a, armeabi-v7a, x86_64).
- Built-in **management mode**: admins and agents can run the panel from their phone.
- QR import, per-config latency testing, split-tunneling, kill-switch, and a live traffic gauge.

---

## 🏗️ Architecture

```
                 ┌───────────────┐      ┌──────────────┐
   Browser ─────▶│  FastAPI app  │◀────▶│  PostgreSQL  │
   Mobile  ─────▶│  (Spiritus)   │◀────▶│    Redis     │
                 └──────┬────────┘      └──────────────┘
                        │ privileged helper (mTLS)
                        ▼
        ┌──────────────────────────────────────────┐
        │  Xray-core · sing-box · WireGuard · DPI   │
        └──────────────────────────────────────────┘
```

- **`app/protocol_engine.py`** — single source of truth for every protocol & share-link.
- **`app/api/`** — admin, agents, resellers, payments, security, system, DPI, and domain routers.
- **`app/middleware/`** — CSRF + rate-limit. **`app/privileged_helper*`** — least-privilege service control over mTLS.

---

## 🧪 Development

```bash
pip install -r requirements-dev.txt
pytest -q                 # security & contract test suite
pip-audit                 # dependency CVE scan
bandit -c pyproject.toml -r app main.py   # static analysis
ruff check app tests main.py             # lint
```

Kubernetes: a Helm chart lives in [`deploy/helm/spiritus`](deploy/helm/spiritus) (probes: `/api/ready`, `/api/live`).

---

## 📜 License

Released under the [MIT License](LICENSE).

> Spiritus is intended for lawful privacy, anti-censorship, and authorized network administration. You are responsible for complying with the laws and regulations that apply to you.

---

<a id="فارسی"></a>

## 🇮🇷 فارسی

**Spiritus** یک پنل مدیریت VPN مدرن و **امنیت‌محور** برای Xray-core و sing-box است؛ ساخته‌شده برای شبکه‌های پرسانسور، نمایندگی/رزلرِ چندمستاجری، و یک **کلاینت موبایل بومی**.

**ویژگی‌ها**
- **۱۳ پروتکل** روی Xray / sing-box / mita — REALITY، XHTTP، Vision، CDN-fronting، Hysteria2، TUIC، ShadowTLS، NaiveProxy، WireGuard، Mieru — همه با کلاینت واقعی تست‌شده.
- **اعمال فوری کاربر** — ساخت، تمدید، قطع یا حذف کاربر در حدود یک ثانیه روی سرور اعمال می‌شود؛ بدون ری‌استارت و بدون قطع شدن بقیه.
- **حجم، انقضا و محدودیت سرعت واقعی** — مصرف هر کاربر (و هر روز) شمرده می‌شود، با تمام شدن حجم یا تاریخ قطع می‌شود و با تمدید برمی‌گردد؛ محدودیت سرعت در کرنل (tc + nftables) اعمال می‌شود.
- **اشتراک برای هر برنامه** — لینک Base64، JSON برای Xray، پروفایل sing-box (Hiddify و NekoBox) و Clash Meta (Clash Verge و FlClash)، با صفحه‌ی اشتراک دوزبانه و افزودن با یک لمس.
- **دور زدن DPI** — فرگمنت TLS، نویز، REALITY، port hopping در Hysteria2، چرخش SNI، و پوشش اضطراری خودکار بر اساس پراب‌های داخل ایران.
- **چندمستاجری** — ادمین، نماینده با سهمیه‌ی ترافیک و پنل جداگانه، و رزلر با کمیسیون.
- **سه تم** — Obsidian، CyberOps و Midnight (تصاویر بالا).
- **اپ اندروید بومی** (Kotlin/Compose) با موتورهای Xray + sing-box + tun2socks که با هر پنلی کار می‌کند.

**امنیت** — CSP با nonce، HSTS preload، CSRF دو-کوکی، JWT با الگوریتم pin‌شده، 2FA، allowlist هاست، محدودیت حجم بدنه، rate-limit + fail2ban، و وابستگی‌های **بدون CVE شناخته‌شده**.

**نصب سریع (یک‌خط)** — دامنه لازم نیست. نصب‌کننده خودش ریپو را در `/opt/v7lthronyx` clone می‌کند و در آخر آدرس پنل، نام کاربری و رمز را نشان می‌دهد:
```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/v74all/Spiritus/main/install.sh)"
```
راهنمای قدم‌به‌قدم و مشکلات رایج: [INSTALL.md](INSTALL.md)

> ⚠️ فایل `.env` واقعی هرگز نباید commit شود (پیش‌فرض در `.gitignore` است).

پروژه تحت لایسنس **MIT** منتشر شده و فقط برای استفاده‌ی قانونی، حفظ حریم خصوصی و مدیریت مجاز شبکه در نظر گرفته شده است.

### Troubleshooting

- **Error 401 Unauthorized during login or after deployment:**
  If you are unable to login to the panel after installation or receive repeated 401 Unauthorized errors despite correct credentials, ensure that the Redis service is running. The panel uses Redis to verify session revocations, and for security reasons, it fails-closed (denies access) if it cannot reach Redis. You can check the logs using `journalctl -u redis-server` to diagnose any startup issues.
