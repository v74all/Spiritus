# Changelog

All notable changes to Spiritus VPN Panel will be documented in this file.

## [Unreleased]

### 🔐 Security
- **VPN users could reach the server's loopback and private networks.** Every engine sent user traffic to `direct` with no address filter, so any customer could open the unauthenticated Xray API (`127.0.0.1:10085`: add users, read everyone's traffic), Redis, the panel as a loopback client (bypassing `ADMIN_IP_ALLOWLIST` and login rate limits), the cloud metadata service and the provider's private network. Xray (first routing rule, `IPOnDemand` so `localhost` is caught too), sing-box (`resolve` + `reject`) and mita (egress `REJECT`) now refuse `app/egress_policy.py`'s list. The sing-box Clash API, which listed every user's connections, now needs a secret.
- **Panel user → root.** The root helper ran `python -m` from `/opt/v7lthronyx` with the panel's `.env` as its `EnvironmentFile`, and root's cron ran `/opt/v7lthronyx/scripts/auto-update.sh`, all owned by `vpnpanel`. A panel compromise could edit the code, the venv or the script, plant `json.py` next to `app/`, set `LD_PRELOAD` in `.env`, or point a symlink at `/etc/shadow` for the root-run cert hook to `chown`. `install.sh` now keeps the tree root-owned (`secure_install_tree`); the panel owns only `data/`, `backups/`, `mtls/`, its logs and `.env`. The helper no longer reads `.env` as its environment, the updater lives in `/usr/local/sbin`, the beat schedule moved to `data/` and `vpn-settings.json` follows `PANEL_DATA_DIR`.
- **The domain proxy hid every client IP.** nginx's SNI split reached the panel as `127.0.0.1`, which the admin IP allowlist always lets in and which put every visitor in one login bucket. nginx now speaks PROXY protocol to the panel and to Xray behind it.
- **Root wrote panel-chosen strings into nginx.conf and acme.sh.** The helper accepted any certificate path under `/opt/v7lthronyx` (a `;` or newline in a file name added nginx directives, parsed by root), and the ACME email only had a length check (acme.sh sources it from a shell file). Paths must now be plain names inside the TLS directories; emails must be plain addresses.
- Agent and reseller tokens were accepted as admin-account tokens when the names matched; `/api/auth/setup-2fa` replaced an existing second factor with a session token alone. It now needs the password, plus the current code when 2FA is on.
- Redis gets a password on bare-metal installs (`requirepass`, as docker-compose already did).
- Log messages are kept to one line, so a username cannot forge `Failed login attempt ... from <ip>` lines for fail2ban.
- Bounds on bulk-create (`pad` built gigabyte names) and on `days`.
- Dependencies: ~180 known advisories in the pinned DPI/firewall/dev sets (aiohttp 3.9.1, scapy 2.5.0, h2, hpack, dnspython, black) and floors in `requirements.txt` that allowed vulnerable aiohttp, cryptography, PyJWT, requests, jinja2 and scapy. All files now audit clean; CI audits the pinned sets too.

## [2.1.0] - 2026-10-12

### 🔐 Security
- **Tamper-evident audit log**: `audit_log` rows are HMAC hash-chained (`app/audit.py`); login, 2FA, logout, password change, backups, reseller/wallet actions are recorded. `GET /api/security/audit`, `GET /api/security/audit/verify`.
- **Mobile refresh tokens** with single-use rotation and reuse detection (`POST /api/mobile/auth/refresh`); logout and reuse revoke the whole session family.
- **Logout now revokes the token** on the legacy cookie endpoint (previously only the cookie was cleared, so a stolen token stayed valid).
- **Admin IP allowlist** (`ADMIN_IP_ALLOWLIST`) for the admin API; public endpoints stay open.
- **Encrypted backups** (Fernet, `BACKUP_ENCRYPTION_KEY`), `0600` files in a `0700` directory; strict backup-name validation on restore. Legacy plain `.json` backups can still be restored.
- Honeypot endpoints feed the audit log and fail2ban; privileged-helper config files are created `0640` atomically.
- Replaced `python-jose` (pulled in vulnerable `ecdsa`, PYSEC-2026-1325) with `PyJWT`; replaced unmaintained `passlib` with `argon2-cffi` (existing hashes remain valid); dropped unused `pycryptodome`.

### 🐛 Fixes
- **Duplicate VPN usernames are now refused** across every create path (admin, agent, bulk, reseller, mobile). The `vpn_users` table has no unique constraint, so two users could share a name; every by-name action (`/users/{name}/toggle|renew|delete`) then failed with a `MultipleResultsFound`-style error and the user became unmanageable. Centralised in `app/services/user_names.py`.
- **`constraints.txt` could not resolve**: it pinned `pydantic-settings==2.14.0` while `requirements.txt` required `>=2.14.2` (the GHSA fix), so every constrained install — the Docker image and CI — failed. Pinned to `2.14.2`.

### ✨ Features
- **Multi-level resellers**: sub-resellers (depth ≤ 3), differential commissions up the tree, wallet ledger with atomic non-overdraw debits, reseller self-service endpoints (`/api/resellers/me*`).
- **Telegram self-service** (`/link`, `/usage`, `/plans`, `/renew`) and an authenticated webhook (`TELEGRAM_WEBHOOK_SECRET`).
- uTLS fingerprint rotation and automatic protocol failover (`/api/dpi/fingerprint*`, `/api/dpi/protocol-rotation*`); Hysteria2 port-hop (`mport` share links + NAT rule generator); plain WireGuard protocol spec.
- Multi-node config sync: `POST /api/agents/sync-config` pushes one config to all online agent nodes, skipping unchanged nodes and isolating per-node failures (HTTP agent channel; no gRPC).
- Helm chart (`deploy/helm/spiritus`), Dependabot, hardened Dockerfile/compose (Python 3.13, `cap_drop`, `no-new-privileges`).

### 🔧 Maintenance
- `app/api/compat.py` split into the `app/api/compat/` package (same routes, same order).
- Missing `greenlet` dependency added (async SQLAlchemy failed to import on a clean install).
- Ruff clean on `app/`, `tests/`; Bandit clean at medium severity; CI runs Python 3.13, Semgrep and pip-audit.
- Tests: 94 → 140+.

## [1.0.0] - April 2026

### 🎉 Initial Public Release

### ✨ Features
- User management with search, bulk operations, and statistics
- Multi-protocol support (VMess, VLESS, Trojan, gRPC, HTTPUpgrade, SS2022)
- Agent system with quotas and group management
- Traffic analytics and reporting
- Backup and restore system
- Data export (CSV/JSON)
- System health monitoring
- DPI evasion techniques
- Dark theme UI with glassmorphism
- Responsive design for mobile
- Rate limiting and security headers
- Auto-update from GitHub

### 🔧 Infrastructure
- Easy install script with one-command setup
- Systemd service configuration
- Automatic daily update checks
- Environment variable configuration
- MIT License
- **Online Users**: View currently connected users
- **Kill Switch**: Automatic disconnection on suspicious activity

### 🔄 Changed
- Improved traffic classification accuracy
- Enhanced DPI evasion techniques
- Better support for regional networks

## [1.0.0] - February 2026

### ✨ Initial Release
- Basic user management
- VMess and VLESS protocols
- Traffic monitoring
- Configuration generation
- Web-based panel

---

## Version Format

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality
- **PATCH**: Backwards-compatible bug fixes

## Upcoming Features

### [2.1.0] - Planned
- [ ] Multi-language support (Persian, Arabic, English)
- [ ] Advanced analytics with charts
- [ ] User notifications system
- [ ] API key management
- [ ] Webhook integrations
- [ ] Mobile app

### [2.2.0] - Planned
- [ ] Load balancing support
- [ ] Geographic routing
- [ ] Advanced firewall rules
- [ ] Custom branding
- [ ] White-label solution

### [3.0.0] - Planned
- [ ] Distributed architecture
- [ ] High availability setup
- [ ] Advanced security features
- [ ] AI-powered traffic analysis
- [ ] Blockchain-based authentication

---

**For more information, visit**: [GitHub Repository](https://github.com/example/vpn-panel)
