# Changelog

All notable changes to Spiritus VPN Panel will be documented in this file.

## [Unreleased]

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
- Network resilience tools
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