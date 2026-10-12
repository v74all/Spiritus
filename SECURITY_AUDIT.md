# Security Audit & Hardening — 2026-05-19

Scope: V7LTHRONYX VPN Panel (FastAPI + Jinja2, multi-role: admin / agent /
reseller). Audit covered authentication & session handling, input/injection,
configuration & secrets, transport, deployment, and frontend.

User directive: maximum hardening even at the cost of UI breakage; sensitive
local files deleted; **do not push until explicitly authorised**.

## Findings & Fixes

| #  | Severity   | Area                  | Finding (file)                                                                                                     | Status   |
|----|------------|-----------------------|--------------------------------------------------------------------------------------------------------------------|----------|
| 1  | CRITICAL   | Secrets               | Hardcoded default JWT/SECRET (`"change-me"`) in `app_config.py:225,231` and runtime-rotating default in `app/config.py:18`. | FIXED    |
| 2  | CRITICAL   | Auth                  | Plaintext password-file fallback in `app/api/auth.py:137` and `app/api/compat.py:1004-1006` allowed file-read → admin. | FIXED    |
| 3  | CRITICAL   | Sessions              | Logout was a no-op; stolen tokens valid until expiry (`app/api/auth.py:252`).                                       | FIXED    |
| 4  | CRITICAL   | SSRF                  | `/api/google-relay` silently passed on DNS failure; IPv4-only; no IPv6 check (`app/main.py:283-302`).                | FIXED    |
| 5  | HIGH       | CSP                   | `'unsafe-eval'` in CSP weakened XSS containment (`app/main.py:153-160`).                                           | FIXED    |
| 6  | HIGH       | CORS                  | Default `cors_origins="*"` combined with credentials toggle (`app/config.py:20`).                                  | FIXED    |
| 7  | HIGH       | Auth                  | No per-IP/username rate limit on `/auth/login/2fa`; 1M-code TOTP space brute-forceable.                            | FIXED    |
| 8  | HIGH       | Secrets               | `install.sh` hardcoded `DB_PASS="securepassword"` for every install (lines 133, 216, 218).                          | FIXED    |
| 9  | HIGH       | Privilege             | All services ran as `root` (`vpn-panel.service`, `install.sh` units).                                              | FIXED    |
| 10 | HIGH       | RNG                   | `random.choice()` for SNI rotation; predictable to adversary (`app/dpi_evasion.py:250`).                            | FIXED    |
| 11 | HIGH       | Network               | App bound to `0.0.0.0` by default (`app/config.py:23`).                                                            | FIXED    |
| 12 | HIGH       | Auth                  | WebAuthn registration stored attestation without parsing/verifying the public key (`app/security.py:146-149`).      | MITIGATED (feature kept off via `ENABLE_WEBAUTHN=false`; full impl tracked separately) |
| 13 | MEDIUM     | Disclosure            | `/api/docs` and `/api/openapi.json` open to unauthenticated callers in production.                                  | FIXED    |
| 14 | MEDIUM     | Logging               | Full stack traces written to disk on every exception (`app/main.py:170-175`).                                       | FIXED    |
| 15 | MEDIUM     | Path traversal        | `/system/logs` used relative log-file names that resolve against CWD (`app/api/system.py:139-161`).                | FIXED    |
| 16 | MEDIUM     | Cookies               | `secure=False`, `samesite="lax"` on session cookies (`app/api/compat.py:1023, 2896`).                              | FIXED    |
| 17 | MEDIUM     | Auth                  | Password policy was `len(new) < 8` only (`app/api/compat.py:1052`).                                                | FIXED    |
| 18 | MEDIUM     | CSRF                  | Cookie-authenticated state-changing endpoints had no CSRF token requirement.                                       | FIXED    |
| 19 | MEDIUM     | Rate limiting         | Auth rate-limit fail-open on Redis outage.                                                                          | FIXED    |
| 20 | MEDIUM     | Data at rest          | `local.db`, `test.db`, `vpn_users.db`, `vpn-panel-password*` present on disk (containing real credentials).         | FIXED    |
| 21 | LOW        | DB                    | `Fail2banBan.id` was `BIGINT PRIMARY KEY` — SQLite couldn't autoincrement, every login attempt crashed.             | FIXED (incidental bug surfaced while smoke-testing)    |
| 22 | LOW        | Dependencies          | `idna 3.13`, `urllib3 2.6.3`, `pip 26.0.1` carried known CVEs.                                                     | FIXED (upgraded; `pip-audit` clean) |

## What changed (by file)

### Backend hardening
- `app/config.py` — `SECRET_KEY` is REQUIRED (no default, ≥32 chars, weak-token blocklist). `cors_origins` defaults to empty; wildcard rejected at startup. `host` defaults to `127.0.0.1`. `jwt_secret_key` / `csrf_secret` derive from `secret_key` when absent.
- `app_config.py` — legacy module hardened the same way; weak-secret check runs when `STRICT_CONFIG=1` so unrelated read-only imports don't crash.
- `app/auth.py` — JWT now carries `jti` / `iat` / `nbf` (`create_access_token`); `_decode_token_to_user` pins `alg=HS256`, requires `exp`/`sub`, and consults a Redis token blacklist via `_is_token_revoked`. New helpers: `revoke_token(jti, ttl)`, `validate_password_strength(pw)` (12-char min + mixed case + digit + symbol + common-password blocklist).
- `app/api/auth.py` — rewritten. Password-file fallback removed. `/login` returns `totp_required` marker without issuing a usable token. `/login/2fa` has dedicated per-IP+username Redis counter. `/logout` writes the jti onto the Redis blacklist with TTL = remaining expiry. New `bootstrap_initial_admin(db)` runs once at startup from `ADMIN_BOOTSTRAP_PASSWORD`. Rate-limit failure on Redis → 503 (fail-closed for auth paths).
- `app/api/compat.py` — legacy `/api/login` no longer falls back to the password file. `/api/change-password` enforces `validate_password_strength`. Cookies: `secure=True` (unless DEBUG), `samesite="strict"`. Dead `_read_password_file` / `_write_password_file` removed.
- `app/api/system.py` — `/system/logs` uses an absolute-path allowlist; unknown `log_type` returns 404.
- `app/api/users.py` — search input capped at 100 chars; LIKE wildcards escaped.
- `app/dpi_evasion.py` — SNI rotation uses `secrets.choice` (CSPRNG).
- `app/models.py` — `Fail2banBan.id` uses `BigInteger().with_variant(Integer, "sqlite")` so SQLite autoincrement works.
- `app/middleware/rate_limit.py` (new) — per-IP per-path Redis budget, with health/static exemption.
- `app/middleware/csrf.py` (new) — double-submit-cookie pattern; exempts Bearer-authenticated requests and a small list of webhook/login paths.
- `app/main.py` — startup admin bootstrap; CSP nonce + `unsafe-eval` removed; `default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`; HSTS preload; `Referrer-Policy: no-referrer`; `X-XSS-Protection: 0`; COOP/CORP same-origin; CORS only added when explicit origin allowlist is configured. SSRF guard now resolves both A & AAAA and rejects private/loopback/link-local/reserved/multicast/unspecified/cloud-metadata; `follow_redirects=False`; 1 MB response cap. `/api/docs`, `/api/redoc`, `/api/openapi.json` gated behind `settings.debug`. Exception handler logs class name only (no stack trace) unless DEBUG.
- `static/js/panel.js` + `templates/agent-panel.html` — global `fetch` wrapper auto-attaches `X-CSRF-Token` for same-origin unsafe methods.

### Deployment hardening
- `.env` — every secret rotated; `chmod 600`; `ADMIN_BOOTSTRAP_PASSWORD` flagged for one-time use.
- `install.sh` — per-install random DB password (persisted only in `.db-secret` mode 600 and in `.env`). Fresh `SECRET_KEY`, `JWT_SECRET_KEY`, `CSRF_SECRET`, `ARGON2_SALT`, `ADMIN_BOOTSTRAP_PASSWORD` are written into `.env`. New `setup_panel_user` step creates an unprivileged `vpnpanel` user with narrow sudo for `systemctl restart xray` only. systemd units now run as `vpnpanel`, with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp`, `PrivateDevices`, `MemoryDenyWriteExecute`, capability boundary cleared, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `RestrictNamespaces`, `LockPersonality`. Service binds `127.0.0.1` only.
- `vpn-panel.service` — same hardening applied to the legacy unit file in the repo.
- `.gitignore` — `.env`, `.env.*` (except `.env.example`), `*.db`, `vpn-panel-password*`, `*.password`, `*.hash` reinforced.

### Files removed from working tree
- `vpn-panel-password` (plaintext admin pw — `ZA5nBlET0ZRM-4yX`).
- `vpn-panel-password-hash`.
- `local.db`, `test.db`, `vpn_users.db`.
- `vpn-panel.log`.

### Tests
`tests/security/` — 31 tests, all passing:
- `test_password_policy.py` — eight policy assertions.
- `test_jwt_hardening.py` — `alg=none` rejection, wrong-secret rejection, missing-claim rejection, revoked-jti rejection, required-claim issuance.
- `test_config_validators.py` — weak-secret / short-secret / wildcard-CORS rejection at config load.
- `test_ssrf_resolver.py` — 7 cases (loopback, link-local metadata, private nets, IPv6 loopback, unresolvable, localhost keyword, public IP).
- `test_csrf_middleware.py` — six behavioural assertions on the new middleware.

### Verification (recorded against the running dev server)

| Check                                                                      | Result |
|----------------------------------------------------------------------------|--------|
| `curl -I http://127.0.0.1:38471/` — CSP without `unsafe-eval`              | PASS   |
| `/api/docs` in non-debug → 404                                              | PASS   |
| Forged JWT `alg=none` → 401                                                 | PASS   |
| Login → /auth/me OK → logout → reuse same token → 401                       | PASS   |
| POST without `X-CSRF-Token` → 403                                           | PASS   |
| SSRF: `127.0.0.1`, `169.254.169.254`, `localhost`, `[::1]`, `10.0.0.1` → 400 | PASS  |
| Rate limit: 110 GET /api/users → 100 × 200, 10 × 429                        | PASS   |
| `/api/health` exempt from rate limit                                         | PASS   |
| `pip-audit --strict`                                                        | CLEAN  |

## Operational follow-ups (not blocking ship)

1. **Rotate exposed credentials**: the previous `.env` shipped `dev-secret-key-local-only-not-for-production-use-32chars` and `Telegram/Zarinpal/IDPay/USDT` keys — anything that was ever populated needs rotation upstream.
2. **Reverse-proxy TLS**: app now binds `127.0.0.1`. Production needs nginx/Caddy terminating TLS on 80/443. HSTS preload is shipped — make sure you can keep HTTPS up before submitting to the preload list.
3. **WebAuthn rollout**: placeholder credentials are invalidated. Production still needs a controlled enrollment window with `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGINS` set to the reverse-proxy hostname.
4. **Legacy UI cleanup**: CSP is nonce-only for scripts and styles. The compatibility binder still migrates old event/style attributes at runtime, so the next UI cleanup should replace those attributes with first-class classes and listeners.
5. **Audit log persistence**: structured login/2FA/logout events are emitted to the Python logger. Wiring them into the `Audit` model (already present) is a small follow-up.
6. **`STRICT_CONFIG=1`** should be set in production `.env` to enforce weak-secret rejection on the legacy `app_config.py` import path as well.

---

# Follow-up hardening — 2026-10-01

| #  | Severity | Finding                                                                                              | Status |
|----|----------|------------------------------------------------------------------------------------------------------|--------|
| 23 | HIGH     | `python-jose` → vulnerable `ecdsa` (PYSEC-2026-1325); `pip-audit` now clean after moving to PyJWT.     | FIXED  |
| 24 | HIGH     | Legacy `/api/logout` only cleared the cookie; a stolen token stayed valid until expiry.              | FIXED  |
| 25 | MEDIUM   | Backups were plaintext JSON (client UUIDs, server keys) with default permissions.                   | FIXED  |
| 26 | MEDIUM   | Audit events existed only as log lines; `audit_log` table unused.                                    | FIXED (HMAC hash-chain; tail truncation is not detectable) |
| 27 | MEDIUM   | No refresh/rotation for mobile tokens (long-lived bearer only).                                      | FIXED  |
| 28 | LOW      | Privileged helper wrote config via `write_text` then `chmod` (brief world-readable window).          | FIXED  |
| 29 | LOW      | `greenlet` missing from requirements (clean installs failed to import async SQLAlchemy).             | FIXED  |

New controls: admin IP allowlist, honeypot endpoints, Telegram webhook secret-token check, link-brute-force throttle on Telegram `/link`.

Not done / out of scope: GeoIP blocking, mTLS for the panel (helpers exist in `app/security.py` but are not enforced), Vault/SOPS secret management, OpenVPN backend.

