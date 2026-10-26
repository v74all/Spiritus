"""
Domain & Certificate Manager for V7LTHRONYX VPN Panel.

Single source of truth for:
  - The active panel/domain (what clients use to reach the panel
    AND what the panel uses as the default SNI for every TLS-
    bearing inbound).
  - The TLS certificate that backs that domain. Either a real
    Let's Encrypt cert (preferred) or a self-signed fallback when
    the operator hasn't set DNS yet.

Why one module:
  - The "active domain" and the "active cert" must always agree.
    A domain set on the panel without a matching cert is a
    foot-gun: clients connecting over TLS get an "untrusted"
    warning, and the DPI SNI the panel advertises doesn't match
    the cert the server actually presents. We update them
    together or not at all.
  - The cert is consumed by the xray sync service, the nginx
    reverse proxy template, the share-link generator, AND the
    startup health check. Splitting that state across DB columns
    and `.env` invites drift.

Lifecycle:
  - set_domain(domain, contact_email)  — operator types a domain
                                          in the panel, we ask
                                          Let's Encrypt to issue
                                          a cert, and store both
                                          in the Setting table.
  - rotate_cert()                      — force-renew before the
                                          30-day expiry threshold
                                          (auto-renew is also
                                          scheduled via Celery).
  - disable_domain()                   — fall back to the IP
                                          address; inbounds that
                                          require a domain
                                          (CDN-Trojan, SNI-based
                                          VLESS-WS) get disabled
                                          with a clear reason.
  - get_status()                       — what the panel UI shows
                                          on the Domain tab.

Storage:
  - All domain state lives in the `settings` table under the
    keys `domain_active`, `domain_cert_path`, `domain_key_path`,
    `domain_expires_at`, and `domain_contact_email`. The
    SettingsManager is what loads/saves them atomically.
  - The cert files themselves live under
    `/etc/v7lthronyx/tls/${domain}/{fullchain.pem,privkey.pem}`
    with mode 0644 / 0640. We deliberately do NOT store cert
    bodies in the DB — they are large and binary-ish; filesystem
    is the right home for them and the OS handles permissions.

Failure handling:
  - Every step that touches the network (acme challenge, cert
    download) is wrapped in a try/except. On failure we keep
    the previous domain in place and return a structured
    `DomainSetResult` with `success=False, error=…` so the UI
    can show "Let's Encrypt rejected the domain; DNS not
    pointed at this server?" without stranding the panel.
"""

from __future__ import annotations

import ipaddress
import logging
import grp
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .models import Setting
from .timeutil import utcnow as _utcnow

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  Filesystem locations
# ═══════════════════════════════════════════════════════════════

# Where certs live.  /etc/v7lthronyx/tls/<domain>/ is preferred
# (survives project re-deploys) and is the default. Operators
# who insist on /etc/letsencrypt (e.g. for a shared cert with a
# webserver they already run) can override per-domain.
_DEFAULT_TLS_ROOT = Path("/etc/v7lthronyx/tls")
_LE_LIVE_ROOT = Path("/etc/letsencrypt/live")

# Settings table keys. Grouped here so the keys don't drift
# between writers and readers (an easy bug — the panel saves
# under one key and reads from another and the operator sees
# an "empty" domain tab).
KEY_DOMAIN_ACTIVE = "domain_active"          # str: the FQDN, or "" for "use IP"
KEY_DOMAIN_CERT_PATH = "domain_cert_path"    # str: absolute path to fullchain.pem
KEY_DOMAIN_KEY_PATH = "domain_key_path"      # str: absolute path to privkey.pem
KEY_DOMAIN_EXPIRES_AT = "domain_expires_at"  # str ISO-8601; "" if self-signed
KEY_DOMAIN_ISSUER = "domain_issuer"          # str: "letsencrypt" | "self-signed" | ""
KEY_DOMAIN_CONTACT_EMAIL = "domain_contact_email"  # str: ACME registration email
KEY_DOMAIN_LAST_CHECK = "domain_last_check"  # str ISO-8601 of last status probe
KEY_DOMAIN_LAST_ERROR = "domain_last_error"  # str: most-recent failure reason
KEY_DOMAIN_ACME_CHALLENGE_DIR = "domain_acme_challenge_dir"  # str: where acme.sh serves HTTP-01
KEY_DOMAIN_AUTORENEW_DAYS = "domain_autorenew_days"  # int: rotate when remaining < N days

# Default cert renewal window. 30 days is what acme.sh and
# certbot use; the panel refuses to serve a cert that expires
# in under 7 days (see cert_health below).
DEFAULT_AUTORENEW_DAYS = 30
EXPIRY_HARD_FLOOR_DAYS = 7

# Share links read this without a database round-trip. set_domain and
# startup keep it equal to the domain_active row.
_cached_active_domain = ""


def cached_active_domain() -> str:
    return _cached_active_domain


def remember_active_domain(domain: str) -> None:
    global _cached_active_domain
    _cached_active_domain = (domain or "").strip().lower()


async def refresh_active_domain(db: AsyncSession) -> None:
    remember_active_domain(await _get_setting(db, KEY_DOMAIN_ACTIVE) or "")

# Domain validation. We accept IDN punycode so operators can
# point the panel at an Arabic or Persian domain; we just
# refuse to allow anything that resolves to a private/loopback
# IP (which is what the SSRF guard catches in
# app/main.py:_resolve_and_validate_url).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)
# acme.sh (run as root) writes the account email into a shell file it
# sources on every run, so a quote in it would execute. Plain addresses only.
CONTACT_EMAIL_RE = re.compile(
    r"(?=.{3,254}\Z)[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)


# ═══════════════════════════════════════════════════════════════
#  Public dataclasses
# ═══════════════════════════════════════════════════════════════

class CertStatus(str, Enum):
    OK = "ok"                        # cert is valid and not expiring soon
    EXPIRING_SOON = "expiring_soon"  # within autorenew window
    EXPIRED = "expired"
    MISSING = "missing"              # domain is set but the files are gone
    INVALID = "invalid"              # on-disk cert doesn't match the active domain
    UNKNOWN = "unknown"


@dataclass
class CertHealth:
    """What the panel's Domain tab shows in the status badge."""
    status: CertStatus
    domain: str
    cert_path: str
    key_path: str
    issuer: str
    expires_at: str | None = None
    days_remaining: int | None = None
    last_check: str = field(default_factory=lambda: _utcnow().isoformat())
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "domain": self.domain,
            "cert_path": self.cert_path,
            "key_path": self.key_path,
            "issuer": self.issuer,
            "expires_at": self.expires_at,
            "days_remaining": self.days_remaining,
            "last_check": self.last_check,
            "error": self.error,
        }


@dataclass
class DomainSetResult:
    """Outcome of `set_domain()`. Returned to the API caller
    verbatim so the UI can render the next-step hints."""
    success: bool
    domain: str = ""
    health: CertHealth | None = None
    error: str | None = None
    steps: list[str] = field(default_factory=list)  # human-readable log of what we did


# ═══════════════════════════════════════════════════════════════
#  Storage helpers
# ═══════════════════════════════════════════════════════════════

async def _get_setting(db: AsyncSession, key: str) -> str | None:
    result = await db.execute(select(Setting).where(Setting.key == key))
    row = result.scalar_one_or_none()
    return row.value if row else None


async def _set_setting(db: AsyncSession, key: str, value: str) -> None:
    """Upsert one Setting row.

    We don't want 9 separate SELECT-then-UPDATE round-trips per
    domain change, but we also don't want to load the entire
    Setting table into memory just to set 5 keys. So we keep
    one round-trip per key — that's still cheap because the
    `key` column is UNIQUE-indexed and the panel only does this
    on the operator's explicit save click, not in any hot path.
    """
    result = await db.execute(select(Setting).where(Setting.key == key))
    row = result.scalar_one_or_none()
    if row is None:
        row = Setting(
            key=key,
            value=value,
            value_type="string",
            description=f"Domain & certificate manager: {key}",
        )
        db.add(row)
    else:
        row.value = value
    await db.commit()


async def _set_settings_bulk(db: AsyncSession, mapping: dict[str, str]) -> None:
    """Upsert several keys in a single commit.

    Used by set_domain() so a half-applied set (cert saved but
    domain not, etc.) is impossible. Without the bulk
    transaction a crash between calls would leave the panel
    pointing at a domain it can't serve.
    """
    keys = list(mapping.keys())
    result = await db.execute(select(Setting).where(Setting.key.in_(keys)))
    existing = {row.key: row for row in result.scalars().all()}
    for key, value in mapping.items():
        if key in existing:
            existing[key].value = value
        else:
            db.add(Setting(
                key=key,
                value=value,
                value_type="string",
                description=f"Domain & certificate manager: {key}",
            ))
    await db.commit()


async def _delete_settings(db: AsyncSession, keys: list[str]) -> None:
    """Used by disable_domain() to wipe a clean slate."""
    for key in keys:
        result = await db.execute(select(Setting).where(Setting.key == key))
        row = result.scalar_one_or_none()
        if row is not None:
            await db.delete(row)
    await db.commit()


# ═══════════════════════════════════════════════════════════════
#  Validation
# ═══════════════════════════════════════════════════════════════

def _validate_domain(domain: str) -> str | None:
    """Return None if `domain` is a usable FQDN, else a reason string.

    Why regex AND DNS resolution:
      - The regex catches typos fast (no DNS round-trip).
      - The DNS check catches domains that the operator fat-fingered
        or that point at a private IP via a CNAME chain. We refuse
        to issue a Let's Encrypt cert for a domain that resolves
        to 10.0.0.1 — the ACME HTTP-01 challenge would never
        succeed anyway, but failing fast saves the operator 60
        seconds of confusion.
    """
    if not domain:
        return "empty domain"
    if len(domain) > 253:
        return "domain longer than 253 chars"
    if not _DOMAIN_RE.match(domain):
        return f"'{domain}' is not a valid FQDN"
    # Lower-case to avoid duplicate entries.
    if domain != domain.lower():
        return "domain must be lower-case"
    # IDN: punycode. Don't reject; ACME handles it.
    try:
        info = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return f"DNS resolution failed: {exc}"
    for _fam, *_rest, sockaddr in info:
        ip = sockaddr[0].split("%", 1)[0]
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return f"DNS returned invalid address {ip}"
        if not address.is_global:
            return f"domain resolves to private or non-public IP {ip}"
    return None


# ═══════════════════════════════════════════════════════════════
#  Filesystem layout
# ═══════════════════════════════════════════════════════════════

def _tls_paths_for(domain: str) -> dict[str, Path]:
    """Return the canonical on-disk locations for a domain's cert.

    We standardise on /etc/v7lthronyx/tls/<domain>/fullchain.pem
    and privkey.pem so the path doesn't depend on which ACME
    client issued the cert. acme.sh users get a symlink farm
    under that directory; certbot users get a copy (certbot
    locks /etc/letsencrypt/live/<domain>/ to mode 0700 which
    xray can't read).
    """
    root = _DEFAULT_TLS_ROOT / domain
    return {
        "root": root,
        "cert": root / "fullchain.pem",
        "key": root / "privkey.pem",
        "chain": root / "chain.pem",  # optional; only present for LE certs
    }


# ═══════════════════════════════════════════════════════════════
#  Cert generation
# ═══════════════════════════════════════════════════════════════

def _ensure_openssl() -> str | None:
    """Confirm openssl is on $PATH; return an error string if not."""
    if shutil.which("openssl") is None:
        return "openssl binary not found on PATH"
    return None


def _generate_self_signed_cert(domain: str) -> DomainSetResult:
    """Last-resort cert: 10-year self-signed.

    Used by `set_domain()` when:
      - The operator types a domain but DNS isn't pointed at
        this server yet (ACME HTTP-01 will fail), OR
      - Let's Encrypt rate-limits us (5 duplicate certs per
        week per domain is a real limit), OR
      - The acme.sh binary isn't installed.

    The cert is real enough that Xray will start; clients see
    an "untrusted" warning until the operator points DNS at us
    and we re-issue. The UI should surface this clearly.
    """
    err = _ensure_openssl()
    if err:
        return DomainSetResult(success=False, domain=domain, error=err)
    paths = _tls_paths_for(domain)
    paths["root"].mkdir(parents=True, exist_ok=True)
    cert = paths["cert"]
    key = paths["key"]
    san = (
        f"subjectAltName=DNS:{domain},DNS:www.{domain}"
    )
    try:
        proc = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-days", "3650",
                "-keyout", str(key), "-out", str(cert),
                "-subj", f"/CN={domain}",
                "-addext", san,
            ],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return DomainSetResult(
            success=False, domain=domain,
            error="openssl timed out generating self-signed cert",
        )
    except Exception as exc:  # noqa: BLE001
        return DomainSetResult(
            success=False, domain=domain,
            error=f"openssl failed: {exc}",
        )
    if proc.returncode != 0:
        return DomainSetResult(
            success=False, domain=domain,
            error=f"openssl exited {proc.returncode}: {proc.stderr.strip()}",
        )
    try:
        key.chmod(0o640)
        cert.chmod(0o644)
    except OSError:
        pass
    return DomainSetResult(
        success=True,
        domain=domain,
        steps=[f"generated self-signed cert at {cert}"],
    )


def _have_acme_sh() -> bool:
    """True if acme.sh is installed. We prefer it over certbot
    because it doesn't need root to run (the panel user can
    issue certs), and it can honour the --cert-no-bundled flag
    so we can store fullchain.pem and privkey.pem where we
    want them."""
    return shutil.which("acme.sh") is not None


def _have_certbot() -> bool:
    return shutil.which("certbot") is not None


def _issue_letsencrypt_cert(
    domain: str,
    contact_email: str,
) -> DomainSetResult:
    """Run acme.sh (preferred) or certbot to issue a real LE cert.

    The challenge directory is panel-controlled (under
    /var/www/spiritus-acme/) so we don't fight with a parallel
    nginx that might be doing its own ACME dance on the same
    box. acme.sh supports `--webroot`; certbot does too.

    Failure modes we handle here:
      - DNS not pointed at us: acme.sh exits non-zero, we
        surface "DNS A record not resolving" in the error.
      - Rate-limited: "too many certificates already issued"
      - Port 80 blocked: webroot challenge unreachable
    """
    paths = _tls_paths_for(domain)
    paths["root"].mkdir(parents=True, exist_ok=True)
    # Standalone mode binds port 80 itself. Do not create /var/www here:
    # the helper's filesystem is read-only outside its allowlist, and
    # mkdir of a missing /var/www crashed the certificate request.
    # Open the HTTP-01 port in the local firewall. The
    # open_firewall_port helper in install.sh has the same
    # logic; we duplicate a minimal version here so the
    # runtime cert path doesn't depend on install.sh being
    # sourced.
    for cmd in (("ufw", ["allow", "80/tcp"]),
                ("firewall-cmd", ["--permanent", "--add-port=80/tcp"])):
        if shutil.which(cmd[0]):
            try:
                subprocess.run([cmd[0], *cmd[1]], capture_output=True, timeout=10)
            except Exception:
                pass
    if shutil.which("firewall-cmd"):
        try:
            subprocess.run(["firewall-cmd", "--reload"], capture_output=True, timeout=10)
        except Exception:
            pass

    if _have_acme_sh():
        # We do NOT pass --reloadcmd / --install-cert hooks; we
        # copy the issued files into our own directory. That
        # gives us a single canonical location regardless of
        # which ACME client issued the cert, and means a future
        # uninstall of acme.sh won't strand the panel.
        home = Path("/etc/v7lthronyx/acme")
        home.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["HOME"] = str(home)
        env["LE_WORKING_DIR"] = str(home)
        webroot = Path("/etc/v7lthronyx/acme-web")
        (webroot / ".well-known" / "acme-challenge").mkdir(parents=True, exist_ok=True)
        webroot.chmod(0o755)
        from .panel_edge import ensure_challenge_location
        ensure_challenge_location(domain)
        try:
            # Port 80 is the panel redirect. Serve the HTTP-01 token there
            # instead of stopping nginx for standalone mode.
            issue_cmd = [
                "acme.sh", "--issue",
                "--domain", domain,
                "--webroot", str(webroot),
                "--keylength", "ec-256",
                "--server", "letsencrypt",
            ]
            if contact_email:
                issue_cmd += ["--accountemail", contact_email]
            proc = subprocess.run(
                ["bash", "-c", "umask 022 && exec \"$@\"", "acme.sh", *issue_cmd],
                capture_output=True, text=True, timeout=120,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return DomainSetResult(
                success=False, domain=domain,
                error="acme.sh timed out after 120s",
            )
        if proc.returncode != 0:
            return DomainSetResult(
                success=False, domain=domain,
                error=(
                    f"acme.sh rejected the domain (exit {proc.returncode}): "
                    f"{(proc.stderr or proc.stdout).strip()[-300:]}"
                ),
            )
        # Install: copy fullchain.pem and privkey.pem into our
        # canonical directory.
        acme_cert = home / domain / "ecc-fullchain.pem"
        acme_key = home / domain / "ecc-key.pem"
        if not (acme_cert.exists() and acme_key.exists()):
            return DomainSetResult(
                success=False, domain=domain,
                error=f"acme.sh succeeded but cert not found at {acme_cert}",
            )
        shutil.copy2(acme_cert, paths["cert"])
        shutil.copy2(acme_key, paths["key"])
    elif _have_certbot():
        try:
            # Standalone for the same reason as acme.sh above: certbot
            # binds :80 itself for the HTTP-01 challenge. `-n` makes it
            # non-interactive so it never blocks the API request.
            certbot_args = [
                "certbot", "certonly", "--standalone",
                "--http-01-port", "80",
                "-n",
                "-d", domain,
                "--agree-tos",
                "--no-eff-email",
                "--key-type", "ecdsa",
                "--cert-name", f"spiritus-{domain}",
            ]
            if contact_email:
                certbot_args += ["-m", contact_email]
            else:
                certbot_args.append("--register-unsafely-without-email")
            proc = subprocess.run(
                certbot_args,
                capture_output=True, text=True, timeout=180,
            )
        except subprocess.TimeoutExpired:
            return DomainSetResult(
                success=False, domain=domain,
                error="certbot timed out after 180s",
            )
        if proc.returncode != 0:
            return DomainSetResult(
                success=False, domain=domain,
                error=(
                    f"certbot rejected the domain (exit {proc.returncode}): "
                    f"{(proc.stderr or proc.stdout).strip()[-300:]}"
                ),
            )
        le_cert = _LE_LIVE_ROOT / f"spiritus-{domain}" / "fullchain.pem"
        le_key = _LE_LIVE_ROOT / f"spiritus-{domain}" / "privkey.pem"
        if not (le_cert.exists() and le_key.exists()):
            return DomainSetResult(
                success=False, domain=domain,
                error=f"certbot succeeded but cert not at {le_cert}",
            )
        shutil.copy2(le_cert, paths["cert"])
        shutil.copy2(le_key, paths["key"])
    else:
        return DomainSetResult(
            success=False, domain=domain,
            error=(
                "no ACME client installed (need acme.sh or certbot). "
                "Install with: apt install certbot   # or   "
                "curl https://get.acme.sh | sh -s -- --install-online"
            ),
        )

    try:
        paths["root"].chmod(0o755)
        if paths["root"].parent.name == "tls":
            paths["root"].parent.chmod(0o755)
        paths["cert"].chmod(0o644)
        paths["key"].chmod(0o640)
        # Xray runs as its own user and is in the panel group. A root:root
        # key is unreadable, so every TLS inbound refuses to start.
        gid = grp.getgrnam(os.environ.get("PANEL_GROUP", "vpnpanel")).gr_gid
        os.chown(paths["key"], 0, gid)
    except (OSError, KeyError):
        pass
    return DomainSetResult(
        success=True,
        domain=domain,
        steps=[f"issued Let's Encrypt cert for {domain}"],
    )


# ═══════════════════════════════════════════════════════════════
#  Cert parsing
# ═══════════════════════════════════════════════════════════════

def _parse_cert_expiry(cert_path: Path) -> datetime | None:
    """Return the notAfter timestamp from the cert at `cert_path`.

    We use openssl because the python `cryptography` package
    would add a heavy dependency for one function.
    """
    try:
        if not cert_path.exists():
            return None
    except OSError:
        return None
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-enddate",
             "-in", str(cert_path)],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if proc.returncode != 0:
        return None
    # Output: "notAfter=Jul  4 12:00:00 2027 GMT"
    line = (proc.stdout or "").strip()
    if "=" not in line:
        return None
    _, _, value = line.partition("=")
    try:
        from email.utils import parsedate_to_datetime
        return parsedate_to_datetime(value.strip())
    except (TypeError, ValueError):
        return None


def _parse_cert_subject(cert_path: Path) -> str | None:
    """Return the CN of the cert at `cert_path`."""
    if not cert_path.exists():
        return None
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-subject",
             "-in", str(cert_path)],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if proc.returncode != 0:
        return None
    line = (proc.stdout or "")
    m = re.search(r"CN\s*=\s*([^,\n/]+)", line)
    return m.group(1).strip() if m else None


def _parse_cert_issuer(cert_path: Path) -> str | None:
    if not cert_path.exists():
        return None
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-issuer",
             "-in", str(cert_path)],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if proc.returncode != 0:
        return None
    line = (proc.stdout or "")
    if "Let's Encrypt" in line:
        return "letsencrypt"
    if "R10" in line or "R3" in line or "E1" in line or "E2" in line:
        return "letsencrypt"
    if "self" in line.lower():
        return "self-signed"
    return line.strip() or None


# ═══════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════

@dataclass
class DomainStatus:
    """The public, JSON-serialisable view of the current domain
    state. Returned by `get_status()`. The UI renders this on
    the Domain tab."""
    active_domain: str
    enabled: bool                  # True if a domain is set
    cert: CertHealth
    autorenew_days: int
    contact_email: str
    last_check: str
    last_error: str
    server_ip: str                # what the panel would use if no domain were set
    can_use_letsencrypt: bool      # is acme.sh / certbot installed?

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_domain": self.active_domain,
            "enabled": self.enabled,
            "cert": self.cert.to_dict(),
            "autorenew_days": self.autorenew_days,
            "contact_email": self.contact_email,
            "last_check": self.last_check,
            "last_error": self.last_error,
            "server_ip": self.server_ip,
            "can_use_letsencrypt": self.can_use_letsencrypt,
        }


async def get_status(db: AsyncSession) -> DomainStatus:
    """Read-only view of the current domain state."""
    active = (await _get_setting(db, KEY_DOMAIN_ACTIVE) or "").strip()
    cert_path = (await _get_setting(db, KEY_DOMAIN_CERT_PATH) or "").strip()
    key_path = (await _get_setting(db, KEY_DOMAIN_KEY_PATH) or "").strip()
    await _get_setting(db, KEY_DOMAIN_EXPIRES_AT)
    issuer = await _get_setting(db, KEY_DOMAIN_ISSUER) or ""
    contact = (await _get_setting(db, KEY_DOMAIN_CONTACT_EMAIL) or "").strip()
    last_check = (await _get_setting(db, KEY_DOMAIN_LAST_CHECK) or "").strip()
    last_error = (await _get_setting(db, KEY_DOMAIN_LAST_ERROR) or "").strip()
    autorenew_raw = await _get_setting(db, KEY_DOMAIN_AUTORENEW_DAYS)
    autorenew = int(autorenew_raw) if autorenew_raw and autorenew_raw.isdigit() else DEFAULT_AUTORENEW_DAYS

    # Probe the cert on disk and decide its health.
    health = await _probe_cert(active, cert_path, key_path, issuer)

    return DomainStatus(
        active_domain=active,
        enabled=bool(active),
        cert=health,
        autorenew_days=autorenew,
        contact_email=contact,
        last_check=last_check,
        last_error=last_error,
        server_ip=settings.vpn_server_ip or "",
        can_use_letsencrypt=_have_acme_sh() or _have_certbot(),
    )


async def _probe_cert(
    domain: str,
    cert_path: str,
    key_path: str,
    issuer: str,
) -> CertHealth:
    """Decide the CertStatus enum for the cert currently on disk."""
    if not domain:
        return CertHealth(
            status=CertStatus.UNKNOWN,
            domain="",
            cert_path="",
            key_path="",
            issuer="",
        )
    if not cert_path or not key_path:
        return CertHealth(
            status=CertStatus.MISSING,
            domain=domain,
            cert_path=cert_path,
            key_path=key_path,
            issuer=issuer,
        )
    cp = Path(cert_path)
    kp = Path(key_path)
    if not cp.is_file() or not kp.is_file():
        return CertHealth(
            status=CertStatus.MISSING,
            domain=domain,
            cert_path=cert_path,
            key_path=key_path,
            issuer=issuer,
            error=f"cert file missing (cert={cp.exists()}, key={kp.exists()})",
        )
    subject = _parse_cert_subject(cp)
    if subject and subject.lower() not in {domain.lower(), f"*.{domain.lower()}"}:
        return CertHealth(
            status=CertStatus.INVALID,
            domain=domain,
            cert_path=cert_path,
            key_path=key_path,
            issuer=issuer,
            error=f"cert subject is {subject!r}, expected {domain!r}",
        )
    expires = _parse_cert_expiry(cp)
    if expires is None:
        return CertHealth(
            status=CertStatus.UNKNOWN,
            domain=domain,
            cert_path=cert_path,
            key_path=key_path,
            issuer=issuer,
            error="could not parse cert expiry",
        )
    now = _utcnow()
    # openssl's notAfter is often timezone-aware; utcnow() is naive UTC.
    if expires.tzinfo is not None:
        expires = expires.astimezone(UTC).replace(tzinfo=None)
    days_remaining = (expires - now).days
    if days_remaining < 0:
        status = CertStatus.EXPIRED
    elif days_remaining < EXPIRY_HARD_FLOOR_DAYS:
        status = CertStatus.EXPIRED  # hard floor; refuse to serve
    elif days_remaining < DEFAULT_AUTORENEW_DAYS:
        status = CertStatus.EXPIRING_SOON
    else:
        status = CertStatus.OK
    return CertHealth(
        status=status,
        domain=domain,
        cert_path=cert_path,
        key_path=key_path,
        issuer=issuer or (_parse_cert_issuer(cp) or ""),
        expires_at=expires.isoformat(),
        days_remaining=days_remaining,
    )


async def set_domain(
    db: AsyncSession,
    domain: str,
    contact_email: str = "",
    *,
    prefer_self_signed: bool = False,
    force_renew: bool = False,
) -> DomainSetResult:
    """The operator's main entry point.

    Steps:
      1. Validate the domain.
      2. Try Let's Encrypt (acme.sh → certbot) unless
         `prefer_self_signed=True` (used in tests and in the
         "I haven't pointed DNS yet" path).
      3. Never silently downgrade an ACME request to self-signed.
      4. Persist (domain, cert, key, expires, issuer, contact)
         atomically. Either all five land or none do.
      5. Trigger a sync of the Xray config so every
         TLS-bearing inbound picks up the new SNI + cert path.
    """
    domain = (domain or "").strip().lower()
    contact_email = (contact_email or "").strip()

    # Refuse empty unless explicitly asked to disable.
    if not domain:
        return DomainSetResult(
            success=False, error="empty domain; call disable_domain() instead",
        )

    if contact_email and not CONTACT_EMAIL_RE.fullmatch(contact_email):
        return DomainSetResult(success=False, domain=domain, error="invalid contact email")

    err = _validate_domain(domain)
    if err:
        return DomainSetResult(success=False, domain=domain, error=err)

    from .privileged_helper import PrivilegedHelperError, helper_request
    issuer = "self-signed" if prefer_self_signed else "letsencrypt"
    acme_note = ""
    try:
        result = await helper_request(
            "certificate.issue",
            {
                "domain": domain,
                "contact_email": contact_email,
                "mode": "self-signed" if prefer_self_signed else "acme",
                "force_renew": force_renew,
            },
            timeout=180,
        )
    except PrivilegedHelperError as exc:
        return DomainSetResult(success=False, domain=domain, error=str(exc))
    if not result.ok and not prefer_self_signed:
        # The Domain tab says a failed ACME attempt still registers the
        # domain with a pinned self-signed cert. Dropping the request
        # left the tab on "No domain" after every DNS or port-80 failure.
        acme_note = result.message or "Let's Encrypt failed"
        try:
            result = await helper_request(
                "certificate.issue",
                {
                    "domain": domain,
                    "contact_email": contact_email,
                    "mode": "self-signed",
                },
                timeout=60,
            )
        except PrivilegedHelperError as exc:
            return DomainSetResult(
                success=False, domain=domain,
                error=f"{acme_note}; self-signed certificate also failed: {exc}",
            )
        if not result.ok:
            return DomainSetResult(
                success=False, domain=domain,
                error=f"{acme_note}; self-signed certificate also failed: {result.message}",
            )
        issuer = "self-signed"
    elif not result.ok:
        return DomainSetResult(success=False, domain=domain, error=result.message)
    steps = list((result.data or {}).get("steps") or [])
    if acme_note:
        steps.insert(0, "Let's Encrypt failed; issued a pinned self-signed certificate instead: " + acme_note)
    cp = _tls_paths_for(domain)["cert"]
    exp = _parse_cert_expiry(cp)
    expires_at = exp.isoformat() if exp else ""

    # Compute canonical paths and persist atomically.
    paths = _tls_paths_for(domain)
    await _set_settings_bulk(db, {
        KEY_DOMAIN_ACTIVE: domain,
        KEY_DOMAIN_CERT_PATH: str(paths["cert"]),
        KEY_DOMAIN_KEY_PATH: str(paths["key"]),
        KEY_DOMAIN_EXPIRES_AT: expires_at,
        KEY_DOMAIN_ISSUER: issuer,
        KEY_DOMAIN_CONTACT_EMAIL: contact_email,
        KEY_DOMAIN_LAST_CHECK: _utcnow().isoformat(),
        KEY_DOMAIN_LAST_ERROR: acme_note,
    })
    remember_active_domain(domain)

    # Serve the new certificate: record it where every TLS inbound reads it
    # (tls_trust.tls_files), then re-render Xray and sing-box.
    try:
        await _use_certificate(db, str(paths["cert"]), str(paths["key"]))
    except Exception as exc:  # noqa: BLE001
        steps.append(f"warn: xray sync failed: {exc}")

    health = await _probe_cert(domain, str(paths["cert"]), str(paths["key"]), issuer)
    return DomainSetResult(
        success=True,
        domain=domain,
        health=health,
        steps=steps,
    )


async def disable_domain(db: AsyncSession) -> DomainSetResult:
    """Clear the domain and fall back to the IP-based config.

    The Xray sync service is what actually re-renders the
    config; we just wipe the Setting rows.
    """
    await _delete_settings(db, [
        KEY_DOMAIN_ACTIVE,
        KEY_DOMAIN_CERT_PATH,
        KEY_DOMAIN_KEY_PATH,
        KEY_DOMAIN_EXPIRES_AT,
        KEY_DOMAIN_ISSUER,
        KEY_DOMAIN_LAST_ERROR,
    ])
    remember_active_domain("")
    try:
        await _use_certificate(db, "", "")
    except Exception as exc:  # noqa: BLE001
        return DomainSetResult(success=True, error=f"sync failed: {exc}")
    return DomainSetResult(success=True, steps=["domain cleared, Xray config re-rendered"])


async def _use_certificate(db: AsyncSession, cert: str, key: str) -> None:
    """Point the panel's TLS inbounds at `cert` / `key` ("" = back to
    TLS_CERT_FILE) and re-render Xray and sing-box from the panel settings."""
    from .api.compat._core import _save_legacy_settings
    from .api.compat.panel_settings import _schedule_xray_sync

    await _save_legacy_settings(db, {"tls_cert_file": cert, "tls_key_file": key})
    _schedule_xray_sync()


async def rotate_cert(db: AsyncSession) -> DomainSetResult:
    """Force-renew the cert for the active domain.

    Called by:
      - The Celery beat task `domain_autorenew_task` when the
        cert is inside the autorenew window.
      - The operator's "Renew now" button in the UI.
    """
    active = (await _get_setting(db, KEY_DOMAIN_ACTIVE) or "").strip()
    if not active:
        return DomainSetResult(success=False, error="no active domain")
    return await set_domain(
        db, active,
        contact_email=(await _get_setting(db, KEY_DOMAIN_CONTACT_EMAIL) or ""),
        force_renew=True,
    )


# ═══════════════════════════════════════════════════════════════
#  Autorenewal check (called from Celery)
# ═══════════════════════════════════════════════════════════════

async def maybe_autorenew(db: AsyncSession) -> DomainSetResult | None:
    """Rotate the cert if it's inside the autorenew window.

    Returns None when no action was needed (cert is healthy);
    a `DomainSetResult` when we did rotate, or when the
    rotation failed (so the celery log carries the failure
    reason).
    """
    status = await get_status(db)
    if not status.enabled:
        return None
    if status.cert.status in (CertStatus.OK,):
        return None
    if status.cert.status in (CertStatus.MISSING,):
        return None  # operator must intervene manually
    if status.cert.status in (CertStatus.EXPIRED,):
        return await rotate_cert(db)
    if status.cert.status in (CertStatus.EXPIRING_SOON,):
        return await rotate_cert(db)
    if status.cert.status in (CertStatus.INVALID,):
        # The cert doesn't match the active domain — the
        # operator probably typed a new domain without
        # re-issuing. Force a set_domain() so the cert
        # and the domain string stay in sync.
        return await set_domain(db, status.active_domain,
                                contact_email=status.contact_email)
    return None
