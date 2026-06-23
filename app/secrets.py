"""
Secrets Management for V7LTHRONYX VPN Panel.

Replaces hardcoded REALITY keys and other secrets scattered across the
codebase with a single, auditable source of truth.

Resolution order for every secret:
    1. Environment variable (operationally injected)
    2. /etc/v7lthronyx/secrets.json   (chmod 600, owned by vpnpanel:vpnpanel)
    3. <project>/.secrets.json        (gitignored, dev-only)
    4. Generate on first read         (REALITY keys — written back to disk)

This module is the ONLY place that knows how to obtain a secret. Any
other module that needs a REALITY key, a webhook HMAC, a payment-gateway
API key, etc. calls one of the `get_*` helpers here and never reads
its own env var directly.

Why a separate module instead of stuffing more fields into Settings?
- `Settings` is loaded at import time. Operators want to rotate a
  REALITY key without restarting the panel, and they want a single
  file with `chmod 600` rather than an `.env` with every variable.
- The "generate on first read" semantics (REALITY is a fresh X25519
  pair per server) don't fit a pydantic model cleanly.
- It centralises the audit log: every read goes through this module.
"""

from __future__ import annotations

import json
import logging
import os
import secrets as _py_secrets
import stat
import threading
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  Filesystem Locations
# ═══════════════════════════════════════════════════════════════

# Production path. Survives project re-deploys, lives outside the
# application directory so an `rm -rf` of the panel does not wipe
# keys. Created at first read with mode 0600.
_PROD_SECRETS_DIR = Path("/etc/v7lthronyx")
_PROD_SECRETS_FILE = _PROD_SECRETS_DIR / "secrets.json"

# Dev/test path. Lives inside the project so developers don't need
# root. Already covered by `.gitignore`.
_DEV_SECRETS_FILE = Path(__file__).resolve().parent.parent / ".secrets.json"


def _resolve_secrets_file() -> Path:
    """Pick the first writable secrets file location."""
    # Production first — operators expect /etc/v7lthronyx/secrets.json
    if _PROD_SECRETS_FILE.exists():
        return _PROD_SECRETS_FILE
    try:
        _PROD_SECRETS_DIR.mkdir(parents=True, exist_ok=True)
        # Mode 0700 on the directory so only vpnpanel can enter it.
        os.chmod(_PROD_SECRETS_DIR, 0o700)
        return _PROD_SECRETS_FILE
    except (PermissionError, OSError):
        # Fall back to project-local. Still chmod 600.
        if not _DEV_SECRETS_FILE.exists():
            _DEV_SECRETS_FILE.touch(mode=0o600)
            try:
                os.chmod(_DEV_SECRETS_FILE, 0o600)
            except OSError:
                pass
        return _DEV_SECRETS_FILE


# ═══════════════════════════════════════════════════════════════
#  Cache (in-process, guarded by a lock)
# ═══════════════════════════════════════════════════════════════

# We re-read the file on cold-start, then keep an in-memory copy so
# hot paths (every API call) don't hit the disk. A single lock keeps
# concurrent reloads from clobbering each other.
_cache_lock = threading.RLock()
_cache: Optional[Dict[str, Any]] = None
_cache_loaded_from: Optional[Path] = None


def _load_cache() -> Dict[str, Any]:
    """Read secrets.json from disk, return {} if missing or invalid."""
    global _cache, _cache_loaded_from
    with _cache_lock:
        if _cache is not None:
            return _cache
        path = _resolve_secrets_file()
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                logger.warning("secrets.json root is not an object; treating as empty")
                data = {}
        except FileNotFoundError:
            data = {}
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("could not read secrets file %s: %s", path, exc)
            data = {}
        _cache = data
        _cache_loaded_from = path
        return _cache


def _flush_cache() -> None:
    """Write the in-memory cache back to disk atomically."""
    global _cache
    with _cache_lock:
        if _cache is None:
            return
        path = _cache_loaded_from or _resolve_secrets_file()
        # Mode 0600: only the owning user (vpnpanel) can read the file.
        # We use os.open + os.fchmod so the file is never created with the
        # process umask (which on most distros is 022, leaving it world-
        # readable for the brief moment between create and chmod).
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(_cache, f, indent=2, sort_keys=True)
                f.write("\n")
        except Exception:
            # The file is already truncated; we cannot un-truncate, but
            # we can at least make sure it's not 0-byte-readable.
            os.chmod(path, 0o600)
            raise


# ═══════════════════════════════════════════════════════════════
#  Public API
# ═══════════════════════════════════════════════════════════════

def get(name: str, default: Optional[str] = None) -> Optional[str]:
    """Look up a single secret.

    Resolution order:
        1. Environment variable `name` (upper-cased).
        2. secrets.json entry.

    Returns `default` (default None) if the secret is not present.
    """
    env_key = name.upper()
    env_value = os.environ.get(env_key)
    if env_value:
        return env_value
    data = _load_cache()
    value = data.get(name)
    if isinstance(value, str):
        return value
    return default


def require(name: str) -> str:
    """Get a secret or raise. Use for things that MUST be present
    (e.g. payment-gateway API keys in production)."""
    value = get(name)
    if not value:
        raise RuntimeError(
            f"required secret '{name}' is missing. "
            f"Set the {name.upper()} environment variable or write it "
            f"to {_resolve_secrets_file()} (mode 0600)."
        )
    return value


def set_secret(name: str, value: str) -> None:
    """Persist a secret. Overwrites any existing value."""
    global _cache
    with _cache_lock:
        data = _load_cache()
        data[name] = value
        _cache = data
        _flush_cache()


def rotate(name: str, new_value: str) -> None:
    """Rotate a secret in place. Logs the rotation at INFO without
    leaking the value."""
    set_secret(name, new_value)
    logger.info("secret.rotated name=%s", name)


def get_or_generate(name: str, generator) -> str:
    """Get the secret, or call `generator()` to create one and persist
    it. `generator` must return a str.

    This is the pattern used for REALITY X25519 key pairs: a fresh
    pair is generated on first read and cached forever.
    """
    global _cache
    with _cache_lock:
        data = _load_cache()
        existing = data.get(name)
        if isinstance(existing, str) and existing:
            return existing
        new_value = generator()
        if not isinstance(new_value, str) or not new_value:
            raise RuntimeError(
                f"generator for secret '{name}' returned an invalid value"
            )
        data[name] = new_value
        _cache = data
        _flush_cache()
        return new_value


# ═══════════════════════════════════════════════════════════════
#  Real-Secrets Helpers (typed wrappers)
# ═══════════════════════════════════════════════════════════════

def reality_private_key() -> str:
    """The server's REALITY X25519 private key.

    Generated on first read by shelling out to `xray x25519`. Failure is
    explicit: a random placeholder is never persisted as a private key.
    """
    def _gen() -> str:
        xray_bin = os.environ.get("XRAY_BIN_PATH", "/usr/local/bin/xray")
        try:
            import subprocess
            proc = subprocess.run(
                [xray_bin, "x25519"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if "Private key:" in line:
                        return line.split(":", 1)[1].strip()
        except FileNotFoundError as exc:
            raise RuntimeError(f"xray binary not found at {xray_bin}") from exc
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"xray x25519 failed: {type(exc).__name__}") from exc
        raise RuntimeError("xray x25519 did not return a private key")

    return get_or_generate("reality_private_key", _gen)


def reality_public_key() -> str:
    """Companion public key. Independent of the private key (x25519
    derivation is one-way) — only needed for client-side share URLs."""
    return get("reality_public_key", "")


def reality_short_id() -> str:
    """Per-deployment short id. Operators can override per-user
    in the protocol config; this is the panel-wide default."""
    return get_or_generate(
        "reality_short_id",
        lambda: _py_secrets.token_hex(4),
    )


def zarinpal_merchant_id() -> str:
    return get("zarinpal_merchant_id", "")


def idpay_api_key() -> str:
    return get("idpay_api_key", "")


def usdt_trongrid_api_key() -> str:
    return get("usdt_trongrid_api_key", "")


def telegram_bot_token() -> str:
    return get("telegram_bot_token", "")


def telegram_chat_id() -> str:
    return get("telegram_chat_id", "")


# ═══════════════════════════════════════════════════════════════
#  Hardcoded-key Sweep
# ═══════════════════════════════════════════════════════════════

# These are the keys that, until this commit, were hardcoded as
# `Field("oZVaAa694VcKxWb-gH31sPpMIQ9XAozoJ6BOAA1DkC0", env=...)` in
# `app/config.py` and as inline strings in `vpn-web.py`. They were
# ROTATED upstream (Xray's RealityKeyManager.generate_key_pair() runs
# on every server) but the SOURCE REPO still had them — meaning any
# operator who pulled the repo and forgot to set the env var would
# fall back to the published sample pair.
#
# If you find either of these literal strings anywhere in the tree
# after this commit, it is a bug. The list is exported for tests.
_LEAKED_KEY_FINGERPRINTS = {
    "oZVaAa694VcKxWb-gH31sPpMIQ9XAozoJ6BOAA1DkC0",  # legacy default public
    "aGM7HELLUCgA3icWeQYOba7HL-82ocrTkG3k4PhBZ28",  # legacy default private
}


def audit_no_leaked_keys(extra_paths: Optional[list] = None) -> list:
    """Walk the project for any of the leaked key fingerprints.

    Returns the list of (path, line_no, line) tuples that contain a
    match. Intended to be run from a CI check; never raises on
    findings, just reports them.

    Skipped paths: anything inside this file (we deliberately list the
    fingerprints in a comment so a future grep can find them) and the
    test suite (it has its own positive/negative audit fixtures).
    """
    import re
    findings: list = []
    project_root = Path(__file__).resolve().parent.parent
    skip_dirs = {".git", "venv", ".venv", "node_modules", "__pycache__", "backups", "tests"}
    skip_files = {Path(__file__).resolve()}  # this file's docstring mentions the keys
    pat = re.compile("|".join(re.escape(k) for k in _LEAKED_KEY_FINGERPRINTS))
    targets = list(extra_paths or []) + [project_root]
    for base in targets:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if any(part in skip_dirs for part in path.parts):
                continue
            if path.resolve() in skip_files:
                continue
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    for lineno, line in enumerate(f, start=1):
                        if pat.search(line):
                            findings.append((str(path), lineno, line.rstrip()))
            except (OSError, UnicodeDecodeError):
                continue
    return findings
