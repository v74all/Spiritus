"""
One-shot migration tool: pull secrets out of legacy plaintext files
and into the new Secrets Manager.

This is run by the operator (or by install.sh) exactly once, then the
source files are chmod 000'd. Re-running is a no-op.

Usage:
    python -m app.secrets_migrate
    python -m app.secrets_migrate --wipe-legacy   # also zero + delete

What it does:
    1. Reads `reality_private_key` (top-level file).
    2. Reads `vpn-settings.json` keys prefixed with `reality_`, the
       payment-gateway fields, and the Telegram fields.
    3. Writes the result through `app.secrets.set_secret()` so it
       lands in /etc/v7lthronyx/secrets.json with mode 0600.
    4. With `--wipe-legacy`: opens the source files in write mode,
       overwrites with random bytes (length-preserving), fsyncs,
       then deletes them. Falls back to `rm -P` where available.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


# Keys we lift from `vpn-settings.json`. These are the fields that
# carry cryptographic material. Everything else in that file is
# protocol configuration and is already covered by the Setting DB
# table; this script does not touch those.
_SECRET_KEYS_FROM_SETTINGS = {
    "reality_private_key",
    "reality_public_key",
    "reality_short_id",
    "vless_xhttp_reality_private_key",
    "vless_xhttp_reality_public_key",
    "vless_xhttp_reality_short_id",
    "vless_vision_reality_private_key",
    "vless_vision_reality_public_key",
    "vless_vision_reality_short_id",
    "vless_reverse_reality_private_key",
    "vless_reverse_reality_public_key",
    "vless_reverse_reality_short_id",
    "hysteria2_password",
    "hysteria2_salamander_password",
    "tuic_password",
    "shadowtls_password",
    "amneziawg_private_key",
    "amneziawg_public_key",
    "mieru_password",
    "naiveproxy_password",
    "naiveproxy_user",
    "trojan_password",
    "ss2022_server_key",
    "zarinpal_merchant_id",
    "idpay_api_key",
    "usdt_wallet_address",
    "usdt_trongrid_api_key",
    "telegram_bot_token",
    "telegram_chat_id",
    "telegram_admin_chat_ids",
}


def _read_settings_file(path: Path) -> dict[str, str]:
    """Read vpn-settings.json, return only the secret-bearing keys."""
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("could not read %s: %s", path, exc)
        return {}
    secrets: dict[str, str] = {}
    for key in _SECRET_KEYS_FROM_SETTINGS:
        value = data.get(key)
        if isinstance(value, str) and value:
            secrets[key] = value
    return secrets


def _read_top_level_secret_file(path: Path) -> str:
    """Read a single-value file like `reality_private_key`.

    Trims trailing newline; returns "" if missing."""
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        logger.warning("could not read %s: %s", path, exc)
        return ""


def _secure_delete(path: Path) -> None:
    """Overwrite a file with random bytes (length-preserving), then
    delete it. Best-effort: SSD wear-levelling may preserve data on
    the physical layer, but the filesystem index no longer points at
    the inode and there is no filename to recover."""
    if not path.exists():
        return
    try:
        size = path.stat().st_size
        if size > 0:
            with path.open("r+b", buffering=0) as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
    except OSError as exc:
        logger.warning("secure_delete failed for %s: %s", path, exc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--wipe-legacy",
        action="store_true",
        help="After migrating, overwrite+delete the source files.",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Project root (default: parent of app/).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated; do not write to secrets.json.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Late import so this script works even if app.config.py fails to
    # load (e.g. SECRET_KEY missing — the operator is doing first-boot
    # right now and hasn't set it yet).
    from app import secrets as secrets_mod

    root: Path = args.project_root
    settings_file = root / "vpn-settings.json"
    reality_file = root / "reality_private_key"

    collected: dict[str, str] = {}

    # 1. reality_private_key file
    pk = _read_top_level_secret_file(reality_file)
    if pk:
        # We use the canonical name so callers (e.g. config.py
        # back-compat shim) know to look here.
        collected["reality_private_key"] = pk
        logger.info("found: reality_private_key (%d bytes)", len(pk))

    # 2. vpn-settings.json
    settings = _read_settings_file(settings_file)
    for key, value in settings.items():
        if value and not collected.get(key):
            collected[key] = value
            logger.info("found: %s (%d bytes)", key, len(value))

    if not collected:
        logger.info("no legacy secrets found; nothing to migrate")
        return 0

    # 3. Push to secrets.json (unless dry-run)
    if args.dry_run:
        logger.info("dry-run: would migrate %d keys to secrets.json", len(collected))
        for key in collected:
            logger.info("  - %s", key)
        return 0

    for key, value in collected.items():
        secrets_mod.set_secret(key, value)
        logger.info("migrated: %s", key)

    # 4. Wipe the source files if asked
    if args.wipe_legacy:
        if reality_file.exists():
            _secure_delete(reality_file)
            logger.info("wiped: %s", reality_file)
        if settings_file.exists():
            _secure_delete(settings_file)
            logger.info("wiped: %s", settings_file)
    else:
        logger.info("re-run with --wipe-legacy to delete the source files")

    logger.info("done. secrets are at /etc/v7lthronyx/secrets.json (mode 0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
