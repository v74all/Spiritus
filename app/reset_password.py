"""
Reset an admin's password from the server shell.

For an operator locked out of the panel (forgotten password, lost 2FA
device). Run as the panel user from the install dir so .env, the secrets
store and the database credentials load exactly as they do for the service:

    cd /opt/v7lthronyx && runuser -u vpnpanel -- venv/bin/python -m app.reset_password
    ... --username admin       # required when more than one admin exists
    ... --disable-2fa          # also turn off TOTP for that admin

`install.sh reset-password` wraps this. A random password is generated and
printed rather than taken as an argument, so it never lands in shell
history or `ps` output. Every existing session for the admin is
invalidated.
"""

from __future__ import annotations

import argparse
import asyncio
import re
import secrets
import string
import sys

from sqlalchemy import select

_SYMBOLS = "!@#%^*-_=+"


def generate_password(length: int = 20) -> str:
    """Same shape as the installer's bootstrap password: every character
    class validate_password_strength requires is guaranteed present."""
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + _SYMBOLS
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw)
                and re.search(r"[0-9]", pw) and re.search(r"[^A-Za-z0-9]", pw)):
            return pw


async def reset_admin_password(username: str | None, disable_2fa: bool) -> tuple[int, str | None]:
    """Returns (exit_code, new_password). The password is None on failure."""
    from .audit import record_audit
    from .auth import get_password_hash, invalidate_sessions
    from .database import AsyncSessionLocal
    from .models import Admin

    async with AsyncSessionLocal() as db:
        admins = (await db.execute(select(Admin).order_by(Admin.id))).scalars().all()
        if not admins:
            print("No admin account exists yet. Restart the panel so it creates one "
                  "from ADMIN_BOOTSTRAP_PASSWORD in .env.", file=sys.stderr)
            return 1, None

        names = ", ".join(a.username for a in admins)
        if username is None:
            if len(admins) > 1:
                print(f"More than one admin exists ({names}). Pass --username.", file=sys.stderr)
                return 2, None
            admin = admins[0]
        else:
            admin = next((a for a in admins if a.username == username), None)
            if admin is None:
                print(f"No admin named '{username}'. Existing admins: {names}", file=sys.stderr)
                return 2, None

        new_password = generate_password()
        admin.password_hash = get_password_hash(new_password)
        if disable_2fa:
            admin.totp_enabled = False
            admin.totp_secret = None
        await db.commit()
        await record_audit(
            db, "password_reset_cli", admin_id=admin.id,
            details={"disable_2fa": disable_2fa},
        )
        username = admin.username

    sessions_cleared = await invalidate_sessions(username)

    print(f"Username: {username}")
    print(f"Password: {new_password}")
    if disable_2fa:
        print("2FA:      disabled")
    if sessions_cleared:
        print("All existing sessions for this admin were logged out.")
    else:
        print("Warning: Redis is unreachable, so existing sessions were NOT logged out. "
              "Start Redis and run this again to log them out.", file=sys.stderr)
    return 0, new_password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 2)[1])
    parser.add_argument("--username", help="admin to reset (default: the only admin)")
    parser.add_argument("--disable-2fa", action="store_true", help="also turn off TOTP 2FA")
    args = parser.parse_args(argv)

    async def _run() -> int:
        from .database import async_engine
        try:
            code, _ = await reset_admin_password(args.username, args.disable_2fa)
            return code
        finally:
            await async_engine.dispose()

    return asyncio.run(_run())


if __name__ == "__main__":
    sys.exit(main())
