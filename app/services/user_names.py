"""VPN user names must be unique.

The panel UI, the agent panel, the Telegram bot and the mobile app address
users by name (`/users/{name}/toggle`, renew, delete, ...), and those lookups
use `scalar_one_or_none()`. A second row with the same name makes every one
of them fail, so the user can no longer be managed. The table has no unique
constraint (existing installs may already hold duplicates), so every create
path checks here first.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import VpnUser

# Quotes, angle brackets and path/URL separators break the panel (they land in
# HTML attributes and in /users/{name} paths). Letters from any language stay.
_UNSAFE_NAME = re.compile(r"[\x00-\x1f\x7f/\\?#%<>\"']")


def display_name_error(value: str, *, label: str = "Name") -> str | None:
    """Return a reason the label cannot be stored, or None when it is fine."""
    if not isinstance(value, str):
        return f"{label} is required."
    name = value.strip()
    if not name or len(name) > 100:
        return f"{label} must be 1–100 characters."
    if _UNSAFE_NAME.search(name):
        return f"{label} contains characters that are not allowed."
    return None


async def taken_vpn_user_names(db: AsyncSession, names: Iterable[str]) -> set[str]:
    """Return the subset of ``names`` already used by a VPN user."""
    wanted = list(dict.fromkeys(names))
    if not wanted:
        return set()
    result = await db.execute(select(VpnUser.name).where(VpnUser.name.in_(wanted)))
    return set(result.scalars().all())
