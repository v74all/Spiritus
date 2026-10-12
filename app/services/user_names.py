"""VPN user names must be unique.

The panel UI, the agent panel, the Telegram bot and the mobile app address
users by name (`/users/{name}/toggle`, renew, delete, ...), and those lookups
use `scalar_one_or_none()`. A second row with the same name makes every one
of them fail, so the user can no longer be managed. The table has no unique
constraint (existing installs may already hold duplicates), so every create
path checks here first.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import VpnUser


async def taken_vpn_user_names(db: AsyncSession, names: Iterable[str]) -> set[str]:
    """Return the subset of ``names`` already used by a VPN user."""
    wanted = list(dict.fromkeys(names))
    if not wanted:
        return set()
    result = await db.execute(select(VpnUser.name).where(VpnUser.name.in_(wanted)))
    return set(result.scalars().all())
