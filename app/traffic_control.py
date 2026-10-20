"""Per-user packet marks: speed limits for every engine but mita, and exact
byte counts for sing-box users (sing-box keeps no per-user statistics).

The engine sets the mark (SO_MARK) on each connection it opens for a user:
  Xray     0x100000 | id   only users with a speed limit; Xray counts its own
  sing-box 0x200000 | id   every user: the kernel counts their bytes
The kernel side (nftables counters, tc shaping) is app/traffic_kernel.py,
reached through the privileged helper.

Speed limits are in KB/s, as the panel shows them (0 = unlimited). Mieru is
not limited: mita cannot mark one user's connections.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import func, select, update

from .models import VpnUser

logger = logging.getLogger(__name__)

XRAY_MARK = 0x100000
SINGBOX_MARK = 0x200000
ID_MASK = 0x0FFFFF


def xray_mark(user_id: int) -> int:
    return XRAY_MARK | (user_id & ID_MASK)


def singbox_mark(user_id: int) -> int:
    return SINGBOX_MARK | (user_id & ID_MASK)


CAP_NET_ADMIN = 12


def engine_can_mark(process: str, proc: str = "/proc") -> bool:
    """Whether the running engine may set SO_MARK (CAP_NET_ADMIN). Without
    it every marked connection fails with EPERM, so callers leave marks out.
    The installer's units and the official Xray / sing-box ones grant it;
    an engine that is not running yet is assumed to get it too."""
    import os

    for pid in filter(str.isdigit, os.listdir(proc)):
        try:
            with open(f"{proc}/{pid}/comm") as fh:
                if fh.read().strip() != process:
                    continue
            with open(f"{proc}/{pid}/status") as fh:
                for line in fh:
                    if line.startswith("CapEff:"):
                        return bool(int(line.split()[1], 16) >> CAP_NET_ADMIN & 1)
        except OSError:
            continue
    return True


def has_limit(user: VpnUser) -> bool:
    return bool((user.speed_limit_up or 0) > 0 or (user.speed_limit_down or 0) > 0)


def xray_limit_tag(user_id: int) -> str:
    return f"limit-{user_id}"


def xray_limit_parts(users: list[VpnUser]) -> tuple[list[dict], list[dict]]:
    """Outbounds and routing rules that send limited users out marked."""
    outbounds, rules = [], []
    if not engine_can_mark("xray"):
        logger.warning("Xray lacks CAP_NET_ADMIN: speed limits are not applied to Xray users")
        return outbounds, rules
    for u in users:
        if not has_limit(u):
            continue
        tag = xray_limit_tag(u.id)
        outbounds.append({"tag": tag, "protocol": "freedom",
                          "streamSettings": {"sockopt": {"mark": xray_mark(u.id)}}})
        rules.append({"type": "field", "user": [u.name], "outboundTag": tag, "ruleTag": tag})
    return outbounds, rules


def shaping_spec(users: list[VpnUser]) -> list[dict[str, Any]]:
    return [
        {"marks": [xray_mark(u.id), singbox_mark(u.id)],
         "up_kbit": int(u.speed_limit_up or 0) * 8, "down_kbit": int(u.speed_limit_down or 0) * 8}
        for u in users if has_limit(u)
    ]


_last_spec: str | None = None


async def apply_shaping(users: list[VpnUser]) -> str:
    """Push the speed limits to the kernel when they changed."""
    global _last_spec
    from .privileged_helper import PrivilegedHelperError, helper_request

    spec = shaping_spec(users)
    key = json.dumps(spec, sort_keys=True)
    if key == _last_spec:
        return "unchanged"
    try:
        out = await helper_request("traffic.shaping.apply", {"users": spec}, timeout=120)
    except PrivilegedHelperError as exc:
        return f"failed: {exc}"
    if not out.ok:
        logger.warning("Speed limits not applied: %s", out.message)
        return f"failed: {out.message}"
    _last_spec = key
    return out.message


async def add_bytes(db, by_id: dict[int, tuple[int, int]] | None = None,
                    by_name: dict[str, tuple[int, int]] | None = None) -> int:
    """Add (up, down) bytes to users' totals and to today's row in
    traffic_daily, keyed by user id or by name. Caller commits."""
    from sqlalchemy.exc import IntegrityError

    from .models import TrafficDaily
    from .timeutil import utcnow

    per_id: dict[int, list[int]] = {}
    for uid, (up, down) in (by_id or {}).items():
        if up or down:
            acc = per_id.setdefault(int(uid), [0, 0])
            acc[0] += up
            acc[1] += down
    names = {n: v for n, v in (by_name or {}).items() if v[0] or v[1]}
    if names:
        rows = await db.execute(select(VpnUser.id, VpnUser.name).where(VpnUser.name.in_(list(names))))
        for uid, name in rows.all():
            acc = per_id.setdefault(uid, [0, 0])
            acc[0] += names[name][0]
            acc[1] += names[name][1]
    day = utcnow().date()
    for uid, (up, down) in per_id.items():
        await db.execute(update(VpnUser).where(VpnUser.id == uid).values(**_increments(up, down)))
        bumped = await db.execute(
            update(TrafficDaily).where(TrafficDaily.day == day, TrafficDaily.user_id == uid)
            .values(upload=TrafficDaily.upload + up, download=TrafficDaily.download + down)
        )
        if not bumped.rowcount:
            try:
                async with db.begin_nested():
                    db.add(TrafficDaily(day=day, user_id=uid, upload=up, download=down))
            except IntegrityError:  # another collector made today's row first
                await db.execute(
                    update(TrafficDaily).where(TrafficDaily.day == day, TrafficDaily.user_id == uid)
                    .values(upload=TrafficDaily.upload + up, download=TrafficDaily.download + down)
                )
    return len(per_id)


def _increments(up: int, down: int) -> dict:
    return {
        "traffic_upload": func.coalesce(VpnUser.traffic_upload, 0) + up,
        "traffic_download": func.coalesce(VpnUser.traffic_download, 0) + down,
        "traffic_used": func.coalesce(VpnUser.traffic_used, 0) + up + down,
    }


async def collect_engine_traffic(db) -> dict[str, int]:
    """sing-box users' bytes from the kernel counters, Mieru users' from mita.
    Both reads return only bytes not read before, so runners never overlap."""
    from .privileged_helper import PrivilegedHelperError, helper_request
    from .standalone_engines import engine_installed

    result = {"sing-box": 0, "mieru": 0}
    if engine_installed("sing-box"):
        try:
            out = await helper_request("traffic.accounting.read", {}, timeout=20)
            if out.ok and out.data:
                up, down = out.data.get("up", {}), out.data.get("down", {})
                by_id: dict[int, tuple[int, int]] = {}
                for mark in set(up) | set(down):
                    uid = int(mark) & ID_MASK
                    by_id[uid] = (int(up.get(mark, 0)), int(down.get(mark, 0)))
                result["sing-box"] = await add_bytes(db, by_id=by_id)
        except PrivilegedHelperError:
            pass
    if engine_installed("mita"):
        try:
            out = await helper_request("traffic.mieru.read", {}, timeout=20)
            if out.ok and out.data:
                # mita knows users by their Mieru name: the user's own name
                # unless one name is shared by everyone (then nobody matches).
                names = {n: (int(v.get("up", 0)), int(v.get("down", 0))) for n, v in out.data.items()}
                result["mieru"] = await add_bytes(db, by_name=names)
        except PrivilegedHelperError:
            pass
    if result["sing-box"] or result["mieru"]:
        await db.commit()
    return result


OLD_FORM_DEFAULT = 200  # KB/s the add-user forms used to fill in


async def retire_unenforced_default_limits(db) -> int:
    """Speed limits used to be stored but never enforced, and the forms
    filled in 200 KB/s by default. Now that they are enforced, keep the
    speed users actually had: the untouched default (200 up and down, and an
    agent default of 200) becomes unlimited. Any other value was chosen on
    purpose and is kept. Runs once per install."""
    from .api.compat._core import _load_legacy_settings, _save_legacy_settings
    from .models import Agent

    s = await _load_legacy_settings(db)
    if s.get("speed_limits_enforced"):
        return 0
    result = await db.execute(
        update(VpnUser)
        .where(VpnUser.speed_limit_up == OLD_FORM_DEFAULT, VpnUser.speed_limit_down == OLD_FORM_DEFAULT)
        .values(speed_limit_up=0, speed_limit_down=0)
    )
    for agent in (await db.execute(select(Agent))).scalars().all():
        meta = dict(agent.ech_config) if isinstance(agent.ech_config, dict) else {}
        if int(meta.get("speed_limit_default") or 0) == OLD_FORM_DEFAULT:
            meta["speed_limit_default"] = 0
            agent.ech_config = meta
    await db.commit()
    await _save_legacy_settings(db, {"speed_limits_enforced": True})
    if result.rowcount:
        logger.info("Speed limits now enforced: %d users on the old unenforced 200 KB/s default set to unlimited",
                    result.rowcount)
    return result.rowcount or 0
