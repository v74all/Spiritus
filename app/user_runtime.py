"""Keep the running proxy engines in step with the users in the database.

Xray takes users live through its API (`xray api adu` / `rmu`): creating,
renewing, disabling or deleting a user takes effect at once, without
restarting Xray or dropping anyone else's connection. Every change is a
reconcile — the active users in the DB against the users each live inbound
actually holds — so it also repairs drift (an Xray restarted on an old
config, a change made by another worker). When the live inbounds no longer
match the settings, a full config install + restart is the fallback.

Also here: traffic accounting and the quota / expiry rules. Traffic is read
with `statsquery --reset`, so every reader gets its own bytes: two panel
workers and Celery can all collect without ever counting a byte twice.

User status (VpnUser.active): 1 active, 0 disabled by hand, -1 expired,
-2 traffic quota used up. Only 1 is served. -1 and -2 come back on their own
once the user is renewed or given more traffic; 0 stays until switched on.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import time
from typing import Any

from sqlalchemy import event, select
from sqlalchemy.orm import Session

from .config import settings
from .models import VpnUser
from .timeutil import utcnow

logger = logging.getLogger(__name__)

ACTIVE, DISABLED, EXPIRED, QUOTA = 1, 0, -1, -2

# Protocols whose inbounds take per-user credentials through the API.
_USER_PROTOCOLS = {"vmess", "vless", "trojan", "shadowsocks"}
_SYNC_DEBOUNCE = 1.0
COLLECT_INTERVAL = 30.0


# ── Xray CLI ────────────────────────────────────────────────────────────

def _api_server() -> str:
    return f"127.0.0.1:{getattr(settings, 'api_port', 10085) or 10085}"


def _xray_api(command: str, *args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    # Flags before positionals: Go's flag parsing stops at the first
    # positional, so a trailing --server= would be taken as a file or email.
    return subprocess.run(
        [settings.xray_bin_path or "/usr/local/bin/xray", "api", command, f"--server={_api_server()}", *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _json_out(proc: subprocess.CompletedProcess) -> dict[str, Any] | None:
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return None


def query_user_stats(reset: bool = False) -> dict[str, dict[str, int]]:
    """Per-user Xray traffic counters: {email: {"up": n, "down": n}}.

    Blocking (runs the CLI): call through asyncio.to_thread from async code.
    """
    args = ["statsquery", "-pattern", "user>>>"]
    if reset:
        args.append("-reset")
    try:
        data = _json_out(_xray_api(*args, timeout=10))
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("xray statsquery failed: %s", exc)
        return {}
    stats: dict[str, dict[str, int]] = {}
    for stat in (data or {}).get("stat", []):
        parts = str(stat.get("name", "")).split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
            continue
        entry = stats.setdefault(parts[1], {"up": 0, "down": 0})
        entry["up" if parts[3] == "uplink" else "down"] = int(stat.get("value") or 0)
    return stats


def online_ips(email: str) -> list[str]:
    """IPs of the user's live sessions (needs policy statsUserOnline)."""
    try:
        data = _json_out(_xray_api("statsonlineiplist", f"-email={email}", timeout=5))
    except (OSError, subprocess.SubprocessError):
        return []
    return sorted((data or {}).get("ips", {}) or {})


# ── Reconcile ───────────────────────────────────────────────────────────

def _identity(entry: dict[str, Any]) -> tuple:
    """What a client is known by: its credential, and the VLESS flow."""
    secret = entry.get("id") or entry.get("password") or entry.get("key") or ""
    return (secret, entry.get("flow") or "")


def _live_users(tag: str) -> dict[str, tuple] | None:
    data = _json_out(_xray_api("inbounduser", f"-tag={tag}"))
    if data is None:
        return None
    return {u.get("email", ""): _identity(u.get("account") or {}) for u in data.get("users", []) or []}


def _reconcile_blocking(config: dict[str, Any]) -> dict[str, Any]:
    """Make the live Xray users match `config`. Blocking; run in a thread."""
    listed = _json_out(_xray_api("lsi"))
    if listed is None:
        return {"ok": False, "reason": "Xray API unreachable"}
    live_tags = {ib.get("tag") for ib in listed.get("inbounds", []) if ib.get("tag")}
    wanted_tags = {ib["tag"] for ib in config.get("inbounds", [])}
    if live_tags != wanted_tags:
        return {"ok": False, "reason": "inbounds differ from settings"}

    to_add: list[dict[str, Any]] = []
    removed = added = 0
    for ib in config["inbounds"]:
        if ib.get("protocol") not in _USER_PROTOCOLS:
            continue
        live = _live_users(ib["tag"])
        if live is None:
            return {"ok": False, "reason": f"cannot list users of {ib['tag']}"}
        wanted = {c.get("email", ""): c for c in ib.get("settings", {}).get("clients", [])}
        stale = [e for e, ident in live.items() if e not in wanted or ident != _identity(wanted[e])]
        if stale:
            out = _xray_api("rmu", f"-tag={ib['tag']}", *stale)
            if out.returncode != 0:
                return {"ok": False, "reason": f"rmu failed on {ib['tag']}"}
            removed += len(stale)
        missing = [c for e, c in wanted.items() if e not in live or e in stale]
        if missing:
            clone = json.loads(json.dumps(ib))
            clone["settings"]["clients"] = missing
            to_add.append(clone)
            added += len(missing)
    if to_add:
        fd, path = tempfile.mkstemp(prefix="xray-adu-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"inbounds": to_add}, fh)
            out = _xray_api("adu", path)
        finally:
            os.unlink(path)
        # Another worker may have added the same user a moment ago.
        errors = [ln for ln in (out.stdout + out.stderr).splitlines()
                  if "rpc error" in ln and "already exists" not in ln]
        if out.returncode != 0 or errors:
            return {"ok": False, "reason": "adu failed: " + " ".join(errors)[-200:]}
    limits = _reconcile_limits(config)
    if not limits["ok"]:
        return limits
    return {"ok": True, "added": added, "removed": removed, "limits": limits["changed"]}


def _api_with_file(command: str, payload: dict[str, Any]) -> subprocess.CompletedProcess:
    fd, path = tempfile.mkstemp(prefix=f"xray-{command}-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        return _xray_api(command, path)
    finally:
        os.unlink(path)


def _reconcile_limits(config: dict[str, Any]) -> dict[str, Any]:
    """Speed-limited users leave through marked outbounds picked by routing
    rules (app/traffic_control.py); keep the live ones matching `config`."""
    listed = _json_out(_xray_api("lso"))
    rules_now = _json_out(_xray_api("lsrules"))
    if listed is None or rules_now is None:
        return {"ok": False, "reason": "cannot list outbounds / rules"}
    live_out = {o.get("tag", "") for o in listed.get("outbounds", [])}
    want_out = {o["tag"]: o for o in config.get("outbounds", []) if o["tag"].startswith("limit-")}
    rules = config.get("routing", {}).get("rules", [])
    live_rules = {r.get("ruleTag", "") for r in rules_now.get("rules", []) or []} - {""}
    new_out = [o for t, o in want_out.items() if t not in live_out]
    stale_out = [t for t in live_out if t.startswith("limit-") and t not in want_out]
    changed = bool(new_out or stale_out or live_rules != {r["ruleTag"] for r in rules})
    if not changed:
        return {"ok": True, "changed": 0}
    if new_out and _api_with_file("ado", {"outbounds": new_out}).returncode != 0:
        return {"ok": False, "reason": "ado failed"}
    # adrules without -append replaces the whole rule list: one atomic swap.
    if rules:
        if _api_with_file("adrules", {"routing": {"rules": rules}}).returncode != 0:
            return {"ok": False, "reason": "adrules failed"}
    elif live_rules and _xray_api("rmrules", *sorted(live_rules)).returncode != 0:
        return {"ok": False, "reason": "rmrules failed"}
    if stale_out and _xray_api("rmo", *stale_out).returncode != 0:
        return {"ok": False, "reason": "rmo failed"}
    return {"ok": True, "changed": len(new_out) + len(stale_out) or 1}


async def _desired_xray_config(db) -> tuple[dict[str, Any], int]:
    from .api.compat import _load_legacy_settings
    from .api.compat.panel_settings import _generate_xray_server_config
    from .traffic_control import xray_limit_parts

    await _load_legacy_settings(db)
    users = (await db.execute(select(VpnUser).where(VpnUser.active == ACTIVE))).scalars().all()
    vmess = [{"id": u.uuid, "alterId": 0, "email": u.name} for u in users]
    vless = [{"id": u.uuid, "email": u.name} for u in users]
    trojan = [{"password": u.uuid, "email": u.name} for u in users]
    return _generate_xray_server_config(vmess, vless, trojan, xray_limit_parts(users)), len(users)


async def sync_engines() -> dict[str, Any]:
    """Apply the DB's active users to Xray live, persist the config file,
    and rebuild the sing-box / mita configs (they have no user API)."""
    from .api.compat.panel_settings import _sync_xray_config_async
    from .database import AsyncSessionLocal
    from .privileged_helper import PrivilegedHelperError, helper_request

    async with AsyncSessionLocal() as db:
        config, n_users = await _desired_xray_config(db)
        result = await asyncio.to_thread(_reconcile_blocking, config)
        if not result["ok"]:
            logger.info("Live user sync unavailable (%s); reinstalling Xray config", result["reason"])
            await _sync_xray_config_async(delay=0)
        elif result["added"] or result["removed"] or result.get("limits"):
            # Keep the file in step so the next restart serves the same users.
            try:
                await helper_request("config.install", {"target": "xray", "content": json.dumps(config)})
            except PrivilegedHelperError as exc:
                logger.warning("Could not persist Xray config: %s", exc)
            logger.info("Xray users synced live: +%d -%d (%d active)", result["added"], result["removed"], n_users)
        result["standalone"] = await sync_standalone_engines(db)
        from .traffic_control import apply_shaping

        users = (await db.execute(select(VpnUser).where(VpnUser.active == ACTIVE))).scalars().all()
        result["speed_limits"] = await apply_shaping(users)
    return result


async def sync_standalone_engines(db) -> dict[str, Any]:
    """sing-box (Hysteria2, TUIC, ShadowTLS, Naive) and mita (Mieru)."""
    from .standalone_engines import apply_standalone_engines

    return await apply_standalone_engines(db)


# Debounced, coalescing trigger: a burst of changes (bulk create, a whole
# reseller deleted) costs one reconcile.
_dirty = False
_task: asyncio.Task | None = None


def request_sync() -> None:
    global _dirty, _task
    _dirty = True
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    if _task is None or _task.done():
        _task = loop.create_task(_sync_soon())


async def _sync_soon() -> None:
    global _dirty
    while _dirty:
        await asyncio.sleep(_SYNC_DEBOUNCE)
        _dirty = False
        try:
            await sync_engines()
        except Exception:
            logger.exception("User sync failed")


_TRACKED = ("active", "uuid", "name", "speed_limit_up", "speed_limit_down")


@event.listens_for(Session, "after_flush")
def _note_user_changes(session: Session, flush_context) -> None:
    from sqlalchemy import inspect

    for obj in (*session.new, *session.deleted):
        if isinstance(obj, VpnUser):
            session.info["vpn_users_changed"] = True
            return
    for obj in session.dirty:
        if isinstance(obj, VpnUser):
            attrs = inspect(obj).attrs
            if any(attrs[a].history.has_changes() for a in _TRACKED):
                session.info["vpn_users_changed"] = True
                return


@event.listens_for(Session, "after_commit")
def _sync_after_commit(session: Session) -> None:
    if session.info.pop("vpn_users_changed", False) and settings.user_runtime_sync:
        request_sync()


@event.listens_for(Session, "after_rollback")
def _forget_after_rollback(session: Session) -> None:
    session.info.pop("vpn_users_changed", None)


# ── Status rules ────────────────────────────────────────────────────────

def status_for(user: VpnUser, now=None) -> int:
    """The status a user should have by its expiry and quota. A user
    switched off by hand stays off."""
    if user.active == DISABLED:
        return DISABLED
    now = now or utcnow()
    if user.expire_at is not None and user.expire_at < now:
        return EXPIRED
    limit = int(user.traffic_limit or 0)
    if limit > 0 and int(user.traffic_used or 0) >= limit:
        return QUOTA
    return ACTIVE


def refresh_status(user: VpnUser) -> int:
    """Apply status_for() to one user now (after a renew, more traffic...)."""
    user.active = status_for(user)
    return user.active


def status_name(active: int | None) -> str:
    return {ACTIVE: "active", EXPIRED: "expired", QUOTA: "limited"}.get(active, "disabled")


async def enforce_limits(db) -> int:
    """Expire, limit or bring back users by the rules above. Returns how
    many changed; the commit triggers the engine sync."""
    users = (await db.execute(
        select(VpnUser).where(VpnUser.active.in_((ACTIVE, EXPIRED, QUOTA)))
    )).scalars().all()
    now = utcnow()
    changed = 0
    for u in users:
        new = status_for(u, now)
        if new != u.active:
            logger.info("User %s: %s -> %s", u.name, status_name(u.active), status_name(new))
            u.active = new
            changed += 1
    if changed:
        await db.commit()
    return changed


# ── Traffic ─────────────────────────────────────────────────────────────

async def collect_traffic(db) -> int:
    """Add Xray's per-user bytes since the last read to the DB."""
    from .api.compat._core import _user_last_seen
    from .traffic_control import add_bytes, collect_engine_traffic

    stats = await asyncio.to_thread(query_user_stats, True)
    now = time.time()
    moved = {n: (int(s.get("up") or 0), int(s.get("down") or 0)) for n, s in stats.items()}
    moved = {n: v for n, v in moved.items() if v[0] or v[1]}
    for name in moved:
        _user_last_seen[name] = now
    counted = await add_bytes(db, by_name=moved) if moved else 0
    if counted:
        await db.commit()
    engines = await collect_engine_traffic(db)
    return counted + engines["sing-box"] + engines["mieru"]


async def run_cycle() -> dict[str, int]:
    """One accounting + enforcement pass (panel loop and Celery)."""
    from .database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        counted = await collect_traffic(db)
        changed = await enforce_limits(db)
    if changed:
        await sync_engines()
    return {"counted": counted, "status_changes": changed}


async def run_forever() -> None:
    """Panel background loop. Celery runs the same cycle; with read-and-
    reset stats, extra runners split the bytes instead of doubling them."""
    reconcile_every = 10  # cycles: a periodic drift repair (~5 min)
    n = 0
    while True:
        await asyncio.sleep(COLLECT_INTERVAL)
        n += 1
        try:
            await run_cycle()
            if n % reconcile_every == 0:
                await sync_engines()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Traffic / limits cycle failed")
