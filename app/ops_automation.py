"""Automatic operations, run by Celery beat every minute
(``app.celery_tasks.ops_monitor``).

- Re-checks edge nodes every 5 minutes.
- Alerts admins on Telegram when Xray, an edge node, a protocol on a carrier
  or an in-country probe changes state. Only the change is announced, never
  repeated, and nothing is announced for the state found on the first run.
- Engages Emergency Cloak when in-country probes show the network turning
  hostile and releases it once they show it healthy again. A cloak an
  operator switched on is never released automatically, and a manual
  switch-off holds automation back for six hours.

The task runs in the Celery worker, not in the web process, so all state
lives in the database (settings row ``ops_automation_state``).
"""

from __future__ import annotations

import html
import json
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .api import ops
from .api.compat._core import _load_legacy_settings
from .audit import record_audit
from .config import settings
from .models import EdgeNode, ProbeAgent, ProbeReport, Setting
from .telegram_bot import TelegramBot
from .timeutil import utcnow

logger = logging.getLogger(__name__)

STATE_KEY = "ops_automation_state"
NODE_CHECK_INTERVAL = timedelta(minutes=5)
BLOCK_WINDOW = timedelta(hours=1)
BLOCK_MIN_ATTEMPTS = 3
PROBE_SILENT_AFTER = timedelta(hours=2)
CLOAK_ENGAGE_WINDOW = timedelta(minutes=30)
CLOAK_RELEASE_WINDOW = timedelta(hours=1)
CLOAK_MIN_RESULTS = 10
CLOAK_ENGAGE_MIN_PROBES = 2
CLOAK_ENGAGE_MAX_OK = 0.3
CLOAK_RELEASE_MIN_OK = 0.7
CLOAK_MIN_ON = timedelta(hours=1)
MANUAL_OFF_COOLDOWN = timedelta(hours=6)
LOG_SIZE = 30

AUTOMATION_DEFAULTS: dict[str, bool] = {
    "auto_cloak_enabled": True,
    "auto_protocol_order_enabled": True,
    "ops_alerts_enabled": True,
}

Notifier = Callable[[str], Awaitable[bool]]
_FOOTER = "\n\n🤖 V7LTHRONYX Panel"
_RLM = "\u200f"  # right-to-left mark


def automation_settings(s: dict[str, Any]) -> dict[str, bool]:
    return {k: bool(s.get(k, default)) for k, default in AUTOMATION_DEFAULTS.items()}


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value)).replace(tzinfo=None)
    except ValueError:
        return None


# ── State ────────────────────────────────────────────────────────

async def load_state(db: AsyncSession) -> dict[str, Any]:
    row = (await db.execute(select(Setting).where(Setting.key == STATE_KEY))).scalar_one_or_none()
    if row and row.value:
        try:
            data = json.loads(row.value)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            logger.warning("ops automation: ignoring unreadable state")
    return {}


async def save_state(db: AsyncSession, state: dict[str, Any]) -> None:
    row = (await db.execute(select(Setting).where(Setting.key == STATE_KEY))).scalar_one_or_none()
    value = json.dumps(state)
    if row is None:
        db.add(Setting(key=STATE_KEY, value=value, value_type="json",
                       description="Ops automation state (written by Celery beat)"))
    else:
        row.value = value
    await db.commit()


# ── Telegram ─────────────────────────────────────────────────────

def _telegram_target(s: dict[str, Any]) -> tuple[str, list[str]]:
    """Token and chat ids from the panel's Telegram settings."""
    if s.get("telegram_enabled") and s.get("telegram_bot_token") and s.get("telegram_chat_id"):
        return str(s["telegram_bot_token"]).strip(), [str(s["telegram_chat_id"]).strip()]
    token = str(getattr(settings, "telegram_bot_token", "") or "")
    chats = [str(getattr(settings, "telegram_chat_id", "") or "")]
    chats += str(getattr(settings, "telegram_admin_chat_ids", "") or "").split(",")
    return token.strip(), [c.strip() for c in dict.fromkeys(chats) if c and c.strip()]


def telegram_configured(s: dict[str, Any]) -> bool:
    token, chats = _telegram_target(s)
    return bool(token and chats)


async def send_telegram(s: dict[str, Any], text: str) -> bool:
    token, chats = _telegram_target(s)
    if not token or not chats:
        return False
    bot = TelegramBot(token=token, chat_id=chats[0])
    try:
        results = [await bot.send_message(chat, text) for chat in chats]
    finally:
        await bot.close()
    return any(r.get("ok") for r in results)


def _event(state_list: list[tuple[str, str]], title: str, *lines: str) -> None:
    """Queue one alert: (plain summary for the panel log, Telegram HTML).

    ``title`` is plain text and may hold probe-supplied names, so it is
    escaped here; ``lines`` are HTML the caller already escaped.
    """
    # Telegram picks each line's direction from its first strong character;
    # titles often start with an English name, so mark every line RTL.
    body = "\n".join(_RLM + line for line in lines)
    state_list.append((title, f"{_RLM}<b>{html.escape(title)}</b>" + (f"\n\n{body}" if body else "") + _FOOTER))


# ── Checks ───────────────────────────────────────────────────────

async def _check_xray(state: dict[str, Any], events: list[tuple[str, str]]) -> None:
    up = ops._process_running("xray")
    before = state.get("xray_running")
    if before is not None and before != up:
        if up:
            _event(events, "✅ Xray دوباره در حال اجراست")
        else:
            _event(events, "🔴 Xray متوقف شده", "اتصال همهٔ کاربران قطع است. از پنل وضعیت سرور را بررسی کنید.")
    state["xray_running"] = up


async def _check_nodes(db: AsyncSession, state: dict[str, Any], events, now: datetime) -> None:
    nodes = list((await db.execute(select(EdgeNode).order_by(EdgeNode.id))).scalars().all())
    last = _parse(state.get("nodes_checked_at"))
    if nodes and (last is None or now - last >= NODE_CHECK_INTERVAL):
        await ops._check_nodes(db, nodes)
        state["nodes_checked_at"] = now.isoformat()
    before = state.get("nodes") or {}
    current: dict[str, bool] = {}
    for n in nodes:
        if n.reachable is None:
            continue
        current[str(n.id)] = bool(n.reachable)
        was = before.get(str(n.id))
        if was is None or was == n.reachable:
            continue
        where = html.escape(f"{n.address}:{n.port}")
        name = html.escape(n.name)
        if n.reachable:
            _event(events, f"✅ نود {n.name} دوباره در دسترس است", f"🖥 <code>{name}</code> · <code>{where}</code>",
                   f"⏱ RTT: <code>{n.rtt_ms} ms</code>")
        else:
            _event(events, f"🔴 نود {n.name} از دسترس خارج شد", f"🖥 <code>{name}</code> · <code>{where}</code>",
                   f"⚠️ <code>{html.escape(n.last_error or 'unreachable')}</code>")
    state["nodes"] = current


async def _check_blocks(db: AsyncSession, state: dict[str, Any], events, now: datetime) -> None:
    rows = (
        await db.execute(
            select(ProbeReport.carrier, ProbeReport.protocol, ProbeReport.ok)
            .where(ProbeReport.created_at >= now - BLOCK_WINDOW)
        )
    ).all()
    acc: dict[str, list[int]] = {}
    for carrier, protocol, ok in rows:
        cell = acc.setdefault(f"{carrier}|{protocol}", [0, 0])
        cell[0] += 1
        cell[1] += 1 if ok else 0
    blocked = {k for k, (attempts, ok) in acc.items() if attempts >= BLOCK_MIN_ATTEMPTS and ok == 0}
    if state.get("blocked") is None:  # first run: record, don't announce
        state["blocked"] = sorted(blocked)
        return
    before = set(state["blocked"])
    labels = {p[0]: p[1] for p in ops._PROTOCOLS}
    for key in sorted(blocked - before):
        carrier, protocol = key.split("|", 1)
        _event(events, f"⛔ {labels.get(protocol, protocol)} روی {carrier} بسته شده",
               f"📡 اپراتور: <code>{html.escape(carrier)}</code>",
               f"🔌 پروتکل: <code>{html.escape(labels.get(protocol, protocol))}</code>",
               f"🧪 {acc[key][0]} تست ناموفق در یک ساعت گذشته")
    for key in sorted(before - blocked):
        # Announce recovery only on evidence; a probe that just went quiet
        # is reported separately as silent.
        if acc.get(key, [0, 0])[1] > 0:
            carrier, protocol = key.split("|", 1)
            _event(events, f"✅ {labels.get(protocol, protocol)} روی {carrier} دوباره کار می‌کند",
                   f"📡 اپراتور: <code>{html.escape(carrier)}</code>")
    state["blocked"] = sorted(blocked)


async def _check_probes(db: AsyncSession, state: dict[str, Any], events, now: datetime) -> None:
    probes = (await db.execute(select(ProbeAgent).where(ProbeAgent.active.is_(True)))).scalars().all()
    by_id = {str(p.id): p for p in probes}
    silent = {pid for pid, p in by_id.items() if p.last_seen_at and now - p.last_seen_at > PROBE_SILENT_AFTER}
    if state.get("silent_probes") is None:  # first run: record, don't announce
        state["silent_probes"] = sorted(silent)
        return
    before = set(state["silent_probes"])
    for pid in sorted(silent - before):
        _event(events, f"📴 probe {by_id[pid].name} بیش از ۲ ساعت گزارشی نفرستاده",
               "ممکن است دستگاه خاموش باشد، یا پنل از داخل ایران در دسترس نباشد.",
               f"📡 آخرین اپراتور: <code>{html.escape(by_id[pid].last_carrier or '—')}</code>")
    for pid in sorted((before - silent) & by_id.keys()):
        _event(events, f"📶 probe {by_id[pid].name} دوباره گزارش می‌فرستد")
    state["silent_probes"] = sorted(silent)


async def _window_stats(db: AsyncSession, since: datetime) -> tuple[int, int, int]:
    """(results, ok results, distinct probes) since ``since``."""
    results, ok, probes = (
        await db.execute(
            select(
                func.count(ProbeReport.id),
                func.coalesce(func.sum(case((ProbeReport.ok, 1), else_=0)), 0),
                func.count(func.distinct(ProbeReport.probe_id)),
            ).where(ProbeReport.created_at >= since)
        )
    ).one()
    return int(results or 0), int(ok or 0), int(probes or 0)


async def _auto_cloak(db: AsyncSession, s: dict[str, Any], events, now: datetime) -> None:
    if not s.get("emergency_cloak_active"):
        manual_off = _parse(s.get("emergency_cloak_manual_off_at"))
        if manual_off and now - manual_off < MANUAL_OFF_COOLDOWN:
            return
        results, ok, probes = await _window_stats(db, now - CLOAK_ENGAGE_WINDOW)
        if results < CLOAK_MIN_RESULTS or probes < CLOAK_ENGAGE_MIN_PROBES or ok / results >= CLOAK_ENGAGE_MAX_OK:
            return
        changed, _ = await ops.apply_cloak(db, True, "auto")
        if not changed:
            return
        reason = f"probe success {round(100 * ok / results)}% over {results} tests from {probes} probes (30 min)"
        await record_audit(db, "emergency_cloak_on", details={"source": "auto", "reason": reason})
        _event(events, "🛡 Emergency Cloak خودکار روشن شد",
               f"📉 موفقیت تست‌های داخل ایران: <code>{round(100 * ok / results)}%</code> "
               f"({results} تست از {probes} probe در ۳۰ دقیقهٔ گذشته)",
               "کاربران با به‌روزرسانی لینک اشتراک، تنظیمات fragment و noise را می‌گیرند.")
        return

    if s.get("emergency_cloak_source") != "auto":
        return  # an operator switched it on; only an operator switches it off
    since = _parse(s.get("emergency_cloak_since"))
    if since and now - since < CLOAK_MIN_ON:
        return
    results, ok, _ = await _window_stats(db, now - CLOAK_RELEASE_WINDOW)
    if results < CLOAK_MIN_RESULTS or ok / results < CLOAK_RELEASE_MIN_OK:
        return
    changed, _ = await ops.apply_cloak(db, False, "auto")
    if not changed:
        return
    reason = f"probe success {round(100 * ok / results)}% over {results} tests (1 h)"
    await record_audit(db, "emergency_cloak_off", details={"source": "auto", "reason": reason})
    _event(events, "🟢 Emergency Cloak خودکار خاموش شد",
           f"📈 موفقیت تست‌ها در یک ساعت گذشته: <code>{round(100 * ok / results)}%</code>",
           "تنظیمات قبلی fragment و noise برگردانده شد.")


# ── Entry point ──────────────────────────────────────────────────

async def run_monitor(db: AsyncSession, *, notify: Notifier | None = None,
                      now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    s = await _load_legacy_settings(db)
    auto = automation_settings(s)
    state = await load_state(db)
    events: list[tuple[str, str]] = []

    for step, check in (
        ("xray", lambda: _check_xray(state, events)),
        ("nodes", lambda: _check_nodes(db, state, events, now)),
        ("blocks", lambda: _check_blocks(db, state, events, now)),
        ("probes", lambda: _check_probes(db, state, events, now)),
    ):
        try:
            await check()
        except Exception:  # noqa: BLE001 - one failing check must not stop the rest
            logger.exception("ops automation: %s check failed", step)
    if auto["auto_cloak_enabled"]:
        try:
            await _auto_cloak(db, s, events, now)
        except Exception:  # noqa: BLE001
            logger.exception("ops automation: auto cloak failed")

    delivered = None
    if events and auto["ops_alerts_enabled"] and (notify or telegram_configured(s)):
        send = notify or (lambda text: send_telegram(s, text))
        delivered = False
        for _, text in events:
            try:
                delivered = bool(await send(text)) or delivered
            except Exception:  # noqa: BLE001 - alerting is best effort
                logger.exception("ops automation: alert delivery failed")

    state["log"] = (
        [{"at": now.isoformat(), "text": title} for title, _ in events] + list(state.get("log") or [])
    )[:LOG_SIZE]
    state["last_run_at"] = now.isoformat()
    if delivered is not None:
        state["last_delivery_ok"] = delivered
    await save_state(db, state)
    return {"events": len(events), "delivered": delivered}
