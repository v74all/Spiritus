"""Telegram self-service for end users.

A user binds their chat with ``/link <subscription-uuid>`` (the UUID is the
bearer secret they already hold), then can check usage, list plans and start a
renewal payment. Replies are HTML-escaped plain strings; the caller sends them.
"""

from __future__ import annotations

import html
import logging
import time

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import VpnUser
from .payments import PLANS
from .reseller import self_service_portal

logger = logging.getLogger(__name__)

_UUID_LEN = 36
_LINK_WINDOW = 600
_LINK_MAX_FAILURES = 5
_link_failures: dict[str, list[float]] = {}

HELP = (
    "/link &lt;uuid&gt; — connect your subscription\n"
    "/usage — traffic and expiry\n"
    "/plans — available plans\n"
    "/renew &lt;plan&gt; [zarinpal|idpay|usdt_trc20] — renew\n"
    "/unlink — disconnect this chat"
)


def _too_many_failures(chat_id: str) -> bool:
    now = time.monotonic()
    recent = [t for t in _link_failures.get(chat_id, []) if now - t < _LINK_WINDOW]
    _link_failures[chat_id] = recent
    return len(recent) >= _LINK_MAX_FAILURES


async def _linked_user(db: AsyncSession, chat_id: str) -> VpnUser | None:
    return (
        await db.execute(select(VpnUser).where(VpnUser.telegram_chat_id == chat_id))
    ).scalar_one_or_none()


async def handle_user_command(db: AsyncSession, chat_id: str, cmd: str, args: str) -> str:
    cmd = cmd.lower().split("@", 1)[0]
    args = args.strip()

    if cmd in ("/start", "/help"):
        return "👋 Spiritus\n\n" + HELP

    if cmd == "/link":
        if _too_many_failures(chat_id):
            return "Too many attempts. Try again later."
        if len(args) != _UUID_LEN:
            _link_failures.setdefault(chat_id, []).append(time.monotonic())
            return "Usage: /link &lt;subscription uuid&gt;"
        user = (await db.execute(select(VpnUser).where(VpnUser.uuid == args))).scalar_one_or_none()
        if user is None:
            _link_failures.setdefault(chat_id, []).append(time.monotonic())
            return "Subscription not found."
        if user.telegram_chat_id and user.telegram_chat_id != chat_id:
            return "This subscription is already linked to another chat. Ask support to unlink it."
        user.telegram_chat_id = chat_id
        await db.commit()
        return f"✅ Linked to <b>{html.escape(user.name)}</b>."

    user = await _linked_user(db, chat_id)
    if user is None:
        return "Not linked. Send /link &lt;uuid&gt; first."

    if cmd == "/unlink":
        user.telegram_chat_id = None
        await db.commit()
        return "Unlinked."

    if cmd == "/usage":
        st = await self_service_portal.get_user_status(db, user.uuid)
        return (
            f"<b>{html.escape(st['name'])}</b>\n"
            f"Status: {'active' if st['active'] else 'inactive'}\n"
            f"Used: {st['traffic_used_gb']} GB / "
            f"{st['traffic_limit_gb'] or 'unlimited'}{' GB' if st['traffic_limit_gb'] else ''}\n"
            f"Days left: {st['days_remaining']}"
        )

    if cmd == "/plans":
        lines = [
            f"<code>{html.escape(p.id)}</code> — {p.traffic_gb or 'unlimited'} GB / {p.days}d — "
            f"{p.price_irr:,} IRR / {p.price_usdt} USDT"
            for p in PLANS.values()
        ]
        return "\n".join(lines)

    if cmd == "/renew":
        parts = args.split()
        if not parts or parts[0] not in PLANS:
            return "Usage: /renew &lt;plan&gt; [gateway]. See /plans."
        gateway = parts[1] if len(parts) > 1 else "zarinpal"
        if gateway not in {"zarinpal", "idpay", "usdt_trc20"}:
            return "Unknown gateway."
        result = await self_service_portal.create_payment_for_user(db, user.uuid, parts[0], gateway)
        if not result.get("success"):
            logger.info("telegram renew failed chat=%s err=%s", chat_id, result.get("error"))
            return "Could not create the payment. Try another gateway or contact support."
        if result.get("pay_url"):
            return f"💳 Pay here: {html.escape(str(result['pay_url']))}"
        if result.get("wallet_address"):
            return (
                f"Send exactly <code>{html.escape(str(result.get('amount_usdt', '')))}</code> USDT (TRC20) to "
                f"<code>{html.escape(str(result['wallet_address']))}</code>"
            )
        return f"Payment #{result.get('payment_id')} created."

    return "Unknown command.\n\n" + HELP
