"""Telegram webhook receiver (authenticated by Telegram's secret-token header)."""

import hmac
import logging

from fastapi import APIRouter, HTTPException, Request

from ..config import settings
from ..telegram_bot import telegram_bot

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/telegram", tags=["telegram"])

_MIN_SECRET_LEN = 16


@router.post("/webhook")
async def telegram_webhook(request: Request):
    secret = settings.telegram_webhook_secret
    if len(secret) < _MIN_SECRET_LEN:
        raise HTTPException(status_code=404, detail="Not Found")
    supplied = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not hmac.compare_digest(supplied.encode(), secret.encode()):
        raise HTTPException(status_code=403, detail="Forbidden")
    try:
        update = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid JSON") from None
    if not isinstance(update, dict):
        raise HTTPException(status_code=400, detail="Invalid update")
    try:
        await telegram_bot.handle_update(update)
    except Exception:
        # Always 200 so Telegram doesn't retry-storm on a bug in one handler.
        logger.exception("telegram webhook handler failed")
    return {"ok": True}
