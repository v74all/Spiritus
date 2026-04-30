"""
Telegram Bot for V7LTHRONYX VPN Panel.

Features:
- Admin notifications (user created/expired, anomalies, payments)
- User management commands (list, create, disable)
- System status queries
- Payment notifications
- Interactive inline keyboards
"""

import json
import logging
import asyncio
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime
from dataclasses import dataclass

import httpx

from .config import settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  Telegram Bot API Client
# ═══════════════════════════════════════════════════════════════

class TelegramBot:
    """Telegram Bot for V7LTHRONYX VPN Panel notifications and management."""

    API_BASE = "https://api.telegram.org/bot{token}/{method}"

    def __init__(self, token: str = "", chat_id: str = "", admin_chat_ids: List[str] = None):
        self.token = token
        self.chat_id = chat_id
        self.admin_chat_ids = admin_chat_ids or []
        self._client: Optional[httpx.AsyncClient] = None
        self._command_handlers: Dict[str, Callable] = {}
        self._running = False
        self._last_update_id = 0

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _call_api(self, method: str, data: Dict = None) -> Dict:
        """Call Telegram Bot API."""
        if not self.token:
            return {"ok": False, "error": "No bot token configured"}

        url = self.API_BASE.format(token=self.token, method=method)
        client = await self._get_client()

        try:
            if data:
                resp = await client.post(url, json=data)
            else:
                resp = await client.get(url)
            return resp.json()
        except Exception as e:
            logger.error(f"Telegram API error: {e}")
            return {"ok": False, "error": str(e)}

    # ── Send Messages ──────────────────────────────────────

    async def send_message(
        self,
        chat_id: str,
        text: str,
        parse_mode: str = "HTML",
        reply_markup: Dict = None,
    ) -> Dict:
        """Send a text message."""
        data = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode,
        }
        if reply_markup:
            data["reply_markup"] = json.dumps(reply_markup)
        return await self._call_api("sendMessage", data)

    async def send_to_admins(self, text: str, parse_mode: str = "HTML") -> None:
        """Send message to all admin chat IDs."""
        targets = list(set([self.chat_id] + self.admin_chat_ids))
        for chat_id in targets:
            if chat_id:
                await self.send_message(chat_id, text, parse_mode)

    async def send_photo(self, chat_id: str, photo_url: str, caption: str = "") -> Dict:
        """Send a photo."""
        return await self._call_api("sendPhoto", {
            "chat_id": chat_id,
            "photo": photo_url,
            "caption": caption,
        })

    # ── Notification Methods ────────────────────────────────

    async def notify_user_created(self, user_name: str, traffic_gb: float, expire_at: str = "") -> None:
        """Notify admins about new user creation."""
        text = (
            f"🟢 <b>کاربر جدید ایجاد شد</b>\n\n"
            f"👤 نام: <code>{user_name}</code>\n"
            f"📊 حجم: <code>{traffic_gb} GB</code>\n"
            f"⏰ انقضا: <code>{expire_at or 'نامحدود'}</code>\n\n"
            f"🤖 V7LTHRONYX Panel"
        )
        await self.send_to_admins(text)

    async def notify_user_expired(self, user_name: str) -> None:
        """Notify admins about user expiration."""
        text = (
            f"🔴 <b>کاربر منقضی شد</b>\n\n"
            f"👤 نام: <code>{user_name}</code>\n\n"
            f"🤖 V7LTHRONYX Panel"
        )
        await self.send_to_admins(text)

    async def notify_payment_received(
        self,
        user_name: str,
        amount: int,
        gateway: str,
        plan: str = "",
    ) -> None:
        """Notify about payment received."""
        text = (
            f"💰 <b>پرداخت جدید</b>\n\n"
            f"👤 کاربر: <code>{user_name}</code>\n"
            f"💵 مبلغ: <code>{amount:,} IRR</code>\n"
            f"🏦 درگاه: <code>{gateway}</code>\n"
            f"📦 پلن: <code>{plan}</code>\n\n"
            f"🤖 V7LTHRONYX Panel"
        )
        await self.send_to_admins(text)

    async def notify_anomaly(self, user_name: str, alert_type: str, details: str) -> None:
        """Notify about anomaly detection."""
        text = (
            f"⚠️ <b>هشدار آنومالی</b>\n\n"
            f"👤 کاربر: <code>{user_name}</code>\n"
            f"🔍 نوع: <code>{alert_type}</code>\n"
            f"📝 جزئیات: <code>{details}</code>\n\n"
            f"🤖 V7LTHRONYX Panel"
        )
        await self.send_to_admins(text)

    async def notify_port_scan(self, source_ip: str, port_count: int) -> None:
        """Notify about port scan detection."""
        text = (
            f"🚨 <b>پورت اسکن شناسایی شد</b>\n\n"
            f"🌐 IP: <code>{source_ip}</code>\n"
            f"🔌 پورت‌ها: <code>{port_count}</code>\n\n"
            f"🤖 V7LTHRONYX Panel"
        )
        await self.send_to_admins(text)

    async def notify_system_alert(self, alert_type: str, details: str) -> None:
        """Notify about system alerts."""
        text = (
            f"🚨 <b>هشدار سیستمی</b>\n\n"
            f"🔍 نوع: <code>{alert_type}</code>\n"
            f"📝 جزئیات: <code>{details}</code>\n\n"
            f"🤖 V7LTHRONYX Panel"
        )
        await self.send_to_admins(text)

    # ── Command Handlers ───────────────────────────────────

    def command(self, name: str):
        """Decorator to register command handlers."""
        def decorator(func):
            self._command_handlers[name] = func
            return func
        return decorator

    async def handle_update(self, update: Dict) -> None:
        """Handle an incoming update from Telegram."""
        message = update.get("message", {})
        if not message:
            return

        text = message.get("text", "")
        chat_id = str(message.get("chat", {}).get("id", ""))
        from_user = message.get("from", {})

        # Verify admin
        if chat_id not in [self.chat_id] + self.admin_chat_ids:
            await self.send_message(chat_id, "⛔ دسترسی غیرمجاز")
            return

        # Handle commands
        if text.startswith("/"):
            parts = text.split(maxsplit=1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            handler = self._command_handlers.get(cmd)
            if handler:
                await handler(chat_id, args, from_user)
            else:
                await self._handle_default_command(chat_id, cmd, args)

    async def _handle_default_command(self, chat_id: str, cmd: str, args: str) -> None:
        """Handle built-in commands."""
        if cmd == "/start":
            keyboard = {
                "inline_keyboard": [
                    [{"text": "📊 وضعیت سیستم", "callback_data": "status"}],
                    [{"text": "👥 کاربران", "callback_data": "users"}],
                    [{"text": "💰 پرداخت‌ها", "callback_data": "payments"}],
                    [{"text": "🔒 امنیت", "callback_data": "security"}],
                ]
            }
            await self.send_message(
                chat_id,
                "🤖 <b>V7LTHRONYX Panel Bot</b>\n\n"
                "به ربات مدیریت VPN خوش آمدید!\n"
                "از منوی زیر انتخاب کنید:",
                reply_markup=keyboard,
            )

        elif cmd == "/status":
            await self.send_message(
                chat_id,
                "📊 <b>وضعیت سیستم</b>\n\n"
                "برای دریافت وضعیت، از پنل وب استفاده کنید:\n"
                "<code>http://your-server:38471</code>",
            )

        elif cmd == "/help":
            await self.send_message(
                chat_id,
                "📖 <b>راهنمای ربات</b>\n\n"
                "/start - منوی اصلی\n"
                "/status - وضعیت سیستم\n"
                "/help - راهنما\n",
            )

    # ── Polling ────────────────────────────────────────────

    async def start_polling(self) -> None:
        """Start long-polling for updates (alternative to webhook)."""
        if not self.enabled:
            logger.warning("Telegram bot not configured, skipping polling")
            return

        self._running = True
        logger.info("Telegram bot polling started")

        while self._running:
            try:
                result = await self._call_api("getUpdates", {
                    "offset": self._last_update_id + 1,
                    "timeout": 30,
                    "allowed_updates": ["message", "callback_query"],
                })

                if result.get("ok"):
                    for update in result.get("result", []):
                        self._last_update_id = update.get("update_id", 0)
                        await self.handle_update(update)

            except Exception as e:
                logger.error(f"Telegram polling error: {e}")
                await asyncio.sleep(5)

    async def stop_polling(self) -> None:
        """Stop the polling loop."""
        self._running = False
        logger.info("Telegram bot polling stopped")

    async def setup_webhook(self, webhook_url: str) -> Dict:
        """Setup webhook for receiving updates (alternative to polling)."""
        return await self._call_api("setWebhook", {
            "url": webhook_url,
            "allowed_updates": ["message", "callback_query"],
        })


# Global bot instance
telegram_bot = TelegramBot()