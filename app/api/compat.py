"""
Legacy compatibility router for V7LTHRONYX VPN Panel.

The frontend (panel.js) was built against an older API surface. This router
maps the legacy endpoint paths and response shapes to the current backend
implementation so the panel works without rewriting the frontend.

Legacy contract:
- POST /api/login   body: {password}        response: {ok: true} or {ok: false, error, locked?}
- POST /api/logout                          response: {ok: true}
"""

from fastapi import APIRouter, Request, Response, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional
import os
import time
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..auth import verify_password, create_access_token
from ..config import settings
from ..database import get_async_db
from ..models import Admin
from ..security import fail2ban_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["compat"])

_login_attempts: dict = {}


class LegacyLoginRequest(BaseModel):
    password: str
    username: Optional[str] = "admin"


def _is_locked_out(ip: str) -> bool:
    if ip not in _login_attempts:
        return False
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < settings.lockout_seconds]
    return len(_login_attempts[ip]) >= settings.max_login_attempts


def _record_failed_attempt(ip: str):
    if ip not in _login_attempts:
        _login_attempts[ip] = []
    _login_attempts[ip].append(time.time())


def _clear_attempts(ip: str):
    _login_attempts.pop(ip, None)


@router.post("/login")
async def legacy_login(
    request: LegacyLoginRequest,
    req: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    """Legacy login endpoint. Returns {ok: bool, error?, locked?}."""
    client_ip = req.client.host if req.client else "0.0.0.0"

    if await fail2ban_manager.is_banned(client_ip, "panel", db):
        return {"ok": False, "error": "IP banned. Contact admin.", "locked": True}

    if _is_locked_out(client_ip):
        return {"ok": False, "error": f"Too many attempts. Try again in {settings.lockout_seconds}s", "locked": True}

    username = request.username or "admin"
    admin_id = None
    is_admin = True

    db_result = await db.execute(select(Admin).where(Admin.username == username))
    admin_user = db_result.scalar_one_or_none()

    authenticated = False

    if admin_user:
        if verify_password(request.password, admin_user.password_hash):
            authenticated = True
            admin_id = admin_user.id

    if not authenticated:
        pw_file = os.path.join(os.getcwd(), "vpn-panel-password")
        if os.path.exists(pw_file):
            try:
                with open(pw_file) as f:
                    stored_pw = f.read().strip()
                if request.password == stored_pw:
                    authenticated = True
            except Exception as e:
                logger.error(f"Failed to read password file: {e}")

    if not authenticated:
        _record_failed_attempt(client_ip)
        await fail2ban_manager.record_failed_attempt(client_ip, "panel", db, "Failed panel login")
        return {"ok": False, "error": "Invalid password"}

    _clear_attempts(client_ip)

    token_data = {"sub": username, "is_admin": is_admin}
    if admin_id is not None:
        token_data["user_id"] = admin_id

    access_token = create_access_token(data=token_data)

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.session_lifetime_hours * 3600,
        path="/",
    )

    return {"ok": True, "access_token": access_token}


@router.post("/logout")
async def legacy_logout(response: Response):
    """Legacy logout endpoint."""
    response.delete_cookie("access_token", path="/")
    return {"ok": True}
