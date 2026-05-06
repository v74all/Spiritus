"""
Authentication API router for V7LTHRONYX VPN Panel.

Endpoints:
- POST /auth/login - Login with username/password
- POST /auth/login/2fa - Login with 2FA/TOTP
- POST /auth/token - Get JWT token
- POST /auth/setup-2fa - Setup 2FA for current user
- POST /auth/verify-2fa - Verify 2FA token
- POST /auth/logout - Logout
- GET  /auth/me - Get current user info
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from typing import Optional
import logging

from ..auth import (
    verify_password, get_password_hash, create_access_token,
    generate_totp_secret, get_totp_uri, verify_totp,
    get_current_user, User, Token
)
from ..config import settings
from ..database import get_async_db
from ..models import Admin
from ..security import fail2ban_manager

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])

# Models
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=100)

class Login2FARequest(BaseModel):
    username: str
    password: str
    totp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")

class Setup2FAResponse(BaseModel):
    secret: str
    uri: str
    qr_code_data: str

class Verify2FARequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")

class MessageResponse(BaseModel):
    message: str
    success: bool = True

# Redis-backed login attempt tracking
async def _is_locked_out(ip: str) -> bool:
    """Check if IP is locked out due to too many failed attempts (Redis-backed)."""
    from ..redis_client import get_redis
    try:
        redis = await get_redis()
        key = f"login_attempts:{ip}"
        current = await redis.get(key)
        if current and int(current) >= settings.max_login_attempts:
            return True
    except Exception:
        pass  # If Redis is down, allow through
    return False

async def _record_failed_attempt(ip: str):
    """Record a failed login attempt (Redis-backed)."""
    from ..redis_client import get_redis
    try:
        redis = await get_redis()
        key = f"login_attempts:{ip}"
        current = await redis.incr(key)
        if current == 1:
            await redis.expire(key, settings.lockout_seconds)
    except Exception:
        pass  # If Redis is down, skip rate limiting

async def _clear_attempts(ip: str):
    """Clear login attempts for an IP (Redis-backed)."""
    from ..redis_client import get_redis
    try:
        redis = await get_redis()
        await redis.delete(f"login_attempts:{ip}")
    except Exception:
        pass

@router.post("/login", response_model=Token)
async def login(request: LoginRequest, req: Request, db: AsyncSession = Depends(get_async_db)):
    """Login with username and password."""
    client_ip = req.client.host

    # Check fail2ban
    if await fail2ban_manager.is_banned(client_ip, "panel", db):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"IP banned. Contact admin."
        )

    if await _is_locked_out(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {settings.lockout_seconds}s"
        )

    # Try database admin lookup first
    db_result = await db.execute(select(Admin).where(Admin.username == request.username))
    admin_user = db_result.scalar_one_or_none()

    if admin_user:
        if not verify_password(request.password, admin_user.password_hash):
            await _record_failed_attempt(client_ip)
            await fail2ban_manager.record_failed_attempt(client_ip, "panel", db, "Failed admin login")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        await _clear_attempts(client_ip)

        totp_required = admin_user.totp_enabled and bool(admin_user.totp_secret)

        access_token = create_access_token(
            data={"sub": request.username, "is_admin": True, "user_id": admin_user.id}
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.session_lifetime_hours * 3600,
            totp_required=totp_required
        )

    # Fallback: check panel password file (for initial setup)
    import os
    pw_file = os.path.join(os.getcwd(), "vpn-panel-password")
    if os.path.exists(pw_file):
        with open(pw_file) as f:
            stored_pw = f.read().strip()
        if request.password != stored_pw:
            await _record_failed_attempt(client_ip)
            await fail2ban_manager.record_failed_attempt(client_ip, "panel", db, "Failed panel login")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Panel not initialized"
        )

    await _clear_attempts(client_ip)

    access_token = create_access_token(
        data={"sub": request.username, "is_admin": True}
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.session_lifetime_hours * 3600,
        totp_required=False
    )

@router.post("/login/2fa", response_model=Token)
async def login_with_2fa(request: Login2FARequest, req: Request, db: AsyncSession = Depends(get_async_db)):
    """Login with 2FA/TOTP verification."""
    client_ip = req.client.host

    if await _is_locked_out(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {settings.lockout_seconds}s"
        )

    db_result = await db.execute(select(Admin).where(Admin.username == request.username))
    admin_user = db_result.scalar_one_or_none()

    if not admin_user:
        await _record_failed_attempt(client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(request.password, admin_user.password_hash):
        await _record_failed_attempt(client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not admin_user.totp_enabled or not admin_user.totp_secret:
        await _record_failed_attempt(client_ip)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA not enabled for this user")

    if not verify_totp(admin_user.totp_secret, request.totp_code):
        await _record_failed_attempt(client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code")

    await _clear_attempts(client_ip)

    access_token = create_access_token(
        data={"sub": request.username, "is_admin": True, "user_id": admin_user.id}
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.session_lifetime_hours * 3600,
        totp_required=False
    )

@router.post("/setup-2fa", response_model=Setup2FAResponse)
async def setup_2fa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    """Setup 2FA/TOTP for the current user."""
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, current_user.username)

    # Save secret to database
    result = await db.execute(select(Admin).where(Admin.username == current_user.username))
    admin_user = result.scalar_one_or_none()
    if admin_user:
        admin_user.totp_secret = secret
        admin_user.totp_enabled = True
        await db.commit()

    return Setup2FAResponse(
        secret=secret,
        uri=uri,
        qr_code_data=uri  # Frontend will generate QR from this
    )

@router.post("/verify-2fa", response_model=MessageResponse)
async def verify_2fa(request: Verify2FARequest, current_user: User = Depends(get_current_user)):
    """Verify a 2FA/TOTP code."""
    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA not set up for this user"
        )

    if not verify_totp(current_user.totp_secret, request.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA code"
        )

    return MessageResponse(message="2FA code verified successfully")

@router.post("/logout", response_model=MessageResponse)
async def logout(current_user: User = Depends(get_current_user)):
    """Logout (invalidate token on client side)."""
    # JWT tokens are stateless, so logout is handled client-side
    # In production, add token to a Redis blacklist
    return MessageResponse(message="Logged out successfully")

@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "is_admin": current_user.is_admin,
        "2fa_enabled": current_user.totp_secret is not None
    }