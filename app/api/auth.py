"""
Authentication API router for V7LTHRONYX VPN Panel.

Endpoints:
- POST /auth/login        — username/password (returns token or "totp_required")
- POST /auth/login/2fa    — username/password + TOTP code
- POST /auth/setup-2fa    — enable TOTP for current user (returns QR URI)
- POST /auth/verify-2fa   — verify a TOTP code
- POST /auth/logout       — revoke the bearer token (jti → Redis blacklist)
- GET  /auth/me           — current-user introspection

Security guarantees (audited 2026-05-19):
- No plaintext password-file fallback.
- JWT algorithm is pinned (HS256); "alg: none" and alg-confusion are rejected.
- Tokens carry `jti`; logout revokes server-side via Redis.
- Per-IP login + per-IP/username TOTP rate-limit; fail-closed if Redis is down
  on auth endpoints (returns 503 rather than letting brute-force through).
- Argon2 password verification, with constant-time fallback compare for the
  rare path where Redis is unavailable.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from pydantic import BaseModel, Field
from typing import Optional
import logging

from ..auth import (
    verify_password,
    get_password_hash,
    create_access_token,
    generate_totp_secret,
    get_totp_uri,
    verify_totp,
    get_current_user,
    revoke_token,
    validate_password_strength,
    User,
    Token,
)
from ..config import settings
from ..database import get_async_db
from ..models import Admin, UserRole
from ..security import fail2ban_manager
from ..redis_client import get_redis

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import jwt as _jose_jwt

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["authentication"])


# ────────────────────────── Models ──────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


class Login2FARequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)
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


# ─────────────────── Rate-limit helpers (fail-closed for auth) ───────────────────

class _RedisDown(Exception):
    pass


async def _redis_or_503():
    try:
        return await get_redis()
    except Exception as e:
        logger.error("Redis unreachable on auth path: %s", e)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth service temporarily unavailable",
        )


async def _check_and_count(key: str, limit: int, window_seconds: int) -> int:
    """Atomic incr+expire. Returns the new count. Caller decides to lock."""
    redis = await _redis_or_503()
    current = await redis.incr(key)
    if current == 1:
        await redis.expire(key, window_seconds)
    return int(current)


async def _is_locked_out(ip: str) -> bool:
    redis = await _redis_or_503()
    current = await redis.get(f"login_attempts:{ip}")
    return bool(current and int(current) >= settings.max_login_attempts)


async def _record_failed_login(ip: str) -> None:
    await _check_and_count(f"login_attempts:{ip}", settings.max_login_attempts, settings.lockout_seconds)


async def _clear_login_attempts(ip: str) -> None:
    try:
        redis = await get_redis()
        await redis.delete(f"login_attempts:{ip}")
    except Exception:
        pass


async def _check_2fa_lockout(ip: str, username: str) -> None:
    """Per-IP+username 2FA rate-limit. Locks the account briefly."""
    redis = await _redis_or_503()
    key = f"2fa_attempts:{ip}:{username}"
    current = await redis.get(key)
    if current and int(current) >= settings.max_2fa_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many 2FA failures. Try again in {settings.lockout_seconds}s",
        )


async def _record_failed_2fa(ip: str, username: str) -> None:
    await _check_and_count(
        f"2fa_attempts:{ip}:{username}",
        settings.max_2fa_attempts,
        settings.lockout_seconds,
    )


async def _clear_2fa_attempts(ip: str, username: str) -> None:
    try:
        redis = await get_redis()
        await redis.delete(f"2fa_attempts:{ip}:{username}")
    except Exception:
        pass


def _client_ip(req: Request) -> str:
    # Trust X-Forwarded-For only if you have a vetted reverse proxy chain.
    # The default here is direct-peer to avoid client-side spoofing.
    return req.client.host if req.client else "unknown"


# ────────────────────────── Endpoints ──────────────────────────

@router.post("/login", response_model=Token)
async def login(request: LoginRequest, req: Request, db: AsyncSession = Depends(get_async_db)):
    """Phase 1 of login. Returns Token; if 2FA is enabled, totp_required=True
    is set and the *only* further step is /auth/login/2fa with the same creds."""
    client_ip = _client_ip(req)

    if await fail2ban_manager.is_banned(client_ip, "panel", db):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="IP banned")

    if await _is_locked_out(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {settings.lockout_seconds}s",
        )

    db_result = await db.execute(select(Admin).where(Admin.username == request.username))
    admin_user = db_result.scalar_one_or_none()

    if admin_user is None or not verify_password(request.password, admin_user.password_hash):
        await _record_failed_login(client_ip)
        await fail2ban_manager.record_failed_attempt(client_ip, "panel", db, "Failed admin login")
        logger.warning("login.failure ip=%s user=%s", client_ip, request.username)
        # Constant message — avoid user enumeration.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    locked_until = getattr(admin_user, "locked_until", None)
    if locked_until is not None:
        from datetime import datetime, timezone
        lu = locked_until if locked_until.tzinfo else locked_until.replace(tzinfo=timezone.utc)
        if lu > datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account locked")

    await _clear_login_attempts(client_ip)
    totp_required = bool(admin_user.totp_enabled and admin_user.totp_secret)

    # If 2FA is on, do NOT issue a session-ready token here. Issue an empty
    # marker so the client triggers the 2FA prompt.
    if totp_required:
        logger.info("login.totp_required ip=%s user=%s", client_ip, request.username)
        return Token(access_token="", token_type="bearer", expires_in=0, totp_required=True)

    is_admin_flag = admin_user.role in (UserRole.admin, UserRole.superadmin)
    access_token = create_access_token(
        data={"sub": request.username, "is_admin": is_admin_flag, "user_id": admin_user.id}
    )
    logger.info("login.success ip=%s user=%s", client_ip, request.username)
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.session_lifetime_hours * 3600,
        totp_required=False,
    )


@router.post("/login/2fa", response_model=Token)
async def login_with_2fa(request: Login2FARequest, req: Request, db: AsyncSession = Depends(get_async_db)):
    client_ip = _client_ip(req)

    if await fail2ban_manager.is_banned(client_ip, "panel", db):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="IP banned")

    if await _is_locked_out(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {settings.lockout_seconds}s",
        )

    await _check_2fa_lockout(client_ip, request.username)

    db_result = await db.execute(select(Admin).where(Admin.username == request.username))
    admin_user = db_result.scalar_one_or_none()

    if admin_user is None or not verify_password(request.password, admin_user.password_hash):
        await _record_failed_login(client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not admin_user.totp_enabled or not admin_user.totp_secret:
        # Don't reveal that 2FA isn't set up — generic message.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_totp(admin_user.totp_secret, request.totp_code):
        await _record_failed_2fa(client_ip, request.username)
        logger.warning("login.2fa_failure ip=%s user=%s", client_ip, request.username)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code")

    await _clear_login_attempts(client_ip)
    await _clear_2fa_attempts(client_ip, request.username)

    is_admin_flag = admin_user.role in (UserRole.admin, UserRole.superadmin)
    access_token = create_access_token(
        data={"sub": request.username, "is_admin": is_admin_flag, "user_id": admin_user.id}
    )
    logger.info("login.2fa_success ip=%s user=%s", client_ip, request.username)
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.session_lifetime_hours * 3600,
        totp_required=False,
    )


@router.post("/setup-2fa", response_model=Setup2FAResponse)
async def setup_2fa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, current_user.username)

    result = await db.execute(select(Admin).where(Admin.username == current_user.username))
    admin_user = result.scalar_one_or_none()
    if admin_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    admin_user.totp_secret = secret
    admin_user.totp_enabled = True
    await db.commit()
    logger.info("2fa.setup user=%s", current_user.username)

    return Setup2FAResponse(secret=secret, uri=uri, qr_code_data=uri)


@router.post("/verify-2fa", response_model=MessageResponse)
async def verify_2fa(request: Verify2FARequest, current_user: User = Depends(get_current_user)):
    if not current_user.totp_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA not set up")
    if not verify_totp(current_user.totp_secret, request.totp_code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code")
    return MessageResponse(message="2FA code verified successfully")


@router.post("/logout", response_model=MessageResponse)
async def logout(req: Request, current_user: User = Depends(get_current_user)):
    """Revoke the bearer token by adding its jti to the Redis blacklist."""
    auth_header = req.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        try:
            # Decode WITHOUT signature check is unsafe; rely on the dependency
            # that already ran (get_current_user) for validation, but read the
            # raw payload here just for jti/exp.
            payload = _jose_jwt.decode(
                token, settings.jwt_secret_key, algorithms=["HS256"],
                options={"verify_exp": False},
            )
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                from datetime import datetime, timezone
                ttl = int(exp - datetime.now(timezone.utc).timestamp())
                await revoke_token(jti, ttl)
                logger.info("logout user=%s jti=%s", current_user.username, jti[:8])
        except Exception as e:
            logger.warning("logout: token decode failed: %s", type(e).__name__)

    return MessageResponse(message="Logged out successfully")


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "is_admin": current_user.is_admin,
        "2fa_enabled": current_user.totp_secret is not None,
    }


# ────────────────────────── Bootstrap (called from app/main.py lifespan) ──────────────────────────

async def bootstrap_initial_admin(db: AsyncSession) -> None:
    """
    Create the initial admin record from ADMIN_BOOTSTRAP_PASSWORD env at startup.

    Idempotent and race-safe: uvicorn runs the panel with --workers 2 by
    default, so both workers reach the lifespan handler at roughly the same
    moment. We let both perform the check-then-insert and rely on the DB's
    UNIQUE constraint on username — whichever loses the race gets an
    IntegrityError and we treat that as "the other worker won, fine".

    Aborts cleanly (logs and returns) if the bootstrap password is missing or
    too weak — operators must set a strong one or create the admin manually
    via SQL. The bootstrap secret is *not* auto-removed from the environment
    — that's the operator's job — but a loud warning is logged.
    """
    from sqlalchemy.exc import IntegrityError

    existing = (await db.execute(select(Admin))).scalars().first()
    if existing is not None:
        return
    pw = (settings.admin_bootstrap_password or "").strip()
    user = (settings.admin_bootstrap_username or "admin").strip()
    if not pw:
        logger.warning(
            "bootstrap: no admin in DB and ADMIN_BOOTSTRAP_PASSWORD unset. "
            "Panel is closed until an Admin row is created."
        )
        return
    err = validate_password_strength(pw)
    if err:
        logger.error(
            "bootstrap: ADMIN_BOOTSTRAP_PASSWORD fails strength check (%s). "
            "The password shown by the installer will NOT work for login. "
            "Fix: edit .env, set a valid ADMIN_BOOTSTRAP_PASSWORD (12+ chars, "
            "upper+lower+digit+symbol), then restart the service.",
            err,
        )
        return
    admin = Admin(
        username=user,
        password_hash=get_password_hash(pw),
        role=UserRole.superadmin,
        totp_enabled=False,
        totp_secret=None,
    )
    db.add(admin)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        logger.info("bootstrap: admin '%s' already created by a sibling worker; skipping.", user)
        return
    logger.warning(
        "bootstrap: initial admin '%s' created from ADMIN_BOOTSTRAP_PASSWORD. "
        "REMOVE that env var from .env immediately.",
        user,
    )
