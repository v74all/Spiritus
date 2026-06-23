"""Stable token-based authentication contract for the Android client."""

from __future__ import annotations

import json
import secrets
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import create_access_token, revoke_token, verify_password, verify_totp
from ..config import settings
from ..database import get_async_db
from ..models import Admin, Agent
from ..redis_client import get_redis

router = APIRouter(prefix="/mobile/auth", tags=["mobile-auth"])
session_router = APIRouter(prefix="/mobile", tags=["mobile-auth"])
bearer = HTTPBearer(auto_error=False)


class MobileLoginRequest(BaseModel):
    role: Literal["admin", "agent"]
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


class Mobile2FARequest(BaseModel):
    challenge: str = Field(..., min_length=32, max_length=128)
    totp_code: str = Field(..., pattern=r"^\d{6}$")


class MobileTokenResponse(BaseModel):
    access_token: str | None = None
    token_type: str = "bearer"
    expires_in: int
    role: Literal["admin", "agent"]
    principal: str
    totp_required: bool = False
    challenge: str | None = None


async def _rate_limit(request: Request, role: str, username: str) -> None:
    try:
        redis = await get_redis()
        key = f"mobile_login:{request.client.host if request.client else 'unknown'}:{role}:{username}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, settings.lockout_seconds)
        if int(count) > settings.max_login_attempts:
            raise HTTPException(status_code=429, detail="Too many login attempts")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Auth service temporarily unavailable") from exc


def _issue(role: Literal["admin", "agent"], principal: str, entity_id: int) -> MobileTokenResponse:
    lifetime = timedelta(minutes=settings.mobile_token_lifetime_minutes)
    claims = {
        "sub": principal,
        "role": role,
        "is_admin": role == "admin",
        "user_id" if role == "admin" else "agent_id": entity_id,
    }
    token = create_access_token(claims, expires_delta=lifetime)
    return MobileTokenResponse(
        access_token=token,
        expires_in=int(lifetime.total_seconds()),
        role=role,
        principal=principal,
    )


@router.post("/login", response_model=MobileTokenResponse)
async def mobile_login(
    body: MobileLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
):
    username = body.username.strip()
    await _rate_limit(request, body.role, username)

    if body.role == "admin":
        result = await db.execute(select(Admin).where(Admin.username == username))
        admin = result.scalar_one_or_none()
        if admin is None or not verify_password(body.password, admin.password_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if admin.totp_enabled:
            challenge = secrets.token_urlsafe(36)
            redis = await get_redis()
            await redis.setex(
                f"mobile_2fa:{challenge}",
                300,
                json.dumps({"admin_id": admin.id, "username": admin.username}),
            )
            return MobileTokenResponse(
                expires_in=300,
                role="admin",
                principal=admin.username,
                totp_required=True,
                challenge=challenge,
            )
        return _issue("admin", admin.username, admin.id)

    result = await db.execute(select(Agent).where(Agent.name == username))
    agent = result.scalar_one_or_none()
    if agent is None or not agent.api_key or not verify_password(body.password, agent.api_key):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if agent.status and getattr(agent.status, "value", agent.status) == "offline":
        raise HTTPException(status_code=403, detail="Agent account disabled")
    return _issue("agent", agent.name, agent.id)


@router.post("/2fa", response_model=MobileTokenResponse)
async def mobile_2fa(body: Mobile2FARequest, db: AsyncSession = Depends(get_async_db)):
    try:
        redis = await get_redis()
        key = f"mobile_2fa:{body.challenge}"
        raw = await redis.eval(
            "local v=redis.call('get',KEYS[1]); if v then redis.call('del',KEYS[1]); end; return v",
            1,
            key,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Auth service temporarily unavailable") from exc
    if not raw:
        raise HTTPException(status_code=401, detail="Challenge expired or already used")
    data = json.loads(raw)
    result = await db.execute(select(Admin).where(Admin.id == int(data["admin_id"])))
    admin = result.scalar_one_or_none()
    if admin is None or not admin.totp_secret or not verify_totp(admin.totp_secret, body.totp_code):
        raise HTTPException(status_code=401, detail="Invalid verification code")
    return _issue("admin", admin.username, admin.id)


async def _mobile_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> tuple[str, dict]:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "nbf", "jti", "sub"]},
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc
    try:
        redis = await get_redis()
        if await redis.get(f"revoked_jti:{claims['jti']}"):
            raise HTTPException(status_code=401, detail="Token revoked")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Auth service temporarily unavailable") from exc
    return token, claims


@router.get("/session")
@session_router.get("/session")
async def mobile_session(
    auth: tuple[str, dict] = Depends(_mobile_claims),
    db: AsyncSession = Depends(get_async_db),
):
    _, claims = auth
    role = claims.get("role")
    if role == "admin":
        result = await db.execute(select(Admin).where(Admin.id == claims.get("user_id")))
    elif role == "agent":
        result = await db.execute(select(Agent).where(Agent.id == claims.get("agent_id")))
    else:
        raise HTTPException(status_code=403, detail="Unsupported mobile role")
    principal = result.scalar_one_or_none()
    if principal is None:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    return {"role": role, "principal": claims["sub"], "expires_at": claims["exp"]}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def mobile_logout(auth: tuple[str, dict] = Depends(_mobile_claims)):
    _, claims = auth
    from time import time
    await revoke_token(str(claims["jti"]), max(int(claims["exp"]) - int(time()), 1))
    return None
