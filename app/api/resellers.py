"""
Reseller & Self-Service API router for V7LTHRONYX VPN Panel.

Endpoints:
- Reseller CRUD
- Reseller authentication
- Reseller stats
- Self-service portal (user-facing)
"""

import logging

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import record_audit
from ..auth import (
    User,
    _is_token_revoked,
    create_access_token,
    get_current_admin,
    is_session_family_revoked,
    validate_password_strength,
)
from ..commissions import InsufficientBalanceError, post_ledger_entry
from ..config import settings
from ..database import get_async_db
from ..models import Reseller, ResellerLedger
from ..redis_client import get_redis
from ..reseller import reseller_manager, self_service_portal
from ..security import fail2ban_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/resellers", tags=["resellers"])


# ── Models ────────────────────────────────────────────────

class ResellerCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=12, max_length=100)
    commission_rate: float = Field(10.0, ge=0, le=100)
    max_users: int = Field(100, ge=1)
    max_traffic_gb: float = Field(1000, ge=1)
    parent_id: int | None = None

class SubResellerCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=12, max_length=100)
    commission_rate: float = Field(5.0, ge=0, le=100)
    max_users: int = Field(10, ge=1)
    max_traffic_gb: float = Field(100, ge=1)

class WalletAdjustment(BaseModel):
    amount: int = Field(..., description="Signed IRR amount; negative debits the wallet")
    note: str = Field(..., min_length=3, max_length=255)

class ResellerLogin(BaseModel):
    username: str
    password: str

class ResellerCreateUser(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    traffic_limit_gb: float = Field(10, ge=0)
    days: int = Field(30, ge=1)
    agent_id: int | None = None

class ResellerResponse(BaseModel):
    id: int
    username: str
    commission_rate: float
    balance: int
    max_users: int
    max_traffic_gb: float
    active: bool
    portal_enabled: bool
    created_at: str | None = None
    parent_id: int | None = None

class MessageResponse(BaseModel):
    message: str
    success: bool = True


# ── Reseller CRUD ────────────────────────────────────────

@router.get("", response_model=list[ResellerResponse])
async def list_resellers(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """List all resellers."""
    result = await db.execute(select(Reseller).order_by(Reseller.id))
    resellers = result.scalars().all()
    return [
        ResellerResponse(
            id=r.id,
            username=r.username,
            commission_rate=r.commission_rate,
            balance=r.balance,
            max_users=r.max_users,
            max_traffic_gb=r.max_traffic_gb,
            active=r.active,
            portal_enabled=r.portal_enabled,
            created_at=r.created_at.isoformat() if r.created_at else None,
            parent_id=r.parent_id,
        )
        for r in resellers
    ]


@router.post("", response_model=ResellerResponse, status_code=status.HTTP_201_CREATED)
async def create_reseller(
    data: ResellerCreate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a new reseller."""
    password_error = validate_password_strength(data.password)
    if password_error:
        raise HTTPException(status_code=422, detail=password_error)
    result = await reseller_manager.create_reseller(
        db=db,
        username=data.username,
        password=data.password,
        commission_rate=data.commission_rate,
        max_users=data.max_users,
        max_traffic_gb=data.max_traffic_gb,
        parent_id=data.parent_id,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    await record_audit(
        db, "reseller_create", admin_id=admin.id, target_type="reseller", target_id=result["id"],
        details={"parent_id": data.parent_id},
    )

    # Fetch the created reseller
    db_result = await db.execute(select(Reseller).where(Reseller.id == result["id"]))
    reseller = db_result.scalar_one_or_none()

    if reseller is None:
        raise HTTPException(status_code=500, detail="Reseller creation failed")

    return ResellerResponse(
        id=reseller.id,
        username=reseller.username,
        commission_rate=reseller.commission_rate,
        balance=reseller.balance,
        max_users=reseller.max_users,
        max_traffic_gb=reseller.max_traffic_gb,
        active=reseller.active,
        portal_enabled=reseller.portal_enabled,
        created_at=reseller.created_at.isoformat() if reseller.created_at else None,
        parent_id=reseller.parent_id,
    )


# ── Reseller self-service (token issued by /resellers/login) ─────────────

_reseller_bearer = HTTPBearer(auto_error=False)


async def get_current_reseller(
    credentials: HTTPAuthorizationCredentials | None = Depends(_reseller_bearer),
    db: AsyncSession = Depends(get_async_db),
) -> Reseller:
    unauthorized = HTTPException(status_code=401, detail="Not authenticated")
    if credentials is None:
        raise unauthorized
    try:
        claims = jwt.decode(
            credentials.credentials,
            settings.jwt_secret_key,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "nbf", "jti", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise unauthorized from exc
    if claims.get("is_admin") or claims.get("reseller_id") is None:
        raise unauthorized
    if await _is_token_revoked(str(claims["jti"])) or await is_session_family_revoked(claims.get("fam")):
        raise unauthorized
    reseller = (
        await db.execute(select(Reseller).where(Reseller.id == int(claims["reseller_id"])))
    ).scalar_one_or_none()
    if reseller is None or not reseller.active:
        raise unauthorized
    return reseller


async def _ledger(db: AsyncSession, reseller_id: int, limit: int, offset: int) -> list[dict]:
    rows = (
        await db.execute(
            select(ResellerLedger)
            .where(ResellerLedger.reseller_id == reseller_id)
            .order_by(ResellerLedger.id.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    return [
        {
            "id": r.id,
            "kind": r.kind,
            "amount": r.amount,
            "balance_after": r.balance_after,
            "payment_id": r.payment_id,
            "note": r.note,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.get("/me")
async def reseller_me(reseller: Reseller = Depends(get_current_reseller)):
    return {
        "id": reseller.id,
        "username": reseller.username,
        "commission_rate": reseller.commission_rate,
        "balance": reseller.balance,
        "parent_id": reseller.parent_id,
        "max_users": reseller.max_users,
        "max_traffic_gb": reseller.max_traffic_gb,
    }


@router.get("/me/ledger")
async def reseller_my_ledger(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    reseller: Reseller = Depends(get_current_reseller),
    db: AsyncSession = Depends(get_async_db),
):
    return await _ledger(db, reseller.id, limit, offset)


@router.get("/me/downline")
async def reseller_my_downline(
    reseller: Reseller = Depends(get_current_reseller),
    db: AsyncSession = Depends(get_async_db),
):
    rows = await reseller_manager.downline(db, reseller.id)
    return [
        {"id": r.id, "username": r.username, "parent_id": r.parent_id,
         "commission_rate": r.commission_rate, "balance": r.balance, "active": r.active}
        for r in rows
    ]


@router.post("/me/sub-resellers", status_code=status.HTTP_201_CREATED)
async def reseller_create_sub_reseller(
    data: SubResellerCreate,
    reseller: Reseller = Depends(get_current_reseller),
    db: AsyncSession = Depends(get_async_db),
):
    """A reseller recruits a sub-reseller; rate and limits are capped by the parent's."""
    result = await reseller_manager.create_reseller(
        db=db,
        username=data.username,
        password=data.password,
        commission_rate=data.commission_rate,
        max_users=data.max_users,
        max_traffic_gb=data.max_traffic_gb,
        parent_id=reseller.id,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    await record_audit(
        db, "sub_reseller_create", target_type="reseller", target_id=result["id"],
        details={"parent_id": reseller.id},
    )
    return result


@router.get("/{reseller_id}/ledger")
async def reseller_ledger(
    reseller_id: int,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    return await _ledger(db, reseller_id, limit, offset)


@router.get("/{reseller_id}/downline")
async def reseller_downline(
    reseller_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    rows = await reseller_manager.downline(db, reseller_id)
    return [{"id": r.id, "username": r.username, "parent_id": r.parent_id} for r in rows]


@router.post("/{reseller_id}/wallet/adjust")
async def reseller_wallet_adjust(
    reseller_id: int,
    data: WalletAdjustment,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Manual credit/debit (payout, correction). Cannot overdraw the wallet."""
    reseller = (
        await db.execute(select(Reseller).where(Reseller.id == reseller_id))
    ).scalar_one_or_none()
    if reseller is None:
        raise HTTPException(status_code=404, detail="Reseller not found")
    if data.amount == 0:
        raise HTTPException(status_code=422, detail="amount must be non-zero")
    try:
        entry = await post_ledger_entry(
            db, reseller_id, data.amount, "adjustment", note=data.note, allow_negative=False
        )
    except InsufficientBalanceError:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Insufficient balance") from None
    await db.commit()
    await record_audit(
        db, "wallet_adjust", admin_id=admin.id, target_type="reseller", target_id=reseller_id,
        details={"amount": data.amount, "note": data.note},
    )
    return {"success": True, "balance": entry.balance_after}


@router.get("/{reseller_id}/stats")
async def get_reseller_stats(
    reseller_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Get reseller statistics."""
    stats = await reseller_manager.get_reseller_stats(db, reseller_id)
    return stats


@router.put("/{reseller_id}/toggle")
async def toggle_reseller(
    reseller_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Toggle reseller active status."""
    result = await db.execute(select(Reseller).where(Reseller.id == reseller_id))
    reseller = result.scalar_one_or_none()
    if not reseller:
        raise HTTPException(status_code=404, detail="Reseller not found")

    reseller.active = not reseller.active
    await db.commit()
    return MessageResponse(message=f"Reseller {'enabled' if reseller.active else 'disabled'}")


# ── Reseller Auth ────────────────────────────────────────

async def _reseller_ip_locked(ip: str) -> bool:
    # Auth paths fail closed when rate-limit state cannot be verified.
    try:
        redis = await get_redis()
        val = await redis.get(f"reseller_login:{ip}")
        return bool(val and int(val) >= settings.max_login_attempts)
    except Exception as exc:  # noqa: BLE001
        logger.error("reseller rate-limit check failed (Redis?): %s", exc)
        raise HTTPException(status_code=503, detail="Auth service temporarily unavailable") from exc


async def _record_reseller_failure(ip: str) -> None:
    try:
        redis = await get_redis()
        key = f"reseller_login:{ip}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, settings.lockout_seconds)
    except Exception as exc:  # noqa: BLE001
        logger.error("reseller failure-record failed (Redis?): %s", exc)
        raise HTTPException(status_code=503, detail="Auth service temporarily unavailable") from exc


async def _clear_reseller_attempts(ip: str) -> None:
    try:
        redis = await get_redis()
        await redis.delete(f"reseller_login:{ip}")
    except Exception as exc:  # noqa: BLE001
        logger.debug("reseller attempt-clear failed (Redis?): %s", exc)


@router.post("/login")
async def reseller_login(
    data: ResellerLogin,
    req: Request,
    db: AsyncSession = Depends(get_async_db),
):
    """Reseller login."""
    client_ip = req.client.host if req.client else "unknown"

    if await fail2ban_manager.is_banned(client_ip, "panel", db):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="IP banned")

    if await _reseller_ip_locked(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {settings.lockout_seconds}s",
        )

    reseller = await reseller_manager.authenticate_reseller(db, data.username, data.password)
    if not reseller:
        await _record_reseller_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    await _clear_reseller_attempts(client_ip)

    token = create_access_token(
        data={"sub": f"reseller:{reseller.username}", "is_admin": False, "reseller_id": reseller.id}
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "reseller_id": reseller.id,
    }


# ── Reseller User Management ─────────────────────────────

@router.post("/{reseller_id}/users")
async def reseller_create_user(
    reseller_id: int,
    data: ResellerCreateUser,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a VPN user under a reseller."""
    result = await reseller_manager.create_user_for_reseller(
        db=db,
        reseller_id=reseller_id,
        name=data.name,
        traffic_limit_gb=data.traffic_limit_gb,
        days=data.days,
        agent_id=data.agent_id,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


# ═══════════════════════════════════════════════════════════════
#  Self-Service Portal (user-facing, no admin auth required)
# ═══════════════════════════════════════════════════════════════

portal_router = APIRouter(prefix="/portal", tags=["self-service-portal"])


@portal_router.get("/status/{user_uuid}")
async def get_user_status(
    user_uuid: str,
    db: AsyncSession = Depends(get_async_db),
):
    """Get user subscription status (no auth required, UUID-based)."""
    result = await self_service_portal.get_user_status(db, user_uuid)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@portal_router.get("/config/{user_uuid}")
async def get_user_config(
    user_uuid: str,
    protocol: str = Query("vless_vision_reality"),
    db: AsyncSession = Depends(get_async_db),
):
    """Get user configuration for a protocol."""
    result = await self_service_portal.get_user_config(db, user_uuid, protocol)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error"))
    return result


@portal_router.get("/plans")
async def get_available_plans():
    """Get available subscription plans."""
    return await self_service_portal.get_available_plans()


@portal_router.post("/pay/{user_uuid}")
async def create_payment(
    user_uuid: str,
    plan_id: str = Query(...),
    gateway: str = Query("zarinpal"),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a payment for subscription renewal."""
    result = await self_service_portal.create_payment_for_user(
        db=db,
        user_uuid=user_uuid,
        plan_id=plan_id,
        gateway=gateway,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@portal_router.get("/payments/{user_uuid}")
async def get_user_payments(
    user_uuid: str,
    db: AsyncSession = Depends(get_async_db),
):
    """Get payment history for a user."""
    return await self_service_portal.get_user_payments(db, user_uuid)
