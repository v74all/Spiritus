"""
Reseller & Self-Service API router for V7LTHRONYX VPN Panel.

Endpoints:
- Reseller CRUD
- Reseller authentication
- Reseller stats
- Self-service portal (user-facing)
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from typing import Optional, List
import logging

from ..auth import get_current_admin, get_current_user, User, create_access_token
from ..database import get_async_db
from ..models import Reseller
from ..reseller import reseller_manager, self_service_portal

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/resellers", tags=["resellers"])


# ── Models ────────────────────────────────────────────────

class ResellerCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=6, max_length=100)
    commission_rate: float = Field(10.0, ge=0, le=100)
    max_users: int = Field(100, ge=1)
    max_traffic_gb: float = Field(1000, ge=1)

class ResellerLogin(BaseModel):
    username: str
    password: str

class ResellerCreateUser(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    traffic_limit_gb: float = Field(10, ge=0)
    days: int = Field(30, ge=1)
    agent_id: Optional[int] = None

class ResellerResponse(BaseModel):
    id: int
    username: str
    commission_rate: float
    balance: int
    max_users: int
    max_traffic_gb: float
    active: bool
    portal_enabled: bool
    created_at: Optional[str] = None

class MessageResponse(BaseModel):
    message: str
    success: bool = True


# ── Reseller CRUD ────────────────────────────────────────

@router.get("", response_model=List[ResellerResponse])
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
    result = await reseller_manager.create_reseller(
        db=db,
        username=data.username,
        password=data.password,
        commission_rate=data.commission_rate,
        max_users=data.max_users,
        max_traffic_gb=data.max_traffic_gb,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

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
    )


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

@router.post("/login")
async def reseller_login(
    data: ResellerLogin,
    db: AsyncSession = Depends(get_async_db),
):
    """Reseller login."""
    reseller = await reseller_manager.authenticate_reseller(db, data.username, data.password)
    if not reseller:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

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