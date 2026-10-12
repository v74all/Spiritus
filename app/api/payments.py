"""
Payment API router for V7LTHRONYX VPN Panel.

Endpoints:
- Create payment (Zarinpal/IDPay/USDT)
- Verify payment
- Payment callback
- List payments
- Available plans
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import User, get_current_admin
from ..database import get_async_db
from ..models import Payment, PaymentStatus
from ..payments import PLANS, payment_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/payments", tags=["payments"])


# ── Models ────────────────────────────────────────────────

class CreatePaymentRequest(BaseModel):
    user_id: int
    plan_id: str = Field(..., description="basic|standard|premium|unlimited")
    gateway: str = Field("zarinpal", description="zarinpal|idpay|usdt_trc20")
    reseller_id: int | None = None

class VerifyPaymentRequest(BaseModel):
    payment_id: int
    gateway: str = "zarinpal"
    authority: str | None = None
    gateway_id: str | None = None
    tx_hash: str | None = Field(None, min_length=32, max_length=128)

class PaymentResponse(BaseModel):
    id: int
    gateway: str
    status: str
    amount: int
    currency: str
    plan_traffic_gb: float
    plan_days: int
    pay_url: str | None = None
    created_at: str | None = None
    paid_at: str | None = None

class PlanResponse(BaseModel):
    id: str
    name: str
    name_fa: str
    traffic_gb: float
    days: int
    price_irr: int
    price_usdt: float

class MessageResponse(BaseModel):
    message: str
    success: bool = True


# ── Plans ─────────────────────────────────────────────────

@router.get("/plans", response_model=list[PlanResponse])
async def get_plans():
    """Get available subscription plans."""
    return [
        PlanResponse(
            id=p.id,
            name=p.name,
            name_fa=p.name_fa,
            traffic_gb=p.traffic_gb if p.traffic_gb > 0 else -1,
            days=p.days,
            price_irr=p.price_irr,
            price_usdt=p.price_usdt,
        )
        for p in PLANS.values()
    ]


# ── Create Payment ────────────────────────────────────────

@router.post("/create")
async def create_payment(
    data: CreatePaymentRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a new payment."""
    result = await payment_manager.create_payment(
        db=db,
        user_id=data.user_id,
        plan_id=data.plan_id,
        gateway=data.gateway,
        reseller_id=data.reseller_id,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Payment creation failed"))
    return result


# ── Verify Payment ───────────────────────────────────────

@router.post("/verify")
async def verify_payment(
    data: VerifyPaymentRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Verify a payment (called by gateway callback or manually)."""
    result = await payment_manager.verify_payment(
        db=db,
        payment_id=data.payment_id,
        gateway=data.gateway,
        authority=data.authority,
        gateway_id=data.gateway_id,
        tx_hash=data.tx_hash,
    )
    return result


# ── Zarinpal Callback ────────────────────────────────────

@router.get("/callback/zarinpal")
async def zarinpal_callback(
    Authority: str = Query(...),
    Status: str = Query(...),
    db: AsyncSession = Depends(get_async_db),
):
    """Zarinpal payment callback."""
    if Status != "OK":
        return {"success": False, "message": "Payment cancelled by user"}

    # Find payment by authority
    result = await db.execute(
        select(Payment).where(Payment.gateway_authority == Authority)
    )
    payment = result.scalar_one_or_none()

    if not payment:
        return {"success": False, "message": "Payment not found"}

    verify_result = await payment_manager.verify_payment(
        db=db,
        payment_id=payment.id,
        gateway="zarinpal",
        authority=Authority,
    )
    return verify_result


# ── IDPay Callback ────────────────────────────────────────

@router.post("/callback/idpay")
async def idpay_callback(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
):
    """IDPay payment callback."""
    body = await request.json()
    payment_id = body.get("id", "")
    order_id = body.get("order_id", "")
    status_code = body.get("status", 0)

    if status_code != 100:
        return {"success": False, "message": f"Payment status: {status_code}"}

    # Find payment by order_id
    try:
        pid = int(order_id)
    except ValueError:
        return {"success": False, "message": "Invalid order ID"}

    verify_result = await payment_manager.verify_payment(
        db=db,
        payment_id=pid,
        gateway="idpay",
        gateway_id=payment_id,
    )
    return verify_result


# ── List Payments ────────────────────────────────────────

@router.get("", response_model=list[PaymentResponse])
async def list_payments(
    user_id: int | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=500),
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """List payments with optional filters."""
    query = select(Payment).order_by(Payment.created_at.desc()).limit(limit)

    if user_id:
        query = query.where(Payment.user_id == user_id)
    if status_filter:
        try:
            pay_status = PaymentStatus(status_filter)
            query = query.where(Payment.status == pay_status)
        except ValueError:
            pass

    result = await db.execute(query)
    payments = result.scalars().all()

    return [
        PaymentResponse(
            id=p.id,
            gateway=p.gateway.value,
            status=p.status.value,
            amount=p.amount,
            currency=p.currency,
            plan_traffic_gb=p.plan_traffic_gb,
            plan_days=p.plan_days,
            created_at=p.created_at.isoformat() if p.created_at else None,
            paid_at=p.paid_at.isoformat() if p.paid_at else None,
        )
        for p in payments
    ]
