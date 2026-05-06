"""
Payment Gateway Integration for V7LTHRONYX VPN Panel.

Supported gateways:
- Zarinpal (Iranian Rial - IRR)
- IDPay (Iranian Rial - IRR)
- USDT TRC-20 (Cryptocurrency)

Features:
- Payment creation and verification
- Auto-extend user on successful payment
- Payment history and reporting
- Reseller commission tracking
"""

import json
import time
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, timezone
from .timeutil import utcnow as _utcnow
from dataclasses import dataclass
from enum import Enum

import httpx
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Payment, PaymentGateway, PaymentStatus, VpnUser, Reseller
from .config import settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  Payment Plans
# ═══════════════════════════════════════════════════════════════

@dataclass
class PaymentPlan:
    id: str
    name: str
    name_fa: str
    traffic_gb: float
    days: int
    price_irr: int  # Iranian Rial
    price_usdt: float = 0  # USDT cents

PLANS: Dict[str, PaymentPlan] = {
    "basic": PaymentPlan(
        id="basic",
        name="Basic",
        name_fa="پایه",
        traffic_gb=10,
        days=30,
        price_irr=50000,  # 50,000 IRR ≈ 50,000 Toman
        price_usdt=1.0,
    ),
    "standard": PaymentPlan(
        id="standard",
        name="Standard",
        name_fa="استاندارد",
        traffic_gb=30,
        days=30,
        price_irr=120000,
        price_usdt=2.5,
    ),
    "premium": PaymentPlan(
        id="premium",
        name="Premium",
        name_fa="حرفه‌ای",
        traffic_gb=100,
        days=30,
        price_irr=300000,
        price_usdt=6.0,
    ),
    "unlimited": PaymentPlan(
        id="unlimited",
        name="Unlimited",
        name_fa="نامحدود",
        traffic_gb=0,  # Unlimited
        days=30,
        price_irr=500000,
        price_usdt=10.0,
    ),
}


# ═══════════════════════════════════════════════════════════════
#  Zarinpal Gateway
# ═══════════════════════════════════════════════════════════════

class ZarinpalGateway:
    """Zarinpal payment gateway integration."""

    SANDBOX_URL = "https://sandbox.zarinpal.com/pg/v4/payment"
    PRODUCTION_URL = "https://api.zarinpal.com/pg/v4/payment"

    def __init__(self, merchant_id: str, sandbox: bool = False, callback_url: str = ""):
        self.merchant_id = merchant_id
        self.sandbox = sandbox
        self.callback_url = callback_url
        self._base_url = self.SANDBOX_URL if sandbox else self.PRODUCTION_URL

    async def create_payment(
        self,
        amount: int,  # IRR (Toman * 10)
        description: str = "V7LTHRONYX VPN Subscription",
        email: str = "",
        mobile: str = "",
    ) -> Dict[str, Any]:
        """Create a Zarinpal payment request."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/request.json",
                json={
                    "merchant_id": self.merchant_id,
                    "amount": amount,
                    "description": description,
                    "callback_url": self.callback_url,
                    "metadata": {
                        "email": email,
                        "mobile": mobile,
                    },
                },
            )
            data = resp.json()

            if data.get("data", {}).get("code") == 100:
                authority = data["data"]["authority"]
                if self.sandbox:
                    pay_url = f"https://sandbox.zarinpal.com/pg/StartPay/{authority}"
                else:
                    pay_url = f"https://www.zarinpal.com/pg/StartPay/{authority}"

                return {
                    "success": True,
                    "authority": authority,
                    "pay_url": pay_url,
                }

            return {
                "success": False,
                "error": data.get("errors", {}).get("message", "Unknown error"),
            }

    async def verify_payment(
        self,
        authority: str,
        amount: int,
    ) -> Dict[str, Any]:
        """Verify a Zarinpal payment."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/verify.json",
                json={
                    "merchant_id": self.merchant_id,
                    "amount": amount,
                    "authority": authority,
                },
            )
            data = resp.json()

            if data.get("data", {}).get("code") in [100, 101]:
                return {
                    "success": True,
                    "ref_id": data["data"].get("ref_id"),
                    "card_pan": data["data"].get("card_pan", ""),
                }

            return {
                "success": False,
                "error": data.get("errors", {}).get("message", "Verification failed"),
            }


# ═══════════════════════════════════════════════════════════════
#  IDPay Gateway
# ═══════════════════════════════════════════════════════════════

class IDPayGateway:
    """IDPay payment gateway integration."""

    SANDBOX_URL = "https://staging.idpay.ir/v1.1"
    PRODUCTION_URL = "https://api.idpay.ir/v1.1"

    def __init__(self, api_key: str, sandbox: bool = False, callback_url: str = ""):
        self.api_key = api_key
        self.sandbox = sandbox
        self.callback_url = callback_url
        self._base_url = self.SANDBOX_URL if sandbox else self.PRODUCTION_URL

    async def create_payment(
        self,
        order_id: str,
        amount: int,  # IRR
        description: str = "V7LTHRONYX VPN Subscription",
        name: str = "",
        email: str = "",
        phone: str = "",
    ) -> Dict[str, Any]:
        """Create an IDPay payment request."""
        headers = {
            "X-API-KEY": self.api_key,
            "X-SANDBOX": "1" if self.sandbox else "0",
            "Content-Type": "application/json",
        }

        payload = {
            "order_id": order_id,
            "amount": amount,
            "desc": description,
            "callback": self.callback_url,
        }
        if name:
            payload["name"] = name
        if email:
            payload["mail"] = email
        if phone:
            payload["phone"] = phone

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/payment",
                json=payload,
                headers=headers,
            )
            data = resp.json()

            if "id" in data:
                return {
                    "success": True,
                    "id": data["id"],
                    "link": data.get("link", f"https://idpay.ir/p/{data['id']}"),
                }

            return {
                "success": False,
                "error": data.get("error_message", "Unknown error"),
            }

    async def verify_payment(
        self,
        payment_id: str,
        order_id: str,
    ) -> Dict[str, Any]:
        """Verify an IDPay payment."""
        headers = {
            "X-API-KEY": self.api_key,
            "X-SANDBOX": "1" if self.sandbox else "0",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/payment/verify",
                json={"id": payment_id, "order_id": order_id},
                headers=headers,
            )
            data = resp.json()

            if data.get("status") == 100:
                return {
                    "success": True,
                    "track_id": data.get("track_id"),
                    "card_no": data.get("payment", {}).get("card_no", ""),
                }

            return {
                "success": False,
                "error": data.get("error_message", "Verification failed"),
            }


# ═══════════════════════════════════════════════════════════════
#  USDT TRC-20 Gateway
# ═══════════════════════════════════════════════════════════════

class USDTGateway:
    """USDT TRC-20 cryptocurrency payment gateway.

    Monitors TRON blockchain for incoming USDT payments to
    the configured wallet address.
    """

    TRON_GRID_URL = "https://api.trongrid.io"

    def __init__(self, wallet_address: str, api_key: str = ""):
        self.wallet_address = wallet_address
        self.api_key = api_key

    async def check_payment(
        self,
        expected_amount: float,
        since_timestamp: int = 0,
    ) -> Dict[str, Any]:
        """Check for incoming USDT TRC-20 payments."""
        headers = {}
        if self.api_key:
            headers["TRON-PRO-API-KEY"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Get recent transactions for the wallet
                resp = await client.get(
                    f"{self.TRON_GRID_URL}/v1/accounts/{self.wallet_address}/transactions/trc20",
                    params={
                        "contract_address": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",  # USDT contract
                        "limit": 50,
                        "min_timestamp": since_timestamp,
                    },
                    headers=headers,
                )
                data = resp.json()

                for tx in data.get("data", []):
                    value = int(tx.get("value", 0)) / 1_000_000  # USDT has 6 decimals
                    to_addr = tx.get("to", "")

                    if to_addr == self.wallet_address and abs(value - expected_amount) < 0.01:
                        return {
                            "success": True,
                            "tx_hash": tx.get("transaction_id", ""),
                            "amount": value,
                            "from": tx.get("from", ""),
                            "timestamp": tx.get("block_timestamp", 0),
                        }

                return {"success": False, "error": "No matching payment found"}

        except Exception as e:
            logger.error(f"USDT payment check error: {e}")
            return {"success": False, "error": str(e)}

    async def generate_payment_address(self) -> str:
        """Generate a unique payment address or memo.

        In production, you'd generate a unique TRON address per payment
        using a HD wallet. For now, return the main wallet with a memo.
        """
        memo = secrets.token_hex(8)
        return f"{self.wallet_address}?memo={memo}"


# ═══════════════════════════════════════════════════════════════
#  Payment Manager
# ═══════════════════════════════════════════════════════════════

class PaymentManager:
    """Unified payment manager for all gateways."""

    def __init__(self):
        self._gateways: Dict[str, Any] = {}

    def setup_zarinpal(self, merchant_id: str, sandbox: bool = False, callback_url: str = ""):
        self._gateways["zarinpal"] = ZarinpalGateway(merchant_id, sandbox, callback_url)

    def setup_idpay(self, api_key: str, sandbox: bool = False, callback_url: str = ""):
        self._gateways["idpay"] = IDPayGateway(api_key, sandbox, callback_url)

    def setup_usdt(self, wallet_address: str, api_key: str = ""):
        self._gateways["usdt_trc20"] = USDTGateway(wallet_address, api_key)

    async def create_payment(
        self,
        db: AsyncSession,
        user_id: int,
        plan_id: str,
        gateway: str = "zarinpal",
        reseller_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create a new payment."""
        plan = PLANS.get(plan_id)
        if not plan:
            return {"success": False, "error": f"Invalid plan: {plan_id}"}

        gw = self._gateways.get(gateway)
        if not gw:
            return {"success": False, "error": f"Gateway not configured: {gateway}"}

        # Create payment record
        payment = Payment(
            user_id=user_id,
            reseller_id=reseller_id,
            gateway=PaymentGateway(gateway),
            status=PaymentStatus.pending,
            amount=plan.price_irr if gateway != "usdt_trc20" else int(plan.price_usdt * 100),
            currency="IRR" if gateway != "usdt_trc20" else "USDT",
            plan_traffic_gb=plan.traffic_gb,
            plan_days=plan.days,
        )
        db.add(payment)
        await db.commit()
        await db.refresh(payment)

        # Create gateway payment
        if gateway == "zarinpal":
            result = await gw.create_payment(
                amount=payment.amount,
                description=f"V7LTHRONYX - {plan.name_fa} ({plan.traffic_gb}GB / {plan.days} روز)",
            )
            if result.get("success"):
                payment.gateway_authority = result["authority"]
                payment.gateway_callback_url = result.get("pay_url")
                await db.commit()
                return {
                    "success": True,
                    "payment_id": payment.id,
                    "pay_url": result["pay_url"],
                    "authority": result["authority"],
                }
            return result

        elif gateway == "idpay":
            result = await gw.create_payment(
                order_id=str(payment.id),
                amount=payment.amount,
            )
            if result.get("success"):
                payment.gateway_authority = result["id"]
                payment.gateway_callback_url = result.get("link")
                await db.commit()
                return {
                    "success": True,
                    "payment_id": payment.id,
                    "pay_url": result.get("link"),
                    "gateway_id": result["id"],
                }
            return result

        elif gateway == "usdt_trc20":
            address = await gw.generate_payment_address()
            payment.usdt_wallet_address = address
            await db.commit()
            return {
                "success": True,
                "payment_id": payment.id,
                "wallet_address": address,
                "amount_usdt": plan.price_usdt,
            }

        return {"success": False, "error": "Unknown gateway"}

    async def verify_payment(
        self,
        db: AsyncSession,
        payment_id: int,
        gateway: str = "zarinpal",
        **kwargs,
    ) -> Dict[str, Any]:
        """Verify and complete a payment."""
        result = await db.execute(
            select(Payment).where(Payment.id == payment_id)
        )
        payment = result.scalar_one_or_none()

        if not payment:
            return {"success": False, "error": "Payment not found"}

        if payment.status == PaymentStatus.paid:
            return {"success": True, "message": "Already paid"}

        gw = self._gateways.get(gateway)
        if not gw:
            return {"success": False, "error": "Gateway not configured"}

        # Verify with gateway
        if gateway == "zarinpal":
            verify_result = await gw.verify_payment(
                authority=kwargs.get("authority", payment.gateway_authority or ""),
                amount=payment.amount,
            )
        elif gateway == "idpay":
            verify_result = await gw.verify_payment(
                payment_id=kwargs.get("gateway_id", payment.gateway_authority or ""),
                order_id=str(payment.id),
            )
        elif gateway == "usdt_trc20":
            verify_result = await gw.check_payment(
                expected_amount=payment.amount / 100,
                since_timestamp=int(payment.created_at.timestamp() * 1000) if payment.created_at else 0,
            )
        else:
            return {"success": False, "error": "Unknown gateway"}

        if verify_result.get("success"):
            payment.status = PaymentStatus.paid
            payment.paid_at = _utcnow()
            payment.gateway_ref_id = str(verify_result.get("ref_id") or verify_result.get("track_id") or verify_result.get("tx_hash", ""))

            # Extend user
            if payment.user_id:
                user_result = await db.execute(
                    select(VpnUser).where(VpnUser.id == payment.user_id)
                )
                user = user_result.scalar_one_or_none()
                if user:
                    # Add traffic
                    if payment.plan_traffic_gb > 0:
                        user.traffic_limit += int(payment.plan_traffic_gb * 1024 * 1024 * 1024)
                    # Extend expiry
                    if payment.plan_days > 0:
                        if user.expire_at and user.expire_at > _utcnow():
                            user.expire_at += timedelta(days=payment.plan_days)
                        else:
                            user.expire_at = _utcnow() + timedelta(days=payment.plan_days)
                    user.active = 1

            # Process reseller commission
            if payment.reseller_id:
                reseller_result = await db.execute(
                    select(Reseller).where(Reseller.id == payment.reseller_id)
                )
                reseller = reseller_result.scalar_one_or_none()
                if reseller:
                    commission = int(payment.amount * reseller.commission_rate / 100)
                    reseller.balance += commission

            await db.commit()

            return {
                "success": True,
                "payment_id": payment.id,
                "ref_id": payment.gateway_ref_id,
            }

        # Mark as failed
        payment.status = PaymentStatus.failed
        await db.commit()

        return verify_result

    async def get_user_payments(
        self, db: AsyncSession, user_id: int
    ) -> List[Dict[str, Any]]:
        """Get payment history for a user."""
        result = await db.execute(
            select(Payment)
            .where(Payment.user_id == user_id)
            .order_by(Payment.created_at.desc())
        )
        payments = result.scalars().all()

        return [
            {
                "id": p.id,
                "gateway": p.gateway.value,
                "status": p.status.value,
                "amount": p.amount,
                "currency": p.currency,
                "plan_traffic_gb": p.plan_traffic_gb,
                "plan_days": p.plan_days,
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "paid_at": p.paid_at.isoformat() if p.paid_at else None,
            }
            for p in payments
        ]


# Global payment manager
payment_manager = PaymentManager()