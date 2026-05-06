"""
Reseller System & Self-Service Portal for V7LTHRONYX VPN Panel.

Reseller System:
- Reseller account management
- Commission tracking
- User creation with limits
- Payment integration

Self-Service Portal:
- User registration and login
- Subscription purchase
- Config download
- Traffic usage view
- QR code generation
"""

import json
import secrets
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta, timezone
from .timeutil import utcnow as _utcnow

from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext

from .models import (
    VpnUser, Reseller, Payment, Agent,
    PaymentGateway, PaymentStatus,
)
from .payments import payment_manager, PLANS
from .protocol_engine import ClientConfigGenerator, xray_gen
from .orchestrator import orchestrator

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


# ═══════════════════════════════════════════════════════════════
#  Reseller Manager
# ═══════════════════════════════════════════════════════════════

class ResellerManager:
    """Manage reseller accounts and operations."""

    async def create_reseller(
        self,
        db: AsyncSession,
        username: str,
        password: str,
        commission_rate: float = 10.0,
        max_users: int = 100,
        max_traffic_gb: float = 1000,
    ) -> Dict[str, Any]:
        """Create a new reseller account."""
        # Check if username exists
        existing = await db.execute(
            select(Reseller).where(Reseller.username == username)
        )
        if existing.scalar_one_or_none():
            return {"success": False, "error": "Username already exists"}

        reseller = Reseller(
            username=username,
            password_hash=pwd_context.hash(password),
            commission_rate=commission_rate,
            max_users=max_users,
            max_traffic_gb=max_traffic_gb,
        )
        db.add(reseller)
        await db.commit()
        await db.refresh(reseller)

        return {
            "success": True,
            "id": reseller.id,
            "username": reseller.username,
            "commission_rate": reseller.commission_rate,
        }

    async def authenticate_reseller(
        self, db: AsyncSession, username: str, password: str
    ) -> Optional[Reseller]:
        """Authenticate a reseller."""
        result = await db.execute(
            select(Reseller).where(
                Reseller.username == username,
                Reseller.active == True,
            )
        )
        reseller = result.scalar_one_or_none()

        if reseller and pwd_context.verify(password, reseller.password_hash):
            return reseller
        return None

    async def get_reseller_stats(
        self, db: AsyncSession, reseller_id: int
    ) -> Dict[str, Any]:
        """Get reseller statistics."""
        # User count
        user_count = await db.execute(
            select(func.count(VpnUser.id)).where(VpnUser.reseller_id == reseller_id)
        )
        total_users = user_count.scalar() or 0

        # Active users
        active_count = await db.execute(
            select(func.count(VpnUser.id)).where(
                VpnUser.reseller_id == reseller_id,
                VpnUser.active == 1,
            )
        )
        active_users = active_count.scalar() or 0

        # Total traffic used
        traffic_result = await db.execute(
            select(func.sum(VpnUser.traffic_used)).where(VpnUser.reseller_id == reseller_id)
        )
        total_traffic = traffic_result.scalar() or 0

        # Payment stats
        payment_count = await db.execute(
            select(func.count(Payment.id)).where(Payment.reseller_id == reseller_id)
        )
        total_payments = payment_count.scalar() or 0

        paid_result = await db.execute(
            select(func.sum(Payment.amount)).where(
                Payment.reseller_id == reseller_id,
                Payment.status == PaymentStatus.paid,
            )
        )
        total_revenue = paid_result.scalar() or 0

        # Get reseller
        reseller_result = await db.execute(
            select(Reseller).where(Reseller.id == reseller_id)
        )
        reseller = reseller_result.scalar_one_or_none()

        return {
            "id": reseller_id,
            "username": reseller.username if reseller else "",
            "commission_rate": reseller.commission_rate if reseller else 0,
            "balance": reseller.balance if reseller else 0,
            "total_users": total_users,
            "active_users": active_users,
            "max_users": reseller.max_users if reseller else 0,
            "total_traffic_gb": total_traffic / (1024**3),
            "max_traffic_gb": reseller.max_traffic_gb if reseller else 0,
            "total_payments": total_payments,
            "total_revenue": total_revenue,
        }

    async def create_user_for_reseller(
        self,
        db: AsyncSession,
        reseller_id: int,
        name: str,
        traffic_limit_gb: float,
        days: int,
        agent_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create a VPN user under a reseller."""
        # Check limits
        reseller_result = await db.execute(
            select(Reseller).where(Reseller.id == reseller_id)
        )
        reseller = reseller_result.scalar_one_or_none()

        if not reseller:
            return {"success": False, "error": "Reseller not found"}

        if not reseller.active:
            return {"success": False, "error": "Reseller account is disabled"}

        # Check user limit
        user_count = await db.execute(
            select(func.count(VpnUser.id)).where(VpnUser.reseller_id == reseller_id)
        )
        if (user_count.scalar() or 0) >= reseller.max_users:
            return {"success": False, "error": "User limit reached"}

        # Create user
        import uuid
        user_uuid = str(uuid.uuid4())
        expire_at = _utcnow() + timedelta(days=days) if days > 0 else None

        user = VpnUser(
            uuid=user_uuid,
            name=name,
            traffic_limit=int(traffic_limit_gb * 1024 * 1024 * 1024),
            traffic_used=0,
            expire_at=expire_at,
            active=1,
            agent_id=agent_id,
            reseller_id=reseller_id,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

        return {
            "success": True,
            "id": user.id,
            "uuid": user.uuid,
            "name": user.name,
            "traffic_limit_gb": traffic_limit_gb,
            "expire_at": expire_at.isoformat() if expire_at else None,
        }


# ═══════════════════════════════════════════════════════════════
#  Self-Service Portal
# ═══════════════════════════════════════════════════════════════

class SelfServicePortal:
    """Self-service portal for VPN users.

    Users can:
    - View their subscription status
    - Check traffic usage
    - Download configuration
    - Renew subscription via payment
    - Get QR code for mobile apps
    """

    async def get_user_status(
        self, db: AsyncSession, user_uuid: str
    ) -> Dict[str, Any]:
        """Get user subscription status."""
        result = await db.execute(
            select(VpnUser).where(VpnUser.uuid == user_uuid)
        )
        user = result.scalar_one_or_none()

        if not user:
            return {"success": False, "error": "User not found"}

        traffic_limit_gb = user.traffic_limit / (1024**3) if user.traffic_limit else 0
        traffic_used_gb = user.traffic_used / (1024**3) if user.traffic_used else 0
        traffic_remaining_gb = max(0, traffic_limit_gb - traffic_used_gb) if user.traffic_limit else -1  # -1 = unlimited

        is_expired = False
        if user.expire_at and user.expire_at < _utcnow():
            is_expired = True

        return {
            "success": True,
            "name": user.name,
            "uuid": user.uuid,
            "active": user.active == 1 and not is_expired,
            "traffic_limit_gb": traffic_limit_gb,
            "traffic_used_gb": round(traffic_used_gb, 2),
            "traffic_remaining_gb": round(traffic_remaining_gb, 2) if traffic_remaining_gb >= 0 else "unlimited",
            "expire_at": user.expire_at.isoformat() if user.expire_at else None,
            "is_expired": is_expired,
            "days_remaining": (user.expire_at - _utcnow()).days if user.expire_at and not is_expired else 0,
            "speed_limit_up": user.speed_limit_up,
            "speed_limit_down": user.speed_limit_down,
        }

    async def get_user_config(
        self,
        db: AsyncSession,
        user_uuid: str,
        protocol: str = "vless_vision_reality",
        server_address: str = "",
    ) -> Dict[str, Any]:
        """Get user configuration for a specific protocol."""
        result = await db.execute(
            select(VpnUser).where(VpnUser.uuid == user_uuid)
        )
        user = result.scalar_one_or_none()

        if not user:
            return {"success": False, "error": "User not found"}

        if not server_address:
            # Try to get from agent
            if user.agent_id:
                agent_result = await db.execute(
                    select(Agent).where(Agent.id == user.agent_id)
                )
                agent = agent_result.scalar_one_or_none()
                if agent:
                    server_address = agent.address

        # Generate share URL based on protocol
        share_url = ""
        config_text = ""

        if protocol.startswith("vless"):
            share_url = ClientConfigGenerator.generate_vless_share_url(
                uuid=user.uuid,
                address=server_address,
                port=2058,
                security="reality",
                sni="objects.githubusercontent.com",
                fp="chrome",
                pbk="",
                sid="",
                flow="xtls-rprx-vision" if "vision" in protocol else "",
                network="xhttp" if "xhttp" in protocol else "tcp",
            )
        elif protocol == "vmess_ws_tls":
            share_url = ClientConfigGenerator.generate_vmess_share_url(
                uuid=user.uuid,
                address=server_address,
                port=443,
                sni="www.aparat.com",
                path="/api/v1/stream",
            )
        elif protocol.startswith("trojan"):
            share_url = ClientConfigGenerator.generate_trojan_share_url(
                password=user.uuid,  # Use UUID as password
                address=server_address,
                port=2083,
                sni="",
                path="/trojan-ws",
            )
        elif protocol == "hysteria2":
            share_url = ClientConfigGenerator.generate_hysteria2_share_url(
                password=user.uuid,
                address=server_address,
                port=8443,
                sni="",
            )
        elif protocol == "amneziawg":
            # For WG, we need the full config
            config_text = ClientConfigGenerator.generate_wg_config(
                interface_private_key="",  # Would be generated
                interface_address="10.8.0.2/24",
                server_public_key="",
                server_endpoint=f"{server_address}:51820",
            )

        return {
            "success": True,
            "protocol": protocol,
            "share_url": share_url,
            "config_text": config_text,
            "qr_data": share_url,  # Frontend generates QR from this
        }

    async def get_available_plans(self) -> List[Dict[str, Any]]:
        """Get available subscription plans."""
        return [
            {
                "id": plan.id,
                "name": plan.name,
                "name_fa": plan.name_fa,
                "traffic_gb": plan.traffic_gb if plan.traffic_gb > 0 else "unlimited",
                "days": plan.days,
                "price_irr": plan.price_irr,
                "price_usdt": plan.price_usdt,
            }
            for plan in PLANS.values()
        ]

    async def create_payment_for_user(
        self,
        db: AsyncSession,
        user_uuid: str,
        plan_id: str,
        gateway: str = "zarinpal",
    ) -> Dict[str, Any]:
        """Create a payment for user subscription renewal."""
        result = await db.execute(
            select(VpnUser).where(VpnUser.uuid == user_uuid)
        )
        user = result.scalar_one_or_none()

        if not user:
            return {"success": False, "error": "User not found"}

        return await payment_manager.create_payment(
            db=db,
            user_id=user.id,
            plan_id=plan_id,
            gateway=gateway,
            reseller_id=user.reseller_id,
        )

    async def get_user_payments(
        self, db: AsyncSession, user_uuid: str
    ) -> List[Dict[str, Any]]:
        """Get payment history for a user."""
        result = await db.execute(
            select(VpnUser).where(VpnUser.uuid == user_uuid)
        )
        user = result.scalar_one_or_none()

        if not user:
            return []

        return await payment_manager.get_user_payments(db, user.id)


# ═══════════════════════════════════════════════════════════════
#  Global instances
# ═══════════════════════════════════════════════════════════════

reseller_manager = ResellerManager()
self_service_portal = SelfServicePortal()