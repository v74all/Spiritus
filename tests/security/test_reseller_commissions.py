"""Multi-level reseller commissions, wallet ledger and sub-reseller limits."""

import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.auth import create_access_token, get_password_hash
from app.commissions import InsufficientBalanceError, credit_commissions, post_ledger_entry
from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.models import (
    Admin,
    Payment,
    PaymentGateway,
    PaymentStatus,
    Reseller,
    ResellerLedger,
    UserRole,
)
from app.reseller import reseller_manager

PASSWORD = "Sup3rStrong!Pass-1"


def _name():
    return f"r-{uuid.uuid4().hex[:8]}"


async def _tree():
    """root(20%) -> mid(12%) -> leaf(10%)."""
    await init_db()
    async with AsyncSessionLocal() as db:
        ids = []
        parent = None
        for rate in (20.0, 12.0, 10.0):
            res = await reseller_manager.create_reseller(
                db, _name(), PASSWORD, commission_rate=rate, max_users=50, max_traffic_gb=500, parent_id=parent
            )
            assert res["success"], res
            parent = res["id"]
            ids.append(parent)
        return ids


async def _payment(db, reseller_id, amount=1_000_000):
    payment = Payment(reseller_id=reseller_id, gateway=PaymentGateway.zarinpal,
                      status=PaymentStatus.paid, amount=amount)
    db.add(payment)
    await db.flush()
    return payment


def test_differential_commissions_up_the_tree():
    async def go():
        root, mid, leaf = await _tree()
        async with AsyncSessionLocal() as db:
            payment = await _payment(db, leaf)
            entries = await credit_commissions(db, payment)
            await db.commit()
            by_reseller = {e.reseller_id: (e.kind, e.amount) for e in entries}
            # leaf 10%, mid earns the 2% margin, root earns the 8% margin: total == root's 20%.
            assert by_reseller[leaf] == ("commission", 100_000)
            assert by_reseller[mid] == ("override", 20_000)
            assert by_reseller[root] == ("override", 80_000)
            assert sum(a for _, a in by_reseller.values()) == 200_000
            balances = {r.id: r.balance for r in (await db.execute(select(Reseller))).scalars() if r.id in by_reseller}
            assert balances[root] == 80_000

    asyncio.run(go())


def test_commission_credit_is_idempotent_per_payment():
    async def go():
        _, _, leaf = await _tree()
        async with AsyncSessionLocal() as db:
            payment = await _payment(db, leaf)
            await credit_commissions(db, payment)
            await db.commit()
            with pytest.raises(Exception):  # unique (payment, reseller, kind)
                await credit_commissions(db, payment)
                await db.commit()
            await db.rollback()

    asyncio.run(go())


def test_sub_reseller_limits_and_depth():
    async def go():
        root, mid, leaf = await _tree()
        async with AsyncSessionLocal() as db:
            too_rich = await reseller_manager.create_reseller(
                db, _name(), PASSWORD, commission_rate=15.0, max_users=5, max_traffic_gb=10, parent_id=mid
            )
            assert not too_rich["success"] and "rate" in too_rich["error"].lower()
            too_deep = await reseller_manager.create_reseller(
                db, _name(), PASSWORD, commission_rate=1.0, max_users=5, max_traffic_gb=10, parent_id=leaf
            )
            assert not too_deep["success"] and "depth" in too_deep["error"].lower()
            more_users = await reseller_manager.create_reseller(
                db, _name(), PASSWORD, commission_rate=5.0, max_users=999, max_traffic_gb=10, parent_id=mid
            )
            assert not more_users["success"]
            assert {r.id for r in await reseller_manager.downline(db, root)} == {mid, leaf}

    asyncio.run(go())


def test_wallet_cannot_be_overdrawn_and_ledger_tracks_balance():
    async def go():
        _, _, leaf = await _tree()
        async with AsyncSessionLocal() as db:
            await post_ledger_entry(db, leaf, 500, "adjustment", note="topup")
            await db.commit()
            with pytest.raises(InsufficientBalanceError):
                await post_ledger_entry(db, leaf, -501, "adjustment", allow_negative=False)
            await db.rollback()
            rows = (await db.execute(select(ResellerLedger).where(ResellerLedger.reseller_id == leaf))).scalars().all()
            assert [r.balance_after for r in rows] == [500]

    asyncio.run(go())


def test_reseller_self_service_api_flow():
    async def setup():
        await init_db()
        async with AsyncSessionLocal() as db:
            username = _name()
            res = await reseller_manager.create_reseller(
                db, username, PASSWORD, commission_rate=20.0, max_users=50, max_traffic_gb=500
            )
            admin = Admin(username=_name(), password_hash=get_password_hash(PASSWORD), role=UserRole.admin)
            db.add(admin)
            await db.commit()
            return username, res["id"], admin.username

    username, rid, admin_name = asyncio.run(setup())
    admin_h = {"Authorization": "Bearer " + create_access_token({"sub": admin_name, "is_admin": True})}
    with TestClient(app) as client:
        token = create_access_token({"sub": f"reseller:{username}", "is_admin": False, "reseller_id": rid})
        h = {"Authorization": f"Bearer {token}"}

        assert client.get("/api/resellers/me", headers=h).json()["id"] == rid
        sub = client.post("/api/resellers/me/sub-resellers", headers=h,
                          json={"username": _name(), "password": PASSWORD, "commission_rate": 8, "max_users": 5, "max_traffic_gb": 50})
        assert sub.status_code == 201, sub.text
        over = client.post("/api/resellers/me/sub-resellers", headers=h,
                           json={"username": _name(), "password": PASSWORD, "commission_rate": 25, "max_users": 5, "max_traffic_gb": 50})
        assert over.status_code == 400
        assert len(client.get("/api/resellers/me/downline", headers=h).json()) == 1

        # Admin tokens and anonymous callers are not resellers.
        assert client.get("/api/resellers/me", headers=admin_h).status_code == 401
        assert client.get("/api/resellers/me").status_code == 401

        credit = client.post(f"/api/resellers/{rid}/wallet/adjust", headers=admin_h, json={"amount": 1000, "note": "payout fix"})
        assert credit.status_code == 200, credit.text
        overdraw = client.post(f"/api/resellers/{rid}/wallet/adjust", headers=admin_h, json={"amount": -5000, "note": "too much"})
        assert overdraw.status_code == 400
        ledger = client.get("/api/resellers/me/ledger", headers=h).json()
        assert ledger[0]["amount"] == 1000 and ledger[0]["balance_after"] == 1000
