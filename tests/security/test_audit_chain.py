"""Audit log hash chain: append, verify, and tamper detection."""

import asyncio

from sqlalchemy import delete, select, update

from app.audit import GENESIS_HASH, record_audit, verify_chain
from app.database import AsyncSessionLocal, init_db
from app.models import AuditLog


def _run(coro):
    return asyncio.run(coro)


async def _reset():
    await init_db()
    async with AsyncSessionLocal() as db:
        await db.execute(delete(AuditLog))
        await db.commit()


def test_chain_links_and_verifies():
    async def go():
        await _reset()
        async with AsyncSessionLocal() as db:
            first = await record_audit(db, "login", details={"a": 1}, ip_address="10.0.0.1")
            second = await record_audit(db, "logout", ip_address="10.0.0.1")
            assert first.prev_hash == GENESIS_HASH
            assert second.prev_hash == first.entry_hash
            result = await verify_chain(db)
            assert result == {"ok": True, "checked": 2, "broken_at": None}

    _run(go())


def test_modified_row_is_detected():
    async def go():
        await _reset()
        async with AsyncSessionLocal() as db:
            await record_audit(db, "login", ip_address="10.0.0.1")
            victim = await record_audit(db, "password_change", ip_address="10.0.0.1")
            await record_audit(db, "logout", ip_address="10.0.0.1")
            await db.execute(
                update(AuditLog).where(AuditLog.id == victim.id).values(ip_address="6.6.6.6")
            )
            await db.commit()
            result = await verify_chain(db)
            assert result["ok"] is False
            assert result["broken_at"] == victim.id

    _run(go())


def test_deleted_row_is_detected():
    async def go():
        await _reset()
        async with AsyncSessionLocal() as db:
            await record_audit(db, "a")
            middle = await record_audit(db, "b")
            await record_audit(db, "c")
            await db.execute(delete(AuditLog).where(AuditLog.id == middle.id))
            await db.commit()
            result = await verify_chain(db)
            assert result["ok"] is False

    _run(go())


def test_recompute_without_secret_fails():
    """A DB-only attacker rewriting entry_hash with plain SHA-256 must not pass."""
    import hashlib

    async def go():
        await _reset()
        async with AsyncSessionLocal() as db:
            row = await record_audit(db, "login")
            forged = hashlib.sha256(b"x").hexdigest()
            await db.execute(update(AuditLog).where(AuditLog.id == row.id).values(entry_hash=forged))
            await db.commit()
            assert (await verify_chain(db))["ok"] is False
            rows = (await db.execute(select(AuditLog))).scalars().all()
            assert len(rows) == 1

    _run(go())
