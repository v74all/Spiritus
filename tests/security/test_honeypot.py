import asyncio

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.main import app
from app.models import AuditLog


def test_honeypot_hit_is_audited_and_returns_404():
    with TestClient(app) as client:
        r = client.get("/.env")
        assert r.status_code == 404

        async def _check():
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(select(AuditLog).where(AuditLog.action == "honeypot_hit"))).scalars().all()
                return rows

        rows = asyncio.run(_check())
        assert any(r.details.get("path") == "/.env" for r in rows)
