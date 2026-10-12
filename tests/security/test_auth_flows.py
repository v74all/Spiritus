"""End-to-end auth flows: legacy cookie login/logout revocation, audit trail, hashing."""

import asyncio
import uuid

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import app.redis_client as redis_client
from app.audit import verify_chain
from app.auth import get_password_hash, verify_password
from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.models import Admin, AuditLog, UserRole

PASSWORD = "Sup3rStrong!Pass-1"


@pytest.fixture
def fake_redis(monkeypatch):
    server = fakeredis.FakeServer()

    async def _get():
        return fakeredis.FakeAsyncRedis(server=server, decode_responses=True)

    monkeypatch.setattr(redis_client, "get_redis", _get)
    return server


@pytest.fixture
def admin_name():
    async def _setup():
        await init_db()
        async with AsyncSessionLocal() as db:
            name = f"flow-{uuid.uuid4().hex[:8]}"
            db.add(Admin(username=name, password_hash=get_password_hash(PASSWORD), role=UserRole.admin))
            await db.commit()
            return name

    return asyncio.run(_setup())


def test_legacy_logout_revokes_the_session_token(fake_redis, admin_name):
    with TestClient(app) as client:
        r = client.post("/api/login", json={"username": admin_name, "password": PASSWORD})
        assert r.json()["ok"] is True
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        assert client.get("/api/auth/me", headers=headers).status_code == 200

        # Logging out must kill a *copy* of the token, not just clear the browser cookie.
        csrf = {"X-CSRF-Token": client.cookies.get("csrf_token", "")}
        assert client.post("/api/logout", headers=csrf).json() == {"ok": True}
        assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_login_events_are_audited_and_chain_stays_valid(fake_redis, admin_name):
    with TestClient(app) as client:
        client.post("/api/login", json={"username": admin_name, "password": "wrong-password"})
        client.post("/api/login", json={"username": admin_name, "password": PASSWORD})
        actions, chain = asyncio.run(_check())

    assert "login_failed" in actions and "login" in actions
    assert chain["ok"] is True


async def _check():
    async with AsyncSessionLocal() as db:
        actions = [
            a for (a,) in (
                await db.execute(select(AuditLog.action).order_by(AuditLog.id))
            ).all()
        ]
        return actions, await verify_chain(db)


def test_password_hash_is_argon2id_and_rejects_garbage():
    hashed = get_password_hash(PASSWORD)
    assert hashed.startswith("$argon2id$")
    assert verify_password(PASSWORD, hashed)
    assert not verify_password("nope", hashed)
    assert not verify_password(PASSWORD, "not-a-hash")


def test_wellformed_argon2_hash_with_wrong_password_is_false():
    # Standard $argon2id$ strings (as written by the former passlib backend) are parsed, not rejected.
    legacy = (
        "$argon2id$v=19$m=65536,t=3,p=4$"
        "c29tZXNhbHRzb21lc2FsdA$"
        "gk2qdRrbpB3xvbR1N7qKXhpFyyI0sBPf3I1bJ4HcnXk"
    )
    assert verify_password("irrelevant", legacy) is False  # well-formed, wrong password -> False, no exception
