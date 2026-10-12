"""Mobile refresh-token rotation, reuse detection and revocation."""

import asyncio
import uuid

import fakeredis
import pytest
from fastapi.testclient import TestClient

import app.redis_client as redis_client
from app.auth import get_password_hash
from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.models import Admin, UserRole

PASSWORD = "Sup3rStrong!Pass-1"


@pytest.fixture
def fake_redis(monkeypatch):
    server = fakeredis.FakeServer()
    # One connection per event loop: the TestClient runs its own loop.
    async def _get():
        return fakeredis.FakeAsyncRedis(server=server, decode_responses=True)

    monkeypatch.setattr(redis_client, "get_redis", _get)
    import app.api.mobile_auth as mobile_auth
    import app.middleware.rate_limit as rate_limit

    monkeypatch.setattr(mobile_auth, "get_redis", _get)
    if hasattr(rate_limit, "get_redis"):
        monkeypatch.setattr(rate_limit, "get_redis", _get)
    return server


@pytest.fixture
def admin_name():
    async def _setup():
        await init_db()
        async with AsyncSessionLocal() as db:
            name = f"mobile-{uuid.uuid4().hex[:8]}"
            db.add(Admin(username=name, password_hash=get_password_hash(PASSWORD), role=UserRole.admin))
            await db.commit()
            return name

    return asyncio.run(_setup())


@pytest.fixture
def client(fake_redis):
    with TestClient(app) as c:
        yield c


def _login(client, name):
    r = client.post("/api/mobile/auth/login", json={"role": "admin", "username": name, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_login_returns_refresh_token(client, admin_name):
    body = _login(client, admin_name)
    assert body["refresh_token"] and body["refresh_expires_in"] > 0


def test_refresh_rotates_and_old_token_is_single_use(client, admin_name):
    first = _login(client, admin_name)
    r = client.post("/api/mobile/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert r.status_code == 200, r.text
    second = r.json()
    assert second["refresh_token"] != first["refresh_token"]
    assert client.get("/api/mobile/session", headers=_bearer(second["access_token"])).status_code == 200


def test_reusing_a_rotated_refresh_token_revokes_the_family(client, admin_name):
    first = _login(client, admin_name)
    second = client.post("/api/mobile/auth/refresh", json={"refresh_token": first["refresh_token"]}).json()
    # Attacker replays the stolen, already-rotated token.
    replay = client.post("/api/mobile/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert replay.status_code == 401
    # Everything in the family is now dead, including the legitimate newest pair.
    assert client.get("/api/mobile/session", headers=_bearer(second["access_token"])).status_code == 401
    legit = client.post("/api/mobile/auth/refresh", json={"refresh_token": second["refresh_token"]})
    assert legit.status_code == 401


def test_logout_revokes_refresh_family(client, admin_name):
    body = _login(client, admin_name)
    assert client.post("/api/mobile/auth/logout", headers=_bearer(body["access_token"])).status_code == 204
    r = client.post("/api/mobile/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert r.status_code == 401


def test_unknown_refresh_token_rejected(client, fake_redis):
    r = client.post("/api/mobile/auth/refresh", json={"refresh_token": "x" * 48})
    assert r.status_code == 401
