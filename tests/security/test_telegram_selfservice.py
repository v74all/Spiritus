import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient

import app.telegram_selfservice as ss
from app.config import settings
from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.models import VpnUser


def _user():
    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            u = VpnUser(uuid=str(uuid.uuid4()), name="alice <b>", traffic_limit=10 * 1024**3, traffic_used=2 * 1024**3)
            db.add(u)
            await db.commit()
            return u.uuid

    return asyncio.run(go())


def _cmd(chat, cmd, args=""):
    async def go():
        async with AsyncSessionLocal() as db:
            return await ss.handle_user_command(db, chat, cmd, args)

    return asyncio.run(go())


@pytest.fixture(autouse=True)
def _reset():
    ss._link_failures.clear()
    asyncio.run(init_db())


def test_requires_link_before_usage():
    assert "Not linked" in _cmd("111", "/usage")


def test_link_usage_unlink_and_escaping():
    uid = _user()
    chat = f"c{uuid.uuid4().hex[:8]}"
    assert "Linked" in _cmd(chat, "/link", uid)
    out = _cmd(chat, "/usage")
    assert "&lt;b&gt;" in out and "2.0 GB" in out and "<b>alice <b>" not in out
    assert "Unlinked" in _cmd(chat, "/unlink")
    assert "Not linked" in _cmd(chat, "/usage")


def test_subscription_cannot_be_hijacked_by_another_chat():
    uid = _user()
    assert "Linked" in _cmd("owner1", "/link", uid)
    assert "already linked" in _cmd("intruder", "/link", uid)


def test_link_brute_force_is_throttled():
    chat = "bruteforcer"
    for _ in range(ss._LINK_MAX_FAILURES):
        assert "not found" in _cmd(chat, "/link", str(uuid.uuid4())).lower()
    assert "Too many" in _cmd(chat, "/link", str(uuid.uuid4()))


def test_renew_validates_plan_and_gateway():
    uid = _user()
    _cmd("renewer", "/link", uid)
    assert "Usage" in _cmd("renewer", "/renew", "nope")
    assert "Unknown gateway" in _cmd("renewer", "/renew", "basic bitcoin")


def test_webhook_disabled_without_secret(monkeypatch):
    monkeypatch.setattr(settings, "telegram_webhook_secret", "")
    with TestClient(app) as client:
        assert client.post("/api/telegram/webhook", json={}).status_code == 404


def test_webhook_requires_matching_secret(monkeypatch):
    monkeypatch.setattr(settings, "telegram_webhook_secret", "s" * 24)
    with TestClient(app) as client:
        assert client.post("/api/telegram/webhook", json={}).status_code == 403
        bad = client.post("/api/telegram/webhook", json={}, headers={"X-Telegram-Bot-Api-Secret-Token": "x" * 24})
        assert bad.status_code == 403
        ok = client.post("/api/telegram/webhook", json={"update_id": 1},
                         headers={"X-Telegram-Bot-Api-Secret-Token": "s" * 24})
        assert ok.status_code == 200
