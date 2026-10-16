"""Panel bugs found in review: agent sessions, quota, host poisoning, XSS, zip names."""

import asyncio
import re
import time
import uuid
import zipfile
from io import BytesIO
from pathlib import Path

import fakeredis
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

import app.redis_client as redis_client
from app.api.compat import _core
from app.api.compat.legacy_users import _download_stem, _zip_entry_name
from app.auth import get_password_hash
from app.config import settings
from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.models import Admin, Agent, AgentBackend, AgentStatus, Fail2banBan, UserRole, VpnUser
from app.services.user_names import display_name_error

PASSWORD = "Sup3rStrong!Pass-1"
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def fake_redis(monkeypatch):
    server = fakeredis.FakeServer()

    async def _get():
        return fakeredis.FakeAsyncRedis(server=server, decode_responses=True)

    monkeypatch.setattr(redis_client, "get_redis", _get)
    return server


@pytest.fixture(autouse=True)
def _clear_fail2ban():
    yield

    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            await db.execute(delete(Fail2banBan))
            await db.commit()

    asyncio.run(go())


def _admin_name():
    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            name = f"adm-{uuid.uuid4().hex[:8]}"
            db.add(Admin(username=name, password_hash=get_password_hash(PASSWORD), role=UserRole.admin))
            await db.commit()
            return name

    return asyncio.run(go())


def _csrf(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.cookies.get("csrf_token", "")}


def _login_admin(client: TestClient, name: str) -> dict[str, str]:
    r = client.post("/api/login", json={"username": name, "password": PASSWORD})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    return _csrf(client)


class _Headers(dict):
    def get(self, key, default=None):
        return super().get(key.lower(), default)


class _Req:
    def __init__(self, **headers):
        self.headers = _Headers({k.lower(): v for k, v in headers.items()})


def test_display_name_rejects_markup_and_path_characters():
    assert display_name_error("فروشگاه-۱") is None
    assert display_name_error("a'b") is not None
    assert display_name_error("<script>") is not None
    assert display_name_error("a/b") is not None


def test_zip_entry_names_cannot_escape_the_archive():
    used: set[str] = set()
    assert _zip_entry_name("../../etc/cron.d/evil", used) == "etc_cron.d_evil.txt"
    assert "/" not in _zip_entry_name("../../etc/cron.d/evil", used)
    stem = _download_stem('bad"\r\nX-Injected: 1')
    assert "\r" not in stem and "\n" not in stem and '"' not in stem


def test_forwarded_host_does_not_override_or_stick(monkeypatch):
    monkeypatch.setattr(settings, "vpn_server_ip", "203.0.113.50")
    monkeypatch.setattr(settings, "allowed_hosts", "")
    _core._settings_state.pop("server_ip", None)
    _core._settings_state.pop("domain_active", None)
    req = _Req(**{"X-Forwarded-Host": "evil.example", "Host": "panel.example.com"})
    assert _core.resolve_public_host(req) == "203.0.113.50"
    assert _core._settings_state.get("server_ip") != "evil.example"

    monkeypatch.setattr(settings, "vpn_server_ip", "")
    assert _core.resolve_public_host(req) == "panel.example.com"
    poisoned = _Req(**{"Host": "evil.com\r\nSet-Cookie: a=1"})
    assert _core.resolve_public_host(poisoned) == ""

    monkeypatch.setattr(settings, "allowed_hosts", "panel.example.com")
    allowed = _Req(**{"X-Forwarded-Host": "panel.example.com", "Host": "evil.example"})
    assert _core.resolve_public_host(allowed) == "panel.example.com"
    blocked = _Req(Host="evil.example")
    assert _core.resolve_public_host(blocked) == ""


def test_subscription_page_ignores_spoofed_forwarded_host(monkeypatch):
    monkeypatch.setattr(settings, "vpn_server_ip", "203.0.113.50")

    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            user = VpnUser(uuid=str(uuid.uuid4()), name="niloofar", active=1, traffic_limit=10 * 1024**3)
            db.add(user)
            await db.commit()
            return user.uuid

    uid = asyncio.run(go())
    with TestClient(app) as client:
        page = client.get(
            f"/sub/{uid}",
            headers={"X-Forwarded-Host": "evil.example", "Accept-Language": "en"},
        )
    assert page.status_code == 200
    assert "evil.example" not in page.text
    assert "203.0.113.50" in page.text
    assert _core._settings_state.get("server_ip") != "evil.example"


def test_event_handlers_are_not_html_escaped_into_javascript():
    for rel in ("static/js/panel.js", "templates/agent-panel.html"):
        text = (ROOT / rel).read_text()
        for match in re.finditer(r'onclick="[^"]*"', text):
            assert "esc(" not in match.group(0), match.group(0)
        assert "function jsq(" in text


def test_agent_login_survives_node_offline_and_logout_revokes(fake_redis):
    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            name = f"node-{uuid.uuid4().hex[:8]}"
            db.add(Agent(
                name=name,
                backend=AgentBackend.xray,
                status=AgentStatus.offline,
                address="10.1.1.1",
                api_key=get_password_hash(PASSWORD),
                ech_config={"traffic_quota_gb": 20, "panel_enabled": True, "brand_name": ""},
            ))
            await db.commit()
            return name

    name = asyncio.run(go())
    with TestClient(app) as client:
        logged = client.post("/api/agent/login", json={"name": name, "password": PASSWORD})
        assert logged.status_code == 200
        assert logged.json()["ok"] is True
        token = client.cookies.get("agent_access_token")
        assert token
        assert client.get("/api/agent/me").status_code == 200
        assert client.post("/api/agent/logout", headers=_csrf(client)).json()["ok"] is True
        reused = client.get("/api/agent/me", headers={"Authorization": f"Bearer {token}"})
        assert reused.status_code == 401


def test_disabling_an_agent_revokes_the_session(fake_redis):
    admin = _admin_name()
    with TestClient(app) as client:
        csrf = _login_admin(client, admin)
        name = f"shop-{uuid.uuid4().hex[:6]}"
        created = client.post("/api/agents", headers=csrf, json={
            "name": name, "password": PASSWORD, "traffic_quota_gb": 50, "speed_limit_default": 0,
        })
        assert created.json()["ok"] is True, created.text
        agent_id = created.json()["agent"]["id"]
        assert created.json()["agent"]["active"] is False
        assert client.post("/api/agent/login", json={"name": name, "password": "nope"}).json()["ok"] is False
        assert client.post(
            f"/api/agents/{agent_id}/edit", headers=csrf, json={"active": True}
        ).json()["ok"] is True
        assert client.post("/api/agent/login", json={"name": name, "password": PASSWORD}).json()["ok"] is True
        token = client.cookies.get("agent_access_token")
        # Epoch is second-granularity; a token minted in the same second would survive.
        time.sleep(1.1)
        assert client.post(
            f"/api/agents/{agent_id}/edit", headers=csrf, json={"active": False}
        ).json()["ok"] is True
        assert client.get("/api/agent/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_agent_quota_is_allocated_package_size(fake_redis):
    admin = _admin_name()
    with TestClient(app) as client:
        csrf = _login_admin(client, admin)
        name = f"quota-{uuid.uuid4().hex[:6]}"
        created = client.post("/api/agents", headers=csrf, json={
            "name": name, "password": PASSWORD, "traffic_quota_gb": 10, "speed_limit_default": 0,
        })
        agent_id = created.json()["agent"]["id"]
        client.post(f"/api/agents/{agent_id}/edit", headers=csrf, json={"active": True})
        assert client.post("/api/agent/login", json={"name": name, "password": PASSWORD}).json()["ok"] is True
        agent_csrf = _csrf(client)
        first = client.post("/api/agent/users", headers=agent_csrf, json={
            "name": f"u-{uuid.uuid4().hex[:6]}", "traffic": 8, "days": 30,
        })
        assert first.json()["ok"] is True, first.text
        second = client.post("/api/agent/users", headers=agent_csrf, json={
            "name": f"u-{uuid.uuid4().hex[:6]}", "traffic": 5, "days": 30,
        })
        assert second.json()["ok"] is False
        assert "Quota" in second.json()["error"]
        unlimited = client.post("/api/agent/users", headers=agent_csrf, json={
            "name": f"u-{uuid.uuid4().hex[:6]}", "traffic": 0, "days": 30,
        })
        assert unlimited.json()["ok"] is False
        me = client.get("/api/agent/me").json()
        assert me["traffic_allocated_gb"] == 8
        assert me["traffic_remaining_gb"] == 2


def test_agent_login_locks_after_repeated_failures(fake_redis):
    with TestClient(app) as client:
        last = None
        for _ in range(4):
            last = client.post("/api/agent/login", json={"name": "nobody", "password": "wrong-password-1"})
        assert last is not None
        assert last.status_code == 429
        assert last.json()["locked"] is True


def test_weak_agent_password_is_rejected(fake_redis):
    admin = _admin_name()
    with TestClient(app) as client:
        csrf = _login_admin(client, admin)
        created = client.post("/api/agents", headers=csrf, json={
            "name": f"weak-{uuid.uuid4().hex[:6]}", "password": "short", "traffic_quota_gb": 5,
        })
        assert created.json()["ok"] is False
        assert "12" in created.json()["error"]


def test_bulk_export_header_and_entries_are_safe(fake_redis):
    admin = _admin_name()
    with TestClient(app) as client:
        csrf = _login_admin(client, admin)
        response = client.post("/api/bulk-export-zip", headers=csrf, json={
            "prefix": 'a"\r\nX-Evil',
            "users": [{"name": "../../etc/passwd", "vmess": "vmess://example"}],
        })
        assert response.status_code == 200
        disposition = response.headers["content-disposition"]
        assert "\r" not in disposition and "\n" not in disposition
        archive = zipfile.ZipFile(BytesIO(response.content))
        names = archive.namelist()
        assert names == ["etc_passwd.txt"]
        assert b"vmess://example" in archive.read(names[0])


def test_search_does_not_treat_percent_as_a_wildcard(fake_redis):
    admin = _admin_name()

    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            db.add(VpnUser(uuid=str(uuid.uuid4()), name="alice-search", active=1))
            db.add(VpnUser(uuid=str(uuid.uuid4()), name="100%", active=1))
            await db.commit()

    asyncio.run(go())
    with TestClient(app) as client:
        csrf = _login_admin(client, admin)
        found = client.get("/api/search", headers=csrf, params={"q": "%"})
        names = [row["name"] for row in found.json()["users"]]
        assert "100%" in names
        assert "alice-search" not in names
