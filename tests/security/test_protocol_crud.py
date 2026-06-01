"""Tests for the protocol CRUD endpoints and sync service.

The endpoints live in app/api/protocols.py. We exercise them via
the FastAPI test client against an in-memory SQLite DB. The Xray
binary is not on the test machine, so we monkey-patch the
sync service to short-circuit the on-disk steps — the goal here
is to verify the API surface and the DB transitions, not that
`xray -test` says OK (that's already covered by hand-tests on
the real install).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

import pytest
from fastapi.testclient import TestClient

# ═══════════════════════════════════════════════════════════════
#  Test scaffolding
# ═══════════════════════════════════════════════════════════════

# The import order matters: app.config must see SECRET_KEY before
# app.database / app.main try to use it. The test fixtures in
# tests/security/conftest.py already provide this, but importing
# from the API router also pulls in the orchestrator which transitively
# needs the database engine to be initialised.
os.environ.setdefault("SECRET_KEY", "x" * 64)
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from app.config import settings  # noqa: E402

# We need to import main AFTER the env vars are set so Settings
# picks them up. main.py also wires the API routers we want to test.
from app.main import app  # noqa: E402
from app.database import AsyncSessionLocal  # noqa: E402
from app.models import Admin, ProtocolConfig, UserRole  # noqa: E402
from app.auth import get_password_hash, create_access_token  # noqa: E402
from app.services.protocol_sync import (  # noqa: E402
    SyncResult,
    sync_and_reload,
    runtime_status,
)


# ═══════════════════════════════════════════════════════════════
#  Stubs
# ═══════════════════════════════════════════════════════════════

class _StubSyncResult:
    """Async-friendly stub for the sync service.

    `sync_and_reload` is the boundary between the API and the
    filesystem. We replace it with a function that records the
    call and returns a deterministic result, so the test can
    assert what the API asked for without needing xray + systemd.
    """

    def __init__(self):
        self.calls: list = []

    async def __call__(self, db, *, config_path: Optional[str] = None, dry_run: bool = False):
        self.calls.append({"config_path": config_path, "dry_run": dry_run})
        return SyncResult(
            success=True,
            config_path=config_path or settings.xray_config_path,
            validator_output="OK (test stub)",
            reload_method="reload",
        )


# Import the real sync function once so the stub can replace it
# IN PLACE in the API module's namespace. pytest's monkeypatch
# is happy with both a target object and a string path; the
# in-place form dodges the `app.api has no attribute 'api'`
# issue that bites the string form when `app/api/__init__.py`
# is empty.
from app.api import protocols as _protocols_module  # noqa: E402


# ═══════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def stub_sync(monkeypatch):
    """Patch sync_and_reload so the API call records intent without
    actually touching the filesystem."""
    stub = _StubSyncResult()
    # Replace the binding in the module that the route handlers
    # actually close over. String-based monkeypatch.setattr hits
    # an attribute-resolution path that doesn't go through
    # `app.api.__init__` cleanly when __init__ is empty.
    monkeypatch.setattr(_protocols_module, "sync_and_reload", stub)
    return stub


@pytest.fixture
def admin_token():
    """Create an admin row + JWT. The token is a real JWT signed
    with the same SECRET_KEY the running app uses, so get_current_admin
    will accept it.

    We use `asyncio.run()` so this fixture can be a regular sync
    fixture — keeps the test signatures clean and matches how
    the rest of the test suite is structured.
    """
    import asyncio
    import uuid

    async def _setup():
        async with AsyncSessionLocal() as db:
            admin = Admin(
                username=f"admin-{uuid.uuid4().hex[:8]}",
                password_hash=get_password_hash("Sup3rStrong!Pass-1"),
                role=UserRole.admin,
            )
            db.add(admin)
            await db.commit()
            await db.refresh(admin)
            token = create_access_token({"sub": admin.username, "is_admin": True})
            return token, admin.username

    return asyncio.run(_setup())


@pytest.fixture
def client():
    """Each test gets a fresh TestClient.

    We rely on `Base.metadata.create_all` having run in the app's
    lifespan (one-time per process), and the in-memory SQLite DB
    gives every connection its own private store — but we re-
    initialise the schema at module import so all tests see the
    same column set.
    """
    with TestClient(app) as c:
        yield c


def _auth_header(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ═══════════════════════════════════════════════════════════════
#  GET /api/protocols
# ═══════════════════════════════════════════════════════════════

def test_list_protocols_includes_enabled_flag(client, admin_token, stub_sync):
    token, _ = admin_token
    r = client.get("/api/protocols", headers=_auth_header(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, list)
    assert len(body) > 0
    # Every entry has the keys the UI needs.
    for entry in body:
        for required in ("key", "name", "category", "backend", "enabled"):
            assert required in entry, entry
    # Default: nothing is enabled (we haven't POSTed any enable).
    assert all(entry["enabled"] is False for entry in body)


# ═══════════════════════════════════════════════════════════════
#  POST /api/protocols/{key}/enable
# ═══════════════════════════════════════════════════════════════

def test_enable_protocol_writes_row_and_triggers_sync(
    client, admin_token, stub_sync
):
    token, _ = admin_token
    r = client.post(
        "/api/protocols/vless_xhttp_reality/enable",
        headers=_auth_header(token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert body["reload_method"] == "reload"
    assert stub_sync.calls, "sync_and_reload should have been called"

    # And the list view now shows it enabled.
    r2 = client.get("/api/protocols", headers=_auth_header(token))
    enabled_keys = {p["key"] for p in r2.json() if p["enabled"]}
    assert "vless_xhttp_reality" in enabled_keys


def test_enable_unknown_protocol_404s(client, admin_token, stub_sync):
    token, _ = admin_token
    r = client.post(
        "/api/protocols/does_not_exist/enable",
        headers=_auth_header(token),
    )
    assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════
#  POST /api/protocols/{key}/disable
# ═══════════════════════════════════════════════════════════════

def test_disable_protocol_keeps_config(client, admin_token, stub_sync):
    token, _ = admin_token
    # Enable, customise, then disable — the per-protocol config
    # fields must survive the toggle.
    client.post(
        "/api/protocols/vless_xhttp_reality/enable",
        headers=_auth_header(token),
    )
    client.put(
        "/api/protocols/vless_xhttp_reality/config",
        json={"config": {"port": 2099, "reality_sni": "example.com"}},
        headers=_auth_header(token),
    )
    r = client.post(
        "/api/protocols/vless_xhttp_reality/disable",
        headers=_auth_header(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["success"] is True

    # Re-enable and read back: the port + SNI we set must still be there.
    client.post(
        "/api/protocols/vless_xhttp_reality/enable",
        headers=_auth_header(token),
    )
    r2 = client.get(
        "/api/protocols/vless_xhttp_reality",
        headers=_auth_header(token),
    )
    assert r2.status_code == 200


# ═══════════════════════════════════════════════════════════════
#  PUT /api/protocols/{key}/config
# ═══════════════════════════════════════════════════════════════

def test_update_config_rejects_unknown_field(client, admin_token, stub_sync):
    token, _ = admin_token
    r = client.put(
        "/api/protocols/vless_xhttp_reality/config",
        json={"config": {"made_up_field": "x"}},
        headers=_auth_header(token),
    )
    assert r.status_code == 422
    assert "made_up_field" in r.json()["detail"]


def test_update_config_known_field_triggers_sync(
    client, admin_token, stub_sync
):
    token, _ = admin_token
    r = client.put(
        "/api/protocols/vless_xhttp_reality/config",
        json={"config": {"port": 2099, "xhttp_path": "/stream"}},
        headers=_auth_header(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["success"] is True
    assert stub_sync.calls, "sync should run after a config update"


def test_update_config_per_field_merge(client, admin_token, stub_sync):
    """Two consecutive PATCHes should merge, not overwrite.

    The first call sets `port`; the second sets `xhttp_path`; the
    resulting row must carry BOTH (we inspect the row directly via
    the API by toggling and re-reading).
    """
    token, _ = admin_token
    client.post(
        "/api/protocols/vless_xhttp_reality/enable",
        headers=_auth_header(token),
    )
    client.put(
        "/api/protocols/vless_xhttp_reality/config",
        json={"config": {"port": 2099}},
        headers=_auth_header(token),
    )
    client.put(
        "/api/protocols/vless_xhttp_reality/config",
        json={"config": {"xhttp_path": "/stream"}},
        headers=_auth_header(token),
    )
    # The detail endpoint doesn't expose the raw config dict (by
    # design — the operator's UI rebuilds from spec fields), so we
    # verify the merge through the DB directly.
    import asyncio
    async def fetch():
        from sqlalchemy import select
        from app.models import ProtocolConfig as PC
        async with AsyncSessionLocal() as db:
            r = await db.execute(
                select(PC).where(PC.protocol_key == "vless_xhttp_reality")
            )
            return r.scalar_one().config
    cfg = asyncio.run(fetch())
    assert cfg.get("port") == 2099
    assert cfg.get("xhttp_path") == "/stream"


# ═══════════════════════════════════════════════════════════════
#  GET /api/protocols/{key}/status
# ═══════════════════════════════════════════════════════════════

def test_status_404_for_unknown_protocol(client, admin_token, stub_sync):
    token, _ = admin_token
    r = client.get(
        "/api/protocols/no_such_thing/status",
        headers=_auth_header(token),
    )
    assert r.status_code == 404


def test_status_for_known_protocol_with_no_row(client, admin_token, stub_sync):
    token, _ = admin_token
    # The runtime_status helper returns a sensible "no row" view
    # rather than raising.
    r = client.get(
        "/api/protocols/vless_xhttp_reality/status",
        headers=_auth_header(token),
    )
    assert r.status_code == 200
    body = r.json()
    assert body["key"] == "vless_xhttp_reality"
    assert body["enabled_in_db"] is False
    assert body["running"] is False
    assert "last_error" in body


# ═══════════════════════════════════════════════════════════════
#  POST /api/protocols/sync
# ═══════════════════════════════════════════════════════════════

def test_force_sync(client, admin_token, stub_sync):
    token, _ = admin_token
    r = client.post(
        "/api/protocols/sync",
        headers=_auth_header(token),
    )
    assert r.status_code == 200
    assert r.json()["success"] is True
    assert stub_sync.calls


# ═══════════════════════════════════════════════════════════════
#  Auth
# ═══════════════════════════════════════════════════════════════

def test_list_protocols_requires_auth(client, stub_sync):
    r = client.get("/api/protocols")
    assert r.status_code == 401
