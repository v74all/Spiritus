from __future__ import annotations

import asyncio
import secrets as secrets_module

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

import app.privileged_helper_daemon as helper_daemon
import app.redis_client as redis_client_module
import app.security as security_module
from app.config import settings
from app.main import app, readiness_check
from app.models import Base, Payment, PaymentGateway, PaymentStatus
from app.payments import PaymentManager
from app.privileged_helper_daemon import _dispatch
from app.security import WebAuthnManager
from app.services import protocol_sync


class _ChallengeRedis:
    def __init__(self):
        self.values: dict[str, str] = {}

    async def setex(self, key, _ttl, value):
        self.values[key] = value

    async def eval(self, _script, _count, key, *args):
        if args:
            expected = args[0]
            if self.values.get(key) == expected:
                self.values.pop(key, None)
                return 1
            return 0
        return self.values.pop(key, None)

    async def set(self, key, value, *, ex, nx):
        del ex
        if nx and key in self.values:
            return None
        self.values[key] = value
        return True


def _request(auth: str = "") -> Request:
    headers = [(b"authorization", auth.encode())] if auth else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers})


def test_helper_rejects_non_allowlisted_operations(monkeypatch):
    called = False

    def _unexpected(*_args, **_kwargs):
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(helper_daemon, "_run", _unexpected)
    assert _dispatch("shell", {"command": "id"})["ok"] is False
    assert _dispatch("service.restart", {"service": "postgresql"})["ok"] is False
    assert _dispatch("config.install", {"target": "../../etc/passwd", "content": "{}"})["ok"] is False
    assert called is False


@pytest.mark.asyncio
async def test_metrics_requires_exact_bearer(monkeypatch):
    from app.api.system import get_metrics

    token = "metrics-token-" + "x" * 32
    monkeypatch.setattr(settings, "metrics_bearer_token", token)
    with pytest.raises(HTTPException) as denied:
        await get_metrics(_request("Bearer wrong"))
    assert denied.value.status_code == 401

    response = await get_metrics(_request(f"Bearer {token}"))
    assert response.status_code == 200
    assert b"# TYPE vpn_panel_cpu_percent gauge" in response.body


@pytest.mark.asyncio
async def test_webauthn_challenge_is_one_time(monkeypatch):
    redis = _ChallengeRedis()
    monkeypatch.setattr(security_module, "get_redis", lambda: asyncio.sleep(0, result=redis))
    monkeypatch.setattr(settings, "webauthn_rp_id", "panel.example.com")
    monkeypatch.setattr(settings, "webauthn_origins", "https://panel.example.com")

    manager = WebAuthnManager()
    options = await manager.generate_registration_options("admin", [])
    assert options["publicKey"]["rp"]["id"] == "panel.example.com"

    with pytest.raises(ValueError, match="registration verification failed"):
        await manager.verify_registration("admin", "e30", "e30", "YQ")
    with pytest.raises(ValueError, match="already used"):
        await manager.verify_registration("admin", "e30", "e30", "YQ")


def test_placeholder_webauthn_credentials_are_invalid():
    valid = WebAuthnManager._valid_credentials(
        [
            {"id": "old", "public_key": "placeholder"},
            {"id": "new", "public_key": "cHVi", "version": 1},
        ]
    )
    assert [item["id"] for item in valid] == ["new"]


@pytest.mark.asyncio
async def test_protocol_sync_distributed_lock_rejects_overlap(monkeypatch):
    redis = _ChallengeRedis()
    monkeypatch.setattr(protocol_sync, "get_redis", lambda: asyncio.sleep(0, result=redis))

    async with protocol_sync._distributed_sync_lock():
        with pytest.raises(RuntimeError, match="already running"):
            async with protocol_sync._distributed_sync_lock():
                pass
    assert "lock:protocol-sync" not in redis.values


class _USDTGateway:
    async def check_payment(self, **_kwargs):
        return {"success": True, "tx_hash": "a" * 64}


@pytest.mark.asyncio
async def test_usdt_transaction_cannot_be_replayed():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    manager = PaymentManager()
    manager._gateways["usdt_trc20"] = _USDTGateway()
    async with sessions() as db:
        first = Payment(
            gateway=PaymentGateway.usdt_trc20,
            status=PaymentStatus.pending,
            amount=100,
            currency="USDT",
            usdt_expected_amount_micro=1_000_101,
            plan_traffic_gb=0,
            plan_days=0,
        )
        second = Payment(
            gateway=PaymentGateway.usdt_trc20,
            status=PaymentStatus.pending,
            amount=100,
            currency="USDT",
            usdt_expected_amount_micro=1_000_102,
            plan_traffic_gb=0,
            plan_days=0,
        )
        db.add_all([first, second])
        await db.commit()
        assert (await manager.verify_payment(db, first.id, "usdt_trc20"))["success"] is True
        replay = await manager.verify_payment(db, second.id, "usdt_trc20")
        assert replay == {"success": False, "error": "Transaction already claimed"}
    await engine.dispose()


def test_mobile_contract_paths_are_registered():
    # Read from the generated OpenAPI schema rather than walking app.routes:
    # FastAPI wraps included routers in opaque _IncludedRouter objects, so a
    # flat route scan misses prefixed paths. The schema is prefix-resolved.
    paths = set(app.openapi().get("paths", {}).keys())
    assert "/api/mobile/auth/login" in paths
    assert "/api/mobile/auth/2fa" in paths
    assert "/api/mobile/session" in paths
    assert "/api/mobile/auth/logout" in paths


@pytest.mark.asyncio
async def test_legacy_login_cannot_skip_totp():
    """Regression test for a 2FA bypass in the legacy /api/login endpoint.

    Before the fix, POST /api/login only checked the password, so a stolen
    or brute-forced password fully authenticated an admin who had TOTP
    enabled — the second factor was never consulted. It must now: (1) refuse
    to mint a session on password-only requests and signal totp_required,
    (2) reject a wrong code, (3) only succeed with the correct code.
    """
    import pyotp

    from app.auth import get_password_hash
    from app.database import AsyncSessionLocal, init_db
    from app.models import Admin, UserRole

    # Ensure schema exists: this test may run standalone (without another
    # test having gone through the app's lifespan/TestClient startup first).
    # The async sqlite ":memory:" engine defaults to StaticPool (one shared
    # connection), so create_all here is visible to every session after it.
    await init_db()

    password = "Sup3rStrong!Pass-1"
    secret = pyotp.random_base32()
    username = f"totp-admin-{secrets_module.token_hex(4)}"

    async with AsyncSessionLocal() as db:
        db.add(
            Admin(
                username=username,
                password_hash=get_password_hash(password),
                role=UserRole.admin,
                totp_enabled=True,
                totp_secret=secret,
            )
        )
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://testserver") as client:
        # Password alone must NOT issue a session cookie.
        r1 = await client.post("/api/login", json={"username": username, "password": password})
        assert r1.json().get("ok") is False
        assert r1.json().get("totp_required") is True
        assert "access_token" not in client.cookies

        # Wrong code must not authenticate either.
        r2 = await client.post(
            "/api/login",
            json={"username": username, "password": password, "totp_code": "000000"},
        )
        assert r2.json().get("ok") is False
        assert "access_token" not in client.cookies

        # Correct code succeeds.
        code = pyotp.TOTP(secret).now()
        r3 = await client.post(
            "/api/login",
            json={"username": username, "password": password, "totp_code": code},
        )
        assert r3.json().get("ok") is True
        assert "access_token" in client.cookies


@pytest.mark.asyncio
async def test_password_change_invalidates_other_sessions():
    """A password change must kill tokens issued before it.

    Without this, a stolen/leaked token keeps authenticating until its
    natural expiry even after the operator "changed the password" to lock
    the attacker out — the change had no effect on sessions already handed
    out. The admin's own current session must keep working (a fresh cookie
    is reissued by the endpoint).
    """
    from app.auth import get_password_hash
    from app.database import AsyncSessionLocal, init_db
    from app.models import Admin, UserRole

    await init_db()

    old_password = "Sup3rStrong!Pass-1"
    new_password = "EvenStr0nger!Pass-2"
    username = f"pwchange-admin-{secrets_module.token_hex(4)}"

    async with AsyncSessionLocal() as db:
        db.add(
            Admin(
                username=username,
                password_hash=get_password_hash(old_password),
                role=UserRole.admin,
            )
        )
        await db.commit()

    # Two independent clients: `browser` carries the admin's real cookie
    # session; `attacker` carries ONLY the raw stolen JWT as a Bearer header
    # and no cookie jar — otherwise httpx would (correctly, per the app's
    # cookie-takes-precedence-over-header logic) authenticate the attacker's
    # requests using the browser's cookie instead of the token we're testing.
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://testserver") as browser, \
            AsyncClient(transport=ASGITransport(app=app), base_url="https://testserver") as attacker:
        login = await browser.post("/api/login", json={"username": username, "password": old_password})
        assert login.json().get("ok") is True
        stolen_token = login.json()["access_token"]
        attacker_headers = {"Authorization": f"Bearer {stolen_token}"}

        # The "attacker" holds `stolen_token` and can still use it right now
        # — proves the token was valid pre-change.
        pre_change = await attacker.get("/api/users", headers=attacker_headers)
        assert pre_change.status_code == 200

        # JWT `iat` and the invalidation marker are both second-granularity;
        # cross a whole second boundary so "issued before the change" is
        # unambiguous rather than a same-second coin flip.
        await asyncio.sleep(1.1)

        # A GET first, to mint the double-submit CSRF cookie for the POST.
        await browser.get("/api/users")
        csrf_token = browser.cookies.get("csrf_token")
        change = await browser.post(
            "/api/change-password",
            json={"current": old_password, "new": new_password},
            headers={"X-CSRF-Token": csrf_token},
        )
        assert change.json().get("ok") is True

        # The stolen token must now be dead, even though it hasn't expired.
        post_change = await attacker.get("/api/users", headers=attacker_headers)
        assert post_change.status_code == 401

        # The admin's own browser session (reissued cookie) must still work.
        still_logged_in = await browser.get("/api/users")
        assert still_logged_in.status_code == 200


@pytest.mark.asyncio
async def test_script_csp_is_nonce_only():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://testserver") as client:
        response = await client.get("/api/live")
    csp = response.headers["content-security-policy"]
    assert "script-src 'self' 'nonce-" in csp
    assert "style-src 'self' 'nonce-" in csp
    assert "unsafe-inline" not in csp
    assert "script-src-attr 'none'" in csp
    assert "style-src-attr 'none'" in csp


@pytest.mark.asyncio
async def test_readiness_reports_failed_dependencies(monkeypatch):
    class _BrokenDb:
        async def execute(self, _query):
            raise RuntimeError("db unavailable")

    async def _broken_redis():
        raise RuntimeError("redis unavailable")

    monkeypatch.setattr(redis_client_module, "get_redis", _broken_redis)
    response = await readiness_check(db=_BrokenDb())
    assert response.status_code == 503
    assert b"database" in response.body
    assert b"redis" in response.body
