"""
CSRF middleware behavioural tests.

We mount the CSRFMiddleware on a stub Starlette app so we don't depend on the
full panel boot. Tests assert:
- Safe methods (GET) issue/preserve the csrf_token cookie.
- Unsafe methods without a matching header → 403.
- Unsafe methods with a matching cookie+header → pass through.
- Bearer-authenticated requests bypass CSRF (per double-submit semantics).
- Path exemptions (e.g. /api/auth/login) bypass CSRF.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.middleware.csrf import CSRFMiddleware

pytestmark = pytest.mark.asyncio


async def _echo(request):
    return JSONResponse({"method": request.method, "path": request.url.path})


def _build():
    app = Starlette(routes=[
        Route("/api/auth/login", _echo, methods=["POST"]),  # exempt
        Route("/api/users", _echo, methods=["GET", "POST"]),
    ])
    app.add_middleware(CSRFMiddleware)
    return app


def _client():
    return AsyncClient(transport=ASGITransport(app=_build()), base_url="https://testserver")


async def test_get_sets_csrf_cookie():
    async with _client() as c:
        r = await c.get("/api/users")
        assert r.status_code == 200
        assert "csrf_token" in r.cookies


async def test_post_without_token_is_rejected():
    async with _client() as c:
        await c.get("/api/users")
        r = await c.post("/api/users", json={})
        assert r.status_code == 403


async def test_post_with_matching_token_passes():
    async with _client() as c:
        g = await c.get("/api/users")
        token = g.cookies["csrf_token"]
        r = await c.post("/api/users", json={}, headers={"X-CSRF-Token": token})
        assert r.status_code == 200


async def test_post_with_wrong_token_is_rejected():
    async with _client() as c:
        await c.get("/api/users")
        r = await c.post("/api/users", json={}, headers={"X-CSRF-Token": "not-the-real-one"})
        assert r.status_code == 403


async def test_bearer_request_bypasses_csrf():
    async with _client() as c:
        r = await c.post("/api/users", json={}, headers={"Authorization": "Bearer dummy"})
        assert r.status_code == 200


async def test_login_endpoint_is_exempt():
    async with _client() as c:
        r = await c.post("/api/auth/login", json={"u": "x"})
        assert r.status_code == 200
