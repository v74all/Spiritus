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

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.middleware.csrf import CSRFMiddleware


async def _echo(request):
    return JSONResponse({"method": request.method, "path": request.url.path})


def _build():
    app = Starlette(routes=[
        Route("/api/auth/login", _echo, methods=["POST"]),  # exempt
        Route("/api/users", _echo, methods=["GET", "POST"]),
    ])
    app.add_middleware(CSRFMiddleware)
    return TestClient(app)


def test_get_sets_csrf_cookie():
    c = _build()
    r = c.get("/api/users")
    assert r.status_code == 200
    assert "csrf_token" in r.cookies


def test_post_without_token_is_rejected():
    c = _build()
    # Prime the cookie first.
    c.get("/api/users")
    r = c.post("/api/users", json={})
    assert r.status_code == 403


def test_post_with_matching_token_passes():
    c = _build()
    g = c.get("/api/users")
    token = g.cookies["csrf_token"]
    # The cookie is set with Secure=True (because DEBUG is false in this test
    # env), so TestClient on http://testserver won't auto-resend it. Pass it
    # explicitly to verify the matching-cookie-and-header path.
    r = c.post(
        "/api/users",
        json={},
        headers={"X-CSRF-Token": token},
        cookies={"csrf_token": token},
    )
    assert r.status_code == 200


def test_post_with_wrong_token_is_rejected():
    c = _build()
    c.get("/api/users")
    r = c.post("/api/users", json={}, headers={"X-CSRF-Token": "not-the-real-one"})
    assert r.status_code == 403


def test_bearer_request_bypasses_csrf():
    c = _build()
    # No CSRF cookie needed — Authorization header signals API client.
    r = c.post("/api/users", json={}, headers={"Authorization": "Bearer dummy"})
    assert r.status_code == 200


def test_login_endpoint_is_exempt():
    c = _build()
    r = c.post("/api/auth/login", json={"u": "x"})
    assert r.status_code == 200
