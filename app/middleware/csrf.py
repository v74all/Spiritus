"""
Double-submit-cookie CSRF middleware.

How it works:
- On every safe request (GET/HEAD/OPTIONS) the middleware ensures a
  high-entropy `csrf_token` cookie is set (HttpOnly=False, SameSite=Strict,
  Secure unless DEBUG). The cookie value is independent of the session — its
  only job is being readable by same-origin JS so the JS can echo it back.
- On every unsafe request (POST/PUT/PATCH/DELETE) the middleware requires the
  cookie value to match the `X-CSRF-Token` header. If they disagree, the
  request is rejected with 403.

Exemptions:
- Token-based auth (Authorization: Bearer …) bypasses the check because the
  attacker cannot read the token from a cross-origin context.
- The static subscription URLs `/sub/…`, `/sub-api/…`, `/sub-json/…` are
  GET-only and exempt by virtue of method.
- The dedicated login endpoint is exempt because no session exists yet — the
  rate-limiter + fail2ban guard that path.
- Public webhooks (e.g. payment callbacks) listed in _WEBHOOK_PREFIXES are
  exempt; they have their own signature checks.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from typing import Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..config import settings

logger = logging.getLogger(__name__)


SAFE_METHODS: tuple[str, ...] = ("GET", "HEAD", "OPTIONS", "TRACE")
COOKIE_NAME = "csrf_token"
HEADER_NAME = "X-CSRF-Token"


def is_secure_request(request: Request) -> bool:
    """Decide whether the *original* client request reached us over HTTPS.

    Browsers silently drop cookies with the Secure flag when they're set over
    plain HTTP. We need to mirror the actual transport so panels reachable
    over HTTP (direct, no reverse proxy) still receive their CSRF / session
    cookies. When a reverse proxy terminates TLS upstream the `X-Forwarded-
    Proto: https` header — honoured by uvicorn's --proxy-headers — flips
    `request.url.scheme` to "https" for us.
    """
    if request.url.scheme == "https":
        return True
    xfp = (request.headers.get("X-Forwarded-Proto") or "").lower()
    return xfp == "https"

_EXEMPT_PATH_PREFIXES: tuple[str, ...] = (
    "/api/auth/login",            # establishes the first session
    "/api/auth/login/2fa",
    "/api/login",                 # legacy compat login
    "/api/agent/login",           # agent login
    "/api/payments/callback/",    # signed webhooks
    "/api/payments/webhook",
    "/sub/", "/sub-api/", "/sub-json/",
)


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        method = request.method.upper()
        path = request.url.path or "/"

        # Always run the handler first when the request is safe.
        if method in SAFE_METHODS:
            response: Response = await call_next(request)
            self._ensure_cookie(request, response)
            return response

        # Path-based exemptions for unsafe methods.
        if any(path.startswith(p) for p in _EXEMPT_PATH_PREFIXES):
            response = await call_next(request)
            self._ensure_cookie(request, response)
            return response

        # Bearer token? Skip CSRF — JS in attacker.com cannot read the token.
        auth_header = request.headers.get("authorization") or ""
        if auth_header.lower().startswith("bearer "):
            return await call_next(request)

        cookie_val = request.cookies.get(COOKIE_NAME)
        header_val = request.headers.get(HEADER_NAME)

        if not cookie_val or not header_val or not hmac.compare_digest(cookie_val, header_val):
            logger.warning("csrf.reject method=%s path=%s ip=%s", method, path,
                           request.client.host if request.client else "?")
            return JSONResponse({"detail": "CSRF token missing or invalid"}, status_code=403)

        response = await call_next(request)
        self._ensure_cookie(request, response)
        return response

    @staticmethod
    def _ensure_cookie(request: Request, response: Response) -> None:
        if request.cookies.get(COOKIE_NAME):
            return
        token = secrets.token_urlsafe(32)
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            # Must be readable from JS to echo into the header — therefore NOT
            # HttpOnly. The cookie is not a session credential by itself; even
            # if leaked, the attacker still needs same-origin JS to use it.
            httponly=False,
            # Only emit Secure when the request actually came in over HTTPS.
            # Otherwise (e.g. http://server-ip:38471 direct access) the browser
            # drops the cookie and every POST fails CSRF.
            secure=is_secure_request(request),
            samesite="strict",
            max_age=60 * 60 * 24,  # 24h rotation
            path="/",
        )
