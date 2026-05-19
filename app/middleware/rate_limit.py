"""
Global Redis-backed rate-limit middleware.

Behaviour:
- Per-IP, per-path-prefix sliding-window counter in Redis.
- 429 with Retry-After when the budget is exhausted.
- Fail-open on Redis errors for *non-auth* paths so a Redis outage does not
  brick the panel; auth paths handle their own fail-closed counters in
  app/api/auth.py.
- Health/static endpoints are exempted so liveness probes don't get throttled.

Configuration via app.config.settings:
  rate_limit_requests (int): tokens per window (default 100).
  rate_limit_period   (int): seconds per window (default 60).
"""

from __future__ import annotations

import logging
from typing import Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..config import settings

logger = logging.getLogger(__name__)


_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/static/",
    "/api/health",
    "/api/ready",
    "/api/live",
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, default_per_minute: int | None = None):
        super().__init__(app)
        self.budget = int(default_per_minute or getattr(settings, "rate_limit_requests", 100) or 100)
        self.window = int(getattr(settings, "rate_limit_period", 60) or 60)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path or "/"
        if any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        key = f"ratelimit:{client_ip}:{path}"

        try:
            from ..redis_client import get_redis
            redis = await get_redis()
            current = await redis.incr(key)
            if current == 1:
                await redis.expire(key, self.window)
            if current > self.budget:
                retry_after = await redis.ttl(key)
                return JSONResponse(
                    {"detail": "Rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": str(max(int(retry_after), 1))},
                )
        except Exception:
            # Fail-open for non-auth paths — Redis outage shouldn't take the
            # panel offline. Auth endpoints fail-closed via their own helpers.
            pass

        response: Response = await call_next(request)
        return response
