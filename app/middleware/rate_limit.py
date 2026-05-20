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

# Per-prefix overrides. The default budget is generous (100/min) because the
# admin UI polls a few endpoints every couple seconds. Subscription URLs are
# anonymous and abuse-prone, so they get a much tighter budget — 60 hits/min
# per IP is still comfortable for a real user reloading a client config but
# stops a leaked URL from being scraped indefinitely.
_PREFIX_BUDGETS: tuple[tuple[str, int, int], ...] = (
    # (path_prefix, max_requests, window_seconds)
    ("/sub/",        60, 60),
    ("/sub-api/",    60, 60),
    ("/sub-json/",   60, 60),
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, default_per_minute: int | None = None):
        super().__init__(app)
        self.budget = int(default_per_minute or getattr(settings, "rate_limit_requests", 100) or 100)
        self.window = int(getattr(settings, "rate_limit_period", 60) or 60)

    def _budget_for(self, path: str) -> tuple[int, int]:
        for prefix, budget, window in _PREFIX_BUDGETS:
            if path.startswith(prefix):
                return budget, window
        return self.budget, self.window

    async def dispatch(self, request: Request, call_next):
        path = request.url.path or "/"
        if any(path.startswith(p) for p in _EXEMPT_PREFIXES):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        budget, window = self._budget_for(path)
        # For /sub/* paths key on the prefix + the UUID segment, so each
        # subscription gets its own bucket and one popular link doesn't
        # rate-limit unrelated users sharing the same outbound IP (CGNAT).
        if any(path.startswith(p) for p, _, _ in _PREFIX_BUDGETS):
            parts = path.strip("/").split("/", 2)
            sub_key = parts[1] if len(parts) > 1 else ""
            key = f"ratelimit:sub:{client_ip}:{sub_key}"
        else:
            key = f"ratelimit:{client_ip}:{path}"

        try:
            from ..redis_client import get_redis
            redis = await get_redis()
            current = await redis.incr(key)
            if current == 1:
                await redis.expire(key, window)
            if current > budget:
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
