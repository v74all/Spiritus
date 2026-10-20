"""Restrict the admin API surface to configured IPs/CIDRs.

Enabled only when ``ADMIN_IP_ALLOWLIST`` is set. Endpoints that must stay
reachable by end users, agents or payment providers are exempt.
"""

from __future__ import annotations

import ipaddress
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from ..config import settings

logger = logging.getLogger(__name__)

_PUBLIC_PREFIXES: tuple[str, ...] = (
    "/api/health",
    "/api/ready",
    "/api/live",
    "/api/portal/",
    "/api/payments/callback/",
    "/api/payments/webhook",
    "/api/telegram/webhook",
    "/api/agent/",
    "/api/direction",
    # In-country probes report from Iranian networks; they carry their own token.
    "/api/probe/",
)

_LOOPBACK = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))


def parse_networks(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [ipaddress.ip_network(p.strip(), strict=False) for p in (raw or "").split(",") if p.strip()]


def is_allowed(ip: str, networks) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in (*networks, *_LOOPBACK))


class AdminIPAllowlistMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, allowlist: str | None = None, public_prefixes: str | None = None):
        super().__init__(app)
        self.networks = parse_networks(settings.admin_ip_allowlist if allowlist is None else allowlist)
        extra = settings.admin_ip_allowlist_public_prefixes if public_prefixes is None else public_prefixes
        self.public = _PUBLIC_PREFIXES + tuple(p.strip() for p in extra.split(",") if p.strip())

    async def dispatch(self, request: Request, call_next):
        path = request.url.path or "/"
        if path.startswith("/api/") and not any(path.startswith(p) for p in self.public):
            ip = request.client.host if request.client else ""
            if not is_allowed(ip, self.networks):
                logger.warning("admin_ip_allowlist.reject ip=%s path=%s", ip, path)
                return JSONResponse({"detail": "Forbidden"}, status_code=403)
        return await call_next(request)
