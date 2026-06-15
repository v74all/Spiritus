"""
Domain & Certificate API router.

Endpoints:
- GET    /api/domain                   - Current domain state + cert health
- POST   /api/domain                   - Set / change the active domain
- DELETE /api/domain                   - Clear the domain (revert to IP)
- POST   /api/domain/renew             - Force-renew the cert
- GET    /api/domain/options           - Available ACME clients + DNS hint

The router is intentionally read-then-write at every step so
the UI can show progress: status, then "I'm issuing a cert,
wait…", then success or a structured error with the LE
challenge hint.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import User, get_current_admin_cookie
from ..database import get_async_db
from ..domain_manager import (
    DomainSetResult,
    DomainStatus,
    set_domain,
    disable_domain,
    rotate_cert,
    get_status,
    _have_acme_sh,
    _have_certbot,
    CertHealth,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/domain", tags=["domain"])


# ═══════════════════════════════════════════════════════════════
#  Models
# ═══════════════════════════════════════════════════════════════

class DomainSetRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253, description="FQDN, e.g. panel.example.com")
    contact_email: str = Field("", description="ACME registration email (used by Let's Encrypt)")
    prefer_self_signed: bool = Field(
        False,
        description="If true, skip the LE challenge and generate a self-signed cert. "
                    "Useful when DNS isn't pointed at the panel yet.",
    )


class DomainSetResponse(BaseModel):
    success: bool
    domain: str = ""
    health: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    steps: List[str] = []


class DomainStatusResponse(BaseModel):
    active_domain: str
    enabled: bool
    cert: Dict[str, Any]
    autorenew_days: int
    contact_email: str
    last_check: str
    last_error: str
    server_ip: str
    can_use_letsencrypt: bool


class DomainOptionsResponse(BaseModel):
    can_use_letsencrypt: bool
    has_acme_sh: bool
    has_certbot: bool
    server_ip: str
    recommended_dns_record: str
    port_80_open: bool


class MessageResponse(BaseModel):
    message: str
    success: bool = True


# ═══════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════

def _to_response(result: DomainSetResult) -> DomainSetResponse:
    return DomainSetResponse(
        success=result.success,
        domain=result.domain,
        health=result.health.to_dict() if result.health else None,
        error=result.error,
        steps=result.steps,
    )


def _status_to_response(status: DomainStatus) -> DomainStatusResponse:
    return DomainStatusResponse(
        active_domain=status.active_domain,
        enabled=status.enabled,
        cert=status.cert.to_dict(),
        autorenew_days=status.autorenew_days,
        contact_email=status.contact_email,
        last_check=status.last_check,
        last_error=status.last_error,
        server_ip=status.server_ip,
        can_use_letsencrypt=status.can_use_letsencrypt,
    )


# ═══════════════════════════════════════════════════════════════
#  Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("", response_model=DomainStatusResponse)
async def get_domain_status(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Read the current domain state. Used by the Domain tab in
    the UI to render the active domain, cert health, and
    "Renew now" button."""
    status = await get_status(db)
    return _status_to_response(status)


@router.post("", response_model=DomainSetResponse)
async def set_active_domain(
    payload: DomainSetRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Set (or change) the panel's active domain.

    On success the panel:
      1. Issues / fetches a cert (Let's Encrypt or self-signed).
      2. Persists (domain, cert, key, expires, issuer) atomically.
      3. Re-renders the Xray config so every TLS-bearing
         inbound picks up the new SNI + cert path.
    """
    result = await set_domain(
        db,
        domain=payload.domain,
        contact_email=payload.contact_email,
        prefer_self_signed=payload.prefer_self_signed,
    )
    if not result.success:
        # 422: client error (the operator sent us something we
        # can't accept). The error string includes the LE
        # challenge failure so the UI can surface "DNS A
        # record isn't pointing at this server" without the
        # operator opening the server log.
        raise HTTPException(status_code=422, detail=_to_response(result).dict())
    return _to_response(result)


@router.delete("", response_model=MessageResponse)
async def clear_active_domain(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Disable the domain and fall back to the IP address.

    The Xray sync is triggered as part of disable_domain() so
    every TLS-bearing inbound re-renders with the IP as its
    SNI (and, for protocols that need a domain like Trojan-
    CDN, the inbound itself is dropped from the config).
    """
    result = await disable_domain(db)
    if not result.success:
        raise HTTPException(status_code=500, detail=result.error)
    return MessageResponse(message="Domain cleared; the panel now uses the IP address.")


@router.post("/renew", response_model=DomainSetResponse)
async def force_renew_cert(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Force-renew the cert for the active domain.

    Used by the operator's "Renew now" button, and by the
    Celery autorenew task. The latter calls
    `domain_manager.maybe_autorenew()` which is the smarter
    version that only rotates when inside the autorenew
    window; this endpoint rotates unconditionally.
    """
    result = await rotate_cert(db)
    if not result.success:
        raise HTTPException(status_code=422, detail=_to_response(result).dict())
    return _to_response(result)


@router.get("/options", response_model=DomainOptionsResponse)
async def get_domain_options(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Probe-only: what ACME clients are available, what IP
    the operator should point DNS at, and whether port 80
    (needed for the HTTP-01 challenge) is reachable.

    The UI uses this to render the "Setup domain" wizard:
    "Point your DNS A record at <ip>, then come back and
    type the domain here."
    """
    import socket
    has_acme = _have_acme_sh()
    has_cert = _have_certbot()

    # Check whether port 80 is bound locally. The HTTP-01
    # challenge requires that something on this host can
    # answer a `GET /.well-known/acme-challenge/...`. We
    # assume the panel can — there's no upstream proxy on
    # the standard install. Operators who front the panel
    # with nginx can configure the same webroot path on
    # their existing vhost.
    port_80_open = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            port_80_open = s.connect_ex(("127.0.0.1", 80)) == 0
    except OSError:
        port_80_open = False

    from ..config import settings
    server_ip = settings.vpn_server_ip or ""
    record = f"A  @  {server_ip}  (TTL 300)" if server_ip else ""

    return DomainOptionsResponse(
        can_use_letsencrypt=has_acme or has_cert,
        has_acme_sh=has_acme,
        has_certbot=has_cert,
        server_ip=server_ip,
        recommended_dns_record=record,
        port_80_open=port_80_open,
    )
