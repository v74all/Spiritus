"""
DPI Evasion API router for V7LTHRONYX VPN Panel.

Endpoints:
- GET  /dpi/status          — Overall DPI evasion status
- GET  /dpi/sni/pool         — SNI pool status
- POST /dpi/sni/validate     — Validate an SNI
- POST /dpi/sni/scan-asn     — Scan ASN for valid SNIs
- POST /dpi/sni/mark-blocked — Mark an SNI as blocked
- GET  /dpi/sni/best         — Get current best SNI
- GET  /dpi/keys             — REALITY key status
- POST /dpi/keys/rotate      — Rotate REALITY keys
- GET  /dpi/probes           — Active probing stats
- GET  /dpi/flow-rates       — Per-user flow rates
- GET  /dpi/ip-reputation    — Server IP reputation
- POST /dpi/config/generate  — Generate DPI-safe Xray config
- GET  /dpi/threat-model     — Iran DPI threat model info
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import logging

from ..auth import get_current_admin, User
from ..dpi_evasion import (
    sni_manager,
    reality_key_manager,
    active_probing_defense,
    flow_rate_limiter,
    ip_reputation_monitor,
    dpi_safe_generator,
    IranDPIThreat,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/dpi", tags=["dpi-evasion"])


# ── Models ──────────────────────────────────────────────

class SNIValidateRequest(BaseModel):
    domain: str = Field(..., min_length=1)

class SNIMarkBlockedRequest(BaseModel):
    domain: str = Field(..., min_length=1)

class SNIScanASNRequest(BaseModel):
    asn: str = Field("AS24940", description="ASN to scan (default: Hetzner)")

class KeyRotateRequest(BaseModel):
    agent_id: int = Field(..., ge=1)

class DPIConfigGenerateRequest(BaseModel):
    user_uuid: str = Field(..., min_length=1)
    short_id: str = Field("", description="Auto-generated if empty")
    sni: str = Field("", description="Auto-selected if empty")
    protocol: str = Field("vless_xhttp_reality", description="Protocol type for SNI selection")
    xhttp_path: str = Field("/api/v2/stream")
    xhttp_mode: str = Field("auto")
    port: int = Field(443)
    server_address: str = Field("")

class MessageResponse(BaseModel):
    message: str
    success: bool = True


# ── Endpoints ────────────────────────────────────────────

@router.get("/status")
async def get_dpi_status(admin: User = Depends(get_current_admin)):
    """Get overall DPI evasion status."""
    return {
        "threat_model": {
            "burned_snis": len(IranDPIThreat.BURNED_SNIS),
            "udp_protocols_blocked": list(IranDPIThreat.UDP_PROTOCOLS),
            "max_sustained_mbps": IranDPIThreat.MAX_SUSTAINED_MBPS,
        },
        "sni": {
            "pool_size": len(await sni_manager.get_sni_pool_status()),
            "current_sni": sni_manager._current_sni,
            "server_asn": sni_manager._server_asn,
        },
        "probing": active_probing_defense.get_probe_stats(),
        "flow_rates": {
            "monitored_users": len(flow_rate_limiter._flow_history),
            "throttled_users": sum(
                1 for s in flow_rate_limiter._user_state.values() if s.get("throttled")
            ),
        },
        "ip_reputation": ip_reputation_monitor.get_reputation(),
        "reality_keys": {
            "active_keys": len(reality_key_manager.get_active_keys()),
        },
    }


@router.get("/threat-model")
async def get_threat_model(admin: User = Depends(get_current_admin)):
    """Get Iran DPI threat model details."""
    return {
        "country": "Iran",
        "year": 2026,
        "capabilities": [
            {
                "name": "Stateful TLS Fingerprinting (JA3/JA4)",
                "countermeasure": "uTLS chrome fingerprint",
                "status": "defeated",
            },
            {
                "name": "ServerHello Drop (MCI/TCI)",
                "countermeasure": "SNI whitelist + rotation",
                "status": "defeated",
            },
            {
                "name": "Reverse-DNS Check (SNI vs ASN)",
                "countermeasure": "Same-ASN SNI selection",
                "status": "defeated",
            },
            {
                "name": "Active Probing",
                "countermeasure": "HTTP fallback server",
                "status": "defeated",
            },
            {
                "name": "IP Reputation Graylist",
                "countermeasure": "Clean IP monitoring (Hetzner Helsinki)",
                "status": "monitored",
            },
            {
                "name": "UDP Throttling",
                "countermeasure": "TCP/443 only, no UDP protocols",
                "status": "defeated",
            },
            {
                "name": "Long-Flow Detection",
                "countermeasure": "Flow rate limiting (10 Mbps sustained)",
                "status": "defeated",
            },
        ],
        "burned_snis": list(IranDPIThreat.BURNED_SNIS),
        "safe_snis": IranDPIThreat.get_safe_snis(),
        "udp_protocols_avoided": list(IranDPIThreat.UDP_PROTOCOLS),
        "required_stack": {
            "protocol": "VLESS",
            "transport": "XHTTP",
            "security": "REALITY",
            "flow": "xtls-rprx-vision",
            "port": 443,
            "fingerprint": "chrome",
        },
    }


@router.get("/sni/pool")
async def get_sni_pool(admin: User = Depends(get_current_admin)):
    """Get SNI pool status with all candidates."""
    return {
        "pool": await sni_manager.get_sni_pool_status(),
        "current_sni": sni_manager._current_sni,
        "server_asn": sni_manager._server_asn,
    }


@router.get("/sni/best")
async def get_best_sni(admin: User = Depends(get_current_admin)):
    """Get the current best SNI for DPI evasion."""
    sni = await sni_manager.get_best_sni()
    entry = sni_manager._sni_pool.get(sni, {})
    return {
        "sni": sni,
        "tier": getattr(entry, "tier", None),
        "tls13": getattr(entry, "tls13_supported", None),
        "h2": getattr(entry, "h2_supported", None),
        "asn_match": getattr(entry, "asn_match", None),
    }


@router.post("/sni/validate")
async def validate_sni(
    req: SNIValidateRequest,
    admin: User = Depends(get_current_admin),
):
    """Validate an SNI for TLS 1.3 and HTTP/2 support."""
    if IranDPIThreat.is_burned_sni(req.domain):
        return {
            "domain": req.domain,
            "valid": False,
            "reason": "SNI is in burned/known-blocked list",
        }
    result = await sni_manager.validate_sni(req.domain)
    return {"valid": result["tls13"] and result["reachable"], **result}


@router.post("/sni/scan-asn")
async def scan_asn_for_snis(
    req: SNIScanASNRequest = SNIScanASNRequest(),
    admin: User = Depends(get_current_admin),
):
    """Scan an ASN for valid TLS 1.3 + H2 domains."""
    results = await sni_manager.scan_asn_for_snis(req.asn)
    return {
        "asn": req.asn,
        "valid_snis": results,
        "count": len(results),
    }


@router.post("/sni/mark-blocked")
async def mark_sni_blocked(
    req: SNIMarkBlockedRequest,
    admin: User = Depends(get_current_admin),
):
    """Mark an SNI as blocked by DPI."""
    await sni_manager.mark_sni_blocked(req.domain)
    return MessageResponse(message=f"SNI '{req.domain}' marked as blocked")


@router.get("/keys")
async def get_reality_keys(admin: User = Depends(get_current_admin)):
    """Get REALITY key status."""
    active = reality_key_manager.get_active_keys()
    return {
        "active_keys": len(active),
        "keys": [
            {
                "key_id": k["key_id"],
                "agent_id": k["agent_id"],
                "public_key": k["public_key"],
                "created_at": k["created_at"],
                "expires_at": k["expires_at"],
            }
            for k in active
        ],
    }


@router.post("/keys/rotate")
async def rotate_reality_keys(
    req: KeyRotateRequest,
    admin: User = Depends(get_current_admin),
):
    """Rotate REALITY keys for an agent."""
    result = await reality_key_manager.rotate_keys(req.agent_id)
    return {
        "key_id": result["key_id"],
        "public_key": result["public_key"],
        "created_at": result["created_at"],
        "expires_at": result["expires_at"],
        "message": "Keys rotated successfully. Update client configs with new public key.",
    }


@router.get("/probes")
async def get_probe_stats(admin: User = Depends(get_current_admin)):
    """Get active probing detection statistics."""
    return active_probing_defense.get_probe_stats()


@router.get("/flow-rates")
async def get_flow_rates(admin: User = Depends(get_current_admin)):
    """Get per-user flow rates for long-flow detection monitoring."""
    return {
        "max_sustained_mbps": flow_rate_limiter.MAX_SUSTAINED_MBPS,
        "max_burst_mbps": flow_rate_limiter.MAX_BURST_MBPS,
        "users": flow_rate_limiter.get_all_rates(),
    }


@router.get("/ip-reputation")
async def get_ip_reputation(admin: User = Depends(get_current_admin)):
    """Get server IP reputation status."""
    cached = ip_reputation_monitor.get_reputation()
    if not cached:
        result = await ip_reputation_monitor.check_ip_reputation()
        return result
    return cached


@router.post("/ip-reputation/check")
async def check_ip_reputation(admin: User = Depends(get_current_admin)):
    """Force a fresh IP reputation check."""
    result = await ip_reputation_monitor.check_ip_reputation()
    return result


@router.post("/config/generate")
async def generate_dpi_safe_config(
    req: DPIConfigGenerateRequest,
    admin: User = Depends(get_current_admin),
):
    """Generate a DPI-safe Xray configuration for a user."""
    # Auto-generate short_id if not provided
    if not req.short_id:
        req.short_id = reality_key_manager.generate_short_id()

    # Auto-select SNI if not provided, based on protocol type
    if not req.sni:
        protocol_type = ""
        if req.protocol == "vless_xhttp_reality":
            protocol_type = "xhttp"
        elif req.protocol == "vless_vision_reality":
            protocol_type = "vision"
        elif req.protocol == "vless_reverse_reality":
            protocol_type = "reverse"
        req.sni = await sni_manager.get_best_sni(protocol_type)

    # Generate key pair for the config
    keys = await reality_key_manager.generate_key_pair()

    # Generate full server config
    server_config = dpi_safe_generator.generate_full_dpi_safe_config(
        user_uuid=req.user_uuid,
        short_id=req.short_id,
        reality_private_key=keys["private_key"],
        reality_public_key=keys["public_key"],
        sni=req.sni,
        xhttp_path=req.xhttp_path,
        server_address=req.server_address,
    )

    # Generate client config (share URLs)
    client_config = dpi_safe_generator.generate_client_config(
        user_uuid=req.user_uuid,
        short_id=req.short_id,
        reality_public_key=keys["public_key"],
        server_address=req.server_address,
        sni=req.sni,
        xhttp_path=req.xhttp_path,
        xhttp_mode=req.xhttp_mode,
        port=req.port,
    )

    # Determine which URL to return based on protocol
    share_url = client_config.get("xhttp_url", "")
    if req.protocol == "vless_vision_reality":
        share_url = client_config.get("vision_url", "")
    elif req.protocol == "vless_reverse_reality":
        # For reverse, we might want to generate a specific URL
        share_url = client_config.get("vision_url", "").replace("xtls-rprx-vision", "xtls-rprx-vision")

    return {
        "success": True,
        "protocol": req.protocol,
        "server_config": server_config,
        "client_config": client_config,
        "sni": req.sni,
        "short_id": req.short_id,
        "fingerprint": "chrome",
        "port": req.port,
        "share_url": share_url,
        "warnings": [
            "Do NOT use UDP-based protocols (Hysteria2, TUIC, WireGuard) under Iran DPI",
            f"Keep sustained flow rate under {flow_rate_limiter.MAX_SUSTAINED_MBPS} Mbps",
            f"SNI '{req.sni}' must match server ASN for reverse-DNS check",
        ],
    }


@router.get("/fallback-preview")
async def preview_fallback_page(admin: User = Depends(get_current_admin)):
    """Preview the HTTP fallback page served to active probers."""
    response = active_probing_defense.generate_fallback_response()
    return {
        "status_code": response["status_code"],
        "content_type": response["content_type"],
        "headers": response["headers"],
        "html_length": len(response["body"]),
        "html_preview": response["body"][:500] + "..." if len(response["body"]) > 500 else response["body"],
    }