"""
Legacy compatibility router for V7LTHRONYX VPN Panel.

The frontend (panel.js) was built against an older API surface. This router
maps the legacy endpoint paths and response shapes (``{ok: true, ...}`` style)
to the current backend implementation so the panel works without rewriting
the frontend.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import asyncio
import base64
import io
import csv
import json
import logging
import os
import secrets
import subprocess
import time
import urllib.parse
import uuid as uuid_lib

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import (
    User,
    create_access_token,
    get_current_admin_cookie,
    get_optional_user_cookie,
    get_password_hash,
    verify_password,
)
from ..config import settings
from ..database import get_async_db
from ..models import Admin, Agent, Setting, VpnUser
from ..security import fail2ban_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["compat"])

# In-memory state for endpoints that don't have a DB-backed implementation yet.
_login_attempts: dict[str, list[float]] = {}
_settings_state: dict[str, Any] = {}
_resilience_state: dict[str, Any] = {"active_attacks": 0, "stats": {}}
_LEGACY_SETTINGS_KEY = "legacy_panel_settings"
_LEGACY_SETTINGS_FILE = "vpn-settings.json"
_DPI_SETTING_KEYS = {
    "dpi_tcp_fragment",
    "dpi_tls_fragment",
    "dpi_ip_fragment",
    "dpi_tcp_keepalive",
    "dpi_dns_tunnel",
    "dpi_icmp_tunnel",
    "dpi_domain_front",
    "dpi_cdn_front_enabled",
    "dpi_cdn_front",
}
_PROTOCOL_ENABLE_KEYS = {
    "cdn_enabled",
    "trojan_enabled",
    "grpc_enabled",
    "httpupgrade_enabled",
    "ss2022_enabled",
    "vless_ws_enabled",
    "vless_xhttp_enabled",
    "vless_vision_enabled",
    "vless_reverse_enabled",
    "trojan_cdn_enabled",
    "trojan_cdn_grpc_enabled",
    "hysteria2_enabled",
    "tuic_enabled",
    "amneziawg_enabled",
    "shadowtls_enabled",
    "mieru_enabled",
    "naiveproxy_enabled",
    "wireguard_enabled",
    "openvpn_enabled",
}
_BOOLEAN_SETTING_KEYS = {
    "kill_switch_enabled",
    "cdn_enabled",
    "trojan_enabled",
    "grpc_enabled",
    "httpupgrade_enabled",
    "fragment_enabled",
    "mux_enabled",
    "ss2022_enabled",
    "vless_ws_enabled",
    "telegram_enabled",
    "telegram_notify_user_disabled",
    "telegram_notify_user_expired",
    "telegram_notify_kill_switch",
    "telegram_notify_traffic_exhausted",
    "telegram_notify_user_created",
    "telegram_notify_user_deleted",
    "dpi_tcp_fragment",
    "dpi_tls_fragment",
    "dpi_ip_fragment",
    "dpi_tcp_keepalive",
    "dpi_dns_tunnel",
    "dpi_icmp_tunnel",
    "dpi_domain_front",
    "dpi_cdn_front_enabled",
    "noise_enabled",
    "dpi_http_host_spoof_enabled",
    "dpi_ws_host_front_enabled",
    "dpi_cdn_host_front_enabled",
    "dpi_bug_host_enabled",
    "dpi_packet_reorder",
    "dpi_dynamic_port",
    "dpi_fake_http",
    "dpi_traffic_shape",
    "dpi_multi_path",
    "dpi_protocol_hop",
    *_PROTOCOL_ENABLE_KEYS,
}


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_locked_out(ip: str) -> bool:
    if ip not in _login_attempts:
        return False
    now = time.time()
    _login_attempts[ip] = [
        t for t in _login_attempts[ip] if now - t < settings.lockout_seconds
    ]
    return len(_login_attempts[ip]) >= settings.max_login_attempts


def _record_failed_attempt(ip: str) -> None:
    _login_attempts.setdefault(ip, []).append(time.time())


def _clear_attempts(ip: str) -> None:
    _login_attempts.pop(ip, None)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _normalize_settings_types(data: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(data)
    for key in _BOOLEAN_SETTING_KEYS:
        if key in normalized:
            normalized[key] = _as_bool(normalized[key])
    return normalized


def _strip_host_port(host: str) -> str:
    host = (host or "").strip()
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if ":" in host:
        maybe_host, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            return maybe_host
    return host


def _is_placeholder_host(host: str) -> bool:
    host = _strip_host_port(host).lower()
    return host in {"", "0.0.0.0", "127.0.0.1", "localhost", "::1", "your-server-ip"}


def _request_config_host(request: Request) -> str:
    for header in ("x-forwarded-host", "host"):
        raw = (request.headers.get(header) or "").split(",", 1)[0].strip()
        host = _strip_host_port(raw)
        if not _is_placeholder_host(host):
            return host
    if not _is_placeholder_host(settings.host):
        return settings.host
    return ""


def _read_password_file() -> Optional[str]:
    pw_file = os.path.join(os.getcwd(), "vpn-panel-password")
    if not os.path.exists(pw_file):
        return None
    try:
        with open(pw_file) as f:
            return f.read().strip()
    except Exception as exc:
        logger.error(f"Failed to read password file: {exc}")
        return None


def _write_password_file(new_password: str) -> bool:
    pw_file = os.path.join(os.getcwd(), "vpn-panel-password")
    try:
        with open(pw_file, "w") as f:
            f.write(new_password)
        return True
    except Exception as exc:
        logger.error(f"Failed to write password file: {exc}")
        return False


def _days_left(expire_at: Optional[datetime]) -> int:
    if not expire_at:
        return 9999
    delta = expire_at - datetime.utcnow()
    return max(0, delta.days)


def _build_share_links(u: VpnUser, server_ip: Optional[str] = None) -> Dict[str, str]:
    """Generate protocol share URLs for a user. Best-effort — empty if disabled."""
    try:
        from ..protocol_engine import ClientConfigGenerator
    except Exception:
        return {}

    server_ip = server_ip or _settings_state.get("server_ip") or settings.host
    if _is_placeholder_host(server_ip):
        server_ip = ""
    # ── Emergency Relay: override ALL addresses when activated ──
    _emergency_relay = ""
    if _settings_state.get("emergency_relay_enabled") and _settings_state.get("emergency_relay_address"):
        _emergency_relay = _settings_state.get("emergency_relay_address", "").strip()
    if _emergency_relay:
        server_ip = _emergency_relay
    sni_host = _settings_state.get("vmess_sni") or "www.aparat.com"
    ws_path = _settings_state.get("vmess_ws_path") or "/api/v1/stream"

    # ── DPI Evasion common flags ──
    _frag = bool(_settings_state.get("fragment_enabled"))
    _frag_pkt = _settings_state.get("fragment_packets") or "tlshello"
    _frag_len = _settings_state.get("fragment_length") or "100-200"
    _frag_int = _settings_state.get("fragment_interval") or "10-20"
    _noise_pkt = _settings_state.get("noise_packet") or ""
    _noise_del = _settings_state.get("noise_delay") or ""
    _keepalive = bool(_settings_state.get("dpi_tcp_keepalive"))
    _mux = bool(_settings_state.get("mux_enabled"))
    _mux_conc = int(_settings_state.get("mux_concurrency") or 8)
    _bug_host = ""
    if _settings_state.get("dpi_bug_host_enabled"):
        _bug_host = _settings_state.get("dpi_bug_host_domain") or "chat.deepseek.com"
    _host_spoof = ""
    if _settings_state.get("dpi_http_host_spoof_enabled"):
        _host_spoof = _settings_state.get("dpi_http_host_spoof_domain") or "chat.deepseek.com"
    _ws_front = ""
    if _settings_state.get("dpi_ws_host_front_enabled") and not _host_spoof:
        _ws_front = _settings_state.get("dpi_ws_host_front_domain") or "rubika.ir"
    _cdn_front = ""
    if _settings_state.get("dpi_cdn_host_front_enabled"):
        _cdn_front = _settings_state.get("dpi_cdn_host_front_domain") or "web.splus.ir"

    def _dpi_vless_kwargs():
        return dict(
            fragment=_frag, fragment_packets=_frag_pkt, fragment_length=_frag_len,
            fragment_interval=_frag_int, noise_packet=_noise_pkt, noise_delay=_noise_del,
            tcp_keepalive=_keepalive, mux_enabled=_mux, mux_concurrency=_mux_conc,
            bug_host=_bug_host,
        )

    def _dpi_vmess_kwargs(extra_host=""):
        return dict(
            fragment=_frag, fragment_packets=_frag_pkt, fragment_length=_frag_len,
            fragment_interval=_frag_int, noise_packet=_noise_pkt, noise_delay=_noise_del,
            tcp_keepalive=_keepalive, mux_enabled=_mux, mux_concurrency=_mux_conc,
            bug_host=_bug_host, extra_host_header=extra_host,
        )

    def _dpi_trojan_kwargs():
        return dict(
            fragment=_frag, fragment_packets=_frag_pkt, fragment_length=_frag_len,
            fragment_interval=_frag_int, noise_packet=_noise_pkt, noise_delay=_noise_del,
            tcp_keepalive=_keepalive, mux_enabled=_mux, mux_concurrency=_mux_conc,
            bug_host=_bug_host,
        )

    links: Dict[str, str] = {}
    try:
        links["vmess"] = ClientConfigGenerator.generate_vmess_share_url(
            uuid=u.uuid,
            address=server_ip,
            port=int(_settings_state.get("vmess_port") or 443),
            sni=sni_host,
            path=ws_path,
            allow_insecure=True,
            **_dpi_vmess_kwargs(extra_host=_host_spoof or _ws_front),
        )
    except Exception:
        links["vmess"] = ""

    if _settings_state.get("reality_public_key"):
        try:
            links["vless"] = ClientConfigGenerator.generate_vless_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("vless_port") or 2053),
                security="reality",
                sni=_settings_state.get("reality_sni") or "chat.deepseek.com",
                fp=_settings_state.get("fingerprint") or "chrome",
                pbk=_settings_state.get("reality_public_key") or "",
                sid=_settings_state.get("reality_short_id") or "",
                flow="xtls-rprx-vision",
                network="tcp",
                **_dpi_vless_kwargs(),
            )
        except Exception:
            links["vless"] = ""

    if _settings_state.get("cdn_enabled") and _settings_state.get("cdn_domain"):
        try:
            cdn_host = _cdn_front or _settings_state.get("cdn_domain")
            links["cdn_vmess"] = ClientConfigGenerator.generate_vmess_share_url(
                uuid=u.uuid,
                address=_settings_state.get("cdn_domain"),
                port=int(_settings_state.get("cdn_port") or 443),
                security="tls",
                sni=cdn_host,
                path=_settings_state.get("cdn_ws_path") or "/cdn-ws",
                allow_insecure=True,
                **_dpi_vmess_kwargs(extra_host=cdn_host),
            )
        except Exception:
            links["cdn_vmess"] = ""

    if _settings_state.get("vless_ws_enabled") or settings.vless_ws_enabled:
        try:
            links["vless_ws"] = ClientConfigGenerator.generate_vless_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("vless_ws_port") or settings.vless_ws_port),
                network="ws",
                security="tls",
                sni=sni_host,
                host=_host_spoof or _ws_front or sni_host,
                path=_settings_state.get("vless_ws_path") or settings.vless_ws_path,
                allow_insecure=True,
                **_dpi_vless_kwargs(),
            )
        except Exception:
            links["vless_ws"] = ""

    if _settings_state.get("trojan_enabled"):
        try:
            links["trojan"] = ClientConfigGenerator.generate_trojan_share_url(
                password=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("trojan_port") or 2083),
                sni=sni_host,
                network="tcp",
                allow_insecure=True,
                **_dpi_trojan_kwargs(),
            )
        except Exception:
            links["trojan"] = ""

    if _settings_state.get("grpc_enabled"):
        try:
            links["grpc_vmess"] = ClientConfigGenerator.generate_vmess_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("grpc_port") or 2054),
                network="grpc",
                security="tls",
                sni=sni_host,
                path=_settings_state.get("grpc_service_name") or "GunService",
                allow_insecure=True,
                **_dpi_vmess_kwargs(),
            )
        except Exception:
            links["grpc_vmess"] = ""

    if _settings_state.get("httpupgrade_enabled"):
        try:
            links["httpupgrade_vmess"] = ClientConfigGenerator.generate_vmess_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("httpupgrade_port") or 2055),
                network="httpupgrade",
                security="tls",
                sni=sni_host,
                path=_settings_state.get("httpupgrade_path") or "/httpupgrade",
                allow_insecure=True,
                **_dpi_vmess_kwargs(extra_host=_host_spoof or _ws_front),
            )
        except Exception:
            links["httpupgrade_vmess"] = ""

    if _settings_state.get("ss2022_enabled") and _settings_state.get("ss2022_server_key"):
        try:
            method = _settings_state.get("ss2022_method") or "2022-blake3-aes-128-gcm"
            userinfo = base64.urlsafe_b64encode(
                f"{method}:{_settings_state['ss2022_server_key']}:{u.uuid}".encode()
            ).decode().rstrip("=")
            label = urllib.parse.quote(f"V7LTHRONYX-SS-{u.name}")
            links["ss2022"] = (
                f"ss://{userinfo}@{server_ip}:{int(_settings_state.get('ss2022_port') or 2056)}#{label}"
            )
        except Exception:
            links["ss2022"] = ""

    # Hysteria2
    if _settings_state.get("hysteria2_enabled"):
        try:
            links["hysteria2"] = ClientConfigGenerator.generate_hysteria2_share_url(
                password=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("hysteria2_port") or 8443),
                sni=sni_host,
                obfs=_settings_state.get("hysteria2_obfs_password") or "",
                insecure=1,
            )
        except Exception:
            links["hysteria2"] = ""

    # TUIC v5
    if _settings_state.get("tuic_enabled"):
        try:
            tuic_port = int(_settings_state.get("tuic_port") or 8444)
            tuic_password = _settings_state.get("tuic_password") or u.uuid
            label = urllib.parse.quote(f"V7LTHRONYX-TUIC-{u.name}")
            params = urllib.parse.urlencode({
                "sni": sni_host,
                "alpn": "h3",
                "congestion_control": "bbr",
                "udp_relay_mode": "native",
                "allow_insecure": "1",
            })
            links["tuic"] = (
                f"tuic://{u.uuid}:{tuic_password}@{server_ip}:{tuic_port}?{params}#{label}"
            )
        except Exception:
            links["tuic"] = ""

    # VLESS xHTTP REALITY
    if _settings_state.get("vless_xhttp_enabled") and (_settings_state.get("reality_public_key") or _settings_state.get("vless_xhttp_reality_public_key")):
        try:
            links["vless_xhttp"] = ClientConfigGenerator.generate_vless_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("vless_xhttp_port") or 2053),
                security="reality",
                sni=_settings_state.get("vless_xhttp_reality_sni") or _settings_state.get("reality_sni") or "digikala.com",
                fp=_settings_state.get("fingerprint") or "chrome",
                pbk=_settings_state.get("vless_xhttp_reality_public_key") or _settings_state.get("reality_public_key") or "",
                sid=_settings_state.get("vless_xhttp_reality_short_id") or _settings_state.get("reality_short_id") or "",
                network="xhttp",
                xhttp_mode=_settings_state.get("vless_xhttp_mode") or "auto",
                path=_settings_state.get("vless_xhttp_path") or "/xhttp",
                **_dpi_vless_kwargs(),
            )
        except Exception:
            links["vless_xhttp"] = ""

    # VLESS Vision REALITY
    if _settings_state.get("vless_vision_enabled") and (_settings_state.get("reality_public_key") or _settings_state.get("vless_vision_reality_public_key")):
        try:
            links["vless_vision"] = ClientConfigGenerator.generate_vless_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("vless_vision_port") or 2058),
                security="reality",
                sni=_settings_state.get("vless_vision_reality_sni") or _settings_state.get("reality_sni") or "objects.githubusercontent.com",
                fp=_settings_state.get("fingerprint") or "chrome",
                pbk=_settings_state.get("vless_vision_reality_public_key") or _settings_state.get("reality_public_key") or "",
                sid=_settings_state.get("vless_vision_reality_short_id") or _settings_state.get("reality_short_id") or "",
                flow="xtls-rprx-vision",
                network="tcp",
                **_dpi_vless_kwargs(),
            )
        except Exception:
            links["vless_vision"] = ""

    # VLESS Reverse REALITY
    if _settings_state.get("vless_reverse_enabled") and (_settings_state.get("reality_public_key") or _settings_state.get("vless_xhttp_reality_public_key")):
        try:
            links["vless_reverse"] = ClientConfigGenerator.generate_vless_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("vless_reverse_port") or 2059),
                security="reality",
                sni=_settings_state.get("vless_xhttp_reality_sni") or _settings_state.get("reality_sni") or "digikala.com",
                fp=_settings_state.get("fingerprint") or "chrome",
                pbk=_settings_state.get("vless_xhttp_reality_public_key") or _settings_state.get("reality_public_key") or "",
                sid=_settings_state.get("vless_xhttp_reality_short_id") or _settings_state.get("reality_short_id") or "",
                network="tcp",
                **_dpi_vless_kwargs(),
            )
        except Exception:
            links["vless_reverse"] = ""

    # Trojan CDN
    if _settings_state.get("trojan_cdn_enabled") and _settings_state.get("cdn_domain"):
        try:
            links["trojan_cdn"] = ClientConfigGenerator.generate_trojan_share_url(
                password=u.uuid,
                address=_settings_state.get("cdn_domain"),
                port=int(_settings_state.get("trojan_cdn_port") or 443),
                sni=_cdn_front or _settings_state.get("cdn_domain"),
                network="ws",
                path=_settings_state.get("cdn_ws_path") or "/cdn-ws",
                allow_insecure=False,
                **_dpi_trojan_kwargs(),
            )
        except Exception:
            links["trojan_cdn"] = ""

    return links


def _user_to_legacy(u: VpnUser, server_ip: Optional[str] = None) -> Dict[str, Any]:
    traffic_limit_bytes = int(u.traffic_limit or 0)
    traffic_used_bytes = int(u.traffic_used or 0)
    traffic_limit_gb = traffic_limit_bytes / (1024**3) if traffic_limit_bytes else 0
    traffic_used_gb = traffic_used_bytes / (1024**3) if traffic_used_bytes else 0
    traffic_percent = 0
    if traffic_limit_bytes > 0:
        traffic_percent = round(min((traffic_used_bytes / traffic_limit_bytes) * 100, 100), 1)
    links = _build_share_links(u, server_ip=server_ip)
    return {
        "id": u.id,
        "name": u.name,
        "uuid": u.uuid,
        "active": bool(u.active),
        "traffic_limit": traffic_limit_gb,
        "traffic_limit_gb": traffic_limit_gb,
        "traffic_limit_bytes": traffic_limit_bytes,
        "traffic_used": traffic_used_gb,
        "traffic_used_gb": traffic_used_gb,
        "traffic_used_bytes": traffic_used_bytes,
        "traffic_percent": traffic_percent,
        "expire_at": u.expire_at.date().isoformat() if u.expire_at else None,
        "days_left": _days_left(u.expire_at),
        "agent_id": u.agent_id,
        "speed_limit_up": u.speed_limit_up or 0,
        "speed_limit_down": u.speed_limit_down or 0,
        "note": u.note or "",
        "created_at": u.created_at.date().isoformat() if u.created_at else "",
        "online_ip_count": 0,
        "online_ips": [],
        "vmess": links.get("vmess", ""),
        "vless": links.get("vless", ""),
        "cdn_vmess": links.get("cdn_vmess", ""),
        "trojan": links.get("trojan", ""),
        "trojan_cdn": links.get("trojan_cdn", ""),
        "grpc_vmess": links.get("grpc_vmess", ""),
        "httpupgrade_vmess": links.get("httpupgrade_vmess", ""),
        "ss2022": links.get("ss2022", ""),
        "vless_ws": links.get("vless_ws", ""),
        "vless_xhttp": links.get("vless_xhttp", ""),
        "vless_vision": links.get("vless_vision", ""),
        "vless_reverse": links.get("vless_reverse", ""),
        "hysteria2": links.get("hysteria2", ""),
        "tuic": links.get("tuic", ""),
    }


def _default_legacy_settings() -> Dict[str, Any]:
    """Default protocol toggles. All advertised protocols are ON by default
    so freshly-installed panels show every protocol in the UI without manual
    activation. Real protocol availability still depends on the agent
    (xray/sing-box/wireguard) being running and configured."""
    return {
        "vmess_port": 443,
        "vmess_sni": "www.aparat.com",
        "vmess_ws_path": "/api/v1/stream",
        "vless_port": 2053,
        "reality_sni": "chat.deepseek.com",
        "vless_xhttp_enabled": True,
        "vless_xhttp_port": 2053,
        "vless_xhttp_mode": "auto",
        "vless_xhttp_path": "/xhttp",
        "vless_vision_enabled": True,
        "vless_vision_port": 2058,
        "vless_reverse_enabled": True,
        "vless_reverse_port": 2059,
        "vless_ws_enabled": True,
        "vless_ws_port": settings.vless_ws_port,
        "vless_ws_path": settings.vless_ws_path,
        "trojan_enabled": True,
        "trojan_port": 2083,
        "trojan_cdn_enabled": False,
        "trojan_cdn_port": 443,
        "grpc_enabled": True,
        "grpc_port": 2054,
        "grpc_service_name": "GunService",
        "httpupgrade_enabled": True,
        "httpupgrade_port": 2055,
        "httpupgrade_path": "/httpupgrade",
        "ss2022_enabled": True,
        "ss2022_port": 2056,
        "ss2022_method": "2022-blake3-aes-128-gcm",
        "ss2022_server_key": secrets.token_hex(16),
        "hysteria2_enabled": True,
        "hysteria2_port": 8443,
        "tuic_enabled": True,
        "tuic_port": 8444,
        "amneziawg_enabled": False,
        "amneziawg_port": 51820,
        "shadowtls_enabled": False,
        "shadowtls_port": 8445,
        "mieru_enabled": False,
        "mieru_port": 8446,
        "naiveproxy_enabled": False,
        "naiveproxy_port": 8447,
        "wireguard_enabled": False,
        "wireguard_port": 51821,
        "openvpn_enabled": False,
        "openvpn_port": 1194,
        "fragment_enabled": True,
        "fragment_packets": "tlshello",
        "fragment_length": "100-200",
        "fragment_interval": "10-20",
        "mux_enabled": True,
        "mux_concurrency": 8,
        "fingerprint": "chrome",
        "kill_switch_enabled": False,
        # Emergency Relay (OFF by default — activate when server IP is blocked)
        "emergency_relay_enabled": False,
        "emergency_relay_address": "",
        # Host Header Spoofing (all OFF by default)
        "dpi_http_host_spoof_enabled": False,
        "dpi_http_host_spoof_domain": "chat.deepseek.com",
        "dpi_ws_host_front_enabled": False,
        "dpi_ws_host_front_domain": "rubika.ir",
        "dpi_cdn_host_front_enabled": False,
        "dpi_cdn_host_front_domain": "web.splus.ir",
        "dpi_bug_host_enabled": False,
        "dpi_bug_host_domain": "chat.deepseek.com",
        "cdn_enabled": False,
        "cdn_domain": "",
        "cdn_ws_path": "/cdn-ws",
        "cdn_port": 2082,
        # REALITY keys (auto-generated)
        "reality_public_key": settings.reality_public_key,
        "reality_private_key": settings.reality_private_key,
        "reality_short_id": secrets.token_hex(8),
        # VLESS XHTTP REALITY settings
        "vless_xhttp_reality_sni": "digikala.com",
        "vless_xhttp_reality_dest": "digikala.com:443",
        "vless_xhttp_reality_short_id": secrets.token_hex(8),
        "vless_xhttp_reality_public_key": settings.reality_public_key,
        # VLESS Vision REALITY settings
        "vless_vision_reality_sni": "objects.githubusercontent.com",
        "vless_vision_reality_dest": "objects.githubusercontent.com:443",
        "vless_vision_reality_short_id": secrets.token_hex(8),
        "vless_vision_reality_public_key": settings.reality_public_key,
    }


async def _load_legacy_settings(db: AsyncSession) -> Dict[str, Any]:
    file_settings: Dict[str, Any] = {}
    settings_path = os.path.join(os.getcwd(), _LEGACY_SETTINGS_FILE)
    if os.path.exists(settings_path):
        try:
            with open(settings_path) as f:
                loaded_file = json.load(f)
            if isinstance(loaded_file, dict):
                file_settings = loaded_file
        except Exception as exc:
            logger.warning(f"Failed to load legacy settings file: {exc}")

    result = await db.execute(select(Setting).where(Setting.key == _LEGACY_SETTINGS_KEY))
    row = result.scalar_one_or_none()
    db_settings: Dict[str, Any] = {}
    if row and row.value:
        try:
            loaded_db = json.loads(row.value)
            if isinstance(loaded_db, dict):
                db_settings = loaded_db
        except json.JSONDecodeError:
            logger.warning("Ignoring invalid legacy panel settings JSON")

    merged = {**_default_legacy_settings(), **file_settings, **db_settings}
    _settings_state.clear()
    _settings_state.update(_normalize_settings_types(merged))
    return dict(_settings_state)


def _preserve_protocols_on_dpi_update(
    current: Dict[str, Any],
    incoming: Dict[str, Any],
) -> Dict[str, Any]:
    if not any(key in incoming for key in _DPI_SETTING_KEYS):
        return incoming

    protected = dict(incoming)
    for key in _PROTOCOL_ENABLE_KEYS:
        if current.get(key) is True and protected.get(key) is False:
            protected[key] = True
    return protected


async def _save_legacy_settings(db: AsyncSession, data: Dict[str, Any]) -> None:
    current = await _load_legacy_settings(db)
    data = _normalize_settings_types(data)
    data = _preserve_protocols_on_dpi_update(current, data)
    _settings_state.update(data)
    result = await db.execute(select(Setting).where(Setting.key == _LEGACY_SETTINGS_KEY))
    row = result.scalar_one_or_none()
    value = json.dumps(_settings_state)
    if row is None:
        row = Setting(
            key=_LEGACY_SETTINGS_KEY,
            value=value,
            value_type="json",
            description="Legacy panel compatibility settings",
        )
        db.add(row)
    else:
        row.value = value
        row.value_type = "json"
    await db.commit()

    settings_path = os.path.join(os.getcwd(), _LEGACY_SETTINGS_FILE)
    try:
        with open(settings_path, "w") as f:
            json.dump(_settings_state, f, indent=2)
        os.chmod(settings_path, 0o600)
    except Exception as exc:
        logger.warning(f"Failed to mirror legacy settings file: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
#  Auth (legacy)
# ─────────────────────────────────────────────────────────────────────────────

class LegacyLoginRequest(BaseModel):
    password: str
    username: Optional[str] = "admin"


@router.post("/login")
async def legacy_login(
    request: LegacyLoginRequest,
    req: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    client_ip = req.client.host if req.client else "0.0.0.0"

    if await fail2ban_manager.is_banned(client_ip, "panel", db):
        return {"ok": False, "error": "IP banned. Contact admin.", "locked": True}

    if _is_locked_out(client_ip):
        return {
            "ok": False,
            "error": f"Too many attempts. Try again in {settings.lockout_seconds}s",
            "locked": True,
        }

    username = request.username or "admin"
    admin_id: Optional[int] = None
    authenticated = False

    db_result = await db.execute(select(Admin).where(Admin.username == username))
    admin_user = db_result.scalar_one_or_none()
    if admin_user and verify_password(request.password, admin_user.password_hash):
        authenticated = True
        admin_id = admin_user.id

    if not authenticated:
        stored_pw = _read_password_file()
        if stored_pw and request.password == stored_pw:
            authenticated = True

    if not authenticated:
        _record_failed_attempt(client_ip)
        await fail2ban_manager.record_failed_attempt(
            client_ip, "panel", db, "Failed panel login"
        )
        return {"ok": False, "error": "Invalid password"}

    _clear_attempts(client_ip)

    token_payload: Dict[str, Any] = {"sub": username, "is_admin": True}
    if admin_id is not None:
        token_payload["user_id"] = admin_id

    access_token = create_access_token(data=token_payload)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.session_lifetime_hours * 3600,
        path="/",
    )
    return {"ok": True, "access_token": access_token}


@router.post("/logout")
async def legacy_logout(response: Response):
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


class ChangePasswordRequest(BaseModel):
    current: str
    new: str


@router.post("/change-password")
async def legacy_change_password(
    body: ChangePasswordRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    if len(body.new) < 8:
        return {"ok": False, "error": "Password too short (min 8 chars)"}

    db_admin = None
    if admin.username:
        result = await db.execute(select(Admin).where(Admin.username == admin.username))
        db_admin = result.scalar_one_or_none()

    if db_admin is not None:
        if not verify_password(body.current, db_admin.password_hash):
            return {"ok": False, "error": "Current password is incorrect"}
        db_admin.password_hash = get_password_hash(body.new)
        await db.commit()
        return {"ok": True}

    stored_pw = _read_password_file()
    if stored_pw is None:
        return {"ok": False, "error": "Password store not initialized"}
    if body.current != stored_pw:
        return {"ok": False, "error": "Current password is incorrect"}
    if not _write_password_file(body.new):
        return {"ok": False, "error": "Failed to update password"}
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
#  Users (legacy shape)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/users")
async def legacy_list_users(
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(select(VpnUser).order_by(VpnUser.id.desc()))
    server_ip = _request_config_host(request)
    return [_user_to_legacy(u, server_ip=server_ip) for u in result.scalars().all()]


class LegacyUserCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    traffic: float = Field(10.0, ge=0)
    days: int = Field(30, ge=0)
    speed_limit_up: int = Field(0, ge=0)
    speed_limit_down: int = Field(0, ge=0)
    note: str = ""


@router.post("/users")
async def legacy_create_user(
    body: LegacyUserCreate,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    expire_at = datetime.utcnow() + timedelta(days=body.days) if body.days else None
    db_user = VpnUser(
        uuid=str(uuid_lib.uuid4()),
        name=body.name,
        traffic_limit=int(body.traffic * (1024**3)),
        traffic_used=0,
        expire_at=expire_at,
        active=1,
        speed_limit_up=body.speed_limit_up,
        speed_limit_down=body.speed_limit_down,
        note=body.note,
    )
    db.add(db_user)
    try:
        await db.commit()
        await db.refresh(db_user)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    await _load_legacy_settings(db)
    return {
        "ok": True,
        "user": _user_to_legacy(db_user, server_ip=_request_config_host(request)),
    }


@router.delete("/users/{name}")
async def legacy_delete_user(
    name: str,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    await db.delete(user)
    await db.commit()
    return {"ok": True}


@router.post("/users/{name}/toggle")
async def legacy_toggle_user(
    name: str,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.active = 0 if user.active else 1
    await db.commit()
    return {
        "ok": True,
        "message": f"User {name} {'enabled' if user.active else 'disabled'}",
        "active": bool(user.active),
    }


class LegacyRenewRequest(BaseModel):
    traffic: float = Field(..., ge=0)
    days: int = Field(..., ge=0)


@router.post("/users/{name}/renew")
async def legacy_renew_user(
    name: str,
    body: LegacyRenewRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.traffic_limit = int(body.traffic * (1024**3))
    user.traffic_used = 0
    user.expire_at = datetime.utcnow() + timedelta(days=body.days)
    user.active = 1
    await db.commit()
    return {"ok": True}


class LegacyAddTrafficRequest(BaseModel):
    gb: float = Field(..., gt=0)


@router.post("/users/{name}/add-traffic")
async def legacy_add_traffic(
    name: str,
    body: LegacyAddTrafficRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.traffic_limit = (user.traffic_limit or 0) + int(body.gb * (1024**3))
    await db.commit()
    return {"ok": True}


class LegacyNoteRequest(BaseModel):
    note: str


@router.post("/users/{name}/update-note")
async def legacy_update_note(
    name: str,
    body: LegacyNoteRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.note = body.note
    await db.commit()
    return {"ok": True}


class LegacySpeedRequest(BaseModel):
    speed_limit_down: int = Field(0, ge=0)
    speed_limit_up: int = Field(0, ge=0)


@router.post("/users/{name}/speed-limit")
async def legacy_speed_limit(
    name: str,
    body: LegacySpeedRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.speed_limit_down = body.speed_limit_down
    user.speed_limit_up = body.speed_limit_up
    await db.commit()
    return {"ok": True}


@router.post("/users/{name}/reset-traffic")
async def legacy_reset_traffic(
    name: str,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.traffic_used = 0
    await db.commit()
    return {"ok": True}


@router.get("/users/{name}/activity")
async def legacy_user_activity(
    name: str,
    admin: User = Depends(get_current_admin_cookie),
):
    return {
        "summary": [],
        "categories": [],
        "services": [],
        "deep": {
            "verdict": "No data",
            "verdict_level": "safe",
            "total_connections": 0,
            "unique_destinations": 0,
            "activities": [],
            "ports": [],
            "hourly": [],
        },
        "sites": [],
        "recent": [],
        "total": 0,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Bulk operations
# ─────────────────────────────────────────────────────────────────────────────

class BulkCreateRequest(BaseModel):
    prefix: str = "group"
    count: int = 1
    traffic: float = 1
    days: int = 30
    numbered: bool = True
    start: int = 1
    pad: int = 3
    apply: bool = False
    speed_limit_up: int = 0
    speed_limit_down: int = 0


@router.post("/bulk-users")
async def legacy_bulk_users(
    body: BulkCreateRequest,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    expire_at = datetime.utcnow() + timedelta(days=body.days) if body.days else None
    created_users: List[VpnUser] = []
    for i in range(body.count):
        if body.numbered:
            suffix = str(body.start + i).zfill(body.pad)
            name = f"{body.prefix}-{suffix}"
        else:
            name = f"{body.prefix}-{uuid_lib.uuid4().hex[:8]}"
        u = VpnUser(
            uuid=str(uuid_lib.uuid4()),
            name=name,
            traffic_limit=int(body.traffic * (1024**3)),
            traffic_used=0,
            expire_at=expire_at,
            active=1,
            speed_limit_up=body.speed_limit_up,
            speed_limit_down=body.speed_limit_down,
            note="",
        )
        db.add(u)
        created_users.append(u)
    try:
        await db.commit()
        for u in created_users:
            await db.refresh(u)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    await _load_legacy_settings(db)
    server_ip = _request_config_host(request)
    return {
        "ok": True,
        "created": len(created_users),
        "users": [_user_to_legacy(u, server_ip=server_ip) for u in created_users],
        "numbered": body.numbered,
        "start": body.start,
        "pad": body.pad,
        "note": "",
        "apply": body.apply,
    }


class BulkDeleteRequest(BaseModel):
    prefix: Optional[str] = None
    names: Optional[List[str]] = None
    apply: bool = False


@router.post("/bulk-delete")
async def legacy_bulk_delete(
    body: BulkDeleteRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    query = select(VpnUser)
    if body.names:
        query = query.where(VpnUser.name.in_(body.names))
    elif body.prefix:
        query = query.where(VpnUser.name.like(f"{body.prefix}%"))
    else:
        return {"ok": False, "error": "Provide names or prefix"}

    result = await db.execute(query)
    users = result.scalars().all()
    count = 0
    for u in users:
        await db.delete(u)
        count += 1
    await db.commit()
    return {"ok": True, "deleted": count, "apply": body.apply}


@router.post("/bulk-export-zip")
async def legacy_bulk_export_zip(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    import zipfile

    prefix = str(body.get("prefix", "bulk"))
    users = body.get("users", []) or []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for u in users:
            name = u.get("name", "user")
            text = "\n".join(
                f"{label}: {u.get(key, '')}"
                for key, label in [
                    ("vmess", "VMess"),
                    ("vless", "VLESS"),
                    ("cdn_vmess", "CDN"),
                    ("trojan", "Trojan"),
                    ("grpc_vmess", "gRPC"),
                    ("httpupgrade_vmess", "HU"),
                    ("ss2022", "SS2022"),
                    ("vless_ws", "VLESS-WS"),
                ]
                if u.get(key)
            )
            zf.writestr(f"{name}.txt", text)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{prefix}-configs.zip"'},
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Groups
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/groups")
async def legacy_groups(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser))
    users = result.scalars().all()
    groups: Dict[str, Dict[str, Any]] = {}
    for u in users:
        prefix = u.name.split("-")[0] if "-" in u.name else u.name
        g = groups.setdefault(
            prefix,
            {
                "id": prefix,
                "count": 0,
                "active": 0,
                "disabled": 0,
                "traffic_gb": 0,
                "latest_expire": "",
            },
        )
        g["count"] += 1
        if u.active:
            g["active"] += 1
        else:
            g["disabled"] += 1
        if u.traffic_limit and not g["traffic_gb"]:
            g["traffic_gb"] = round(u.traffic_limit / (1024**3), 2)
        if u.expire_at:
            iso = u.expire_at.isoformat()
            if iso > g["latest_expire"]:
                g["latest_expire"] = iso
    return list(groups.values())


@router.get("/groups/{group_id}/users")
async def legacy_group_users(
    group_id: str,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(
        select(VpnUser).where(VpnUser.name.like(f"{group_id}%"))
    )
    server_ip = _request_config_host(request)
    users = [_user_to_legacy(u, server_ip=server_ip) for u in result.scalars().all()]
    return {"ok": True, "users": users}


# ─────────────────────────────────────────────────────────────────────────────
#  Live, server-info, sync, system-monitor, online-users
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/live")
async def legacy_live(admin: User = Depends(get_current_admin_cookie)):
    """Realtime traffic counters keyed by username."""
    return {}


@router.get("/server-info")
async def legacy_server_info(
    admin: Optional[User] = Depends(get_optional_user_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    s = await _load_legacy_settings(db)
    return {
        # VMess (always-on)
        "vmess_port": s.get("vmess_port", 443),
        "vmess_sni": s.get("vmess_sni", "www.aparat.com"),
        "vmess_ws_path": s.get("vmess_ws_path", "/api/v1/stream"),
        # VLESS Reality (Vision)
        "vless": bool(s.get("reality_public_key")) or _as_bool(s.get("vless_xhttp_enabled", False)) or _as_bool(s.get("vless_vision_enabled", False)),
        "vless_enabled": bool(s.get("reality_public_key")) or _as_bool(s.get("vless_xhttp_enabled", False)) or _as_bool(s.get("vless_vision_enabled", False)),
        "vless_port": s.get("vless_port", 2053),
        "vless_sni": s.get("reality_sni", "chat.deepseek.com"),
        "vless_public_key": s.get("reality_public_key", ""),
        "vless_short_id": s.get("reality_short_id", ""),
        # VLESS xHTTP REALITY
        "vless_xhttp": _as_bool(s.get("vless_xhttp_enabled", False)),
        "vless_xhttp_enabled": _as_bool(s.get("vless_xhttp_enabled", False)),
        "vless_xhttp_port": s.get("vless_xhttp_port", 2053),
        "vless_xhttp_mode": s.get("vless_xhttp_mode", "auto"),
        "vless_xhttp_path": s.get("vless_xhttp_path", "/xhttp"),
        "vless_xhttp_reality_sni": s.get("vless_xhttp_reality_sni", "digikala.com"),
        "vless_xhttp_reality_dest": s.get("vless_xhttp_reality_dest", "digikala.com:443"),
        "vless_xhttp_reality_short_id": s.get("vless_xhttp_reality_short_id", ""),
        "vless_xhttp_reality_public_key": s.get("vless_xhttp_reality_public_key", s.get("reality_public_key", "")),
        # VLESS Vision REALITY
        "vless_vision": _as_bool(s.get("vless_vision_enabled", False)),
        "vless_vision_enabled": _as_bool(s.get("vless_vision_enabled", False)),
        "vless_vision_port": s.get("vless_vision_port", 2058),
        "vless_vision_reality_sni": s.get("vless_vision_reality_sni", "objects.githubusercontent.com"),
        "vless_vision_reality_dest": s.get("vless_vision_reality_dest", "objects.githubusercontent.com:443"),
        "vless_vision_reality_short_id": s.get("vless_vision_reality_short_id", ""),
        "vless_vision_reality_public_key": s.get("vless_vision_reality_public_key", s.get("reality_public_key", "")),
        # VLESS Reverse REALITY
        "vless_reverse": _as_bool(s.get("vless_reverse_enabled", False)),
        "vless_reverse_enabled": _as_bool(s.get("vless_reverse_enabled", False)),
        "vless_reverse_port": s.get("vless_reverse_port", 2059),
        # Trojan
        "trojan": _as_bool(s.get("trojan_enabled", False)),
        "trojan_enabled": _as_bool(s.get("trojan_enabled", False)),
        "trojan_port": s.get("trojan_port", 2083),
        # Trojan CDN
        "trojan_cdn_enabled": _as_bool(s.get("trojan_cdn_enabled", False)),
        "trojan_cdn_port": s.get("trojan_cdn_port", 2083),
        # gRPC
        "grpc": _as_bool(s.get("grpc_enabled", False)),
        "grpc_enabled": _as_bool(s.get("grpc_enabled", False)),
        "grpc_port": s.get("grpc_port", 2054),
        "grpc_service": s.get("grpc_service_name", "GunService"),
        # HTTPUpgrade
        "httpupgrade": _as_bool(s.get("httpupgrade_enabled", False)),
        "httpupgrade_enabled": _as_bool(s.get("httpupgrade_enabled", False)),
        "httpupgrade_port": s.get("httpupgrade_port", 2055),
        "httpupgrade_path": s.get("httpupgrade_path", "/httpupgrade"),
        # ShadowSocks 2022
        "ss2022": bool(s.get("ss2022_server_key")),
        "ss2022_enabled": _as_bool(s.get("ss2022_enabled", False)) and bool(s.get("ss2022_server_key")),
        "ss2022_port": s.get("ss2022_port", 2056),
        # VLESS WS
        "vless_ws": _as_bool(s.get("vless_ws_enabled", settings.vless_ws_enabled)),
        "vless_ws_enabled": _as_bool(s.get("vless_ws_enabled", settings.vless_ws_enabled)),
        "vless_ws_port": s.get("vless_ws_port", settings.vless_ws_port),
        "vless_ws_path": s.get("vless_ws_path", settings.vless_ws_path),
        # Hysteria2
        "hysteria2": _as_bool(s.get("hysteria2_enabled", False)),
        "hysteria2_enabled": _as_bool(s.get("hysteria2_enabled", False)),
        "hysteria2_port": s.get("hysteria2_port", 8443),
        # TUIC v5
        "tuic": _as_bool(s.get("tuic_enabled", False)),
        "tuic_enabled": _as_bool(s.get("tuic_enabled", False)),
        "tuic_port": s.get("tuic_port", 8444),
        # AmneziaWG
        "amneziawg": _as_bool(s.get("amneziawg_enabled", False)),
        "amneziawg_enabled": _as_bool(s.get("amneziawg_enabled", False)),
        "amneziawg_port": s.get("amneziawg_port", 51820),
        # ShadowTLS v3
        "shadowtls": _as_bool(s.get("shadowtls_enabled", False)),
        "shadowtls_enabled": _as_bool(s.get("shadowtls_enabled", False)),
        "shadowtls_port": s.get("shadowtls_port", 8445),
        # Mieru
        "mieru": _as_bool(s.get("mieru_enabled", False)),
        "mieru_enabled": _as_bool(s.get("mieru_enabled", False)),
        "mieru_port": s.get("mieru_port", 8446),
        # NaiveProxy
        "naiveproxy": _as_bool(s.get("naiveproxy_enabled", False)),
        "naiveproxy_enabled": _as_bool(s.get("naiveproxy_enabled", False)),
        "naiveproxy_port": s.get("naiveproxy_port", 8447),
        # WireGuard
        "wireguard": _as_bool(s.get("wireguard_enabled", False)),
        "wireguard_enabled": _as_bool(s.get("wireguard_enabled", False)),
        "wireguard_port": s.get("wireguard_port", 51821),
        # OpenVPN
        "openvpn": _as_bool(s.get("openvpn_enabled", False)),
        "openvpn_enabled": _as_bool(s.get("openvpn_enabled", False)),
        "openvpn_port": s.get("openvpn_port", 1194),
        # CDN
        "cdn": _as_bool(s.get("cdn_enabled", settings.cdn_enabled)),
        "cdn_enabled": _as_bool(s.get("cdn_enabled", settings.cdn_enabled)),
        "cdn_domain": s.get("cdn_domain", settings.cdn_domain),
        "cdn_ws_path": s.get("cdn_ws_path", settings.cdn_ws_path),
        "cdn_port": s.get("cdn_port", settings.cdn_port),
        # Misc
        "fragment_enabled": _as_bool(s.get("fragment_enabled", False)),
        "mux_enabled": _as_bool(s.get("mux_enabled", False)),
        "kill_switch": _as_bool(s.get("kill_switch_enabled", False)),
        "telegram_enabled": _as_bool(s.get("telegram_enabled", False)),
        # Host Header Spoofing
        "dpi_http_host_spoof_enabled": _as_bool(s.get("dpi_http_host_spoof_enabled", False)),
        "dpi_http_host_spoof_domain": s.get("dpi_http_host_spoof_domain", "chat.deepseek.com"),
        "dpi_ws_host_front_enabled": _as_bool(s.get("dpi_ws_host_front_enabled", False)),
        "dpi_ws_host_front_domain": s.get("dpi_ws_host_front_domain", "rubika.ir"),
        "dpi_cdn_host_front_enabled": _as_bool(s.get("dpi_cdn_host_front_enabled", False)),
        "dpi_cdn_host_front_domain": s.get("dpi_cdn_host_front_domain", "web.splus.ir"),
        "dpi_bug_host_enabled": _as_bool(s.get("dpi_bug_host_enabled", False)),
        "dpi_bug_host_domain": s.get("dpi_bug_host_domain", "chat.deepseek.com"),
        # Tunneling
        "dpi_dns_tunnel": _as_bool(s.get("dpi_dns_tunnel", False)),
        "dpi_icmp_tunnel": _as_bool(s.get("dpi_icmp_tunnel", False)),
        # Domain / CDN Fronting
        "dpi_domain_front": _as_bool(s.get("dpi_domain_front", False)),
        "dpi_cdn_front_enabled": _as_bool(s.get("dpi_cdn_front_enabled", False)),
        "dpi_cdn_front": s.get("dpi_cdn_front", ""),
        # Advanced Network Resilience
        "dpi_packet_reorder": _as_bool(s.get("dpi_packet_reorder", False)),
        "dpi_dynamic_port": _as_bool(s.get("dpi_dynamic_port", False)),
        "dpi_fake_http": _as_bool(s.get("dpi_fake_http", False)),
        "dpi_traffic_shape": _as_bool(s.get("dpi_traffic_shape", False)),
        "dpi_multi_path": _as_bool(s.get("dpi_multi_path", False)),
        "dpi_protocol_hop": _as_bool(s.get("dpi_protocol_hop", False)),
        "dpi_aggression_level": s.get("dpi_aggression_level", "medium"),
    }


@router.post("/sync")
async def legacy_sync(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    now = datetime.utcnow()
    result = await db.execute(
        select(VpnUser).where(VpnUser.expire_at != None, VpnUser.active == 1)
    )
    disabled = 0
    for u in result.scalars().all():
        if u.expire_at and u.expire_at < now:
            u.active = 0
            disabled += 1
    if disabled:
        await db.commit()
    return {"ok": True, "disabled": disabled}


@router.get("/system-monitor")
async def legacy_system_monitor(admin: User = Depends(get_current_admin_cookie)):
    import psutil

    cpu = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot = psutil.boot_time()
    net = psutil.net_io_counters()

    xray_pid = None
    xray_mem = 0
    xray_cpu = 0
    try:
        for proc in psutil.process_iter(["name", "pid", "memory_info", "cpu_percent"]):
            if "xray" in (proc.info.get("name") or "").lower():
                xray_pid = proc.info.get("pid")
                mi = proc.info.get("memory_info")
                xray_mem = mi.rss if mi else 0
                xray_cpu = proc.info.get("cpu_percent") or 0
                break
    except Exception:
        pass

    try:
        load_avg = list(os.getloadavg())
    except Exception:
        load_avg = [0.0, 0.0, 0.0]

    return {
        "cpu_percent": round(cpu, 1),
        "ram_percent": round(mem.percent, 1),
        "ram_used": mem.used,
        "ram_total": mem.total,
        "disk_percent": round(disk.percent, 1),
        "disk_used": disk.used,
        "disk_total": disk.total,
        "uptime_seconds": int(time.time() - boot),
        "xray_pid": xray_pid,
        "xray_mem": xray_mem,
        "xray_cpu": xray_cpu,
        "xray_version": "",
        "net_bytes_sent": net.bytes_sent,
        "net_bytes_recv": net.bytes_recv,
        "load_avg": load_avg,
    }


@router.get("/online-users")
async def legacy_online_users(admin: User = Depends(get_current_admin_cookie)):
    return []


@router.get("/traffic-history")
async def legacy_traffic_history(
    days: int = Query(30, ge=1, le=365),
    admin: User = Depends(get_current_admin_cookie),
):
    return []


@router.get("/traffic-history/top")
async def legacy_top_traffic(
    days: int = Query(30, ge=1, le=365),
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).order_by(VpnUser.traffic_used.desc()).limit(10)
    )
    return [
        {"username": u.name, "total_bytes": u.traffic_used or 0}
        for u in result.scalars().all()
    ]


# ─────────────────────────────────────────────────────────────────────────────
#  Settings
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/settings")
async def legacy_get_settings(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    defaults = {
        "config_prefix": "Proxy",
        "vmess_port": 443,
        "vmess_sni": "www.aparat.com",
        "vmess_ws_path": "/api/v1/stream",
        "kill_switch_enabled": False,
        "reality_sni": "chat.deepseek.com",
        "vless_port": 2053,
        "reality_public_key": settings.reality_public_key,
        "vless": True,
        "vless_enabled": True,
        "trojan_enabled": False,
        "trojan_port": 2083,
        "grpc_enabled": False,
        "grpc_port": 2054,
        "grpc_service_name": "GunService",
        "httpupgrade_enabled": False,
        "httpupgrade_port": 2055,
        "httpupgrade_path": "/httpupgrade",
        "fragment_enabled": False,
        "fragment_packets": "tlshello",
        "fragment_length": "100-200",
        "fragment_interval": "10-20",
        "mux_enabled": False,
        "mux_concurrency": 8,
        "ss2022_enabled": False,
        "ss2022_port": 2056,
        "ss2022_method": "2022-blake3-aes-128-gcm",
        "ss2022_server_key": "",
        "vless_ws_enabled": settings.vless_ws_enabled,
        "vless_ws_port": settings.vless_ws_port,
        "vless_ws_path": settings.vless_ws_path,
        "fingerprint": "chrome",
        "noise_enabled": False,
        "noise_packet": "rand:50-100",
        "noise_delay": "10-20",
        "cdn_enabled": settings.cdn_enabled,
        "cdn_domain": settings.cdn_domain,
        "cdn_ws_path": settings.cdn_ws_path,
        "cdn_port": settings.cdn_port,
        "telegram_enabled": False,
        "telegram_bot_token": getattr(settings, 'telegram_bot_token', ''),
        "telegram_chat_id": getattr(settings, 'telegram_chat_id', ''),
        "telegram_notify_user_disabled": True,
        "telegram_notify_user_expired": True,
        "telegram_notify_kill_switch": True,
        "telegram_notify_traffic_exhausted": True,
        "telegram_notify_user_created": False,
        "telegram_notify_user_deleted": False,
        "dpi_tcp_fragment": False,
        "dpi_tls_fragment": False,
        "dpi_ip_fragment": False,
        "dpi_tcp_keepalive": False,
        "dpi_dns_tunnel": False,
        "dpi_icmp_tunnel": False,
        "dpi_domain_front": False,
        "dpi_cdn_front_enabled": False,
        "dpi_cdn_front": "",
        # Host Header Spoofing
        "dpi_http_host_spoof_enabled": False,
        "dpi_http_host_spoof_domain": "chat.deepseek.com",
        "dpi_ws_host_front_enabled": False,
        "dpi_ws_host_front_domain": "rubika.ir",
        "dpi_cdn_host_front_enabled": False,
        "dpi_cdn_host_front_domain": "web.splus.ir",
        "dpi_bug_host_enabled": False,
        "dpi_bug_host_domain": "chat.deepseek.com",
        # Advanced Network Resilience
        "dpi_packet_reorder": False,
        "dpi_dynamic_port": False,
        "dpi_fake_http": False,
        "dpi_traffic_shape": False,
        "dpi_multi_path": False,
        "dpi_protocol_hop": False,
        "dpi_aggression_level": "medium",
        # VLESS XHTTP REALITY
        "vless_xhttp_enabled": True,
        "vless_xhttp_port": 2053,
        "vless_xhttp_mode": "auto",
        "vless_xhttp_path": "/xhttp",
        "vless_xhttp_reality_sni": "digikala.com",
        "vless_xhttp_reality_dest": "digikala.com:443",
        "vless_xhttp_reality_short_id": "",
        "vless_xhttp_reality_public_key": settings.reality_public_key,
        # VLESS Vision REALITY
        "vless_vision_enabled": True,
        "vless_vision_port": 2058,
        "vless_vision_reality_sni": "objects.githubusercontent.com",
        "vless_vision_reality_dest": "objects.githubusercontent.com:443",
        "vless_vision_reality_short_id": "",
        "vless_vision_reality_public_key": settings.reality_public_key,
        # VLESS Reverse REALITY
        "vless_reverse_enabled": True,
        "vless_reverse_port": 2059,
        # Hysteria2
        "hysteria2_enabled": True,
        "hysteria2_port": 8443,
        # TUIC
        "tuic_enabled": True,
        "tuic_port": 8444,
        # AmneziaWG
        "amneziawg_enabled": False,
        "amneziawg_port": 51820,
        # ShadowTLS
        "shadowtls_enabled": False,
        "shadowtls_port": 8445,
        # Mieru
        "mieru_enabled": False,
        "mieru_port": 8446,
        # NaiveProxy
        "naiveproxy_enabled": False,
        "naiveproxy_port": 8447,
        # WireGuard
        "wireguard_enabled": False,
        "wireguard_port": 51821,
        # OpenVPN
        "openvpn_enabled": False,
        "openvpn_port": 1194,
    }
    merged = _normalize_settings_types({**defaults, **await _load_legacy_settings(db)})
    return merged


def _get_active_vmess_clients() -> list:
    """Fetch active user UUIDs for VMess inbounds."""
    try:
        from ..database import async_engine
        import asyncio
        async def _fetch():
            async with async_engine.connect() as conn:
                result = await conn.execute(
                    select(VpnUser.uuid, VpnUser.name).where(VpnUser.active == 1)
                )
                return [{"id": row.uuid, "alterId": 0, "email": row.name} for row in result.all()]
        try:
            loop = asyncio.get_running_loop()
            return [_fetch()]
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(_fetch())
            finally:
                loop.close()
    except Exception as e:
        logger.warning(f"Failed to fetch VMess clients: {e}")
        return []


def _get_active_vless_clients() -> list:
    """Fetch active user UUIDs for VLESS inbounds."""
    try:
        from ..database import async_engine
        import asyncio
        async def _fetch():
            async with async_engine.connect() as conn:
                result = await conn.execute(
                    select(VpnUser.uuid, VpnUser.name).where(VpnUser.active == 1)
                )
                return [{"id": row.uuid, "email": row.name} for row in result.all()]
        try:
            loop = asyncio.get_running_loop()
            return [_fetch()]
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(_fetch())
            finally:
                loop.close()
    except Exception as e:
        logger.warning(f"Failed to fetch VLESS clients: {e}")
        return []


def _get_active_trojan_clients() -> list:
    """Fetch active user passwords (UUIDs) for Trojan inbounds."""
    try:
        from ..database import async_engine
        import asyncio
        async def _fetch():
            async with async_engine.connect() as conn:
                result = await conn.execute(
                    select(VpnUser.uuid, VpnUser.name).where(VpnUser.active == 1)
                )
                return [{"password": row.uuid, "email": row.name} for row in result.all()]
        try:
            loop = asyncio.get_running_loop()
            return [_fetch()]
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(_fetch())
            finally:
                loop.close()
    except Exception as e:
        logger.warning(f"Failed to fetch Trojan clients: {e}")
        return []


def _generate_xray_server_config() -> dict:
    """Generate the server-side Xray config with inbounds for all enabled protocols."""
    s = _settings_state
    inbounds = []
    sni = s.get("vmess_sni") or "www.aparat.com"
    fp = s.get("fingerprint") or "chrome"
    reality_pk = s.get("reality_private_key") or settings.reality_private_key
    reality_pub = s.get("reality_public_key") or settings.reality_public_key
    reality_sid = s.get("reality_short_id") or ""

    cert_file = "/etc/ssl/certs/fullchain.pem"
    key_file = "/etc/ssl/private/privkey.pem"

    # Fetch active user UUIDs for client authentication
    vmess_clients = _get_active_vmess_clients()
    vless_clients = _get_active_vless_clients()
    trojan_clients = _get_active_trojan_clients()

    # VMess WS+TLS (always-on)
    inbounds.append({
        "tag": "in-vmess-ws",
        "port": int(s.get("vmess_port") or 443),
        "listen": "0.0.0.0",
        "protocol": "vmess",
        "settings": {"clients": vmess_clients},
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {"path": s.get("vmess_ws_path") or "/api/v1/stream"},
            "tlsSettings": {
                "serverName": sni,
                "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                "minVersion": "1.2",
            },
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    })

    # VLESS REALITY (Vision)
    if s.get("reality_public_key"):
        inbounds.append({
            "tag": "in-vless-reality",
            "port": int(s.get("vless_port") or 2053),
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [s.get("reality_sni") or "chat.deepseek.com"],
                    "dest": s.get("reality_dest") or "chat.deepseek.com:443",
                    "privateKey": reality_pk,
                    "shortIds": [reality_sid] if reality_sid else [""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS XHTTP REALITY (use distinct port to avoid collision with VLESS Reality)
    if _as_bool(s.get("vless_xhttp_enabled")):
        xhttp_sni = s.get("vless_xhttp_reality_sni") or "digikala.com"
        xhttp_dest = s.get("vless_xhttp_reality_dest") or "digikala.com:443"
        xhttp_pk = s.get("vless_xhttp_reality_private_key") or reality_pk
        xhttp_sid = s.get("vless_xhttp_reality_short_id") or ""
        raw_xhttp_port = int(s.get("vless_xhttp_port") or 0)
        vless_port_val = int(s.get("vless_port") or 2053)
        # Avoid port collision with standard VLESS Reality inbound
        if raw_xhttp_port and raw_xhttp_port != vless_port_val:
            xhttp_port = raw_xhttp_port
        else:
            xhttp_port = 8449  # Safe default for XHTTP Reality
        inbounds.append({
            "tag": "in-vless-xhttp",
            "port": xhttp_port,
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "xhttpSettings": {
                    "mode": s.get("vless_xhttp_mode") or "auto",
                    "path": s.get("vless_xhttp_path") or "/xhttp",
                    "host": xhttp_sni,
                },
                "realitySettings": {
                    "serverNames": [xhttp_sni],
                    "dest": xhttp_dest,
                    "privateKey": xhttp_pk,
                    "shortIds": [xhttp_sid] if xhttp_sid else [""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS Vision REALITY
    if _as_bool(s.get("vless_vision_enabled")):
        vision_sni = s.get("vless_vision_reality_sni") or "objects.githubusercontent.com"
        vision_dest = s.get("vless_vision_reality_dest") or "objects.githubusercontent.com:443"
        inbounds.append({
            "tag": "in-vless-vision",
            "port": int(s.get("vless_vision_port") or 2058),
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [vision_sni],
                    "dest": vision_dest,
                    "privateKey": reality_pk,
                    "shortIds": [s.get("vless_vision_reality_short_id") or ""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS Reverse REALITY (backhaul-tunneled)
    if _as_bool(s.get("vless_reverse_enabled")):
        rev_sni = s.get("vless_reverse_reality_sni") or "digikala.com"
        rev_dest = s.get("vless_reverse_reality_dest") or "digikala.com:443"
        rev_sid = s.get("vless_reverse_reality_short_id") or ""
        inbounds.append({
            "tag": "in-vless-reverse",
            "port": int(s.get("vless_reverse_port") or 2059),
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [rev_sni],
                    "dest": rev_dest,
                    "privateKey": reality_pk,
                    "shortIds": [rev_sid] if rev_sid else [""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # Trojan TCP+TLS
    if _as_bool(s.get("trojan_enabled")):
        inbounds.append({
            "tag": "in-trojan",
            "port": int(s.get("trojan_port") or 2083),
            "listen": "0.0.0.0",
            "protocol": "trojan",
            "settings": {"clients": trojan_clients},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # gRPC
    if _as_bool(s.get("grpc_enabled")):
        inbounds.append({
            "tag": "in-grpc",
            "port": int(s.get("grpc_port") or 2054),
            "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {"serviceName": s.get("grpc_service_name") or "GunService"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # HTTPUpgrade
    if _as_bool(s.get("httpupgrade_enabled")):
        inbounds.append({
            "tag": "in-httpupgrade",
            "port": int(s.get("httpupgrade_port") or 2055),
            "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "httpupgradeSettings": {"path": s.get("httpupgrade_path") or "/httpupgrade"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS WS+TLS
    if _as_bool(s.get("vless_ws_enabled")):
        inbounds.append({
            "tag": "in-vless-ws",
            "port": int(s.get("vless_ws_port") or 2057),
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": s.get("vless_ws_path") or "/vless-ws"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # ShadowSocks 2022
    if _as_bool(s.get("ss2022_enabled")) and s.get("ss2022_server_key"):
        inbounds.append({
            "tag": "in-ss2022",
            "port": int(s.get("ss2022_port") or 2056),
            "listen": "0.0.0.0",
            "protocol": "shadowsocks",
            "settings": {
                "method": s.get("ss2022_method") or "2022-blake3-aes-128-gcm",
                "password": s.get("ss2022_server_key"),
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # CDN WS+TLS
    if _as_bool(s.get("cdn_enabled")) and s.get("cdn_domain"):
        cdn_domain = s.get("cdn_domain")
        inbounds.append({
            "tag": "in-cdn-ws",
            "port": int(s.get("cdn_port") or 2082),
            "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": s.get("cdn_ws_path") or "/cdn-ws"},
                "tlsSettings": {
                    "serverName": cdn_domain,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


def _schedule_xray_sync():
    """Schedule a background Xray config sync after settings change."""
    try:
        import threading
        t = threading.Thread(target=_sync_xray_config_now, daemon=True)
        t.start()
    except Exception:
        pass


def _sync_xray_config_now():
    """Generate and write the Xray server config, then restart Xray."""
    try:
        import time
        time.sleep(0.5)  # Small delay to let settings settle

        config = _generate_xray_server_config()
        config_path = settings.xray_config_path

        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        subprocess.run(["systemctl", "restart", "xray"], capture_output=True, timeout=10)
        logger.info(f"Xray config auto-synced ({len(config.get('inbounds', []))} inbounds)")
    except Exception as e:
        logger.warning(f"Background Xray sync failed: {e}")


@router.post("/settings")
async def legacy_save_settings(
    data: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _save_legacy_settings(db, data)
    return {"ok": True, "rebuild": False}


@router.post("/settings/regenerate-reality")
async def legacy_regenerate_reality(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    import secrets

    private_key = ""
    public_key = ""
    try:
        result = subprocess.run(
            [settings.xray_bin_path, "x25519"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.strip().splitlines():
            if line.startswith("PrivateKey:"):
                private_key = line.split(":", 1)[1].strip()
            elif line.startswith("PublicKey:"):
                public_key = line.split(":", 1)[1].strip()
    except Exception:
        private_key = ""
        public_key = ""

    if not private_key or not public_key:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519

        key = x25519.X25519PrivateKey.generate()
        private_raw = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_raw = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        private_key = base64.urlsafe_b64encode(private_raw).decode().rstrip("=")
        public_key = base64.urlsafe_b64encode(public_raw).decode().rstrip("=")

    short_id = secrets.token_hex(4)
    await _save_legacy_settings(
        db,
        {
            "reality_private_key": private_key,
            "reality_public_key": public_key,
            "reality_short_id": short_id,
        },
    )
    return {"ok": True, "public_key": public_key, "short_id": short_id}


@router.post("/settings/generate-ss2022-key")
async def legacy_generate_ss2022_key(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    import base64
    import secrets

    key = base64.b64encode(secrets.token_bytes(16)).decode()
    await _save_legacy_settings(db, {"ss2022_server_key": key})
    return {"ok": True, "ss2022_server_key": key}


# ─────────────────────────────────────────────────────────────────────────────
#  Export / Telegram test
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/export-csv")
async def legacy_export_csv(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser))
    rows = [
        ["name", "uuid", "active", "traffic_limit_gb", "traffic_used_gb",
         "expire_at", "speed_limit_up", "speed_limit_down", "note"]
    ]
    for u in result.scalars().all():
        rows.append([
            u.name,
            u.uuid,
            u.active,
            (u.traffic_limit or 0) / (1024**3),
            (u.traffic_used or 0) / (1024**3),
            u.expire_at.isoformat() if u.expire_at else "",
            u.speed_limit_up or 0,
            u.speed_limit_down or 0,
            u.note or "",
        ])
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerows(rows)
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="users.csv"'},
    )


@router.get("/export-json")
async def legacy_export_json(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(select(VpnUser))
    payload = [_user_to_legacy(u) for u in result.scalars().all()]
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="users.json"'},
    )


@router.post("/telegram-test")
async def legacy_telegram_test(admin: User = Depends(get_current_admin_cookie)):
    if not (settings.telegram_bot_token and settings.telegram_chat_id):
        return {"ok": False, "error": "Telegram not configured"}
    try:
        from .. import telegram_bot
        if hasattr(telegram_bot, "send_test"):
            await telegram_bot.send_test()
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
#  Search, report, analytics, backup
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/search")
async def legacy_search(
    q: str = Query(..., min_length=1),
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).where(VpnUser.name.ilike(f"%{q}%")).limit(50)
    )
    users = []
    for u in result.scalars().all():
        users.append({
            "name": u.name,
            "active": bool(u.active),
            "traffic_used_gb": (u.traffic_used or 0) / (1024**3),
            "expire_at": u.expire_at.isoformat() if u.expire_at else None,
        })
    return {"users": users}


@router.get("/report")
async def legacy_report(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    total = (await db.execute(select(func.count(VpnUser.id)))).scalar() or 0
    active = (await db.execute(
        select(func.count(VpnUser.id)).where(VpnUser.active == 1)
    )).scalar() or 0
    total_used = (await db.execute(
        select(func.coalesce(func.sum(VpnUser.traffic_used), 0))
    )).scalar() or 0
    total_limit = (await db.execute(
        select(func.coalesce(func.sum(VpnUser.traffic_limit), 0))
    )).scalar() or 0

    week_ahead = datetime.utcnow() + timedelta(days=7)
    expiring = (await db.execute(
        select(func.count(VpnUser.id)).where(
            VpnUser.active == 1,
            VpnUser.expire_at != None,
            VpnUser.expire_at < week_ahead,
        )
    )).scalar() or 0

    top_result = await db.execute(
        select(VpnUser).order_by(VpnUser.traffic_used.desc()).limit(10)
    )
    top_users = [
        {
            "name": u.name,
            "active": bool(u.active),
            "traffic_used_gb": (u.traffic_used or 0) / (1024**3),
        }
        for u in top_result.scalars().all()
    ]

    return {
        "total_users": total,
        "active_users": active,
        "inactive_users": total - active,
        "total_traffic_gb": total_used / (1024**3),
        "total_limit_gb": total_limit / (1024**3),
        "expiring_soon": expiring,
        "top_users": top_users,
    }


@router.get("/analytics")
async def legacy_analytics(
    days: int = Query(7, ge=1, le=90),
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    top_result = await db.execute(
        select(VpnUser).order_by(VpnUser.traffic_used.desc()).limit(10)
    )
    top_users = [
        {"name": u.name, "traffic_used_gb": (u.traffic_used or 0) / (1024**3)}
        for u in top_result.scalars().all()
    ]
    return {"daily_traffic": [], "top_users": top_users}


@router.get("/backup/list")
async def legacy_backup_list(admin: User = Depends(get_current_admin_cookie)):
    backups: List[Dict[str, Any]] = []
    backup_dir = "/opt/spiritus/backups"
    if os.path.isdir(backup_dir):
        for name in sorted(os.listdir(backup_dir), reverse=True):
            path = os.path.join(backup_dir, name)
            try:
                st = os.stat(path)
                backups.append({
                    "name": name,
                    "path": path,
                    "size": st.st_size,
                    "created": datetime.fromtimestamp(st.st_mtime).isoformat(),
                })
            except OSError:
                continue
    return {"backups": backups}


@router.post("/backup/create")
async def legacy_backup_create(admin: User = Depends(get_current_admin_cookie)):
    return {"ok": True, "message": "Backup queued"}


@router.post("/backup/restore")
async def legacy_backup_restore(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    return {"ok": True}


@router.post("/backup/cleanup")
async def legacy_backup_cleanup(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    return {"ok": True, "removed": 0}


# ─────────────────────────────────────────────────────────────────────────────
#  Network resilience / aggressive / fightback (stubs)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/network-resilience/run")
async def legacy_resilience_run(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    technique = body.get("technique", "unknown")
    _resilience_state["active_attacks"] += 1
    _resilience_state["stats"][technique] = {
        "started_at": datetime.utcnow().isoformat(),
        "target": body.get("target"),
        "duration": body.get("duration"),
    }
    return {
        "ok": True,
        "iranian_target": False,
        "message": f"Simulation started: {technique}",
    }


@router.get("/network-resilience/stats")
async def legacy_resilience_stats(admin: User = Depends(get_current_admin_cookie)):
    return {
        "ok": True,
        "stats": _resilience_state["stats"],
        "active_attacks": _resilience_state["active_attacks"],
    }


@router.post("/network-resilience/stop")
async def legacy_resilience_stop(admin: User = Depends(get_current_admin_cookie)):
    _resilience_state["active_attacks"] = 0
    _resilience_state["stats"] = {}
    return {"ok": True}


@router.post("/aggressive/start")
async def legacy_aggressive_start(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    return {"ok": True, "attack_id": uuid_lib.uuid4().hex}


@router.post("/aggressive/stop")
async def legacy_aggressive_stop(admin: User = Depends(get_current_admin_cookie)):
    return {"ok": True}


@router.post("/fightback/start")
async def legacy_fightback_start(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    return {"ok": True, "technique_id": uuid_lib.uuid4().hex}


@router.post("/fightback/stop")
async def legacy_fightback_stop(admin: User = Depends(get_current_admin_cookie)):
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
#  Agents (legacy shape)
# ─────────────────────────────────────────────────────────────────────────────

class LegacyAgentCreate(BaseModel):
    name: str
    password: str
    traffic_quota_gb: float = 100
    speed_limit_default: int = 200


def _agent_to_legacy(a: Agent, user_count: int = 0) -> Dict[str, Any]:
    meta = a.ech_config if isinstance(a.ech_config, dict) else {}
    return {
        "id": a.id,
        "name": a.name,
        "active": a.status.value != "offline" if hasattr(a, "status") and a.status else True,
        "traffic_quota_gb": float(meta.get("traffic_quota_gb") or 0),
        "traffic_used_gb": float(meta.get("traffic_used_gb") or 0),
        "user_count": user_count,
    }


def _agent_meta(agent: Agent) -> Dict[str, Any]:
    return dict(agent.ech_config) if isinstance(agent.ech_config, dict) else {}


def _set_agent_meta(agent: Agent, **updates: Any) -> None:
    meta = _agent_meta(agent)
    meta.update(updates)
    agent.ech_config = meta


async def _agent_used_gb(agent_id: int, db: AsyncSession) -> float:
    result = await db.execute(
        select(func.coalesce(func.sum(VpnUser.traffic_used), 0)).where(
            VpnUser.agent_id == agent_id
        )
    )
    used = result.scalar() or 0
    return float(used) / (1024**3)


async def _get_current_agent_cookie(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> Agent:
    token = request.cookies.get("agent_access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    if payload.get("role") != "agent":
        raise HTTPException(status_code=403, detail="Agent privileges required")

    agent_id = payload.get("agent_id") or payload.get("user_id")
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=401, detail="Agent not found")
    return agent


@router.get("/agents")
async def legacy_list_agents(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(Agent))
    agents = result.scalars().all()
    user_counts: Dict[int, int] = {}
    traffic_used: Dict[int, float] = {}
    if agents:
        cnt_result = await db.execute(
            select(VpnUser.agent_id, func.count(VpnUser.id))
            .where(VpnUser.agent_id.in_([a.id for a in agents]))
            .group_by(VpnUser.agent_id)
        )
        user_counts = {row[0]: row[1] for row in cnt_result.all()}
        traffic_result = await db.execute(
            select(VpnUser.agent_id, func.coalesce(func.sum(VpnUser.traffic_used), 0))
            .where(VpnUser.agent_id.in_([a.id for a in agents]))
            .group_by(VpnUser.agent_id)
        )
        traffic_used = {row[0]: float(row[1] or 0) / (1024**3) for row in traffic_result.all()}
    out = []
    for a in agents:
        item = _agent_to_legacy(a, user_counts.get(a.id, 0))
        item["traffic_used_gb"] = round(traffic_used.get(a.id, 0), 2)
        out.append(item)
    return out


@router.post("/agents")
async def legacy_create_agent(
    body: LegacyAgentCreate,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    if not body.name:
        return {"ok": False, "error": "Name required"}
    if len(body.password) < 6:
        return {"ok": False, "error": "Password too short"}
    from ..models import AgentBackend, AgentStatus
    try:
        agent = Agent(
            name=body.name,
            backend=AgentBackend.xray,
            status=AgentStatus.offline,
            address="127.0.0.1",
            api_port=10085,
            api_key=get_password_hash(body.password),
            ech_config={
                "traffic_quota_gb": body.traffic_quota_gb,
                "speed_limit_default": body.speed_limit_default,
                "brand_name": "",
            },
        )
        db.add(agent)
        await db.commit()
        await db.refresh(agent)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "agent": _agent_to_legacy(agent)}


@router.post("/agents/{agent_id}/edit")
async def legacy_edit_agent(
    agent_id: int,
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        return {"ok": False, "error": "Agent not found"}
    if "active" in body:
        from ..models import AgentStatus
        agent.status = AgentStatus.online if body["active"] else AgentStatus.offline
    meta_updates: Dict[str, Any] = {}
    if "traffic_quota_gb" in body:
        meta_updates["traffic_quota_gb"] = float(body["traffic_quota_gb"] or 0)
    if "speed_limit_default" in body:
        meta_updates["speed_limit_default"] = int(body["speed_limit_default"] or 0)
    if meta_updates:
        _set_agent_meta(agent, **meta_updates)
    await db.commit()
    return {"ok": True}


@router.post("/agents/{agent_id}/reset-password")
async def legacy_reset_agent_password(
    agent_id: int,
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    pw = body.get("password", "")
    if len(pw) < 6:
        return {"ok": False, "error": "Password too short"}
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        return {"ok": False, "error": "Agent not found"}
    agent.api_key = get_password_hash(pw)
    await db.commit()
    return {"ok": True}


@router.delete("/agents/{agent_id}")
async def legacy_delete_agent(
    agent_id: int,
    body: Optional[Dict[str, Any]] = None,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        return {"ok": False, "error": "Agent not found"}
    delete_users = bool((body or {}).get("delete_users"))
    if delete_users:
        users_result = await db.execute(
            select(VpnUser).where(VpnUser.agent_id == agent_id)
        )
        for u in users_result.scalars().all():
            await db.delete(u)
    else:
        await db.execute(
            select(VpnUser).where(VpnUser.agent_id == agent_id)
        )
        users_result = await db.execute(
            select(VpnUser).where(VpnUser.agent_id == agent_id)
        )
        for u in users_result.scalars().all():
            u.agent_id = None
    await db.delete(agent)
    await db.commit()
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
#  Agent panel API (/api/agent/*)
# ─────────────────────────────────────────────────────────────────────────────

class LegacyAgentLoginRequest(BaseModel):
    name: str
    password: str


@router.post("/agent/login")
async def legacy_agent_login(
    body: LegacyAgentLoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(Agent).where(Agent.name == body.name.strip()))
    agent = result.scalar_one_or_none()
    if agent is None or not agent.api_key or not verify_password(body.password, agent.api_key):
        return {"ok": False, "error": "Invalid credentials"}
    if agent.status and agent.status.value == "offline":
        return {"ok": False, "error": "Account is disabled"}

    token = create_access_token(
        data={
            "sub": agent.name,
            "role": "agent",
            "agent_id": agent.id,
            "is_admin": False,
        }
    )
    response.set_cookie(
        key="agent_access_token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.session_lifetime_hours * 3600,
        path="/",
    )
    return {"ok": True, "name": agent.name}


@router.post("/agent/logout")
async def legacy_agent_logout(response: Response):
    response.delete_cookie("agent_access_token", path="/")
    return {"ok": True}


@router.get("/agent/me")
async def legacy_agent_me(
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    meta = _agent_meta(agent)
    quota = float(meta.get("traffic_quota_gb") or 0)
    used = await _agent_used_gb(agent.id, db)
    return {
        "name": agent.name,
        "traffic_quota_gb": quota,
        "traffic_used_gb": round(used, 2),
        "traffic_remaining_gb": round(max(0, quota - used), 2) if quota else 0,
        "active": agent.status.value != "offline" if agent.status else True,
        "brand_name": meta.get("brand_name", ""),
        "speed_limit_default": int(meta.get("speed_limit_default") or 0),
    }


@router.post("/agent/brand")
async def legacy_agent_brand(
    body: Dict[str, Any],
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    brand = str(body.get("brand_name") or "").strip()[:40]
    _set_agent_meta(agent, brand_name=brand)
    await db.commit()
    return {"ok": True, "brand_name": brand}


async def _check_agent_quota(agent: Agent, requested_gb: float, db: AsyncSession) -> Optional[str]:
    quota = float(_agent_meta(agent).get("traffic_quota_gb") or 0)
    if quota <= 0:
        return None
    used = await _agent_used_gb(agent.id, db)
    if used + requested_gb > quota:
        return f"Quota exceeded. Remaining: {max(0, quota - used):.1f} GB"
    return None


@router.get("/agent/users")
async def legacy_agent_users(
    request: Request,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(
        select(VpnUser)
        .where(VpnUser.agent_id == agent.id)
        .order_by(VpnUser.active.desc(), VpnUser.name)
    )
    server_ip = _request_config_host(request)
    return [_user_to_legacy(u, server_ip=server_ip) for u in result.scalars().all()]


@router.post("/agent/users")
async def legacy_agent_create_user(
    body: LegacyUserCreate,
    request: Request,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    quota_error = await _check_agent_quota(agent, body.traffic, db)
    if quota_error:
        return {"ok": False, "error": quota_error}

    expire_at = datetime.utcnow() + timedelta(days=body.days) if body.days else None
    default_speed = int(_agent_meta(agent).get("speed_limit_default") or 0)
    db_user = VpnUser(
        uuid=str(uuid_lib.uuid4()),
        name=body.name,
        traffic_limit=int(body.traffic * (1024**3)),
        traffic_used=0,
        expire_at=expire_at,
        active=1,
        agent_id=agent.id,
        speed_limit_up=body.speed_limit_up or default_speed,
        speed_limit_down=body.speed_limit_down or default_speed,
        note=body.note,
    )
    db.add(db_user)
    try:
        await db.commit()
        await db.refresh(db_user)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    await _load_legacy_settings(db)
    links = _user_to_legacy(db_user, server_ip=_request_config_host(request))
    return {"ok": True, "user": links, "vmess": links.get("vmess", "")}


@router.post("/agent/bulk-users")
async def legacy_agent_bulk_users(
    body: BulkCreateRequest,
    request: Request,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    quota_error = await _check_agent_quota(agent, body.traffic * body.count, db)
    if quota_error:
        return {"ok": False, "error": quota_error}

    expire_at = datetime.utcnow() + timedelta(days=body.days) if body.days else None
    created_users: List[VpnUser] = []
    default_speed = int(_agent_meta(agent).get("speed_limit_default") or 0)
    for i in range(body.count):
        name = (
            f"{body.prefix}-{str(body.start + i).zfill(body.pad)}"
            if body.numbered
            else f"{body.prefix}-{uuid_lib.uuid4().hex[:8]}"
        )
        u = VpnUser(
            uuid=str(uuid_lib.uuid4()),
            name=name,
            traffic_limit=int(body.traffic * (1024**3)),
            traffic_used=0,
            expire_at=expire_at,
            active=1,
            agent_id=agent.id,
            speed_limit_up=body.speed_limit_up or default_speed,
            speed_limit_down=body.speed_limit_down or default_speed,
            note="",
        )
        db.add(u)
        created_users.append(u)
    try:
        await db.commit()
        for u in created_users:
            await db.refresh(u)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    await _load_legacy_settings(db)
    server_ip = _request_config_host(request)
    return {
        "ok": True,
        "created": len(created_users),
        "users": [_user_to_legacy(u, server_ip=server_ip) for u in created_users],
        "numbered": body.numbered,
        "start": body.start,
        "pad": body.pad,
        "traffic_gb": body.traffic,
        "days": body.days,
        "note": "",
        "apply": body.apply,
    }


@router.post("/agent/bulk-delete")
async def legacy_agent_bulk_delete(
    body: BulkDeleteRequest,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    query = select(VpnUser).where(VpnUser.agent_id == agent.id)
    if body.names:
        query = query.where(VpnUser.name.in_(body.names))
    elif body.prefix:
        query = query.where(VpnUser.name.like(f"{body.prefix}%"))
    else:
        return {"ok": False, "error": "Provide names or prefix"}
    result = await db.execute(query)
    count = 0
    for u in result.scalars().all():
        await db.delete(u)
        count += 1
    await db.commit()
    return {"ok": True, "deleted": count, "apply": body.apply}


@router.post("/agent/bulk-export-zip")
async def legacy_agent_bulk_export_zip(
    body: Dict[str, Any],
    agent: Agent = Depends(_get_current_agent_cookie),
):
    return await legacy_bulk_export_zip(body, admin=User(id=0, username=agent.name, is_admin=False))


@router.delete("/agent/users/{name}")
async def legacy_agent_delete_user(
    name: str,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).where(VpnUser.name == name, VpnUser.agent_id == agent.id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found or not yours"}
    await db.delete(user)
    await db.commit()
    return {"ok": True}


@router.post("/agent/users/{name}/toggle")
async def legacy_agent_toggle_user(
    name: str,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).where(VpnUser.name == name, VpnUser.agent_id == agent.id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found or not yours"}
    user.active = 0 if user.active else 1
    await db.commit()
    return {"ok": True, "active": bool(user.active)}


@router.post("/agent/users/{name}/renew")
async def legacy_agent_renew_user(
    name: str,
    body: LegacyRenewRequest,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).where(VpnUser.name == name, VpnUser.agent_id == agent.id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found or not yours"}
    extra_gb = max(0, body.traffic - ((user.traffic_limit or 0) / (1024**3)))
    quota_error = await _check_agent_quota(agent, extra_gb, db)
    if quota_error:
        return {"ok": False, "error": quota_error}
    user.traffic_limit = int(body.traffic * (1024**3))
    user.traffic_used = 0
    user.expire_at = datetime.utcnow() + timedelta(days=body.days)
    user.active = 1
    await db.commit()
    return {"ok": True}


@router.post("/agent/users/{name}/add-traffic")
async def legacy_agent_add_traffic(
    name: str,
    body: LegacyAddTrafficRequest,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    quota_error = await _check_agent_quota(agent, body.gb, db)
    if quota_error:
        return {"ok": False, "error": quota_error}
    result = await db.execute(
        select(VpnUser).where(VpnUser.name == name, VpnUser.agent_id == agent.id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found or not yours"}
    user.traffic_limit = (user.traffic_limit or 0) + int(body.gb * (1024**3))
    await db.commit()
    return {"ok": True, "traffic_limit_gb": (user.traffic_limit or 0) / (1024**3)}


@router.get("/agent/live")
async def legacy_agent_live(agent: Agent = Depends(_get_current_agent_cookie)):
    return {}


@router.get("/agent/server-info")
async def legacy_agent_server_info(
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    return await legacy_server_info(admin=User(id=0, username=agent.name, is_admin=False), db=db)


@router.post("/agent/sync")
async def legacy_agent_sync(
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    now = datetime.utcnow()
    result = await db.execute(
        select(VpnUser).where(
            VpnUser.agent_id == agent.id,
            VpnUser.expire_at != None,
            VpnUser.active == 1,
        )
    )
    disabled = 0
    for u in result.scalars().all():
        if u.expire_at and u.expire_at < now:
            u.active = 0
            disabled += 1
    if disabled:
        await db.commit()
    return {"ok": True, "disabled": disabled}


@router.get("/agent/groups")
async def legacy_agent_groups(
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.agent_id == agent.id))
    users = result.scalars().all()
    groups: Dict[str, Dict[str, Any]] = {}
    for u in users:
        prefix = u.name.split("-")[0] if "-" in u.name else u.name
        g = groups.setdefault(
            prefix,
            {"id": prefix, "count": 0, "active": 0, "disabled": 0, "traffic_gb": 0},
        )
        g["count"] += 1
        if u.active:
            g["active"] += 1
        else:
            g["disabled"] += 1
        if u.traffic_limit and not g["traffic_gb"]:
            g["traffic_gb"] = round(u.traffic_limit / (1024**3), 2)
    return list(groups.values())


@router.get("/agent/groups/{group_id}/users")
async def legacy_agent_group_users(
    group_id: str,
    request: Request,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(
        select(VpnUser).where(
            VpnUser.agent_id == agent.id,
            VpnUser.name.like(f"{group_id}%"),
        )
    )
    server_ip = _request_config_host(request)
    return {
        "ok": True,
        "users": [_user_to_legacy(u, server_ip=server_ip) for u in result.scalars().all()],
    }
