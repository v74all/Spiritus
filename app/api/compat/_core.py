"""
Legacy compatibility router for V7LTHRONYX VPN Panel.

The frontend (panel.js) was built against an older API surface. This router
maps the legacy endpoint paths and response shapes (``{ok: true, ...}`` style)
to the current backend implementation so the panel works without rewriting
the frontend.
"""

from __future__ import annotations

import asyncio
import base64
import csv
import io
import json
import logging
import os
import re
import secrets
import subprocess
import time
import urllib.parse
import uuid as uuid_lib
from datetime import datetime, timedelta
from typing import Any

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from jwt import PyJWTError as JWTError
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...audit import record_audit
from ...auth import (
    User,
    create_access_token,
    get_current_admin_cookie,
    get_password_hash,
    revoke_request_token,
    verify_password,
)
from ...backup_crypto import ENCRYPTED_SUFFIX, decrypt_backup, encrypt_backup
from ...config import settings
from ...database import get_async_db, safe_refresh
from ...models import Admin, Agent, Setting, VpnUser
from ...privileged_helper import (
    helper_request,
    helper_request_sync,
)
from ...security import fail2ban_manager
from ...services.user_names import taken_vpn_user_names
from ...timeutil import utcnow as _utcnow

logger = logging.getLogger(__name__)

# In-memory state for endpoints that don't have a DB-backed implementation yet.
# Note: _login_attempts used to live here but has been migrated to Redis (see
# the wrapper helpers below that delegate to app/api/auth.py).
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
    "vless_ws_plain_front_enabled",
    "ipv6_enabled",
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

# These wrap the Redis-backed primitives from app/api/auth.py so the legacy
# compat endpoints share the SAME bucket as the modern /api/auth/login route.
# The previous in-memory dict grew unbounded under an IP-rotating attack and
# also produced split state — locking from the modern endpoint didn't lock the
# legacy one. Both helpers fall back to a no-op if Redis is unreachable; the
# auth-side wrappers (auth.py::_is_locked_out + _record_failed_login) are
# fail-closed for the actual rate-limit decision, which is what we want.
async def _is_locked_out(ip: str) -> bool:
    from ..auth import _is_locked_out as _redis_locked
    try:
        return await _redis_locked(ip)
    except Exception:
        return False


async def _record_failed_attempt(ip: str) -> None:
    from ..auth import _record_failed_login
    try:
        await _record_failed_login(ip)
    except Exception:
        pass


async def _clear_attempts(ip: str) -> None:
    from ..auth import _clear_login_attempts
    try:
        await _clear_login_attempts(ip)
    except Exception:
        pass


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _normalize_settings_types(data: dict[str, Any]) -> dict[str, Any]:
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
    # settings.host is the bind address (0.0.0.0 on most installs) — it is
    # a placeholder and must not appear in client configs. Fall through to
    # VPN_SERVER_IP which is the actual public IP.
    if not _is_placeholder_host(settings.host):
        return settings.host
    if settings.vpn_server_ip and not _is_placeholder_host(settings.vpn_server_ip):
        return settings.vpn_server_ip
    return ""


# NOTE: The legacy _read_password_file / _write_password_file helpers were
# removed as part of the 2026-05 security hardening pass. Admin credentials
# are now stored exclusively in the database (Argon2-hashed via passlib).
# First-run installs use the ADMIN_BOOTSTRAP_PASSWORD env var, which is
# consumed once by app/api/auth.py:bootstrap_initial_admin().


def _days_left(expire_at: datetime | None) -> int:
    if not expire_at:
        return 9999
    delta = expire_at - _utcnow()
    return max(0, delta.days)


def _detect_ipv6() -> str:
    """Detect server's IPv6 address. Returns empty string if none."""
    # Check explicit setting first
    configured = _settings_state.get("server_ipv6") or settings.vpn_server_ipv6
    if configured and not _is_placeholder_host(configured):
        return configured.strip()

    try:
        import re
        result = subprocess.run(
            ["ip", "-6", "addr", "show", "scope", "global"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                m = re.search(r'inet6\s+([0-9a-f:]+)/(\d+)', line)
                if m:
                    addr = m.group(1)
                    # Skip link-local (fe80::) and loopback
                    if not addr.startswith("fe80:") and addr != "::1":
                        return addr
    except Exception:
        pass

    # Fallback: curl to check public IPv6
    try:
        result = subprocess.run(
            ["curl", "-s6", "--max-time", "3", "https://api6.ipify.org"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass

    return ""


def _build_share_links(u: VpnUser, server_ip: str | None = None) -> dict[str, str]:
    """生成用户分享链接。Best-effort — 如果协议关闭则为空字符串。

    当 IPv6 启用时，同时生成所有协议的 IPv6 版本（_ipv6 后缀）。
    """
    try:
        from ...protocol_engine import ClientConfigGenerator
    except Exception:
        return {}

    # Prefer explicit server IP sources over the binding address (0.0.0.0).
    # settings.vpn_server_ip maps to VPN_SERVER_IP in .env — the actual public
    # IP of this server. settings.host is the bind address and is a placeholder
    # when set to 0.0.0.0, so it must not end up in client configs.
    server_ip = (
        server_ip
        or _settings_state.get("server_ip")
        or settings.vpn_server_ip
        or settings.host
    )
    if _is_placeholder_host(server_ip):
        server_ip = ""
    # ── Emergency Relay: override ALL addresses when activated ──
    _emergency_relay = ""
    if _settings_state.get("emergency_relay_enabled") and _settings_state.get("emergency_relay_address"):
        _emergency_relay = _settings_state.get("emergency_relay_address", "").strip()
    if _emergency_relay:
        server_ip = _emergency_relay

    # ── IPv6 address (auto-detect or configured) ──
    _ipv6_enabled = _settings_state.get("ipv6_enabled") or settings.ipv6_enabled
    _ipv6_addr = ""
    if _ipv6_enabled:
        _ipv6_addr = _detect_ipv6()
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
        return {
            "fragment": _frag, "fragment_packets": _frag_pkt, "fragment_length": _frag_len,
            "fragment_interval": _frag_int, "noise_packet": _noise_pkt, "noise_delay": _noise_del,
            "tcp_keepalive": _keepalive, "mux_enabled": _mux, "mux_concurrency": _mux_conc,
            "bug_host": _bug_host,
        }

    def _dpi_vmess_kwargs(extra_host=""):
        return {
            "fragment": _frag, "fragment_packets": _frag_pkt, "fragment_length": _frag_len,
            "fragment_interval": _frag_int, "noise_packet": _noise_pkt, "noise_delay": _noise_del,
            "tcp_keepalive": _keepalive, "mux_enabled": _mux, "mux_concurrency": _mux_conc,
            "bug_host": _bug_host, "extra_host_header": extra_host,
        }

    def _dpi_trojan_kwargs():
        return {
            "fragment": _frag, "fragment_packets": _frag_pkt, "fragment_length": _frag_len,
            "fragment_interval": _frag_int, "noise_packet": _noise_pkt, "noise_delay": _noise_del,
            "tcp_keepalive": _keepalive, "mux_enabled": _mux, "mux_concurrency": _mux_conc,
            "bug_host": _bug_host,
        }

    links: dict[str, str] = {}
    try:
        links["vmess"] = ClientConfigGenerator.generate_vmess_share_url(
            uuid=u.uuid,
            address=server_ip,
            port=int(_settings_state.get("vmess_port") or 443),
            sni=sni_host,
            path=ws_path,
            allow_insecure=True,
            label="VMess",
            **_dpi_vmess_kwargs(extra_host=_host_spoof or _ws_front),
        )
    except Exception:
        logger.warning("Failed to build %s share link", "vmess", exc_info=False)
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
                label="VLESS-Reality",
                **_dpi_vless_kwargs(),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "vless", exc_info=False)
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
                label="CDN-VMess",
                **_dpi_vmess_kwargs(extra_host=cdn_host),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "cdn_vmess", exc_info=False)
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
                label="VLESS-WS",
                **_dpi_vless_kwargs(),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "vless_ws", exc_info=False)
            links["vless_ws"] = ""

    if _settings_state.get("vless_ws_plain_front_enabled"):
        try:
            _front_domain = _settings_state.get("vless_ws_plain_front_domain") or "chat.deepseek.com"
            _front_path = _settings_state.get("vless_ws_plain_front_path") or "/"
            _front_port = int(_settings_state.get("vless_ws_plain_front_port") or 2052)
            links["vless_ws_plain_front"] = ClientConfigGenerator.generate_vless_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=_front_port,
                network="ws",
                security="tls",
                sni=_front_domain,
                fp=_settings_state.get("fingerprint") or "chrome",
                host=_front_domain,
                path=_front_path,
                allow_insecure=True,
                label="VLESS-WS-TLS",
                **_dpi_vless_kwargs(),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "vless_ws_plain_front", exc_info=False)
            links["vless_ws_plain_front"] = ""

    if _settings_state.get("trojan_enabled"):
        try:
            links["trojan"] = ClientConfigGenerator.generate_trojan_share_url(
                password=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("trojan_port") or 2083),
                sni=sni_host,
                network="tcp",
                allow_insecure=True,
                label="Trojan",
                **_dpi_trojan_kwargs(),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "trojan", exc_info=False)
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
                label="gRPC",
                **_dpi_vmess_kwargs(),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "grpc_vmess", exc_info=False)
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
                label="HTTPUpgrade",
                **_dpi_vmess_kwargs(extra_host=_host_spoof or _ws_front),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "httpupgrade_vmess", exc_info=False)
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
            logger.warning("Failed to build %s share link", "ss2022", exc_info=False)
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
                label="Hysteria2",
                port_hop=(
                    str(_settings_state.get("hysteria2_port_hop_ports") or "")
                    if _settings_state.get("hysteria2_port_hop_enabled")
                    else ""
                ),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "hysteria2", exc_info=False)
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
            logger.warning("Failed to build %s share link", "tuic", exc_info=False)
            links["tuic"] = ""

    # ShadowTLS v3 — encoded as a sing-box-style URI. The password is
    # the ShadowTLS user password; clients pair it with the handshake SNI.
    if _settings_state.get("shadowtls_enabled"):
        try:
            stls_port = int(_settings_state.get("shadowtls_port") or 8445)
            stls_password = _settings_state.get("shadowtls_password") or u.uuid
            stls_sni = _settings_state.get("shadowtls_sni") or sni_host
            label = urllib.parse.quote(f"V7LTHRONYX-ShadowTLS-{u.name}")
            params = urllib.parse.urlencode({
                "security": "tls",
                "sni": stls_sni,
                "version": _settings_state.get("shadowtls_version") or "3",
            })
            links["shadowtls"] = (
                f"shadowtls://{stls_password}@{server_ip}:{stls_port}?{params}#{label}"
            )
        except Exception:
            logger.warning("Failed to build %s share link", "shadowtls", exc_info=False)
            links["shadowtls"] = ""

    # NaiveProxy — naive+https URI (username:password@host:port).
    if _settings_state.get("naiveproxy_enabled"):
        try:
            naive_port = int(_settings_state.get("naiveproxy_port") or 8447)
            naive_user = _settings_state.get("naiveproxy_user") or u.name
            naive_password = _settings_state.get("naiveproxy_password") or u.uuid
            naive_sni = _settings_state.get("naiveproxy_sni") or sni_host
            label = urllib.parse.quote(f"V7LTHRONYX-Naive-{u.name}")
            creds = urllib.parse.quote(f"{naive_user}:{naive_password}", safe="")
            links["naiveproxy"] = (
                f"naive+https://{creds}@{server_ip}:{naive_port}?sni={urllib.parse.quote(naive_sni)}#{label}"
            )
        except Exception:
            logger.warning("Failed to build %s share link", "naiveproxy", exc_info=False)
            links["naiveproxy"] = ""

    # Mieru — no universal URI scheme; clients import a JSON profile.
    # We expose it as a base64-encoded JSON so the frontend can offer it
    # as a downloadable mieru profile.
    if _settings_state.get("mieru_enabled"):
        try:
            mieru_port = int(_settings_state.get("mieru_port") or 8446)
            mieru_user = _settings_state.get("mieru_user") or u.name
            mieru_password = _settings_state.get("mieru_password") or u.uuid
            from ...protocol_engine import MieruConfigGenerator
            profile = MieruConfigGenerator.generate_client_profile(
                username=mieru_user,
                password=mieru_password,
                server_ip=server_ip,
                port=mieru_port,
                protocol=_settings_state.get("mieru_transport") or "TCP",
                mtu=int(_settings_state.get("mieru_mtu") or 1400),
            )
            links["mieru"] = "mieru://" + base64.urlsafe_b64encode(
                json.dumps(profile).encode()
            ).decode()
        except Exception:
            logger.warning("Failed to build %s share link", "mieru", exc_info=False)
            links["mieru"] = ""

    # VLESS xHTTP REALITY
    if _settings_state.get("vless_xhttp_enabled") and (_settings_state.get("reality_public_key") or _settings_state.get("vless_xhttp_reality_public_key")):
        try:
            # Resolve port avoiding collision with standard VLESS Reality (same logic as Xray config generator)
            _rxp = int(_settings_state.get("vless_xhttp_port") or 0)
            _vrp = int(_settings_state.get("vless_port") or 2053)
            _xhttp_port = _rxp if (_rxp and _rxp != _vrp) else 8449
            links["vless_xhttp"] = ClientConfigGenerator.generate_vless_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=_xhttp_port,
                security="reality",
                sni=_settings_state.get("vless_xhttp_reality_sni") or _settings_state.get("reality_sni") or "digikala.com",
                fp=_settings_state.get("fingerprint") or "chrome",
                pbk=_settings_state.get("vless_xhttp_reality_public_key") or _settings_state.get("reality_public_key") or "",
                sid=_settings_state.get("vless_xhttp_reality_short_id") or _settings_state.get("reality_short_id") or "",
                network="xhttp",
                xhttp_mode=_settings_state.get("vless_xhttp_mode") or "auto",
                path=_settings_state.get("vless_xhttp_path") or "/xhttp",
                label="VLESS-XHTTP",
                **_dpi_vless_kwargs(),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "vless_xhttp", exc_info=False)
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
                label="VLESS-Vision",
                **_dpi_vless_kwargs(),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "vless_vision", exc_info=False)
            links["vless_vision"] = ""

    # VLESS Reverse REALITY
    if _settings_state.get("vless_reverse_enabled") and (_settings_state.get("reality_public_key") or _settings_state.get("vless_reverse_reality_public_key")):
        try:
            links["vless_reverse"] = ClientConfigGenerator.generate_vless_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("vless_reverse_port") or 2059),
                security="reality",
                sni=_settings_state.get("vless_reverse_reality_sni") or "digikala.com",
                fp=_settings_state.get("fingerprint") or "chrome",
                pbk=_settings_state.get("vless_reverse_reality_public_key") or _settings_state.get("reality_public_key") or "",
                sid=_settings_state.get("vless_reverse_reality_short_id") or "",
                network="tcp",
                label="VLESS-Reverse",
                **_dpi_vless_kwargs(),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "vless_reverse", exc_info=False)
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
                label="Trojan-CDN",
                **_dpi_trojan_kwargs(),
            )
        except Exception:
            logger.warning("Failed to build %s share link", "trojan_cdn", exc_info=False)
            links["trojan_cdn"] = ""

    # ── IPv6 variants: generate dual-stack copies of all non-empty links ──
    if _ipv6_addr and _ipv6_enabled:
        _v6 = _ipv6_addr
        # IPv6 addresses must be bracket-wrapped in URLs
        _v6_bracket = f"[{_v6}]" if ":" in _v6 and not _v6.startswith("[") else _v6

        _ipv6_links = {}
        for key, url in links.items():
            if not url:
                continue
            try:
                # Replace IPv4 address with IPv6 in the URL
                # vless://uuid@1.2.3.4:port?...  →  vless://uuid@[::1]:port?...
                if key.startswith("vless_") or key in ("vmess", "vless", "cdn_vmess", "grpc_vmess", "httpupgrade_vmess") or key == "ss2022" or key == "hysteria2" or key == "tuic" or key == "trojan":
                    _v6_url = url.replace(f"@{server_ip}:", f"@{_v6_bracket}:", 1)
                else:
                    # Generic fallback: try replacing any occurrence
                    _v6_url = url.replace(f"@{server_ip}:", f"@{_v6_bracket}:", 1)
                    if _v6_url == url:
                        _v6_url = url.replace(f"={server_ip}&", f"={_v6_bracket}&", 1)

                if _v6_url != url:
                    _v6_url = _v6_url.replace("#V7LTHRONYX", "#V7LTHRONYX-IPv6")
                    _ipv6_links[f"{key}_ipv6"] = _v6_url
            except Exception:
                pass

        links.update(_ipv6_links)

    return links


def _user_to_legacy(u: VpnUser, server_ip: str | None = None) -> dict[str, Any]:
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
        "vless_ws_plain_front": links.get("vless_ws_plain_front", ""),
        "vless_xhttp": links.get("vless_xhttp", ""),
        "vless_vision": links.get("vless_vision", ""),
        "vless_reverse": links.get("vless_reverse", ""),
        "hysteria2": links.get("hysteria2", ""),
        "tuic": links.get("tuic", ""),
        # IPv6 variants
        "vmess_ipv6": links.get("vmess_ipv6", ""),
        "vless_ipv6": links.get("vless_ipv6", ""),
        "vless_ws_ipv6": links.get("vless_ws_ipv6", ""),
        "vless_ws_plain_front_ipv6": links.get("vless_ws_plain_front_ipv6", ""),
        "vless_xhttp_ipv6": links.get("vless_xhttp_ipv6", ""),
        "vless_vision_ipv6": links.get("vless_vision_ipv6", ""),
        "vless_reverse_ipv6": links.get("vless_reverse_ipv6", ""),
        "cdn_vmess_ipv6": links.get("cdn_vmess_ipv6", ""),
        "trojan_ipv6": links.get("trojan_ipv6", ""),
        "trojan_cdn_ipv6": links.get("trojan_cdn_ipv6", ""),
        "grpc_vmess_ipv6": links.get("grpc_vmess_ipv6", ""),
        "httpupgrade_vmess_ipv6": links.get("httpupgrade_vmess_ipv6", ""),
        "ss2022_ipv6": links.get("ss2022_ipv6", ""),
        "hysteria2_ipv6": links.get("hysteria2_ipv6", ""),
        "tuic_ipv6": links.get("tuic_ipv6", ""),
    }


def _default_legacy_settings() -> dict[str, Any]:
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
        "vless_reverse_reality_short_id": secrets.token_hex(8),
        "vless_reverse_reality_sni": "digikala.com",
        "vless_reverse_reality_public_key": settings.reality_public_key,
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
        # IPv6 dual-stack (auto-detect or manual)
        "ipv6_enabled": settings.ipv6_enabled,
        "server_ipv6": settings.vpn_server_ipv6,
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
        # VLESS WS Plain Front (Iranian domain fronting, no TLS)
        "vless_ws_plain_front_enabled": settings.vless_ws_plain_front_enabled,
        "vless_ws_plain_front_port": settings.vless_ws_plain_front_port,
        "vless_ws_plain_front_domain": settings.vless_ws_plain_front_domain,
        "vless_ws_plain_front_path": settings.vless_ws_plain_front_path,
    }


async def _load_legacy_settings(db: AsyncSession) -> dict[str, Any]:
    file_settings: dict[str, Any] = {}
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
    db_settings: dict[str, Any] = {}
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
    current: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    if not any(key in incoming for key in _DPI_SETTING_KEYS):
        return incoming

    protected = dict(incoming)
    for key in _PROTOCOL_ENABLE_KEYS:
        if current.get(key) is True and protected.get(key) is False:
            protected[key] = True
    return protected


async def _save_legacy_settings(db: AsyncSession, data: dict[str, Any]) -> None:
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
        tmp_path = settings_path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(_settings_state, f, indent=2)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, settings_path)
    except Exception as exc:
        logger.warning(f"Failed to mirror legacy settings file: {exc}")


# Tracks {username: timestamp} of last observed traffic — used by /online-users.
_user_last_seen: dict[str, float] = {}


__all__ = [_n for _n in list(globals()) if not _n.startswith("__")]
