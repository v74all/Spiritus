"""
Spiritus Protocol Engine — Unified protocol management for all VPN protocols.

Supports:
  Xray-Core:    VLESS+XHTTP+REALITY, VLESS+REALITY+Vision, VLESS-Reverse-Reality,
                Trojan+WS/gRPC+CDN, VMess+WS+TLS, VLESS+WS+TLS, SS-2022, gRPC, HTTPUpgrade
  Standalone:   Hysteria2+Salamander+port-hop, TUIC v5, AmneziaWG 2.0,
                ShadowTLS v3, Mieru, NaiveProxy, WireGuard, OpenVPN
"""

from __future__ import annotations

import json
import uuid
import base64
import hashlib
import secrets
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════════
#  Protocol Registry
# ═══════════════════════════════════════════════════════════════

class ProtocolCategory(str, Enum):
    XRAY = "xray"
    STANDALONE = "standalone"


class ProtocolBackend(str, Enum):
    XRAY_CORE = "xray-core"
    SING_BOX = "sing-box"
    HYSTERIA2 = "hysteria2"
    WIREGUARD = "wireguard"
    AMNEZIAWG = "amneziawg"
    OPENVPN = "openvpn"
    SHADOWTLS = "shadowtls"
    MIERU = "mieru"
    NAIVEPROXY = "naiveproxy"
    TUIC = "tuic"


@dataclass
class ProtocolSpec:
    """Specification for a single protocol."""
    key: str
    name: str
    name_fa: str
    category: ProtocolCategory
    backend: ProtocolBackend
    description: str
    requires_tls: bool = False
    requires_udp: bool = False
    requires_cert: bool = False
    supports_cdn: bool = False
    anti_dpi: bool = False
    anti_block: str = ""  # low / medium / high
    default_port: int = 443
    config_fields: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
#  Protocol Definitions
# ═══════════════════════════════════════════════════════════════

PROTOCOL_REGISTRY: Dict[str, ProtocolSpec] = {
    # ── Xray-Core Protocols ──────────────────────────────────
    "vless_xhttp_reality": ProtocolSpec(
        key="vless_xhttp_reality",
        name="VLESS+XHTTP+REALITY",
        name_fa="VLESS+XHTTP+REALITY (رله-فرانت)",
        category=ProtocolCategory.XRAY,
        backend=ProtocolBackend.XRAY_CORE,
        description="VLESS with XHTTP transport and REALITY TLS. Relay-domain fronting for maximum stealth. XHTTP supports HTTP/2 and HTTP/3 streaming.",
        requires_tls=True,
        requires_udp=False,
        requires_cert=False,
        supports_cdn=False,
        anti_dpi=True,
        anti_block="high",
        default_port=2053,
        config_fields=[
            "VLESS_XHTTP_PORT", "VLESS_XHTTP_REALITY_PRIVATE_KEY",
            "VLESS_XHTTP_REALITY_PUBLIC_KEY", "VLESS_XHTTP_REALITY_SHORT_ID",
            "VLESS_XHTTP_REALITY_DEST", "VLESS_XHTTP_REALITY_SNI",
            "VLESS_XHTTP_PATH", "VLESS_XHTTP_MODE",
        ],
    ),
    "vless_vision_reality": ProtocolSpec(
        key="vless_vision_reality",
        name="VLESS+REALITY+Vision",
        name_fa="VLESS+REALITY+Vision (مستقیم، آی‌پی تازه)",
        category=ProtocolCategory.XRAY,
        backend=ProtocolBackend.XRAY_CORE,
        description="VLESS with REALITY TLS and Vision flow. Direct connection to fresh IP, no CDN. Vision flow provides XTLS read-v0 for efficient traffic handling.",
        requires_tls=True,
        requires_udp=False,
        requires_cert=False,
        supports_cdn=False,
        anti_dpi=True,
        anti_block="high",
        default_port=2058,
        config_fields=[
            "VLESS_VISION_PORT", "VLESS_VISION_REALITY_PRIVATE_KEY",
            "VLESS_VISION_REALITY_PUBLIC_KEY", "VLESS_VISION_REALITY_SHORT_ID",
            "VLESS_VISION_REALITY_DEST", "VLESS_VISION_REALITY_SNI",
            "VLESS_VISION_FLOW",
        ],
    ),
    "vless_reverse_reality": ProtocolSpec(
        key="vless_reverse_reality",
        name="VLESS-Reverse-Reality",
        name_fa="VLESS-Reality معکوس (Backhaul/Rathole)",
        category=ProtocolCategory.XRAY,
        backend=ProtocolBackend.XRAY_CORE,
        description="Reverse-tunneled VLESS-Reality for backhaul/rathole relay. Server connects outbound to client, bypassing inbound port blocks. Ideal for networks that block all inbound connections.",
        requires_tls=True,
        requires_udp=False,
        requires_cert=False,
        supports_cdn=False,
        anti_dpi=True,
        anti_block="high",
        default_port=2059,
        config_fields=[
            "VLESS_REVERSE_PORT", "VLESS_REVERSE_REALITY_PRIVATE_KEY",
            "VLESS_REVERSE_REALITY_PUBLIC_KEY", "VLESS_REVERSE_REALITY_SHORT_ID",
            "VLESS_REVERSE_REALITY_DEST", "VLESS_REVERSE_REALITY_SNI",
            "VLESS_REVERSE_TUNNEL_PORT", "VLESS_REVERSE_BACKHAUL_MODE",
        ],
    ),
    "trojan_cdn": ProtocolSpec(
        key="trojan_cdn",
        name="Trojan+WS/gRPC+TLS (CDN)",
        name_fa="Trojan+WS/gRPC+TLS از طریق CDN کلودفلر",
        category=ProtocolCategory.XRAY,
        backend=ProtocolBackend.XRAY_CORE,
        description="Trojan with WebSocket and/or gRPC transport over TLS through Cloudflare CDN. CDN-compatible for IP hiding and DDoS protection. Supports dual transport (WS+gRPC).",
        requires_tls=True,
        requires_udp=False,
        requires_cert=True,
        supports_cdn=True,
        anti_dpi=True,
        anti_block="high",
        default_port=2083,
        config_fields=[
            "TROJAN_CDN_PORT", "TROJAN_CDN_WS_PATH",
            "TROJAN_CDN_GRPC_SERVICE", "TROJAN_CDN_GRPC_ENABLED",
            "TROJAN_CDN_GRPC_PORT", "TROJAN_CDN_TLS_ENABLED",
            "TROJAN_CDN_SNI", "TROJAN_CDN_DOMAIN",
        ],
    ),
    "vmess_ws": ProtocolSpec(
        key="vmess_ws",
        name="VMess+WS+TLS",
        name_fa="VMess+WS+TLS",
        category=ProtocolCategory.XRAY,
        backend=ProtocolBackend.XRAY_CORE,
        description="VMess with WebSocket transport over TLS. Classic and widely supported protocol.",
        requires_tls=True,
        requires_udp=False,
        requires_cert=True,
        supports_cdn=True,
        anti_dpi=True,
        anti_block="medium",
        default_port=443,
        config_fields=[
            "VMESS_PORT", "VMESS_SNI", "VMESS_WS_PATH",
        ],
    ),
    "vless_ws": ProtocolSpec(
        key="vless_ws",
        name="VLESS+WS+TLS (CDN)",
        name_fa="VLESS+WS+TLS (CDN)",
        category=ProtocolCategory.XRAY,
        backend=ProtocolBackend.XRAY_CORE,
        description="VLESS with WebSocket over TLS, CDN-compatible. Lighter than VMess, no encryption overhead.",
        requires_tls=True,
        requires_udp=False,
        requires_cert=True,
        supports_cdn=True,
        anti_dpi=True,
        anti_block="medium",
        default_port=2057,
        config_fields=[
            "VLESS_WS_PORT", "VLESS_WS_PATH",
        ],
    ),
    "ss2022": ProtocolSpec(
        key="ss2022",
        name="Shadowsocks-2022",
        name_fa="Shadowsocks-2022 (blake3)",
        category=ProtocolCategory.XRAY,
        backend=ProtocolBackend.XRAY_CORE,
        description="Shadowsocks 2022 with blake3 authentication. Modern, secure variant with improved key exchange.",
        requires_tls=False,
        requires_udp=False,
        requires_cert=False,
        supports_cdn=False,
        anti_dpi=False,
        anti_block="low",
        default_port=2056,
        config_fields=[
            "SS2022_PORT", "SS2022_METHOD", "SS2022_SERVER_KEY",
        ],
    ),
    "grpc": ProtocolSpec(
        key="grpc",
        name="gRPC Transport",
        name_fa="gRPC Transport",
        category=ProtocolCategory.XRAY,
        backend=ProtocolBackend.XRAY_CORE,
        description="gRPC transport for any Xray protocol. HTTP/2 based, supports multi-plexing.",
        requires_tls=True,
        requires_udp=False,
        requires_cert=True,
        supports_cdn=True,
        anti_dpi=True,
        anti_block="medium",
        default_port=2054,
        config_fields=[
            "GRPC_PORT", "GRPC_SERVICE_NAME",
        ],
    ),
    "httpupgrade": ProtocolSpec(
        key="httpupgrade",
        name="HTTPUpgrade Transport",
        name_fa="HTTPUpgrade Transport",
        category=ProtocolCategory.XRAY,
        backend=ProtocolBackend.XRAY_CORE,
        description="HTTP Upgrade transport. Simpler than WebSocket, lower overhead.",
        requires_tls=True,
        requires_udp=False,
        requires_cert=True,
        supports_cdn=True,
        anti_dpi=True,
        anti_block="medium",
        default_port=2055,
        config_fields=[
            "HTTPUPGRADE_PORT", "HTTPUPGRADE_PATH",
        ],
    ),

    # ── Standalone Protocols (Non-Xray) ──────────────────────
    "hysteria2": ProtocolSpec(
        key="hysteria2",
        name="Hysteria2+Salamander+port-hop",
        name_fa="Hysteria2+Salamander+port-hop",
        category=ProtocolCategory.STANDALONE,
        backend=ProtocolBackend.HYSTERIA2,
        description="QUIC-based proxy with Salamander obfuscation and automatic port-hopping. Extremely fast over UDP. Salamander adds traffic obfuscation. Port-hopping evades port-based blocking.",
        requires_tls=True,
        requires_udp=True,
        requires_cert=True,
        supports_cdn=False,
        anti_dpi=True,
        anti_block="high",
        default_port=8443,
        config_fields=[
            "HYSTERIA2_PORT", "HYSTERIA2_PASSWORD",
            "HYSTERIA2_SALAMANDER_ENABLED", "HYSTERIA2_SALAMANDER_PASSWORD",
            "HYSTERIA2_PORT_HOP_ENABLED", "HYSTERIA2_PORT_HOP_PORTS",
            "HYSTERIA2_BANDWIDTH_UP", "HYSTERIA2_BANDWIDTH_DOWN",
            "HYSTERIA2_QUIC_PORT",
        ],
    ),
    "tuic_v5": ProtocolSpec(
        key="tuic_v5",
        name="TUIC v5",
        name_fa="TUIC v5",
        category=ProtocolCategory.STANDALONE,
        backend=ProtocolBackend.TUIC,
        description="QUIC-based proxy with UDP relay and multiplexing. Supports zero-RTT for fast reconnection. Congestion control: cubic/bbr/new_reno.",
        requires_tls=True,
        requires_udp=True,
        requires_cert=True,
        supports_cdn=False,
        anti_dpi=True,
        anti_block="medium",
        default_port=8444,
        config_fields=[
            "TUIC_PORT", "TUIC_PASSWORD",
            "TUIC_CONGESTION_CONTROL", "TUIC_UDP_RELAY",
            "TUIC_ZERO_RTT", "TUIC_CERT_PATH", "TUIC_KEY_PATH",
        ],
    ),
    "amneziawg": ProtocolSpec(
        key="amneziawg",
        name="AmneziaWG 2.0",
        name_fa="AmneziaWG 2.0",
        category=ProtocolCategory.STANDALONE,
        backend=ProtocolBackend.AMNEZIAWG,
        description="Amnezia's WireGuard fork with advanced obfuscation. Junk packets (JC/JMIN/JMAX) and magic headers (S1/S2/H1-H4) defeat DPI. Drop-in WireGuard replacement.",
        requires_tls=False,
        requires_udp=True,
        requires_cert=False,
        supports_cdn=False,
        anti_dpi=True,
        anti_block="high",
        default_port=51820,
        config_fields=[
            "AMNEZIAWG_PORT", "AMNEZIAWG_PRIVATE_KEY",
            "AMNEZIAWG_ADDRESS", "AMNEZIAWG_DNS",
            "AMNEZIAWG_JC", "AMNEZIAWG_JMIN", "AMNEZIAWG_JMAX",
            "AMNEZIAWG_S1", "AMNEZIAWG_S2",
            "AMNEZIAWG_H1", "AMNEZIAWG_H2", "AMNEZIAWG_H3", "AMNEZIAWG_H4",
            "AMNEZIAWG_MTU",
        ],
    ),
    "shadowtls_v3": ProtocolSpec(
        key="shadowtls_v3",
        name="ShadowTLS v3",
        name_fa="ShadowTLS v3",
        category=ProtocolCategory.STANDALONE,
        backend=ProtocolBackend.SHADOWTLS,
        description="TLS-encrypted SOCKS5 proxy with custom TLS fingerprint. Wraps SOCKS5 traffic inside legitimate TLS handshake. v3 supports custom SNI and password authentication.",
        requires_tls=True,
        requires_udp=False,
        requires_cert=True,
        supports_cdn=False,
        anti_dpi=True,
        anti_block="high",
        default_port=8445,
        config_fields=[
            "SHADOWTLS_PORT", "SHADOWTLS_PASSWORD",
            "SHADOWTLS_SNI", "SHADOWTLS_VERSION",
            "SHADOWTLS_BACKEND", "SHADOWTLS_TLS_CERT_PATH", "SHADOWTLS_TLS_KEY_PATH",
        ],
    ),
    "mieru": ProtocolSpec(
        key="mieru",
        name="Mieru",
        name_fa="Mieru",
        category=ProtocolCategory.STANDALONE,
        backend=ProtocolBackend.MIERU,
        description="TCP/UDP multiplexing proxy with encryption and traffic shaping. Supports AES-256-GCM and ChaCha20-Poly1305. Multiplexing reduces connection overhead.",
        requires_tls=False,
        requires_udp=False,
        requires_cert=False,
        supports_cdn=False,
        anti_dpi=True,
        anti_block="medium",
        default_port=8446,
        config_fields=[
            "MIERU_PORT", "MIERU_PASSWORD",
            "MIERU_ENCRYPTION", "MIERU_TRANSPORT",
            "MIERU_MUX_ENABLED", "MIERU_MUX_CONCURRENCY",
        ],
    ),
    "naiveproxy": ProtocolSpec(
        key="naiveproxy",
        name="NaiveProxy (official)",
        name_fa="NaiveProxy (رسمی)",
        category=ProtocolCategory.STANDALONE,
        backend=ProtocolBackend.NAIVEPROXY,
        description="Chromium network stack proxy with Chrome TLS fingerprint. Uses Chrome's actual networking code for perfect TLS fingerprint match. Official build.",
        requires_tls=True,
        requires_udp=False,
        requires_cert=True,
        supports_cdn=True,
        anti_dpi=True,
        anti_block="high",
        default_port=8447,
        config_fields=[
            "NAIVEPROXY_PORT", "NAIVEPROXY_USER", "NAIVEPROXY_PASSWORD",
            "NAIVEPROXY_SNI", "NAIVEPROXY_CERT_PATH", "NAIVEPROXY_KEY_PATH",
            "NAIVEPROXY_CONCURRENCY",
        ],
    ),
    "wireguard": ProtocolSpec(
        key="wireguard",
        name="WireGuard",
        name_fa="WireGuard (ساده)",
        category=ProtocolCategory.STANDALONE,
        backend=ProtocolBackend.WIREGUARD,
        description="Standard WireGuard VPN tunnel. Fast, modern, no obfuscation. Best for unrestricted networks or as base for AmneziaWG.",
        requires_tls=False,
        requires_udp=True,
        requires_cert=False,
        supports_cdn=False,
        anti_dpi=False,
        anti_block="low",
        default_port=51821,
        config_fields=[
            "WIREGUARD_PORT", "WIREGUARD_PRIVATE_KEY",
            "WIREGUARD_ADDRESS", "WIREGUARD_DNS",
            "WIREGUARD_MTU", "WIREGUARD_PERSISTENT_KEEPALIVE",
        ],
    ),
    "openvpn": ProtocolSpec(
        key="openvpn",
        name="OpenVPN",
        name_fa="OpenVPN (ساده)",
        category=ProtocolCategory.STANDALONE,
        backend=ProtocolBackend.OPENVPN,
        description="Standard OpenVPN tunnel (UDP/TCP). Mature, widely supported. No obfuscation. Use with caution in restricted networks.",
        requires_tls=True,
        requires_udp=False,
        requires_cert=True,
        supports_cdn=False,
        anti_dpi=False,
        anti_block="low",
        default_port=1194,
        config_fields=[
            "OPENVPN_PORT", "OPENVPN_PROTO",
            "OPENVPN_NETWORK", "OPENVPN_DNS",
            "OPENVPN_CERT_PATH", "OPENVPN_KEY_PATH",
            "OPENVPN_DH_PATH", "OPENVPN_TA_PATH",
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════
#  Protocol Engine
# ═══════════════════════════════════════════════════════════════

class ProtocolEngine:
    """Unified protocol management engine for Spiritus."""

    def __init__(self, settings: Any = None):
        self._settings = settings
        self._registry = PROTOCOL_REGISTRY

    # ── Registry Operations ──────────────────────────────────

    def get_protocol(self, key: str) -> Optional[ProtocolSpec]:
        return self._registry.get(key)

    def list_protocols(self, category: Optional[ProtocolCategory] = None) -> Dict[str, ProtocolSpec]:
        if category is None:
            return dict(self._registry)
        return {k: v for k, v in self._registry.items() if v.category == category}

    def list_xray_protocols(self) -> Dict[str, ProtocolSpec]:
        return self.list_protocols(ProtocolCategory.XRAY)

    def list_standalone_protocols(self) -> Dict[str, ProtocolSpec]:
        return self.list_protocols(ProtocolCategory.STANDALONE)

    def get_enabled_protocols(self, user_protocols: Dict[str, bool]) -> Dict[str, ProtocolSpec]:
        return {
            k: v for k, v in self._registry.items()
            if user_protocols.get(k, False)
        }

    def get_high_resistance_protocols(self) -> Dict[str, ProtocolSpec]:
        return {k: v for k, v in self._registry.items() if v.anti_block == "high"}

    def get_cdn_compatible_protocols(self) -> Dict[str, ProtocolSpec]:
        return {k: v for k, v in self._registry.items() if v.supports_cdn}

    # ── Config Generation ────────────────────────────────────

    def generate_xray_config(self, user_uuid: str, settings: Any) -> Dict:
        """Generate complete Xray-core configuration for all enabled Xray protocols."""
        config = {
            "log": {"loglevel": "warning"},
            "stats": {},
            "api": {
                "services": ["HandlerService", "StatsService"],
                "tag": "api",
            },
            "policy": {
                "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
                "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
            },
            "inbounds": [],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        }

        inbounds = config["inbounds"]

        # VLESS+XHTTP+REALITY
        if settings.get("vless_xhttp_enabled", False):
            inbounds.append(self._make_vless_xhttp_reality(user_uuid, settings))

        # VLESS+REALITY+Vision
        if settings.get("vless_vision_enabled", False):
            inbounds.append(self._make_vless_vision_reality(user_uuid, settings))

        # VLESS-Reverse-Reality
        if settings.get("vless_reverse_enabled", False):
            inbounds.append(self._make_vless_reverse_reality(user_uuid, settings))

        # Trojan+WS/gRPC+CDN
        if settings.get("trojan_cdn_enabled", False):
            inbounds.extend(self._make_trojan_cdn(user_uuid, settings))

        # VMess+WS+TLS
        if settings.get("vmess_enabled", True):
            inbounds.append(self._make_vmess_ws(user_uuid, settings))

        # VLESS+WS+TLS
        if settings.get("vless_ws_enabled", False):
            inbounds.append(self._make_vless_ws(user_uuid, settings))

        # SS-2022
        if settings.get("ss2022_enabled", False):
            inbounds.append(self._make_ss2022(user_uuid, settings))

        # gRPC
        if settings.get("grpc_enabled", False):
            inbounds.append(self._make_grpc(user_uuid, settings))

        # HTTPUpgrade
        if settings.get("httpupgrade_enabled", False):
            inbounds.append(self._make_httpupgrade(user_uuid, settings))

        return config

    # ── Xray Inbound Builders ────────────────────────────────

    def _make_vless_xhttp_reality(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "port": s.get("vless_xhttp_port", 2053),
            "tag": "vless-xhttp-reality",
            "settings": {
                "clients": [{"id": user_uuid, "flow": ""}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "realitySettings": {
                    "privateKey": s.get("vless_xhttp_reality_private_key", ""),
                    "shortIds": [s.get("vless_xhttp_reality_short_id", "")],
                    "dest": s.get("vless_xhttp_reality_dest", "www.microsoft.com:443"),
                    "serverNames": [s.get("vless_xhttp_reality_sni", "www.microsoft.com")],
                },
                "xhttpSettings": {
                    "path": s.get("vless_xhttp_path", "/xhttp-stream"),
                    "mode": s.get("vless_xhttp_mode", "auto"),
                },
            },
        }

    def _make_vless_vision_reality(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "port": s.get("vless_vision_port", 2058),
            "tag": "vless-vision-reality",
            "settings": {
                "clients": [{"id": user_uuid, "flow": s.get("vless_vision_flow", "xtls-rprx-vision")}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "privateKey": s.get("vless_vision_reality_private_key", ""),
                    "shortIds": [s.get("vless_vision_reality_short_id", "")],
                    "dest": s.get("vless_vision_reality_dest", "www.yahoo.com:443"),
                    "serverNames": [s.get("vless_vision_reality_sni", "www.yahoo.com")],
                },
            },
        }

    def _make_vless_reverse_reality(self, user_uuid: str, s: Any) -> Dict:
        tunnel_port = s.get("vless_reverse_tunnel_port", 0) or 0
        return {
            "protocol": "vless",
            "port": s.get("vless_reverse_port", 2059),
            "tag": "vless-reverse-reality",
            "settings": {
                "clients": [{"id": user_uuid, "flow": ""}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "privateKey": s.get("vless_reverse_reality_private_key", ""),
                    "shortIds": [s.get("vless_reverse_reality_short_id", "")],
                    "dest": s.get("vless_reverse_reality_dest", "www.amazon.com:443"),
                    "serverNames": [s.get("vless_reverse_reality_sni", "www.amazon.com")],
                },
            },
            # Reverse tunnel via Xray's reverse proxy feature
            "reverse": {
                "bridges": [{
                    "tag": "reverse-bridge",
                    "domain": f"reverse.{user_uuid[:8]}.tunnel",
                }],
            },
        }

    def _make_trojan_cdn(self, user_uuid: str, s: Any) -> List[Dict]:
        inbounds = []
        password = user_uuid  # Trojan uses UUID as password

        # Trojan+WS+TLS (CDN)
        inbounds.append({
            "protocol": "trojan",
            "port": s.get("trojan_cdn_port", 2083),
            "tag": "trojan-cdn-ws",
            "settings": {
                "clients": [{"password": password}],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": s.get("trojan_cdn_sni", ""),
                    "certificates": [],  # filled from cert files
                },
                "wsSettings": {
                    "path": s.get("trojan_cdn_ws_path", "/trojan-ws"),
                    "headers": {
                        "Host": s.get("trojan_cdn_domain", ""),
                    },
                },
            },
        })

        # Trojan+gRPC+TLS (CDN) — optional second transport
        if s.get("trojan_cdn_grpc_enabled", False):
            inbounds.append({
                "protocol": "trojan",
                "port": s.get("trojan_cdn_grpc_port", 2060),
                "tag": "trojan-cdn-grpc",
                "settings": {
                    "clients": [{"password": password}],
                },
                "streamSettings": {
                    "network": "grpc",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": s.get("trojan_cdn_sni", ""),
                    },
                    "grpcSettings": {
                        "serviceName": s.get("trojan_cdn_grpc_service", "TrojanService"),
                    },
                },
            })

        return inbounds

    def _make_vmess_ws(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "port": s.get("vmess_port", 443),
            "tag": "vmess-ws",
            "settings": {
                "clients": [{"id": user_uuid, "alterId": 0}],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": s.get("vmess_sni", "www.aparat.com"),
                },
                "wsSettings": {
                    "path": s.get("vmess_ws_path", "/api/v1/stream"),
                },
            },
        }

    def _make_vless_ws(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "port": s.get("vless_ws_port", 2057),
            "tag": "vless-ws",
            "settings": {
                "clients": [{"id": user_uuid, "flow": ""}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": s.get("vpn_sni_host", ""),
                },
                "wsSettings": {
                    "path": s.get("vless_ws_path", "/vless-ws"),
                },
            },
        }

    def _make_ss2022(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "shadowsocks",
            "port": s.get("ss2022_port", 2056),
            "tag": "ss2022",
            "settings": {
                "clients": [{"password": user_uuid}],
                "method": s.get("ss2022_method", "2022-blake3-aes-128-gcm"),
                "password": s.get("ss2022_server_key", ""),
            },
        }

    def _make_grpc(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "port": s.get("grpc_port", 2054),
            "tag": "grpc",
            "settings": {
                "clients": [{"id": user_uuid, "alterId": 0}],
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {
                    "serviceName": s.get("grpc_service_name", "GunService"),
                },
            },
        }

    def _make_httpupgrade(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "port": s.get("httpupgrade_port", 2055),
            "tag": "httpupgrade",
            "settings": {
                "clients": [{"id": user_uuid, "alterId": 0}],
            },
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "httpupgradeSettings": {
                    "path": s.get("httpupgrade_path", "/httpupgrade"),
                },
            },
        }

    # ── Standalone Protocol Configs ─────────────────────────

    def generate_hysteria2_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate Hysteria2 server configuration."""
        config = {
            "listen": f":{getattr(s, 'HYSTERIA2_PORT', 8443)}",
            "protocol": "hy2",
            "users": {user_uuid: s.get("hysteria2_password", "")},
            "tls": {
                "cert": s.get("tuic_cert_path", ""),
                "key": s.get("tuic_key_path", ""),
            },
            "bandwidth": {
                "up": s.get("hysteria2_bandwidth_up", "100 mbps"),
                "down": s.get("hysteria2_bandwidth_down", "200 mbps"),
            },
        }
        if s.get("hysteria2_salamander_enabled", False):
            config["obfs"] = {
                "type": "salamander",
                "password": s.get("hysteria2_salamander_password", ""),
            }
        if s.get("hysteria2_port_hop_enabled", False):
            config["portHop"] = {
                "enabled": True,
                "ports": s.get("hysteria2_port_hop_ports", "20000-50000"),
            }
        return config

    def generate_tuic_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate TUIC v5 server configuration."""
        return {
            "server": f"[::]:{getattr(s, 'TUIC_PORT', 8444)}",
            "users": {user_uuid: s.get("tuic_password", "")},
            "certificate": s.get("tuic_cert_path", ""),
            "private_key": s.get("tuic_key_path", ""),
            "congestion_control": s.get("tuic_congestion_control", "cubic"),
            "udp_relay": s.get("tuic_udp_relay", "native"),
            "zero_rtt": s.get("tuic_zero_rtt", False),
        }

    def generate_amneziawg_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate AmneziaWG 2.0 server configuration."""
        return {
            "interface": {
                "private_key": s.get("amneziawg_private_key", ""),
                "address": s.get("amneziawg_address", "10.8.0.1/24"),
                "listen_port": s.get("amneziawg_port", 51820),
                "dns": s.get("amneziawg_dns", "1.1.1.1"),
                "mtu": s.get("amneziawg_mtu", 1280),
            },
            "junk_packets": {
                "jc": s.get("amneziawg_jc", 4),
                "jmin": s.get("amneziawg_jmin", 50),
                "jmax": s.get("amneziawg_jmax", 1000),
            },
            "magic_headers": {
                "s1": s.get("amneziawg_s1", 0),
                "s2": s.get("amneziawg_s2", 0),
                "h1": s.get("amneziawg_h1", 1),
                "h2": s.get("amneziawg_h2", 2),
                "h3": s.get("amneziawg_h3", 3),
                "h4": s.get("amneziawg_h4", 4),
            },
        }

    def generate_shadowtls_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate ShadowTLS v3 server configuration."""
        return {
            "server": f"0.0.0.0:{getattr(s, 'SHADOWTLS_PORT', 8445)}",
            "version": s.get("shadowtls_version", 3),
            "password": s.get("shadowtls_password", ""),
            "sni": s.get("shadowtls_sni", "www.google.com"),
            "backend": s.get("shadowtls_backend", "127.0.0.1:1080"),
            "tls_cert": s.get("shadowtls_tls_cert_path", ""),
            "tls_key": s.get("shadowtls_tls_key_path", ""),
        }

    def generate_mieru_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate Mieru server configuration."""
        return {
            "port": s.get("mieru_port", 8446),
            "password": s.get("mieru_password", ""),
            "encryption": s.get("mieru_encryption", "aes-256-gcm"),
            "transport": s.get("mieru_transport", "tcp"),
            "multiplexing": {
                "enabled": s.get("mieru_mux_enabled", True),
                "concurrency": s.get("mieru_mux_concurrency", 8),
            },
        }

    def generate_naiveproxy_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate NaiveProxy server configuration."""
        return {
            "listen": f"0.0.0.0:{getattr(s, 'NAIVEPROXY_PORT', 8447)}",
            "user": s.get("naiveproxy_user", ""),
            "password": s.get("naiveproxy_password", ""),
            "sni": s.get("naiveproxy_sni", ""),
            "cert": s.get("naiveproxy_cert_path", ""),
            "key": s.get("naiveproxy_key_path", ""),
            "concurrency": s.get("naiveproxy_concurrency", 4),
        }

    def generate_wireguard_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate plain WireGuard server configuration."""
        return {
            "interface": {
                "private_key": s.get("wireguard_private_key", ""),
                "address": s.get("wireguard_address", "10.9.0.1/24"),
                "listen_port": s.get("wireguard_port", 51821),
                "dns": s.get("wireguard_dns", "1.1.1.1"),
                "mtu": s.get("wireguard_mtu", 1280),
                "persistent_keepalive": s.get("wireguard_persistent_keepalive", 25),
            },
        }

    def generate_openvpn_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate plain OpenVPN server configuration."""
        return {
            "port": s.get("openvpn_port", 1194),
            "proto": s.get("openvpn_proto", "udp"),
            "dev": "tun",
            "server": s.get("openvpn_network", "10.10.0.0/24"),
            "dns": s.get("openvpn_dns", "1.1.1.1"),
            "cert": s.get("openvpn_cert_path", ""),
            "key": s.get("openvpn_key_path", ""),
            "dh": s.get("openvpn_dh_path", ""),
            "tls_auth": s.get("openvpn_ta_path", ""),
        }

    # ── Client Config Generation ────────────────────────────

    def generate_client_config(self, protocol_key: str, user_uuid: str, settings: Any) -> Dict:
        """Generate client-side configuration for a specific protocol."""
        spec = self.get_protocol(protocol_key)
        if not spec:
            raise ValueError(f"Unknown protocol: {protocol_key}")

        generators = {
            "vless_xhttp_reality": self._client_vless_xhttp_reality,
            "vless_vision_reality": self._client_vless_vision_reality,
            "vless_reverse_reality": self._client_vless_reverse_reality,
            "trojan_cdn": self._client_trojan_cdn,
            "vmess_ws": self._client_vmess_ws,
            "vless_ws": self._client_vless_ws,
            "ss2022": self._client_ss2022,
            "grpc": self._client_grpc,
            "httpupgrade": self._client_httpupgrade,
            "hysteria2": self._client_hysteria2,
            "tuic_v5": self._client_tuic_v5,
            "amneziawg": self._client_amneziawg,
            "shadowtls_v3": self._client_shadowtls_v3,
            "mieru": self._client_mieru,
            "naiveproxy": self._client_naiveproxy,
            "wireguard": self._client_wireguard,
            "openvpn": self._client_openvpn,
        }

        gen = generators.get(protocol_key)
        if gen:
            return gen(user_uuid, settings)
        return {"error": f"No client config generator for {protocol_key}"}

    def _client_vless_xhttp_reality(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": s.get("vpn_server_ip", ""),
                    "port": s.get("vless_xhttp_port", 2053),
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": "",
                    }],
                }],
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "realitySettings": {
                    "publicKey": s.get("vless_xhttp_reality_public_key", ""),
                    "shortId": s.get("vless_xhttp_reality_short_id", ""),
                    "serverName": s.get("vless_xhttp_reality_sni", "www.microsoft.com"),
                    "fingerprint": s.get("utls_fingerprint", "chrome"),
                },
                "xhttpSettings": {
                    "path": s.get("vless_xhttp_path", "/xhttp-stream"),
                    "mode": s.get("vless_xhttp_mode", "auto"),
                },
            },
        }

    def _client_vless_vision_reality(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": s.get("vpn_server_ip", ""),
                    "port": s.get("vless_vision_port", 2058),
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": s.get("vless_vision_flow", "xtls-rprx-vision"),
                    }],
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "publicKey": s.get("vless_vision_reality_public_key", ""),
                    "shortId": s.get("vless_vision_reality_short_id", ""),
                    "serverName": s.get("vless_vision_reality_sni", "www.yahoo.com"),
                    "fingerprint": s.get("utls_fingerprint", "chrome"),
                },
            },
        }

    def _client_vless_reverse_reality(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": s.get("vpn_server_ip", ""),
                    "port": s.get("vless_reverse_port", 2059),
                    "users": [{"id": uuid, "encryption": "none", "flow": ""}],
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "publicKey": s.get("vless_reverse_reality_public_key", ""),
                    "shortId": s.get("vless_reverse_reality_short_id", ""),
                    "serverName": s.get("vless_reverse_reality_sni", "www.amazon.com"),
                    "fingerprint": s.get("utls_fingerprint", "chrome"),
                },
            },
            "reverse": {
                "bridges": [{
                    "tag": "reverse-bridge",
                    "domain": f"reverse.{uuid[:8]}.tunnel",
                }],
            },
        }

    def _client_trojan_cdn(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": s.get("trojan_cdn_domain", "") or s.get("vpn_server_ip", ""),
                    "port": s.get("trojan_cdn_port", 2083),
                    "password": uuid,
                }],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": s.get("trojan_cdn_sni", ""),
                },
                "wsSettings": {
                    "path": s.get("trojan_cdn_ws_path", "/trojan-ws"),
                },
            },
        }

    def _client_vmess_ws(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": s.get("vpn_server_ip", ""),
                    "port": s.get("vmess_port", 443),
                    "users": [{"id": uuid, "alterId": 0, "security": "auto"}],
                }],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": s.get("vmess_sni", "www.aparat.com"),
                },
                "wsSettings": {
                    "path": s.get("vmess_ws_path", "/api/v1/stream"),
                },
            },
        }

    def _client_vless_ws(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": s.get("vpn_server_ip", ""),
                    "port": s.get("vless_ws_port", 2057),
                    "users": [{"id": uuid, "encryption": "none"}],
                }],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": s.get("vless_ws_path", "/vless-ws")},
            },
        }

    def _client_ss2022(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": s.get("vpn_server_ip", ""),
                    "port": s.get("ss2022_port", 2056),
                    "method": s.get("ss2022_method", "2022-blake3-aes-128-gcm"),
                    "password": uuid,
                }],
            },
        }

    def _client_grpc(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": s.get("vpn_server_ip", ""),
                    "port": s.get("grpc_port", 2054),
                    "users": [{"id": uuid, "alterId": 0}],
                }],
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {
                    "serviceName": s.get("grpc_service_name", "GunService"),
                },
            },
        }

    def _client_httpupgrade(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": s.get("vpn_server_ip", ""),
                    "port": s.get("httpupgrade_port", 2055),
                    "users": [{"id": uuid, "alterId": 0}],
                }],
            },
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "httpupgradeSettings": {
                    "path": s.get("httpupgrade_path", "/httpupgrade"),
                },
            },
        }

    def _client_hysteria2(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "hy2",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'HYSTERIA2_PORT', 8443)}",
            "password": s.get("hysteria2_password", ""),
            "obfs": {
                "type": "salamander" if s.get("hysteria2_salamander_enabled", False) else "",
                "password": s.get("hysteria2_salamander_password", ""),
            } if s.get("hysteria2_salamander_enabled", False) else {},
            "bandwidth": {
                "up": s.get("hysteria2_bandwidth_up", "100 mbps"),
                "down": s.get("hysteria2_bandwidth_down", "200 mbps"),
            },
        }

    def _client_tuic_v5(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "tuic",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'TUIC_PORT', 8444)}",
            "password": s.get("tuic_password", ""),
            "congestion_control": s.get("tuic_congestion_control", "cubic"),
            "udp_relay": s.get("tuic_udp_relay", "native"),
            "zero_rtt": s.get("tuic_zero_rtt", False),
        }

    def _client_amneziawg(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "amneziawg",
            "interface": {
                "address": s.get("amneziawg_address", "10.8.0.1/24"),
                "dns": s.get("amneziawg_dns", "1.1.1.1"),
                "mtu": s.get("amneziawg_mtu", 1280),
            },
            "peer": {
                "endpoint": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'AMNEZIAWG_PORT', 51820)}",
                "persistent_keepalive": 25,
            },
            "junk_packets": {
                "jc": s.get("amneziawg_jc", 4),
                "jmin": s.get("amneziawg_jmin", 50),
                "jmax": s.get("amneziawg_jmax", 1000),
            },
            "magic_headers": {
                "s1": s.get("amneziawg_s1", 0),
                "s2": s.get("amneziawg_s2", 0),
                "h1": s.get("amneziawg_h1", 1),
                "h2": s.get("amneziawg_h2", 2),
                "h3": s.get("amneziawg_h3", 3),
                "h4": s.get("amneziawg_h4", 4),
            },
        }

    def _client_shadowtls_v3(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "shadowtls",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'SHADOWTLS_PORT', 8445)}",
            "version": s.get("shadowtls_version", 3),
            "password": s.get("shadowtls_password", ""),
            "sni": s.get("shadowtls_sni", "www.google.com"),
        }

    def _client_mieru(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "mieru",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'MIERU_PORT', 8446)}",
            "password": s.get("mieru_password", ""),
            "encryption": s.get("mieru_encryption", "aes-256-gcm"),
            "transport": s.get("mieru_transport", "tcp"),
        }

    def _client_naiveproxy(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "naiveproxy",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'NAIVEPROXY_PORT', 8447)}",
            "user": s.get("naiveproxy_user", ""),
            "password": s.get("naiveproxy_password", ""),
            "sni": s.get("naiveproxy_sni", ""),
        }

    def _client_wireguard(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "wireguard",
            "interface": {
                "address": s.get("wireguard_address", "10.9.0.1/24"),
                "dns": s.get("wireguard_dns", "1.1.1.1"),
                "mtu": s.get("wireguard_mtu", 1280),
            },
            "peer": {
                "endpoint": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'WIREGUARD_PORT', 51821)}",
                "persistent_keepalive": s.get("wireguard_persistent_keepalive", 25),
            },
        }

    def _client_openvpn(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "openvpn",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'OPENVPN_PORT', 1194)}",
            "proto": s.get("openvpn_proto", "udp"),
        }

    # ── Subscription Link Generation ───────────────────────

    def generate_subscription_link(self, protocol_key: str, user_uuid: str, settings: Any) -> str:
        """Generate subscription link for a protocol (v2ray/xray share link format)."""
        client_config = self.generate_client_config(protocol_key, user_uuid, settings)

        if protocol_key in ("hysteria2", "tuic_v5", "amneziawg", "shadowtls_v3",
                            "mieru", "naiveproxy", "wireguard", "openvpn"):
            return base64.b64encode(
                json.dumps(client_config).encode()
            ).decode()

        # Xray share link format
        server_ip = settings.get("vpn_server_ip", "")
        if protocol_key in ("vless_xhttp_reality", "vless_vision_reality", "vless_reverse_reality", "vless_ws"):
            return self._vless_share_link(protocol_key, user_uuid, server_ip, settings)
        elif protocol_key == "vmess_ws":
            return self._vmess_share_link(user_uuid, server_ip, settings)
        elif protocol_key == "trojan_cdn":
            return self._trojan_share_link(user_uuid, server_ip, settings)
        elif protocol_key == "ss2022":
            return self._ss_share_link(user_uuid, server_ip, settings)

        return base64.b64encode(json.dumps(client_config).encode()).decode()

    def _vless_share_link(self, protocol_key: str, uuid: str, server: str, s: Any) -> str:
        if protocol_key == "vless_xhttp_reality":
            port = s.get("vless_xhttp_port", 2053)
            sni = s.get("vless_xhttp_reality_sni", "www.microsoft.com")
            pbk = s.get("vless_xhttp_reality_public_key", "")
            sid = s.get("vless_xhttp_reality_short_id", "")
            fp = s.get("utls_fingerprint", "chrome")
            path = s.get("vless_xhttp_path", "/xhttp-stream")
            mode = s.get("vless_xhttp_mode", "auto")
            return (f"vless://{uuid}@{server}:{port}?type=xhttp&security=reality"
                    f"&sni={sni}&fp={fp}&pbk={pbk}&sid={sid}"
                    f"&path={path}&mode={mode}#Spiritus-VLESS-XHTTP-Reality")
        elif protocol_key == "vless_vision_reality":
            port = s.get("vless_vision_port", 2058)
            sni = s.get("vless_vision_reality_sni", "www.yahoo.com")
            pbk = s.get("vless_vision_reality_public_key", "")
            sid = s.get("vless_vision_reality_short_id", "")
            fp = s.get("utls_fingerprint", "chrome")
            flow = s.get("vless_vision_flow", "xtls-rprx-vision")
            return (f"vless://{uuid}@{server}:{port}?type=tcp&security=reality"
                    f"&sni={sni}&fp={fp}&pbk={pbk}&sid={sid}"
                    f"&flow={flow}#Spiritus-VLESS-Vision-Reality")
        elif protocol_key == "vless_reverse_reality":
            port = s.get("vless_reverse_port", 2059)
            sni = s.get("vless_reverse_reality_sni", "www.amazon.com")
            pbk = s.get("vless_reverse_reality_public_key", "")
            sid = s.get("vless_reverse_reality_short_id", "")
            fp = s.get("utls_fingerprint", "chrome")
            return (f"vless://{uuid}@{server}:{port}?type=tcp&security=reality"
                    f"&sni={sni}&fp={fp}&pbk={pbk}&sid={sid}"
                    f"#Spiritus-VLESS-Reverse-Reality")
        else:  # vless_ws
            port = s.get("vless_ws_port", 2057)
            path = s.get("vless_ws_path", "/vless-ws")
            sni = s.get("vpn_sni_host", "")
            return (f"vless://{uuid}@{server}:{port}?type=ws&security=tls"
                    f"&sni={sni}&path={path}#Spiritus-VLESS-WS")

    def _vmess_share_link(self, uuid: str, server: str, s: Any) -> str:
        import json as _json
        port = s.get("vmess_port", 443)
        sni = s.get("vmess_sni", "www.aparat.com")
        path = s.get("vmess_ws_path", "/api/v1/stream")
        vmess_obj = {
            "v": "2", "ps": "Spiritus-VMess-WS",
            "add": server, "port": port,
            "id": uuid, "aid": 0,
            "net": "ws", "type": "none",
            "host": sni, "path": path,
            "tls": "tls", "sni": sni,
        }
        return "vmess://" + base64.b64encode(_json.dumps(vmess_obj).encode()).decode()

    def _trojan_share_link(self, uuid: str, server: str, s: Any) -> str:
        port = s.get("trojan_cdn_port", 2083)
        sni = s.get("trojan_cdn_sni", "")
        path = s.get("trojan_cdn_ws_path", "/trojan-ws")
        host = s.get("trojan_cdn_domain", "") or server
        return (f"trojan://{uuid}@{host}:{port}?type=ws&security=tls"
                f"&sni={sni}&path={path}#Spiritus-Trojan-CDN")

    def _ss_share_link(self, uuid: str, server: str, s: Any) -> str:
        port = s.get("ss2022_port", 2056)
        method = s.get("ss2022_method", "2022-blake3-aes-128-gcm")
        return f"ss://{method}:{uuid}@{server}:{port}#Spiritus-SS2022"

    # ── Utility ──────────────────────────────────────────────

    def get_protocol_summary(self) -> List[Dict]:
        """Get summary of all registered protocols."""
        return [
            {
                "key": spec.key,
                "name": spec.name,
                "name_fa": spec.name_fa,
                "category": spec.category.value,
                "backend": spec.backend.value,
                "anti_block": spec.anti_block,
                "supports_cdn": spec.supports_cdn,
                "requires_tls": spec.requires_tls,
                "requires_udp": spec.requires_udp,
                "default_port": spec.default_port,
            }
            for spec in self._registry.values()
        ]

    def get_recommended_protocols(self, has_cdn: bool = False, has_fresh_ip: bool = False) -> List[str]:
        """Get recommended protocols based on server capabilities."""
        recommended = []

        if has_fresh_ip:
            recommended.extend(["vless_vision_reality", "vless_xhttp_reality"])

        if has_cdn:
            recommended.extend(["trojan_cdn", "vless_ws", "vmess_ws", "naiveproxy"])

        recommended.extend(["hysteria2", "amneziawg", "tuic_v5"])

        return list(dict.fromkeys(recommended))  # deduplicate preserving order


# ═══════════════════════════════════════════════════════════════
#  Singleton
# ═══════════════════════════════════════════════════════════════

_engine_instance: Optional[ProtocolEngine] = None


def get_protocol_engine(settings: Any = None) -> ProtocolEngine:
    """Get or create the protocol engine singleton."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ProtocolEngine(settings)
    return _engine_instance