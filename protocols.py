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
        if getattr(settings, "VLESS_XHTTP_ENABLED", False):
            inbounds.append(self._make_vless_xhttp_reality(user_uuid, settings))

        # VLESS+REALITY+Vision
        if getattr(settings, "VLESS_VISION_ENABLED", False):
            inbounds.append(self._make_vless_vision_reality(user_uuid, settings))

        # VLESS-Reverse-Reality
        if getattr(settings, "VLESS_REVERSE_ENABLED", False):
            inbounds.append(self._make_vless_reverse_reality(user_uuid, settings))

        # Trojan+WS/gRPC+CDN
        if getattr(settings, "TROJAN_CDN_ENABLED", False):
            inbounds.extend(self._make_trojan_cdn(user_uuid, settings))

        # VMess+WS+TLS
        if getattr(settings, "VMESS_ENABLED", True):
            inbounds.append(self._make_vmess_ws(user_uuid, settings))

        # VLESS+WS+TLS
        if getattr(settings, "VLESS_WS_ENABLED", False):
            inbounds.append(self._make_vless_ws(user_uuid, settings))

        # SS-2022
        if getattr(settings, "SS2022_ENABLED", False):
            inbounds.append(self._make_ss2022(user_uuid, settings))

        # gRPC
        if getattr(settings, "GRPC_ENABLED", False):
            inbounds.append(self._make_grpc(user_uuid, settings))

        # HTTPUpgrade
        if getattr(settings, "HTTPUPGRADE_ENABLED", False):
            inbounds.append(self._make_httpupgrade(user_uuid, settings))

        return config

    # ── Xray Inbound Builders ────────────────────────────────

    def _make_vless_xhttp_reality(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "port": getattr(s, "VLESS_XHTTP_PORT", 2053),
            "tag": "vless-xhttp-reality",
            "settings": {
                "clients": [{"id": user_uuid, "flow": ""}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "realitySettings": {
                    "privateKey": getattr(s, "VLESS_XHTTP_REALITY_PRIVATE_KEY", ""),
                    "shortIds": [getattr(s, "VLESS_XHTTP_REALITY_SHORT_ID", "")],
                    "dest": getattr(s, "VLESS_XHTTP_REALITY_DEST", "www.microsoft.com:443"),
                    "serverNames": [getattr(s, "VLESS_XHTTP_REALITY_SNI", "www.microsoft.com")],
                },
                "xhttpSettings": {
                    "path": getattr(s, "VLESS_XHTTP_PATH", "/xhttp-stream"),
                    "mode": getattr(s, "VLESS_XHTTP_MODE", "auto"),
                },
            },
        }

    def _make_vless_vision_reality(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "port": getattr(s, "VLESS_VISION_PORT", 2058),
            "tag": "vless-vision-reality",
            "settings": {
                "clients": [{"id": user_uuid, "flow": getattr(s, "VLESS_VISION_FLOW", "xtls-rprx-vision")}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "privateKey": getattr(s, "VLESS_VISION_REALITY_PRIVATE_KEY", ""),
                    "shortIds": [getattr(s, "VLESS_VISION_REALITY_SHORT_ID", "")],
                    "dest": getattr(s, "VLESS_VISION_REALITY_DEST", "www.yahoo.com:443"),
                    "serverNames": [getattr(s, "VLESS_VISION_REALITY_SNI", "www.yahoo.com")],
                },
            },
        }

    def _make_vless_reverse_reality(self, user_uuid: str, s: Any) -> Dict:
        tunnel_port = getattr(s, "VLESS_REVERSE_TUNNEL_PORT", 0) or 0
        return {
            "protocol": "vless",
            "port": getattr(s, "VLESS_REVERSE_PORT", 2059),
            "tag": "vless-reverse-reality",
            "settings": {
                "clients": [{"id": user_uuid, "flow": ""}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "privateKey": getattr(s, "VLESS_REVERSE_REALITY_PRIVATE_KEY", ""),
                    "shortIds": [getattr(s, "VLESS_REVERSE_REALITY_SHORT_ID", "")],
                    "dest": getattr(s, "VLESS_REVERSE_REALITY_DEST", "www.amazon.com:443"),
                    "serverNames": [getattr(s, "VLESS_REVERSE_REALITY_SNI", "www.amazon.com")],
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
            "port": getattr(s, "TROJAN_CDN_PORT", 2083),
            "tag": "trojan-cdn-ws",
            "settings": {
                "clients": [{"password": password}],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": getattr(s, "TROJAN_CDN_SNI", ""),
                    "certificates": [],  # filled from cert files
                },
                "wsSettings": {
                    "path": getattr(s, "TROJAN_CDN_WS_PATH", "/trojan-ws"),
                    "headers": {
                        "Host": getattr(s, "TROJAN_CDN_DOMAIN", ""),
                    },
                },
            },
        })

        # Trojan+gRPC+TLS (CDN) — optional second transport
        if getattr(s, "TROJAN_CDN_GRPC_ENABLED", False):
            inbounds.append({
                "protocol": "trojan",
                "port": getattr(s, "TROJAN_CDN_GRPC_PORT", 2060),
                "tag": "trojan-cdn-grpc",
                "settings": {
                    "clients": [{"password": password}],
                },
                "streamSettings": {
                    "network": "grpc",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": getattr(s, "TROJAN_CDN_SNI", ""),
                    },
                    "grpcSettings": {
                        "serviceName": getattr(s, "TROJAN_CDN_GRPC_SERVICE", "TrojanService"),
                    },
                },
            })

        return inbounds

    def _make_vmess_ws(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "port": getattr(s, "VMESS_PORT", 443),
            "tag": "vmess-ws",
            "settings": {
                "clients": [{"id": user_uuid, "alterId": 0}],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": getattr(s, "VMESS_SNI", "www.aparat.com"),
                },
                "wsSettings": {
                    "path": getattr(s, "VMESS_WS_PATH", "/api/v1/stream"),
                },
            },
        }

    def _make_vless_ws(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "port": getattr(s, "VLESS_WS_PORT", 2057),
            "tag": "vless-ws",
            "settings": {
                "clients": [{"id": user_uuid, "flow": ""}],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": getattr(s, "VPN_SNI_HOST", ""),
                },
                "wsSettings": {
                    "path": getattr(s, "VLESS_WS_PATH", "/vless-ws"),
                },
            },
        }

    def _make_ss2022(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "shadowsocks",
            "port": getattr(s, "SS2022_PORT", 2056),
            "tag": "ss2022",
            "settings": {
                "clients": [{"password": user_uuid}],
                "method": getattr(s, "SS2022_METHOD", "2022-blake3-aes-128-gcm"),
                "password": getattr(s, "SS2022_SERVER_KEY", ""),
            },
        }

    def _make_grpc(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "port": getattr(s, "GRPC_PORT", 2054),
            "tag": "grpc",
            "settings": {
                "clients": [{"id": user_uuid, "alterId": 0}],
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {
                    "serviceName": getattr(s, "GRPC_SERVICE_NAME", "GunService"),
                },
            },
        }

    def _make_httpupgrade(self, user_uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "port": getattr(s, "HTTPUPGRADE_PORT", 2055),
            "tag": "httpupgrade",
            "settings": {
                "clients": [{"id": user_uuid, "alterId": 0}],
            },
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "httpupgradeSettings": {
                    "path": getattr(s, "HTTPUPGRADE_PATH", "/httpupgrade"),
                },
            },
        }

    # ── Standalone Protocol Configs ─────────────────────────

    def generate_hysteria2_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate Hysteria2 server configuration."""
        config = {
            "listen": f":{getattr(s, 'HYSTERIA2_PORT', 8443)}",
            "protocol": "hy2",
            "users": {user_uuid: getattr(s, "HYSTERIA2_PASSWORD", "")},
            "tls": {
                "cert": getattr(s, "TUIC_CERT_PATH", ""),
                "key": getattr(s, "TUIC_KEY_PATH", ""),
            },
            "bandwidth": {
                "up": getattr(s, "HYSTERIA2_BANDWIDTH_UP", "100 mbps"),
                "down": getattr(s, "HYSTERIA2_BANDWIDTH_DOWN", "200 mbps"),
            },
        }
        if getattr(s, "HYSTERIA2_SALAMANDER_ENABLED", False):
            config["obfs"] = {
                "type": "salamander",
                "password": getattr(s, "HYSTERIA2_SALAMANDER_PASSWORD", ""),
            }
        if getattr(s, "HYSTERIA2_PORT_HOP_ENABLED", False):
            config["portHop"] = {
                "enabled": True,
                "ports": getattr(s, "HYSTERIA2_PORT_HOP_PORTS", "20000-50000"),
            }
        return config

    def generate_tuic_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate TUIC v5 server configuration."""
        return {
            "server": f"[::]:{getattr(s, 'TUIC_PORT', 8444)}",
            "users": {user_uuid: getattr(s, "TUIC_PASSWORD", "")},
            "certificate": getattr(s, "TUIC_CERT_PATH", ""),
            "private_key": getattr(s, "TUIC_KEY_PATH", ""),
            "congestion_control": getattr(s, "TUIC_CONGESTION_CONTROL", "cubic"),
            "udp_relay": getattr(s, "TUIC_UDP_RELAY", "native"),
            "zero_rtt": getattr(s, "TUIC_ZERO_RTT", False),
        }

    def generate_amneziawg_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate AmneziaWG 2.0 server configuration."""
        return {
            "interface": {
                "private_key": getattr(s, "AMNEZIAWG_PRIVATE_KEY", ""),
                "address": getattr(s, "AMNEZIAWG_ADDRESS", "10.8.0.1/24"),
                "listen_port": getattr(s, "AMNEZIAWG_PORT", 51820),
                "dns": getattr(s, "AMNEZIAWG_DNS", "1.1.1.1"),
                "mtu": getattr(s, "AMNEZIAWG_MTU", 1280),
            },
            "junk_packets": {
                "jc": getattr(s, "AMNEZIAWG_JC", 4),
                "jmin": getattr(s, "AMNEZIAWG_JMIN", 50),
                "jmax": getattr(s, "AMNEZIAWG_JMAX", 1000),
            },
            "magic_headers": {
                "s1": getattr(s, "AMNEZIAWG_S1", 0),
                "s2": getattr(s, "AMNEZIAWG_S2", 0),
                "h1": getattr(s, "AMNEZIAWG_H1", 1),
                "h2": getattr(s, "AMNEZIAWG_H2", 2),
                "h3": getattr(s, "AMNEZIAWG_H3", 3),
                "h4": getattr(s, "AMNEZIAWG_H4", 4),
            },
        }

    def generate_shadowtls_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate ShadowTLS v3 server configuration."""
        return {
            "server": f"0.0.0.0:{getattr(s, 'SHADOWTLS_PORT', 8445)}",
            "version": getattr(s, "SHADOWTLS_VERSION", 3),
            "password": getattr(s, "SHADOWTLS_PASSWORD", ""),
            "sni": getattr(s, "SHADOWTLS_SNI", "www.google.com"),
            "backend": getattr(s, "SHADOWTLS_BACKEND", "127.0.0.1:1080"),
            "tls_cert": getattr(s, "SHADOWTLS_TLS_CERT_PATH", ""),
            "tls_key": getattr(s, "SHADOWTLS_TLS_KEY_PATH", ""),
        }

    def generate_mieru_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate Mieru server configuration."""
        return {
            "port": getattr(s, "MIERU_PORT", 8446),
            "password": getattr(s, "MIERU_PASSWORD", ""),
            "encryption": getattr(s, "MIERU_ENCRYPTION", "aes-256-gcm"),
            "transport": getattr(s, "MIERU_TRANSPORT", "tcp"),
            "multiplexing": {
                "enabled": getattr(s, "MIERU_MUX_ENABLED", True),
                "concurrency": getattr(s, "MIERU_MUX_CONCURRENCY", 8),
            },
        }

    def generate_naiveproxy_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate NaiveProxy server configuration."""
        return {
            "listen": f"0.0.0.0:{getattr(s, 'NAIVEPROXY_PORT', 8447)}",
            "user": getattr(s, "NAIVEPROXY_USER", ""),
            "password": getattr(s, "NAIVEPROXY_PASSWORD", ""),
            "sni": getattr(s, "NAIVEPROXY_SNI", ""),
            "cert": getattr(s, "NAIVEPROXY_CERT_PATH", ""),
            "key": getattr(s, "NAIVEPROXY_KEY_PATH", ""),
            "concurrency": getattr(s, "NAIVEPROXY_CONCURRENCY", 4),
        }

    def generate_wireguard_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate plain WireGuard server configuration."""
        return {
            "interface": {
                "private_key": getattr(s, "WIREGUARD_PRIVATE_KEY", ""),
                "address": getattr(s, "WIREGUARD_ADDRESS", "10.9.0.1/24"),
                "listen_port": getattr(s, "WIREGUARD_PORT", 51821),
                "dns": getattr(s, "WIREGUARD_DNS", "1.1.1.1"),
                "mtu": getattr(s, "WIREGUARD_MTU", 1280),
                "persistent_keepalive": getattr(s, "WIREGUARD_PERSISTENT_KEEPALIVE", 25),
            },
        }

    def generate_openvpn_config(self, user_uuid: str, s: Any) -> Dict:
        """Generate plain OpenVPN server configuration."""
        return {
            "port": getattr(s, "OPENVPN_PORT", 1194),
            "proto": getattr(s, "OPENVPN_PROTO", "udp"),
            "dev": "tun",
            "server": getattr(s, "OPENVPN_NETWORK", "10.10.0.0/24"),
            "dns": getattr(s, "OPENVPN_DNS", "1.1.1.1"),
            "cert": getattr(s, "OPENVPN_CERT_PATH", ""),
            "key": getattr(s, "OPENVPN_KEY_PATH", ""),
            "dh": getattr(s, "OPENVPN_DH_PATH", ""),
            "tls_auth": getattr(s, "OPENVPN_TA_PATH", ""),
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
                    "address": getattr(s, "VPN_SERVER_IP", ""),
                    "port": getattr(s, "VLESS_XHTTP_PORT", 2053),
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
                    "publicKey": getattr(s, "VLESS_XHTTP_REALITY_PUBLIC_KEY", ""),
                    "shortId": getattr(s, "VLESS_XHTTP_REALITY_SHORT_ID", ""),
                    "serverName": getattr(s, "VLESS_XHTTP_REALITY_SNI", "www.microsoft.com"),
                    "fingerprint": getattr(s, "UTLS_FINGERPRINT", "chrome"),
                },
                "xhttpSettings": {
                    "path": getattr(s, "VLESS_XHTTP_PATH", "/xhttp-stream"),
                    "mode": getattr(s, "VLESS_XHTTP_MODE", "auto"),
                },
            },
        }

    def _client_vless_vision_reality(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": getattr(s, "VPN_SERVER_IP", ""),
                    "port": getattr(s, "VLESS_VISION_PORT", 2058),
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": getattr(s, "VLESS_VISION_FLOW", "xtls-rprx-vision"),
                    }],
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "publicKey": getattr(s, "VLESS_VISION_REALITY_PUBLIC_KEY", ""),
                    "shortId": getattr(s, "VLESS_VISION_REALITY_SHORT_ID", ""),
                    "serverName": getattr(s, "VLESS_VISION_REALITY_SNI", "www.yahoo.com"),
                    "fingerprint": getattr(s, "UTLS_FINGERPRINT", "chrome"),
                },
            },
        }

    def _client_vless_reverse_reality(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": getattr(s, "VPN_SERVER_IP", ""),
                    "port": getattr(s, "VLESS_REVERSE_PORT", 2059),
                    "users": [{"id": uuid, "encryption": "none", "flow": ""}],
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "publicKey": getattr(s, "VLESS_REVERSE_REALITY_PUBLIC_KEY", ""),
                    "shortId": getattr(s, "VLESS_REVERSE_REALITY_SHORT_ID", ""),
                    "serverName": getattr(s, "VLESS_REVERSE_REALITY_SNI", "www.amazon.com"),
                    "fingerprint": getattr(s, "UTLS_FINGERPRINT", "chrome"),
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
                    "address": getattr(s, "TROJAN_CDN_DOMAIN", "") or getattr(s, "VPN_SERVER_IP", ""),
                    "port": getattr(s, "TROJAN_CDN_PORT", 2083),
                    "password": uuid,
                }],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": getattr(s, "TROJAN_CDN_SNI", ""),
                },
                "wsSettings": {
                    "path": getattr(s, "TROJAN_CDN_WS_PATH", "/trojan-ws"),
                },
            },
        }

    def _client_vmess_ws(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": getattr(s, "VPN_SERVER_IP", ""),
                    "port": getattr(s, "VMESS_PORT", 443),
                    "users": [{"id": uuid, "alterId": 0, "security": "auto"}],
                }],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": getattr(s, "VMESS_SNI", "www.aparat.com"),
                },
                "wsSettings": {
                    "path": getattr(s, "VMESS_WS_PATH", "/api/v1/stream"),
                },
            },
        }

    def _client_vless_ws(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": getattr(s, "VPN_SERVER_IP", ""),
                    "port": getattr(s, "VLESS_WS_PORT", 2057),
                    "users": [{"id": uuid, "encryption": "none"}],
                }],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": getattr(s, "VLESS_WS_PATH", "/vless-ws")},
            },
        }

    def _client_ss2022(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": getattr(s, "VPN_SERVER_IP", ""),
                    "port": getattr(s, "SS2022_PORT", 2056),
                    "method": getattr(s, "SS2022_METHOD", "2022-blake3-aes-128-gcm"),
                    "password": uuid,
                }],
            },
        }

    def _client_grpc(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": getattr(s, "VPN_SERVER_IP", ""),
                    "port": getattr(s, "GRPC_PORT", 2054),
                    "users": [{"id": uuid, "alterId": 0}],
                }],
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {
                    "serviceName": getattr(s, "GRPC_SERVICE_NAME", "GunService"),
                },
            },
        }

    def _client_httpupgrade(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": getattr(s, "VPN_SERVER_IP", ""),
                    "port": getattr(s, "HTTPUPGRADE_PORT", 2055),
                    "users": [{"id": uuid, "alterId": 0}],
                }],
            },
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "httpupgradeSettings": {
                    "path": getattr(s, "HTTPUPGRADE_PATH", "/httpupgrade"),
                },
            },
        }

    def _client_hysteria2(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "hy2",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'HYSTERIA2_PORT', 8443)}",
            "password": getattr(s, "HYSTERIA2_PASSWORD", ""),
            "obfs": {
                "type": "salamander" if getattr(s, "HYSTERIA2_SALAMANDER_ENABLED", False) else "",
                "password": getattr(s, "HYSTERIA2_SALAMANDER_PASSWORD", ""),
            } if getattr(s, "HYSTERIA2_SALAMANDER_ENABLED", False) else {},
            "bandwidth": {
                "up": getattr(s, "HYSTERIA2_BANDWIDTH_UP", "100 mbps"),
                "down": getattr(s, "HYSTERIA2_BANDWIDTH_DOWN", "200 mbps"),
            },
        }

    def _client_tuic_v5(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "tuic",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'TUIC_PORT', 8444)}",
            "password": getattr(s, "TUIC_PASSWORD", ""),
            "congestion_control": getattr(s, "TUIC_CONGESTION_CONTROL", "cubic"),
            "udp_relay": getattr(s, "TUIC_UDP_RELAY", "native"),
            "zero_rtt": getattr(s, "TUIC_ZERO_RTT", False),
        }

    def _client_amneziawg(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "amneziawg",
            "interface": {
                "address": getattr(s, "AMNEZIAWG_ADDRESS", "10.8.0.1/24"),
                "dns": getattr(s, "AMNEZIAWG_DNS", "1.1.1.1"),
                "mtu": getattr(s, "AMNEZIAWG_MTU", 1280),
            },
            "peer": {
                "endpoint": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'AMNEZIAWG_PORT', 51820)}",
                "persistent_keepalive": 25,
            },
            "junk_packets": {
                "jc": getattr(s, "AMNEZIAWG_JC", 4),
                "jmin": getattr(s, "AMNEZIAWG_JMIN", 50),
                "jmax": getattr(s, "AMNEZIAWG_JMAX", 1000),
            },
            "magic_headers": {
                "s1": getattr(s, "AMNEZIAWG_S1", 0),
                "s2": getattr(s, "AMNEZIAWG_S2", 0),
                "h1": getattr(s, "AMNEZIAWG_H1", 1),
                "h2": getattr(s, "AMNEZIAWG_H2", 2),
                "h3": getattr(s, "AMNEZIAWG_H3", 3),
                "h4": getattr(s, "AMNEZIAWG_H4", 4),
            },
        }

    def _client_shadowtls_v3(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "shadowtls",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'SHADOWTLS_PORT', 8445)}",
            "version": getattr(s, "SHADOWTLS_VERSION", 3),
            "password": getattr(s, "SHADOWTLS_PASSWORD", ""),
            "sni": getattr(s, "SHADOWTLS_SNI", "www.google.com"),
        }

    def _client_mieru(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "mieru",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'MIERU_PORT', 8446)}",
            "password": getattr(s, "MIERU_PASSWORD", ""),
            "encryption": getattr(s, "MIERU_ENCRYPTION", "aes-256-gcm"),
            "transport": getattr(s, "MIERU_TRANSPORT", "tcp"),
        }

    def _client_naiveproxy(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "naiveproxy",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'NAIVEPROXY_PORT', 8447)}",
            "user": getattr(s, "NAIVEPROXY_USER", ""),
            "password": getattr(s, "NAIVEPROXY_PASSWORD", ""),
            "sni": getattr(s, "NAIVEPROXY_SNI", ""),
        }

    def _client_wireguard(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "wireguard",
            "interface": {
                "address": getattr(s, "WIREGUARD_ADDRESS", "10.9.0.1/24"),
                "dns": getattr(s, "WIREGUARD_DNS", "1.1.1.1"),
                "mtu": getattr(s, "WIREGUARD_MTU", 1280),
            },
            "peer": {
                "endpoint": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'WIREGUARD_PORT', 51821)}",
                "persistent_keepalive": getattr(s, "WIREGUARD_PERSISTENT_KEEPALIVE", 25),
            },
        }

    def _client_openvpn(self, uuid: str, s: Any) -> Dict:
        return {
            "protocol": "openvpn",
            "server": f"{getattr(s, 'VPN_SERVER_IP', '')}:{getattr(s, 'OPENVPN_PORT', 1194)}",
            "proto": getattr(s, "OPENVPN_PROTO", "udp"),
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
        server_ip = getattr(settings, "VPN_SERVER_IP", "")
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
            port = getattr(s, "VLESS_XHTTP_PORT", 2053)
            sni = getattr(s, "VLESS_XHTTP_REALITY_SNI", "www.microsoft.com")
            pbk = getattr(s, "VLESS_XHTTP_REALITY_PUBLIC_KEY", "")
            sid = getattr(s, "VLESS_XHTTP_REALITY_SHORT_ID", "")
            fp = getattr(s, "UTLS_FINGERPRINT", "chrome")
            path = getattr(s, "VLESS_XHTTP_PATH", "/xhttp-stream")
            mode = getattr(s, "VLESS_XHTTP_MODE", "auto")
            return (f"vless://{uuid}@{server}:{port}?type=xhttp&security=reality"
                    f"&sni={sni}&fp={fp}&pbk={pbk}&sid={sid}"
                    f"&path={path}&mode={mode}#Spiritus-VLESS-XHTTP-Reality")
        elif protocol_key == "vless_vision_reality":
            port = getattr(s, "VLESS_VISION_PORT", 2058)
            sni = getattr(s, "VLESS_VISION_REALITY_SNI", "www.yahoo.com")
            pbk = getattr(s, "VLESS_VISION_REALITY_PUBLIC_KEY", "")
            sid = getattr(s, "VLESS_VISION_REALITY_SHORT_ID", "")
            fp = getattr(s, "UTLS_FINGERPRINT", "chrome")
            flow = getattr(s, "VLESS_VISION_FLOW", "xtls-rprx-vision")
            return (f"vless://{uuid}@{server}:{port}?type=tcp&security=reality"
                    f"&sni={sni}&fp={fp}&pbk={pbk}&sid={sid}"
                    f"&flow={flow}#Spiritus-VLESS-Vision-Reality")
        elif protocol_key == "vless_reverse_reality":
            port = getattr(s, "VLESS_REVERSE_PORT", 2059)
            sni = getattr(s, "VLESS_REVERSE_REALITY_SNI", "www.amazon.com")
            pbk = getattr(s, "VLESS_REVERSE_REALITY_PUBLIC_KEY", "")
            sid = getattr(s, "VLESS_REVERSE_REALITY_SHORT_ID", "")
            fp = getattr(s, "UTLS_FINGERPRINT", "chrome")
            return (f"vless://{uuid}@{server}:{port}?type=tcp&security=reality"
                    f"&sni={sni}&fp={fp}&pbk={pbk}&sid={sid}"
                    f"#Spiritus-VLESS-Reverse-Reality")
        else:  # vless_ws
            port = getattr(s, "VLESS_WS_PORT", 2057)
            path = getattr(s, "VLESS_WS_PATH", "/vless-ws")
            sni = getattr(s, "VPN_SNI_HOST", "")
            return (f"vless://{uuid}@{server}:{port}?type=ws&security=tls"
                    f"&sni={sni}&path={path}#Spiritus-VLESS-WS")

    def _vmess_share_link(self, uuid: str, server: str, s: Any) -> str:
        import json as _json
        port = getattr(s, "VMESS_PORT", 443)
        sni = getattr(s, "VMESS_SNI", "www.aparat.com")
        path = getattr(s, "VMESS_WS_PATH", "/api/v1/stream")
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
        port = getattr(s, "TROJAN_CDN_PORT", 2083)
        sni = getattr(s, "TROJAN_CDN_SNI", "")
        path = getattr(s, "TROJAN_CDN_WS_PATH", "/trojan-ws")
        host = getattr(s, "TROJAN_CDN_DOMAIN", "") or server
        return (f"trojan://{uuid}@{host}:{port}?type=ws&security=tls"
                f"&sni={sni}&path={path}#Spiritus-Trojan-CDN")

    def _ss_share_link(self, uuid: str, server: str, s: Any) -> str:
        port = getattr(s, "SS2022_PORT", 2056)
        method = getattr(s, "SS2022_METHOD", "2022-blake3-aes-128-gcm")
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