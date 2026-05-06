"""
Protocol Engine for V7LTHRONYX VPN Panel.

Generates Xray/sing-box/WireGuard configurations for all supported protocols:
- VLESS + XHTTP + REALITY (relay-domain fronting)
- VLESS + REALITY + Vision (direct, fresh IP)
- VLESS-Reverse-Reality (backhaul/rathole tunnel)
- VMess + WS + TLS
- VLESS + WS + TLS (CDN compatible)
- Trojan + WS/gRPC + TLS (CDN)
- Shadowsocks-2022
- Hysteria2 + Salamander + port-hop
- TUIC v5
- AmneziaWG 2.0
- ShadowTLS v3
- Mieru
- NaiveProxy
- ECH (Encrypted Client Hello) support
"""

import json
import uuid
import base64
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlencode

from .config import settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  Protocol Definitions
# ═══════════════════════════════════════════════════════════════

class ProtocolBackend(str, Enum):
    xray = "xray"
    singbox = "singbox"
    wireguard = "wireguard"
    openvpn = "openvpn"
    hysteria2 = "hysteria2"
    tuic = "tuic"
    shadowtls = "shadowtls"
    mieru = "mieru"
    naiveproxy = "naiveproxy"


class ProtocolCategory(str, Enum):
    xray = "xray"
    standalone = "standalone"
    wireguard = "wireguard"


@dataclass
class ProtocolSpec:
    key: str
    name: str
    name_fa: str
    category: ProtocolCategory
    backend: ProtocolBackend
    description: str
    description_fa: str
    config_fields: List[Dict[str, Any]] = field(default_factory=list)
    requires_tls: bool = False
    supports_cdn: bool = False
    supports_reality: bool = False
    supports_ech: bool = False


# ═══════════════════════════════════════════════════════════════
#  Protocol Registry
# ═══════════════════════════════════════════════════════════════

PROTOCOLS: Dict[str, ProtocolSpec] = {
    # ── Xray-core protocols ──
    "vless_xhttp_reality": ProtocolSpec(
        key="vless_xhttp_reality",
        name="VLESS + XHTTP + REALITY",
        name_fa="VLESS + XHTTP + REALITY",
        category=ProtocolCategory.xray,
        backend=ProtocolBackend.xray,
        description="VLESS with XHTTP transport and REALITY TLS. Uses relay-domain fronting for maximum stealth.",
        description_fa="VLESS با XHTTP و REALITY. از relay-domain fronting برای حداکثر پنهان‌کاری استفاده می‌کند.",
        requires_tls=True,
        supports_cdn=False,
        supports_reality=True,
        supports_ech=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 2053, "label": "Port"},
            {"key": "reality_private_key", "type": "string", "label": "REALITY Private Key"},
            {"key": "reality_public_key", "type": "string", "label": "REALITY Public Key"},
            {"key": "reality_short_id", "type": "string", "label": "Short ID"},
            {"key": "reality_dest", "type": "string", "default": "digikala.com:443", "label": "Dest (relay domain)"},
            {"key": "reality_sni", "type": "string", "default": "digikala.com", "label": "SNI"},
            {"key": "xhttp_path", "type": "string", "default": "/xhttp-stream", "label": "XHTTP Path"},
            {"key": "xhttp_mode", "type": "string", "default": "auto", "label": "XHTTP Mode (auto/stream/packet)"},
        ],
    ),
    "vless_vision_reality": ProtocolSpec(
        key="vless_vision_reality",
        name="VLESS + REALITY + Vision",
        name_fa="VLESS + REALITY + Vision",
        category=ProtocolCategory.xray,
        backend=ProtocolBackend.xray,
        description="VLESS with XTLS-Vision flow and REALITY. Direct connection to fresh IP, no CDN.",
        description_fa="VLESS با XTLS-Vision و REALITY. اتصال مستقیم به IP تمیز، بدون CDN.",
        requires_tls=True,
        supports_reality=True,
        supports_ech=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 2058, "label": "Port"},
            {"key": "reality_private_key", "type": "string", "label": "REALITY Private Key"},
            {"key": "reality_public_key", "type": "string", "label": "REALITY Public Key"},
            {"key": "reality_short_id", "type": "string", "label": "Short ID"},
            {"key": "reality_dest", "type": "string", "default": "objects.githubusercontent.com:443", "label": "Dest"},
            {"key": "reality_sni", "type": "string", "default": "objects.githubusercontent.com", "label": "SNI"},
            {"key": "flow", "type": "string", "default": "xtls-rprx-vision", "label": "Flow"},
        ],
    ),
    "vless_reverse_reality": ProtocolSpec(
        key="vless_reverse_reality",
        name="VLESS-Reverse-Reality",
        name_fa="VLESS-Reverse-Reality (Backhaul)",
        category=ProtocolCategory.xray,
        backend=ProtocolBackend.xray,
        description="Reverse-tunneled VLESS with REALITY. Uses backhaul/rathole to tunnel through a relay server.",
        description_fa="VLESS معکوس با REALITY. از backhaul/rathole برای تونل از طریق سرور رله استفاده می‌کند.",
        requires_tls=True,
        supports_reality=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 2059, "label": "Port"},
            {"key": "reality_private_key", "type": "string", "label": "REALITY Private Key"},
            {"key": "reality_public_key", "type": "string", "label": "REALITY Public Key"},
            {"key": "reality_short_id", "type": "string", "label": "Short ID"},
            {"key": "reality_dest", "type": "string", "default": "digikala.com:443", "label": "Dest"},
            {"key": "reality_sni", "type": "string", "default": "digikala.com", "label": "SNI"},
            {"key": "tunnel_port", "type": "int", "default": 0, "label": "Tunnel Port (0=auto)"},
            {"key": "backhaul_mode", "type": "string", "default": "rathole", "label": "Backhaul Mode (rathole/frp)"},
        ],
    ),
    "vmess_ws_tls": ProtocolSpec(
        key="vmess_ws_tls",
        name="VMess + WS + TLS",
        name_fa="VMess + WS + TLS",
        category=ProtocolCategory.xray,
        backend=ProtocolBackend.xray,
        description="VMess with WebSocket and TLS. Classic protocol, CDN compatible.",
        description_fa="VMess با WebSocket و TLS. پروتکل کلاسیک، سازگار با CDN.",
        requires_tls=True,
        supports_cdn=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 443, "label": "Port"},
            {"key": "sni", "type": "string", "default": "www.aparat.com", "label": "SNI"},
            {"key": "ws_path", "type": "string", "default": "/api/v1/stream", "label": "WS Path"},
        ],
    ),
    "vless_ws_tls": ProtocolSpec(
        key="vless_ws_tls",
        name="VLESS + WS + TLS",
        name_fa="VLESS + WS + TLS",
        category=ProtocolCategory.xray,
        backend=ProtocolBackend.xray,
        description="VLESS with WebSocket and TLS. CDN compatible.",
        description_fa="VLESS با WebSocket و TLS. سازگار با CDN.",
        requires_tls=True,
        supports_cdn=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 2057, "label": "Port"},
            {"key": "ws_path", "type": "string", "default": "/vless-ws", "label": "WS Path"},
            {"key": "host", "type": "string", "label": "Host Header"},
        ],
    ),
    "trojan_cdn": ProtocolSpec(
        key="trojan_cdn",
        name="Trojan + WS/gRPC + TLS (CDN)",
        name_fa="Trojan + WS/gRPC + TLS (CDN)",
        category=ProtocolCategory.xray,
        backend=ProtocolBackend.xray,
        description="Trojan with WebSocket or gRPC over Cloudflare CDN.",
        description_fa="Trojan با WebSocket یا gRPC از طریق Cloudflare CDN.",
        requires_tls=True,
        supports_cdn=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 2083, "label": "Port"},
            {"key": "ws_path", "type": "string", "default": "/trojan-ws", "label": "WS Path"},
            {"key": "grpc_service", "type": "string", "default": "TrojanService", "label": "gRPC Service Name"},
            {"key": "grpc_enabled", "type": "bool", "default": False, "label": "Enable gRPC"},
            {"key": "grpc_port", "type": "int", "default": 2060, "label": "gRPC Port"},
            {"key": "sni", "type": "string", "label": "SNI"},
            {"key": "domain", "type": "string", "label": "Domain"},
        ],
    ),
    "ss2022": ProtocolSpec(
        key="ss2022",
        name="Shadowsocks-2022",
        name_fa="Shadowsocks-2022",
        category=ProtocolCategory.xray,
        backend=ProtocolBackend.xray,
        description="Shadowsocks 2022 with modern AEAD cipher.",
        description_fa="Shadowsocks 2022 با رمزنگاری AEAD مدرن.",
        config_fields=[
            {"key": "port", "type": "int", "default": 2056, "label": "Port"},
            {"key": "method", "type": "string", "default": "2022-blake3-aes-128-gcm", "label": "Method"},
            {"key": "server_key", "type": "string", "label": "Server Key (base64)"},
        ],
    ),
    "grpc_transport": ProtocolSpec(
        key="grpc_transport",
        name="gRPC Transport",
        name_fa="gRPC Transport",
        category=ProtocolCategory.xray,
        backend=ProtocolBackend.xray,
        description="gRPC transport for VLESS/VMess. CDN compatible with Cloudflare.",
        description_fa="gRPC برای VLESS/VMess. سازگار با Cloudflare CDN.",
        requires_tls=True,
        supports_cdn=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 2054, "label": "Port"},
            {"key": "service_name", "type": "string", "default": "GunService", "label": "Service Name"},
        ],
    ),
    "httpupgrade": ProtocolSpec(
        key="httpupgrade",
        name="HTTPUpgrade Transport",
        name_fa="HTTPUpgrade Transport",
        category=ProtocolCategory.xray,
        backend=ProtocolBackend.xray,
        description="HTTPUpgrade transport for VLESS/VMess.",
        description_fa="HTTPUpgrade برای VLESS/VMess.",
        requires_tls=True,
        supports_cdn=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 2055, "label": "Port"},
            {"key": "path", "type": "string", "default": "/httpupgrade", "label": "Path"},
        ],
    ),

    # ── Standalone protocols ──
    "hysteria2": ProtocolSpec(
        key="hysteria2",
        name="Hysteria2 + Salamander + port-hop",
        name_fa="Hysteria2 + Salamander + port-hop",
        category=ProtocolCategory.standalone,
        backend=ProtocolBackend.hysteria2,
        description="Hysteria2 QUIC-based proxy with Salamander obfuscation and port hopping.",
        description_fa="پروکسی QUIC Hysteria2 با Salamander و port hopping.",
        requires_tls=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 8443, "label": "Port"},
            {"key": "password", "type": "string", "label": "Password"},
            {"key": "salamander_enabled", "type": "bool", "default": False, "label": "Salamander"},
            {"key": "salamander_password", "type": "string", "label": "Salamander Password"},
            {"key": "port_hop_enabled", "type": "bool", "default": False, "label": "Port Hop"},
            {"key": "port_hop_ports", "type": "string", "default": "20000-50000", "label": "Port Hop Range"},
            {"key": "bandwidth_up", "type": "string", "default": "100 mbps", "label": "Upload Bandwidth"},
            {"key": "bandwidth_down", "type": "string", "default": "200 mbps", "label": "Download Bandwidth"},
        ],
    ),
    "tuic": ProtocolSpec(
        key="tuic",
        name="TUIC v5",
        name_fa="TUIC v5",
        category=ProtocolCategory.standalone,
        backend=ProtocolBackend.tuic,
        description="TUIC v5 QUIC proxy with zero-RTT support.",
        description_fa="پروکسی QUIC TUIC v5 با پشتیبانی zero-RTT.",
        requires_tls=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 8444, "label": "Port"},
            {"key": "password", "type": "string", "label": "Password"},
            {"key": "congestion_control", "type": "string", "default": "cubic", "label": "Congestion Control"},
            {"key": "udp_relay", "type": "string", "default": "native", "label": "UDP Relay Mode"},
            {"key": "zero_rtt", "type": "bool", "default": False, "label": "0-RTT"},
        ],
    ),
    "shadowtls": ProtocolSpec(
        key="shadowtls",
        name="ShadowTLS v3",
        name_fa="ShadowTLS v3",
        category=ProtocolCategory.standalone,
        backend=ProtocolBackend.shadowtls,
        description="ShadowTLS v3 with TLS fingerprint spoofing.",
        description_fa="ShadowTLS v3 با جعل TLS fingerprint.",
        requires_tls=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 8445, "label": "Port"},
            {"key": "password", "type": "string", "label": "Password"},
            {"key": "sni", "type": "string", "default": "chat.deepseek.com", "label": "SNI"},
            {"key": "version", "type": "string", "default": "3", "label": "Version"},
            {"key": "backend", "type": "string", "default": "127.0.0.1:1080", "label": "Backend"},
        ],
    ),
    "mieru": ProtocolSpec(
        key="mieru",
        name="Mieru",
        name_fa="Mieru",
        category=ProtocolCategory.standalone,
        backend=ProtocolBackend.mieru,
        description="Mieru proxy with multiplexing support.",
        description_fa="پروکسی Mieru با پشتیبانی multiplexing.",
        config_fields=[
            {"key": "port", "type": "int", "default": 8446, "label": "Port"},
            {"key": "password", "type": "string", "label": "Password"},
            {"key": "encryption", "type": "string", "default": "aes-256-gcm", "label": "Encryption"},
            {"key": "transport", "type": "string", "default": "tcp", "label": "Transport"},
            {"key": "mux_enabled", "type": "bool", "default": True, "label": "MUX"},
            {"key": "mux_concurrency", "type": "int", "default": 8, "label": "MUX Concurrency"},
        ],
    ),
    "naiveproxy": ProtocolSpec(
        key="naiveproxy",
        name="NaiveProxy",
        name_fa="NaiveProxy",
        category=ProtocolCategory.standalone,
        backend=ProtocolBackend.naiveproxy,
        description="NaiveProxy using Chrome network stack.",
        description_fa="NaiveProxy با استفاده از Chrome network stack.",
        requires_tls=True,
        config_fields=[
            {"key": "port", "type": "int", "default": 8447, "label": "Port"},
            {"key": "user", "type": "string", "label": "Username"},
            {"key": "password", "type": "string", "label": "Password"},
            {"key": "sni", "type": "string", "label": "SNI"},
            {"key": "concurrency", "type": "int", "default": 4, "label": "Concurrency"},
        ],
    ),

    # ── WireGuard ──
    "vless_ws_plain_front": ProtocolSpec(
        key="vless_ws_plain_front",
        name="VLESS + WS+TLS (Domain Fronting)",
        name_fa="VLESS + WS+TLS (Domain Fronting)",
        category=ProtocolCategory.xray,
        backend=ProtocolBackend.xray,
        description="VLESS with WebSocket over TLS. Uses a trusted domain as SNI for DPI bypass via TLS domain fronting.",
        description_fa="VLESS با WebSocket روی TLS. از دامنه معتبر به عنوان SNI برای دور زدن DPI با Domain Fronting استفاده می‌کند.",
        requires_tls=True,
        supports_cdn=False,
        supports_reality=False,
        config_fields=[
            {"key": "port", "type": "int", "default": 2052, "label": "Port"},
            {"key": "ws_path", "type": "string", "default": "/", "label": "WS Path"},
            {"key": "front_domain", "type": "string", "default": "chat.deepseek.com", "label": "SNI Domain"},
        ],
    ),
    "amneziawg": ProtocolSpec(
        key="amneziawg",
        name="AmneziaWG 2.0",
        name_fa="AmneziaWG 2.0",
        category=ProtocolCategory.wireguard,
        backend=ProtocolBackend.wireguard,
        description="AmneziaWG 2.0 with DPI evasion junk packets.",
        description_fa="AmneziaWG 2.0 با بسته‌های junk برای دور زدن DPI.",
        config_fields=[
            {"key": "port", "type": "int", "default": 51820, "label": "Port"},
            {"key": "address", "type": "string", "default": "10.8.0.1/24", "label": "Address"},
            {"key": "dns", "type": "string", "default": "1.1.1.1", "label": "DNS"},
            {"key": "jc", "type": "int", "default": 4, "label": "Junk Packets (jc)"},
            {"key": "jmin", "type": "int", "default": 50, "label": "Junk Min (jmin)"},
            {"key": "jmax", "type": "int", "default": 1000, "label": "Junk Max (jmax)"},
            {"key": "s1", "type": "int", "default": 0, "label": "s1"},
            {"key": "s2", "type": "int", "default": 0, "label": "s2"},
            {"key": "h1", "type": "int", "default": 1, "label": "h1"},
            {"key": "h2", "type": "int", "default": 2, "label": "h2"},
            {"key": "h3", "type": "int", "default": 3, "label": "h3"},
            {"key": "h4", "type": "int", "default": 4, "label": "h4"},
            {"key": "mtu", "type": "int", "default": 1280, "label": "MTU"},
        ],
    ),
}


# ═══════════════════════════════════════════════════════════════
#  Xray Config Generator
# ═══════════════════════════════════════════════════════════════

class XrayConfigGenerator:
    """Generate Xray-core server configuration."""

    @staticmethod
    def generate_vless_xhttp_reality(
        user_uuid: str,
        port: int = 2053,
        reality_private_key: str = "",
        reality_short_id: str = "",
        reality_dest: str = "digikala.com:443",
        reality_sni: str = "digikala.com",
        xhttp_path: str = "/xhttp-stream",
        xhttp_mode: str = "auto",
        ech_config: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Generate VLESS + XHTTP + REALITY inbound config."""
        config = {
            "tag": "vless-xhttp-reality",
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": user_uuid,
                        "flow": ""
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "realitySettings": {
                    "dest": reality_dest,
                    "serverNames": [reality_sni],
                    "privateKey": reality_private_key,
                    "shortIds": [reality_short_id] if reality_short_id else [""],
                },
                "xhttpSettings": {
                    "path": xhttp_path,
                    "mode": xhttp_mode,
                }
            }
        }

        # ECH support
        if ech_config and ech_config.get("enabled"):
            config["streamSettings"]["realitySettings"]["ech"] = {
                "enabled": True,
                "config": ech_config.get("keys", []),
                "publicName": ech_config.get("public_name", reality_sni),
            }

        return config

    @staticmethod
    def generate_vless_vision_reality(
        user_uuid: str,
        port: int = 2058,
        reality_private_key: str = "",
        reality_short_id: str = "",
        reality_dest: str = "objects.githubusercontent.com:443",
        reality_sni: str = "objects.githubusercontent.com",
        flow: str = "xtls-rprx-vision",
        ech_config: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Generate VLESS + REALITY + Vision inbound config."""
        config = {
            "tag": "vless-vision-reality",
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": user_uuid,
                        "flow": flow
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": reality_dest,
                    "serverNames": [reality_sni],
                    "privateKey": reality_private_key,
                    "shortIds": [reality_short_id] if reality_short_id else [""],
                }
            }
        }

        if ech_config and ech_config.get("enabled"):
            config["streamSettings"]["realitySettings"]["ech"] = {
                "enabled": True,
                "config": ech_config.get("keys", []),
                "publicName": ech_config.get("public_name", reality_sni),
            }

        return config

    @staticmethod
    def generate_vless_reverse_reality(
        user_uuid: str,
        port: int = 2059,
        reality_private_key: str = "",
        reality_short_id: str = "",
        reality_dest: str = "digikala.com:443",
        reality_sni: str = "digikala.com",
        tunnel_port: int = 0,
        backhaul_mode: str = "rathole",
    ) -> Dict[str, Any]:
        """Generate VLESS-Reverse-Reality (backhaul tunnel) config.

        This creates:
        1. A VLESS+REALITY inbound on the public-facing port
        2. A reverse tunnel outbound that connects to the backhaul relay
        """
        if tunnel_port == 0:
            tunnel_port = secrets.randbelow(50000) + 10000

        config = {
            "inbounds": [
                {
                    "tag": "vless-reverse-reality",
                    "listen": "0.0.0.0",
                    "port": port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            {
                                "id": user_uuid,
                                "flow": ""
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": reality_dest,
                            "serverNames": [reality_sni],
                            "privateKey": reality_private_key,
                            "shortIds": [reality_short_id] if reality_short_id else [""],
                        }
                    }
                }
            ],
            "outbounds": [
                {
                    "tag": "reverse-tunnel",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": "127.0.0.1",
                                "port": tunnel_port,
                                "users": [
                                    {
                                        "id": user_uuid,
                                        "encryption": "none"
                                    }
                                ]
                            }
                        ]
                    }
                }
            ],
            "reverse": {
                "bridges": [
                    {
                        "tag": "bridge",
                        "domain": f"tunnel-{user_uuid[:8]}.reverse",
                    }
                ]
            },
            "_tunnel_port": tunnel_port,
            "_backhaul_mode": backhaul_mode,
        }

        return config

    @staticmethod
    def generate_vmess_ws_tls(
        user_uuid: str,
        alter_id: int = 0,
        port: int = 443,
        sni: str = "www.aparat.com",
        ws_path: str = "/api/v1/stream",
    ) -> Dict[str, Any]:
        """Generate VMess + WS + TLS inbound config."""
        return {
            "tag": "vmess-ws-tls",
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": user_uuid,
                        "alterId": alter_id,
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                },
                "wsSettings": {
                    "path": ws_path,
                }
            }
        }

    @staticmethod
    def generate_vless_ws_tls(
        user_uuid: str,
        port: int = 2057,
        ws_path: str = "/vless-ws",
        host: str = "",
    ) -> Dict[str, Any]:
        """Generate VLESS + WS + TLS inbound config."""
        ws_settings = {"path": ws_path}
        if host:
            ws_settings["headers"] = {"Host": host}

        return {
            "tag": "vless-ws-tls",
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": user_uuid}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": ws_settings
            }
        }

    @staticmethod
    def generate_vless_ws_plain(
        user_uuid: str,
        port: int = 2052,
        ws_path: str = "/",
        host: str = "",
    ) -> Dict[str, Any]:
        """Generate VLESS + WS Plain (no TLS) inbound for domain fronting.

        Used with Iranian trusted domains (snapp.ir, digikala.com) as the
        front address. The actual connection is routed through CDN/proxy
        based on the Host header.
        """
        ws_settings = {"path": ws_path}
        if host:
            ws_settings["headers"] = {"Host": host}

        return {
            "tag": "vless-ws-plain-front",
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": user_uuid}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": ws_settings
            }
        }

    @staticmethod
    def generate_trojan_cdn(
        user_password: str,
        port: int = 2083,
        ws_path: str = "/trojan-ws",
        grpc_service: str = "TrojanService",
        grpc_enabled: bool = False,
        grpc_port: int = 2060,
        sni: str = "",
        domain: str = "",
    ) -> Dict[str, Any]:
        """Generate Trojan + WS/gRPC + TLS (CDN) inbound config."""
        inbounds = [
            {
                "tag": "trojan-ws-cdn",
                "listen": "0.0.0.0",
                "port": port,
                "protocol": "trojan",
                "settings": {
                    "clients": [{"password": user_password}]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": sni or domain,
                    },
                    "wsSettings": {
                        "path": ws_path,
                    }
                }
            }
        ]

        if grpc_enabled:
            inbounds.append({
                "tag": "trojan-grpc-cdn",
                "listen": "0.0.0.0",
                "port": grpc_port,
                "protocol": "trojan",
                "settings": {
                    "clients": [{"password": user_password}]
                },
                "streamSettings": {
                    "network": "grpc",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": sni or domain,
                    },
                    "grpcSettings": {
                        "serviceName": grpc_service,
                    }
                }
            })

        return {"inbounds": inbounds}

    @staticmethod
    def generate_ss2022(
        server_key: str,
        user_key: str,
        port: int = 2056,
        method: str = "2022-blake3-aes-128-gcm",
    ) -> Dict[str, Any]:
        """Generate Shadowsocks-2022 inbound config."""
        return {
            "tag": "ss2022",
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "shadowsocks",
            "settings": {
                "method": method,
                "password": f"{server_key}:{user_key}",
                "network": "tcp,udp"
            }
        }

    @staticmethod
    def generate_full_config(
        inbounds: List[Dict],
        outbound_tag: str = "direct",
        api_port: int = 10085,
    ) -> Dict[str, Any]:
        """Generate a complete Xray config.json with all inbounds."""
        return {
            "log": {
                "loglevel": "warning",
                "access": "/var/log/xray/access.log",
                "error": "/var/log/xray/error.log"
            },
            "api": {
                "tag": "api",
                "services": ["HandlerService", "StatsService", "LoggerService"]
            },
            "stats": {},
            "policy": {
                "levels": {
                    "0": {
                        "statsUplink": True,
                        "statsDownlink": True,
                        "statsUserUplink": True,
                        "statsUserDownlink": True,
                    }
                },
                "system": {
                    "statsInboundUplink": True,
                    "statsInboundDownlink": True,
                    "statsOutboundUplink": True,
                    "statsOutboundDownlink": True,
                }
            },
            "inbounds": [
                {
                    "tag": "api",
                    "listen": "127.0.0.1",
                    "port": api_port,
                    "protocol": "api",
                    "settings": {}
                }
            ] + inbounds,
            "outbounds": [
                {
                    "tag": outbound_tag,
                    "protocol": "freedom",
                    "settings": {}
                },
                {
                    "tag": "blocked",
                    "protocol": "blackhole",
                    "settings": {}
                }
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["api"],
                        "outboundTag": "api"
                    },
                    {
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "blocked"
                    }
                ]
            }
        }


# ═══════════════════════════════════════════════════════════════
#  Client Config Generator (for sharing)
# ═══════════════════════════════════════════════════════════════

class ClientConfigGenerator:
    """Generate client-side configurations for VPN users."""

    @staticmethod
    def generate_vless_share_url(
        uuid: str,
        address: str,
        port: int,
        security: str = "reality",
        sni: str = "",
        fp: str = "chrome",
        pbk: str = "",
        sid: str = "",
        flow: str = "",
        network: str = "tcp",
        path: str = "",
        host: str = "",
        xhttp_mode: str = "",
        allow_insecure: bool = False,
        ech: Optional[Dict] = None,
        label: str = "",
        # DPI evasion parameters
        fragment: bool = False,
        fragment_packets: str = "tlshello",
        fragment_length: str = "100-200",
        fragment_interval: str = "10-20",
        noise_packet: str = "",
        noise_delay: str = "",
        tcp_keepalive: bool = False,
        mux_enabled: bool = False,
        mux_concurrency: int = 8,
        bug_host: str = "",
    ) -> str:
        """Generate VLESS share URL (vless://...)."""
        params = {
            "type": network,
            "security": security,
            "fp": fp,
            "sni": sni,
            "pbk": pbk,
            "sid": sid,
        }
        if flow:
            params["flow"] = flow
        if path:
            params["path"] = path
        if host:
            params["host"] = host
        if xhttp_mode:
            params["mode"] = xhttp_mode
        if allow_insecure and security == "tls":
            params["allowInsecure"] = "1"
        if ech and ech.get("enabled"):
            params["ech"] = "1"
            params["ech_config"] = base64.b64encode(
                json.dumps(ech.get("keys", [])).encode()
            ).decode()
        # DPI evasion query params
        if fragment:
            params["fragment"] = f"{fragment_packets},{fragment_length},{fragment_interval}"
        if noise_packet:
            params["noisePacket"] = noise_packet
        if noise_delay:
            params["noiseDelay"] = noise_delay
        if tcp_keepalive:
            params["keepAlive"] = "1"
        if mux_enabled:
            params["mux"] = "1"
            params["mconcurrency"] = str(mux_concurrency)
        if bug_host:
            params["bugHost"] = bug_host

        query = urlencode({k: v for k, v in params.items() if v})
        tag = f"V7LTHRONYX-{label}" if label else "V7LTHRONYX"
        return f"vless://{uuid}@{address}:{port}?{query}#{tag}"

    @staticmethod
    def generate_vmess_share_url(
        uuid: str,
        address: str,
        port: int,
        alter_id: int = 0,
        network: str = "ws",
        security: str = "tls",
        sni: str = "",
        path: str = "",
        allow_insecure: bool = False,
        label: str = "",
        # DPI evasion parameters
        fragment: bool = False,
        fragment_packets: str = "tlshello",
        fragment_length: str = "100-200",
        fragment_interval: str = "10-20",
        noise_packet: str = "",
        noise_delay: str = "",
        tcp_keepalive: bool = False,
        mux_enabled: bool = False,
        mux_concurrency: int = 8,
        bug_host: str = "",
        extra_host_header: str = "",
    ) -> str:
        """Generate VMess share URL (vmess://base64...)."""
        tag = f"V7LTHRONYX-{label}" if label else "V7LTHRONYX"
        vmess_obj = {
            "v": "2",
            "ps": tag,
            "add": address,
            "port": str(port),
            "id": uuid,
            "aid": str(alter_id),
            "net": network,
            "type": "none",
            "host": extra_host_header or sni,
            "path": path,
            "tls": security,
        }
        if allow_insecure and security == "tls":
            vmess_obj["allowInsecure"] = "1"
        # DPI evasion: sockopt and MUX
        if fragment or noise_packet or tcp_keepalive:
            sockopt_fields = {}
            if fragment:
                sockopt_fields["fragment"] = {
                    "packets": fragment_packets,
                    "length": fragment_length,
                    "interval": fragment_interval,
                }
            if noise_packet:
                sockopt_fields["noisePacket"] = noise_packet
            if noise_delay:
                sockopt_fields["noiseDelay"] = noise_delay
            if tcp_keepalive:
                sockopt_fields["tcpKeepAlive"] = True
            vmess_obj["sockopt"] = json.dumps(sockopt_fields)
        if mux_enabled:
            vmess_obj["mux"] = "true"
            vmess_obj["muxConcurrency"] = str(mux_concurrency)
        if bug_host:
            vmess_obj["bugHost"] = bug_host
        encoded = base64.b64encode(
            json.dumps(vmess_obj).encode()
        ).decode()
        return f"vmess://{encoded}"

    @staticmethod
    def generate_trojan_share_url(
        password: str,
        address: str,
        port: int,
        sni: str = "",
        network: str = "tcp",
        path: str = "",
        allow_insecure: bool = False,
        label: str = "",
        # DPI evasion parameters
        fragment: bool = False,
        fragment_packets: str = "tlshello",
        fragment_length: str = "100-200",
        fragment_interval: str = "10-20",
        noise_packet: str = "",
        noise_delay: str = "",
        tcp_keepalive: bool = False,
        mux_enabled: bool = False,
        mux_concurrency: int = 8,
        bug_host: str = "",
    ) -> str:
        """Generate Trojan share URL (trojan://...)."""
        params = {
            "type": network,
            "security": "tls",
            "sni": sni,
        }
        if path:
            params["path"] = path
        if allow_insecure:
            params["allowInsecure"] = "1"
        # DPI evasion query params
        if fragment:
            params["fragment"] = f"{fragment_packets},{fragment_length},{fragment_interval}"
        if noise_packet:
            params["noisePacket"] = noise_packet
        if noise_delay:
            params["noiseDelay"] = noise_delay
        if tcp_keepalive:
            params["keepAlive"] = "1"
        if mux_enabled:
            params["mux"] = "1"
            params["mconcurrency"] = str(mux_concurrency)
        if bug_host:
            params["bugHost"] = bug_host
        query = urlencode({k: v for k, v in params.items() if v})
        tag = f"V7LTHRONYX-{label}" if label else "V7LTHRONYX"
        return f"trojan://{password}@{address}:{port}?{query}#{tag}"

    @staticmethod
    def generate_hysteria2_share_url(
        password: str,
        address: str,
        port: int,
        sni: str = "",
        obfs: str = "",
        insecure: int = 0,
        label: str = "",
    ) -> str:
        """Generate Hysteria2 share URL."""
        params = {
            "sni": sni,
            "insecure": str(insecure),
        }
        if obfs:
            params["obfs"] = "salamander"
            params["obfs-password"] = obfs
        query = urlencode({k: v for k, v in params.items() if v})
        tag = f"V7LTHRONYX-{label}" if label else "V7LTHRONYX"
        return f"hysteria2://{password}@{address}:{port}?{query}#{tag}"

    @staticmethod
    def generate_wg_config(
        interface_private_key: str,
        interface_address: str,
        server_public_key: str,
        server_endpoint: str,
        dns: str = "1.1.1.1",
        mtu: int = 1280,
        jc: int = 0,
        jmin: int = 0,
        jmax: int = 0,
        s1: int = 0,
        s2: int = 0,
        h1: int = 0,
        h2: int = 0,
        h3: int = 0,
        h4: int = 0,
    ) -> str:
        """Generate WireGuard/AmneziaWG client config."""
        is_amnezia = jc > 0 or any([s1, s2, h1, h2, h3, h4])

        lines = [
            "[Interface]",
            f"PrivateKey = {interface_private_key}",
            f"Address = {interface_address}",
            f"DNS = {dns}",
            f"MTU = {mtu}",
        ]

        if is_amnezia:
            lines.extend([
                f"Jc = {jc}",
                f"Jmin = {jmin}",
                f"Jmax = {jmax}",
                f"S1 = {s1}",
                f"S2 = {s2}",
                f"H1 = {h1}",
                f"H2 = {h2}",
                f"H3 = {h3}",
                f"H4 = {h4}",
            ])

        lines.extend([
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
            f"Endpoint = {server_endpoint}",
            "AllowedIPs = 0.0.0.0/0, ::/0",
            "PersistentKeepalive = 25",
        ])

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
#  ECH (Encrypted Client Hello) Manager
# ═══════════════════════════════════════════════════════════════

class ECHManager:
    """Manage Encrypted Client Hello (ECH) configuration.

    ECH encrypts the SNI in TLS ClientHello, preventing DPI from
    seeing which domain the client is connecting to.
    """

    @staticmethod
    def generate_ech_keys() -> Dict[str, str]:
        """Generate ECH key pair (HPKE public/private keys)."""
        # In production, use hpke library. For now, generate placeholder keys.
        private_key = secrets.token_hex(32)
        public_key = secrets.token_hex(32)
        return {
            "private_key": private_key,
            "public_key": public_key,
        }

    @staticmethod
    def generate_ech_config(
        public_key: str,
        public_name: str = "cloudflare-ech.com",
        config_id: int = 0,
        kem_id: int = 32,  # DHKEM(X25519, HKDF-SHA256)
        sym_id: int = 1,   # HKDF-SHA256 + AES-128-GCM
    ) -> Dict[str, Any]:
        """Generate ECHConfig for DNS HTTPS record."""
        return {
            "version": 0xfe0d,
            "config_id": config_id,
            "kem_id": kem_id,
            "sym_id": sym_id,
            "public_key": public_key,
            "public_name": public_name,
            "maximum_name_length": 0,
            "extensions": [],
        }

    @staticmethod
    def generate_dns_https_record(
        ech_config: Dict[str, Any],
        target: str = ".",
        port: int = 443,
    ) -> str:
        """Generate DNS HTTPS/SVCB record with ECH config.

        This should be published in DNS as:
        _443._tcp.example.com IN SVCB 1 example.com ech=...
        """
        import base64
        ech_bytes = base64.b64encode(
            json.dumps(ech_config).encode()
        ).decode()
        return f'1 . port={port} ech={ech_bytes}'


# ═══════════════════════════════════════════════════════════════
#  Convenience instances
# ═══════════════════════════════════════════════════════════════

xray_gen = XrayConfigGenerator()
client_gen = ClientConfigGenerator()
ech_mgr = ECHManager()
