"""FastAPI Application Configuration and Setup"""

from datetime import timedelta
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""
    
    # App
    APP_NAME: str = "Spiritus"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = int(__import__("os").environ.get("VPN_WEB_PORT", 38471))
    API_PORT: int = int(__import__("os").environ.get("VPN_API_PORT", 10085))
    
    # Database
    DATABASE_URL: str = "postgresql://spiritus:spiritus@localhost/spiritus"
    SQLALCHEMY_ECHO: bool = False
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_CACHE_TTL: int = 3600
    
    # ═══ Xray-Core ═══
    XRAY_API_HOST: str = "127.0.0.1"
    XRAY_API_PORT: int = 10085
    VPN_SERVER_IP: str = __import__("os").environ.get("VPN_SERVER_IP", "127.0.0.1")
    VPN_SERVER_PORT: int = int(__import__("os").environ.get("VPN_SERVER_PORT", 443))
    VPN_SNI_HOST: str = __import__("os").environ.get("VPN_SNI_HOST", "www.google.com")

    # ── VLESS+XHTTP+REALITY (relay-fronted) ──
    VLESS_XHTTP_ENABLED: bool = False
    VLESS_XHTTP_PORT: int = 2053
    VLESS_XHTTP_REALITY_PRIVATE_KEY: str = ""
    VLESS_XHTTP_REALITY_PUBLIC_KEY: str = ""
    VLESS_XHTTP_REALITY_SHORT_ID: str = ""
    VLESS_XHTTP_REALITY_DEST: str = "digikala.com:443"
    VLESS_XHTTP_REALITY_SNI: str = "digikala.com"
    VLESS_XHTTP_PATH: str = "/xhttp-stream"
    VLESS_XHTTP_MODE: str = "auto"  # auto / packet-up / stream-up / stream-one

    # ── VLESS+REALITY+Vision (direct, fresh IP) ──
    VLESS_VISION_ENABLED: bool = False
    VLESS_VISION_PORT: int = 2058
    VLESS_VISION_REALITY_PRIVATE_KEY: str = ""
    VLESS_VISION_REALITY_PUBLIC_KEY: str = ""
    VLESS_VISION_REALITY_SHORT_ID: str = ""
    VLESS_VISION_REALITY_DEST: str = "objects.githubusercontent.com:443"
    VLESS_VISION_REALITY_SNI: str = "objects.githubusercontent.com"
    VLESS_VISION_FLOW: str = "xtls-rprx-vision"

    # ── Reverse-tunneled VLESS-Reality (Backhaul/Rathole) ──
    VLESS_REVERSE_ENABLED: bool = False
    VLESS_REVERSE_PORT: int = 2059
    VLESS_REVERSE_REALITY_PRIVATE_KEY: str = ""
    VLESS_REVERSE_REALITY_PUBLIC_KEY: str = ""
    VLESS_REVERSE_REALITY_SHORT_ID: str = ""
    VLESS_REVERSE_REALITY_DEST: str = "www.amazon.com:443"
    VLESS_REVERSE_REALITY_SNI: str = "www.amazon.com"
    VLESS_REVERSE_TUNNEL_PORT: int = 0  # 0 = auto-assign
    VLESS_REVERSE_BACKHAUL_MODE: str = "rathole"  # rathole / backhaul / relay

    # ── Trojan+WS/gRPC+TLS over Cloudflare CDN ──
    TROJAN_CDN_ENABLED: bool = False
    TROJAN_CDN_PORT: int = 2083
    TROJAN_CDN_WS_PATH: str = "/trojan-ws"
    TROJAN_CDN_GRPC_SERVICE: str = "TrojanService"
    TROJAN_CDN_GRPC_ENABLED: bool = False
    TROJAN_CDN_GRPC_PORT: int = 2060
    TROJAN_CDN_TLS_ENABLED: bool = True
    TROJAN_CDN_SNI: str = ""
    TROJAN_CDN_DOMAIN: str = ""  # Cloudflare domain

    # ── Shadowsocks-2022 ──
    SS2022_ENABLED: bool = False
    SS2022_PORT: int = 2056
    SS2022_METHOD: str = "2022-blake3-aes-128-gcm"
    SS2022_SERVER_KEY: str = ""

    # ── VMess+WS+TLS ──
    VMESS_ENABLED: bool = True
    VMESS_PORT: int = 443
    VMESS_SNI: str = "www.aparat.com"
    VMESS_WS_PATH: str = "/api/v1/stream"

    # ── gRPC ──
    GRPC_ENABLED: bool = False
    GRPC_PORT: int = 2054
    GRPC_SERVICE_NAME: str = "GunService"

    # ── HTTPUpgrade ──
    HTTPUPGRADE_ENABLED: bool = False
    HTTPUPGRADE_PORT: int = 2055
    HTTPUPGRADE_PATH: str = "/httpupgrade"

    # ── VLESS+WS+TLS (CDN compatible) ──
    VLESS_WS_ENABLED: bool = False
    VLESS_WS_PORT: int = 2057
    VLESS_WS_PATH: str = "/vless-ws"

    # ── Fragment (client-side anti-DPI) ──
    FRAGMENT_ENABLED: bool = False
    FRAGMENT_PACKETS: str = "tlshello"
    FRAGMENT_LENGTH: str = "100-200"
    FRAGMENT_INTERVAL: str = "10-20"

    # ── MUX ──
    MUX_ENABLED: bool = False
    MUX_CONCURRENCY: int = 8

    # ── uTLS Fingerprint ──
    UTLS_FINGERPRINT: str = "chrome"  # chrome / firefox / safari / edge / randomized

    # ── Noise / padding ──
    NOISE_ENABLED: bool = False
    NOISE_PACKET: str = "rand:50-100"
    NOISE_DELAY: str = "10-20"

    # ── DPI Evasion (server-side) ──
    DPI_TCP_FRAGMENT: bool = False
    DPI_TLS_FRAGMENT: bool = False
    DPI_IP_FRAGMENT: bool = False
    DPI_TCP_KEEPALIVE: bool = False
    DPI_DNS_TUNNEL: bool = False
    DPI_ICMP_TUNNEL: bool = False
    DPI_DOMAIN_FRONT: bool = False
    DPI_CDN_FRONT: str = ""

    # ═══ Standalone Protocols (Non-Xray) ═══

    # ── Hysteria2+Salamander+port-hop ──
    HYSTERIA2_ENABLED: bool = False
    HYSTERIA2_PORT: int = 8443
    HYSTERIA2_PASSWORD: str = ""
    HYSTERIA2_SALAMANDER_ENABLED: bool = False
    HYSTERIA2_SALAMANDER_PASSWORD: str = ""
    HYSTERIA2_PORT_HOP_ENABLED: bool = False
    HYSTERIA2_PORT_HOP_PORTS: str = "20000-50000"  # port range for hopping
    HYSTERIA2_BANDWIDTH_UP: str = "100 mbps"
    HYSTERIA2_BANDWIDTH_DOWN: str = "200 mbps"
    HYSTERIA2_QUIC_PORT: int = 8443  # UDP port for QUIC

    # ── TUIC v5 ──
    TUIC_ENABLED: bool = False
    TUIC_PORT: int = 8444
    TUIC_PASSWORD: str = ""
    TUIC_CONGESTION_CONTROL: str = "cubic"  # cubic / bbr / new_reno
    TUIC_UDP_RELAY: str = "native"  # native / quic
    TUIC_ZERO_RTT: bool = False
    TUIC_CERT_PATH: str = ""
    TUIC_KEY_PATH: str = ""

    # ── AmneziaWG 2.0 ──
    AMNEZIAWG_ENABLED: bool = False
    AMNEZIAWG_PORT: int = 51820
    AMNEZIAWG_PRIVATE_KEY: str = ""
    AMNEZIAWG_ADDRESS: str = "10.8.0.1/24"
    AMNEZIAWG_DNS: str = "1.1.1.1"
    AMNEZIAWG_JC: int = 4          # Junk packets count
    AMNEZIAWG_JMIN: int = 50       # Min junk packet size
    AMNEZIAWG_JMAX: int = 1000     # Max junk packet size
    AMNEZIAWG_S1: int = 0          # Magic header byte 1
    AMNEZIAWG_S2: int = 0          # Magic header byte 2
    AMNEZIAWG_H1: int = 1          # Handshake mask byte 1
    AMNEZIAWG_H2: int = 2          # Handshake mask byte 2
    AMNEZIAWG_H3: int = 3          # Handshake mask byte 3
    AMNEZIAWG_H4: int = 4          # Handshake mask byte 4
    AMNEZIAWG_MTU: int = 1280      # MTU for WireGuard

    # ── ShadowTLS v3 ──
    SHADOWTLS_ENABLED: bool = False
    SHADOWTLS_PORT: int = 8445
    SHADOWTLS_PASSWORD: str = ""
    SHADOWTLS_SNI: str = "www.google.com"
    SHADOWTLS_VERSION: int = 3
    SHADOWTLS_BACKEND: str = "127.0.0.1:1080"  # SOCKS5 backend
    SHADOWTLS_TLS_CERT_PATH: str = ""
    SHADOWTLS_TLS_KEY_PATH: str = ""

    # ── Mieru ──
    MIERU_ENABLED: bool = False
    MIERU_PORT: int = 8446
    MIERU_PASSWORD: str = ""
    MIERU_ENCRYPTION: str = "aes-256-gcm"  # aes-256-gcm / chacha20-poly1305
    MIERU_TRANSPORT: str = "tcp"  # tcp / udp / multiplex
    MIERU_MUX_ENABLED: bool = True
    MIERU_MUX_CONCURRENCY: int = 8

    # ── NaiveProxy (official) ──
    NAIVEPROXY_ENABLED: bool = False
    NAIVEPROXY_PORT: int = 8447
    NAIVEPROXY_USER: str = ""
    NAIVEPROXY_PASSWORD: str = ""
    NAIVEPROXY_SNI: str = ""
    NAIVEPROXY_CERT_PATH: str = ""
    NAIVEPROXY_KEY_PATH: str = ""
    NAIVEPROXY_CONCURRENCY: int = 4  # Chrome connection concurrency

    # ── Plain WireGuard ──
    WIREGUARD_ENABLED: bool = False
    WIREGUARD_PORT: int = 51821
    WIREGUARD_PRIVATE_KEY: str = ""
    WIREGUARD_ADDRESS: str = "10.9.0.1/24"
    WIREGUARD_DNS: str = "1.1.1.1"
    WIREGUARD_MTU: int = 1280
    WIREGUARD_PERSISTENT_KEEPALIVE: int = 25

    # ── Plain OpenVPN ──
    OPENVPN_ENABLED: bool = False
    OPENVPN_PORT: int = 1194
    OPENVPN_PROTO: str = "udp"  # udp / tcp
    OPENVPN_NETWORK: str = "10.10.0.0/24"
    OPENVPN_DNS: str = "1.1.1.1"
    OPENVPN_CERT_PATH: str = ""
    OPENVPN_KEY_PATH: str = ""
    OPENVPN_DH_PATH: str = ""
    OPENVPN_TA_PATH: str = ""
    
    # Security
    SECRET_KEY: str = __import__("os").environ.get("SECRET_KEY", "change-me-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # JWT
    JWT_SECRET_KEY: str = __import__("os").environ.get("JWT_SECRET_KEY", "change-me")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION: int = 3600
    
    # TOTP
    TOTP_ISSUER: str = "Spiritus"
    TOTP_WINDOW: int = 1
    
    # Security Headers
    CORS_ORIGINS: list = ["*"]
    CORS_CREDENTIALS: bool = True
    CORS_METHODS: list = ["*"]
    CORS_HEADERS: list = ["*"]
    
    # Audit
    AUDIT_LOG_RETENTION_DAYS: int = 90
    AUDIT_LOG_ENABLED: bool = True
    
    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_PERIOD: int = 60
    
    # IP Allowlist
    ADMIN_IP_ALLOWLIST: list = []
    ENABLE_GEO_BLOCKING: bool = False
    BLOCKED_COUNTRIES: list = []
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json or text
    
    # Features
    ENABLE_2FA: bool = True
    ENABLE_WEBAUTHN: bool = False
    ENABLE_TELEGRAM_BOT: bool = False
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
