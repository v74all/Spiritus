"""
Configuration management for V7LTHRONYX VPN Panel.

Uses Pydantic Settings for type-safe configuration with environment variables.

Security note: secret_key, jwt_secret_key, and database_url MUST be supplied
via environment variables (typically .env, chmod 600). Startup will hard-fail
if a critical secret is missing or shorter than 32 chars — this is intentional
to prevent accidentally running with weak/default credentials.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
from typing import Optional
import os
import secrets

_WEAK_SECRETS = {
    "change-me",
    "change-me-in-production",
    "change-me-to-a-random-secret-key",
    "dev-secret-key-local-only-not-for-production-use-32chars",
    "secret",
    "password",
    "default",
}


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # Core
    app_name: str = "V7LTHRONYX VPN Panel"
    debug: bool = False
    # secret_key is REQUIRED via env. No default — fail-closed.
    secret_key: str = Field(..., env="SECRET_KEY", min_length=32)
    jwt_secret_key: str = Field("", env="JWT_SECRET_KEY")
    csrf_secret: str = Field("", env="CSRF_SECRET")
    # CORS — comma-separated list of allowed origins. Empty = no CORS middleware.
    # Wildcard "*" is REJECTED at startup (see validator below).
    cors_origins: str = Field("", env="CORS_ORIGINS")

    # Server — default to loopback. Expose externally only via reverse proxy.
    host: str = Field("127.0.0.1", env="HOST")
    port: int = 38471
    web_port: int = Field(38471, env="VPN_WEB_PORT")
    api_port: int = Field(10085, env="VPN_API_PORT")

    # Database — MUST be set via DATABASE_URL env var
    database_url: str = Field(
        "",
        env="DATABASE_URL"
    )
    database_pool_size: int = 20
    database_max_overflow: int = 10

    # Redis
    redis_url: str = Field(
        "redis://localhost:6379/0",
        env="REDIS_URL"
    )
    redis_pool_size: int = 50

    # Security
    argon2_salt: str = Field(
        default_factory=lambda: secrets.token_hex(16),
        env="ARGON2_SALT"
    )
    session_lifetime_hours: int = 1
    max_login_attempts: int = 5
    max_2fa_attempts: int = Field(10, env="MAX_2FA_ATTEMPTS")
    lockout_seconds: int = 1800
    # Bootstrap admin (one-shot, cleared after first use)
    admin_bootstrap_username: str = Field("admin", env="ADMIN_BOOTSTRAP_USERNAME")
    admin_bootstrap_password: str = Field("", env="ADMIN_BOOTSTRAP_PASSWORD")

    @field_validator("secret_key", "jwt_secret_key")
    @classmethod
    def _reject_weak_secret(cls, v: str, info):
        if not v:
            return v  # jwt_secret_key may be empty and derive from secret_key
        if v.lower() in _WEAK_SECRETS:
            raise ValueError(
                f"{info.field_name} is set to a known weak/default value. "
                "Generate a strong secret: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )
        if len(v) < 32:
            raise ValueError(f"{info.field_name} must be at least 32 chars")
        return v

    @field_validator("cors_origins")
    @classmethod
    def _reject_wildcard_cors(cls, v: str):
        parts = [p.strip() for p in (v or "").split(",") if p.strip()]
        if "*" in parts:
            raise ValueError(
                "CORS_ORIGINS=* is forbidden. Use an explicit comma-separated allowlist, "
                "or leave empty to disable CORS."
            )
        return v
    
    # Xray
    vpn_server_ip: str = Field("", env="VPN_SERVER_IP")
    vpn_server_ipv6: str = Field("", env="VPN_SERVER_IPV6")
    ipv6_enabled: bool = Field(False, env="IPV6_ENABLED")
    vpn_server_port: int = Field(443, env="VPN_SERVER_PORT")
    vpn_sni_host: str = Field("www.google.com", env="VPN_SNI_HOST")
    xray_config_path: str = "/usr/local/etc/xray/config.json"
    xray_bin_path: str = "/usr/local/bin/xray"

    # TLS certificate paths used by all TLS-bearing Xray inbounds.
    # Override via TLS_CERT_FILE / TLS_KEY_FILE for non-standard layouts
    # (e.g. /etc/letsencrypt/live/<domain>/fullchain.pem).
    tls_cert_file: str = Field("/etc/ssl/certs/fullchain.pem", env="TLS_CERT_FILE")
    tls_key_file: str = Field("/etc/ssl/private/privkey.pem", env="TLS_KEY_FILE")
    
    # REALITY — MUST be set via environment variables; no insecure defaults
    reality_private_key: str = Field("", env="REALITY_PRIVATE_KEY")
    reality_public_key: str = Field("", env="REALITY_PUBLIC_KEY")
    
    # Protocols
    vless_ws_enabled: bool = Field(False, env="VLESS_WS_ENABLED")
    vless_ws_port: int = Field(2057, env="VLESS_WS_PORT")
    vless_ws_path: str = Field("/vless-ws", env="VLESS_WS_PATH")
    vless_ws_host: str = Field("", env="VLESS_WS_HOST")
    vless_ws_plain_front_enabled: bool = Field(True, env="VLESS_WS_PLAIN_FRONT_ENABLED")
    vless_ws_plain_front_port: int = Field(2052, env="VLESS_WS_PLAIN_FRONT_PORT")
    vless_ws_plain_front_domain: str = Field("chat.deepseek.com", env="VLESS_WS_PLAIN_FRONT_DOMAIN")
    vless_ws_plain_front_path: str = Field("/", env="VLESS_WS_PLAIN_FRONT_PATH")

    # VLESS XHTTP REALITY
    vless_xhttp_enabled: bool = Field(True, env="VLESS_XHTTP_ENABLED")
    vless_xhttp_port: int = Field(2053, env="VLESS_XHTTP_PORT")
    vless_xhttp_mode: str = Field("auto", env="VLESS_XHTTP_MODE")
    vless_xhttp_path: str = Field("/xhttp", env="VLESS_XHTTP_PATH")
    vless_xhttp_reality_sni: str = Field("digikala.com", env="VLESS_XHTTP_REALITY_SNI")
    vless_xhttp_reality_dest: str = Field("digikala.com:443", env="VLESS_XHTTP_REALITY_DEST")
    vless_xhttp_reality_short_id: str = Field("", env="VLESS_XHTTP_REALITY_SHORT_ID")
    # Public key: empty by default. We do NOT bake a published sample
    # pair into the source tree — operators either set
    # VLESS_XHTTP_REALITY_PUBLIC_KEY in their .env or, preferably, let
    # `app.secrets.reality_public_key()` generate one on first read.
    vless_xhttp_reality_public_key: str = Field("", env="VLESS_XHTTP_REALITY_PUBLIC_KEY")

    # VLESS Vision REALITY
    vless_vision_enabled: bool = Field(True, env="VLESS_VISION_ENABLED")
    vless_vision_port: int = Field(2058, env="VLESS_VISION_PORT")
    vless_vision_reality_sni: str = Field("objects.githubusercontent.com", env="VLESS_VISION_REALITY_SNI")
    vless_vision_reality_dest: str = Field("objects.githubusercontent.com:443", env="VLESS_VISION_REALITY_DEST")
    vless_vision_reality_short_id: str = Field("", env="VLESS_VISION_REALITY_SHORT_ID")
    vless_vision_reality_public_key: str = Field("", env="VLESS_VISION_REALITY_PUBLIC_KEY")
    
    # CDN
    cdn_enabled: bool = Field(False, env="CDN_ENABLED")
    cdn_domain: str = Field("", env="CDN_DOMAIN")
    cdn_port: int = Field(2082, env="CDN_PORT")
    cdn_ws_path: str = Field("/cdn-ws", env="CDN_WS_PATH")
    
    # Model configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    def model_post_init(self, __context):
        # If JWT_SECRET_KEY is not explicitly set, derive from SECRET_KEY so
        # both signing keys stay strong-by-default (no "change-me" fallback).
        if not self.jwt_secret_key:
            object.__setattr__(self, "jwt_secret_key", self.secret_key)
        if not self.csrf_secret:
            object.__setattr__(self, "csrf_secret", self.secret_key)


# Initialize settings — will raise at import time if SECRET_KEY missing/weak.
settings = Settings()