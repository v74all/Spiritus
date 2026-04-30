"""
Configuration management for V7LTHRONYX VPN Panel.

Uses Pydantic Settings for type-safe configuration with environment variables.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, PostgresDsn, RedisDsn
from typing import Optional
import secrets

class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Core
    app_name: str = "V7LTHRONYX VPN Panel"
    debug: bool = False
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    
    # Server
    host: str = "0.0.0.0"
    port: int = 38471
    web_port: int = Field(38471, env="VPN_WEB_PORT")
    api_port: int = Field(10085, env="VPN_API_PORT")
    
    # Database
    database_url: PostgresDsn = Field(
        "postgresql://vpnadmin:securepassword@localhost:5432/vpnpanel",
        env="DATABASE_URL"
    )
    database_pool_size: int = 20
    database_max_overflow: int = 10
    
    # Redis
    redis_url: RedisDsn = Field(
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
    max_login_attempts: int = 3
    lockout_seconds: int = 1800
    
    # Xray
    xray_config_path: str = "/usr/local/etc/xray/config.json"
    xray_bin_path: str = "/usr/local/bin/xray"
    
    # Protocols
    vless_ws_enabled: bool = Field(False, env="VLESS_WS_ENABLED")
    vless_ws_port: int = Field(2057, env="VLESS_WS_PORT")
    vless_ws_path: str = Field("/vless-ws", env="VLESS_WS_PATH")
    vless_ws_host: str = Field("", env="VLESS_WS_HOST")
    
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

# Initialize settings
settings = Settings()