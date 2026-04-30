"""
Configuration management for V7LTHRONYX VPN Panel.

Uses Pydantic Settings for type-safe configuration with environment variables.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
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
    database_url: str = Field(
        "postgresql://vpnadmin:securepassword@localhost:5432/vpnpanel",
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
    max_login_attempts: int = 3
    lockout_seconds: int = 1800
    
    # Xray
    xray_config_path: str = "/usr/local/etc/xray/config.json"
    xray_bin_path: str = "/usr/local/bin/xray"
    
    # Telegram Bot
    telegram_bot_token: str = Field("", env="TELEGRAM_BOT_TOKEN")
    telegram_chat_id: str = Field("", env="TELEGRAM_CHAT_ID")
    telegram_admin_chat_ids: str = Field("", env="TELEGRAM_ADMIN_CHAT_IDS")
    
    # Payment Gateways
    zarinpal_merchant_id: str = Field("", env="ZARINPAL_MERCHANT_ID")
    zarinpal_sandbox: bool = Field(True, env="ZARINPAL_SANDBOX")
    zarinpal_callback_url: str = Field("", env="ZARINPAL_CALLBACK_URL")
    idpay_api_key: str = Field("", env="IDPAY_API_KEY")
    idpay_sandbox: bool = Field(True, env="IDPAY_SANDBOX")
    idpay_callback_url: str = Field("", env="IDPAY_CALLBACK_URL")
    usdt_wallet_address: str = Field("", env="USDT_WALLET_ADDRESS")
    usdt_trongrid_api_key: str = Field("", env="USDT_TRONGRID_API_KEY")
    
    # mTLS
    mtls_ca_cert_path: str = Field("/opt/spiritus/mtls/ca.crt", env="MTLS_CA_CERT_PATH")
    mtls_ca_key_path: str = Field("/opt/spiritus/mtls/ca.key", env="MTLS_CA_KEY_PATH")
    mtls_clients_dir: str = Field("/opt/spiritus/mtls/clients", env="MTLS_CLIENTS_DIR")
    
    # Fail2ban
    fail2ban_max_retries: int = Field(3, env="FAIL2BAN_MAX_RETRIES")
    fail2ban_ban_time: int = Field(3600, env="FAIL2BAN_BAN_TIME")
    fail2ban_find_time: int = Field(600, env="FAIL2BAN_FIND_TIME")
    
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