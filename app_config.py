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
    
    # Xray
    XRAY_API_HOST: str = "127.0.0.1"
    XRAY_API_PORT: int = 10085
    VPN_SERVER_IP: str = __import__("os").environ.get("VPN_SERVER_IP", "127.0.0.1")
    VPN_SERVER_PORT: int = int(__import__("os").environ.get("VPN_SERVER_PORT", 443))
    VPN_SNI_HOST: str = __import__("os").environ.get("VPN_SNI_HOST", "www.google.com")
    
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
