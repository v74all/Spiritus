"""Security utilities - Password hashing, JWT, TOTP, etc."""

from datetime import datetime, timedelta
from typing import Optional
import secrets
import hashlib
import json
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from jose import JWTError, jwt
import pyotp
from app_config import settings


# ═══ Password Hashing ═══
password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str, pepper: Optional[str] = None) -> str:
    """
    Hash password using Argon2id with optional pepper.
    
    Args:
        password: Plain text password
        pepper: Optional pepper to add to password (kept separate from salt)
    
    Returns:
        Hash string
    """
    if pepper:
        password = f"{password}{pepper}"
    return password_hasher.hash(password)


def verify_password(hashed: str, password: str, pepper: Optional[str] = None) -> bool:
    """
    Verify password against hash.
    
    Args:
        hashed: Stored hash
        password: Plain text password to verify
        pepper: Optional pepper (must match original)
    
    Returns:
        True if valid, False otherwise
    """
    if pepper:
        password = f"{password}{pepper}"
    
    try:
        password_hasher.verify(hashed, password)
        return True
    except (VerifyMismatchError, VerificationError):
        return False


# ═══ JWT Handling ═══
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create JWT access token.
    
    Args:
        data: Claims to include in token
        expires_delta: Custom expiration (default: from settings)
    
    Returns:
        JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    to_encode.update({"exp": expire, "type": "access"})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    to_encode.update({"exp": expire, "type": "refresh"})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> Optional[dict]:
    """
    Verify and decode JWT token.
    
    Args:
        token: JWT token to verify
        token_type: Expected token type ("access" or "refresh")
    
    Returns:
        Decoded claims or None if invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        
        if payload.get("type") != token_type:
            return None
        
        return payload
    except JWTError:
        return None


# ═══ TOTP (2FA) ═══
def generate_totp_secret(name: str, issuer: str = settings.TOTP_ISSUER) -> str:
    """
    Generate new TOTP secret for 2FA setup.
    
    Args:
        name: User identifier (email/username)
        issuer: Issuer name (app name)
    
    Returns:
        Base32 encoded secret
    """
    return pyotp.random_base32()


def get_totp_uri(secret: str, name: str, issuer: str = settings.TOTP_ISSUER) -> str:
    """
    Get provisioning URI for TOTP (for QR code generation).
    
    Args:
        secret: TOTP secret
        name: User identifier
        issuer: Issuer name
    
    Returns:
        Provisioning URI
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=name, issuer_name=issuer)


def verify_totp(secret: str, token: str) -> bool:
    """
    Verify TOTP token.
    
    Args:
        secret: TOTP secret
        token: 6-digit token from authenticator app
    
    Returns:
        True if valid, False otherwise
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=settings.TOTP_WINDOW)


# ═══ Audit Logging ═══
def generate_audit_hash(prev_hash: Optional[str], data: dict) -> str:
    """
    Generate hash-chain for audit log (like Sigstore transparency log).
    
    Args:
        prev_hash: Previous log entry hash
        data: Current log entry data
    
    Returns:
        SHA256 hash
    """
    chain_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "data": data,
        "prev_hash": prev_hash or "genesis",
    }
    
    chain_json = json.dumps(chain_data, sort_keys=True)
    return hashlib.sha256(chain_json.encode()).hexdigest()


# ═══ Token Revocation ═══
class TokenRevocationManager:
    """Manage revoked tokens (stored in Redis)"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    async def revoke_token(self, token: str, exp_time: datetime) -> None:
        """Add token to revocation list."""
        ttl = int((exp_time - datetime.utcnow()).total_seconds())
        if ttl > 0:
            await self.redis.setex(
                f"revoked_token:{hashlib.sha256(token.encode()).hexdigest()}",
                ttl,
                "1",
            )
    
    async def is_revoked(self, token: str) -> bool:
        """Check if token is revoked."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return await self.redis.exists(f"revoked_token:{token_hash}") > 0


# ═══ API Key Management ═══
def generate_api_key() -> str:
    """Generate secure API key."""
    return secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    """Hash API key for storage."""
    return hashlib.sha256(api_key.encode()).hexdigest()


# ═══ Honey Tokens ═══
class HoneyTokenManager:
    """Manage honey tokens for intrusion detection"""
    
    HONEY_USERS = [
        {"username": "admin_backup", "uuid": "honey-admin-001"},
        {"username": "system_test", "uuid": "honey-test-001"},
        {"username": "guest_account", "uuid": "honey-guest-001"},
    ]
    
    @staticmethod
    def is_honey_token(username: str) -> bool:
        """Check if username is a honey token."""
        return any(u["username"] == username for u in HoneyTokenManager.HONEY_USERS)
    
    @staticmethod
    def get_honey_uuid(username: str) -> Optional[str]:
        """Get honey token UUID."""
        for user in HoneyTokenManager.HONEY_USERS:
            if user["username"] == username:
                return user["uuid"]
        return None
