"""
Authentication and authorization module for V7LTHRONYX VPN Panel.

Supports:
- JWT authentication
- 2FA/TOTP
- Rate limiting
- Session management
"""

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import pyotp
import logging
import re
import secrets as _secrets
import uuid
from pydantic import BaseModel

from .config import settings
from .database import AsyncSession, get_async_db
from sqlalchemy import select

# JWT algorithm is pinned. We explicitly pass it to jwt.decode() and refuse to
# fall back to any other algorithm — this defends against alg-confusion and
# the "alg: none" downgrade.
_JWT_ALG = "HS256"

# Configure logging
logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")
security = HTTPBearer()

# Models
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    totp_required: bool = False
    totp_uri: Optional[str] = None

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None
    is_admin: bool = False

class User(BaseModel):
    id: int
    username: str
    is_admin: bool
    totp_secret: Optional[str] = None

# Utility functions
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against the hashed version."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generate a password hash."""
    return pwd_context.hash(password)

def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token with `jti` (revocable) and `iat`/`nbf` claims."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(hours=settings.session_lifetime_hours)
    to_encode.update({
        "exp": expire,
        "iat": now,
        "nbf": now,
        "jti": uuid.uuid4().hex,
    })
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=_JWT_ALG)


# Password complexity policy. Centralised here so every entrypoint that sets a
# password (admin bootstrap, change-password, reseller register) uses the same
# rules.
_COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "qwerty", "qwerty123", "admin", "admin123", "letmein", "welcome",
    "iloveyou", "abc12345", "monkey", "dragon", "master",
}


def validate_password_strength(pw: str) -> Optional[str]:
    """Return None if password is acceptable, else a human-readable reason."""
    if pw is None or len(pw) < 12:
        return "Password must be at least 12 characters long."
    if pw.lower() in _COMMON_PASSWORDS:
        return "Password is on the common-password blocklist."
    if not re.search(r"[A-Z]", pw):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", pw):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", pw):
        return "Password must contain at least one digit."
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "Password must contain at least one symbol."
    return None

def generate_totp_secret() -> str:
    """Generate a new TOTP secret."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str) -> str:
    """Generate TOTP URI for QR code."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="V7LTHRONYX"
    )

def verify_totp(secret: str, token: str) -> bool:
    """Verify a TOTP token."""
    totp = pyotp.TOTP(secret)
    return totp.verify(token)

# Dependency functions
async def _is_token_revoked(jti: str) -> bool:
    """Check the Redis token blacklist for this jti."""
    if not jti:
        return False
    try:
        from .redis_client import get_redis
        redis = await get_redis()
        return bool(await redis.get(f"revoked_jti:{jti}"))
    except Exception:
        # Fail-closed for auth: if we can't verify revocation we must not
        # accept the token. The exception is for short-lived dev/test runs
        # where Redis is unreachable — return False there if settings.debug.
        return not settings.debug


async def revoke_token(jti: str, ttl_seconds: int) -> None:
    """Add a jti to the Redis blacklist with TTL matching token expiry."""
    if not jti:
        return
    try:
        from .redis_client import get_redis
        redis = await get_redis()
        await redis.setex(f"revoked_jti:{jti}", max(ttl_seconds, 1), "1")
    except Exception:
        logger.warning("token revocation failed: Redis unavailable")


async def invalidate_sessions(username: str) -> None:
    """Invalidate every previously-issued token for this admin at once.

    The jti blacklist (revoke_token) only kills one specific session on
    /logout. Without this, changing a compromised password does NOT log out
    an attacker who already holds a stolen token — it keeps working until
    natural expiry, defeating the whole point of the password change. Stores
    the invalidation instant in Redis; _decode_token_to_user rejects any
    token whose `iat` predates it. Call this on password change (and on any
    other "kick everyone out" action, e.g. 2FA reset).
    """
    try:
        from .redis_client import get_redis
        redis = await get_redis()
        # Whole seconds only: JWT `iat` is second-granularity (NumericDate),
        # so comparing it against a sub-second float epoch could reject a
        # token minted in the very same second as the invalidation (e.g. the
        # replacement cookie this same request is about to issue).
        now = int(datetime.now(timezone.utc).timestamp())
        await redis.setex(
            f"pwd_epoch:{username}",
            settings.session_lifetime_hours * 3600,
            str(now),
        )
    except Exception:
        logger.warning("session invalidation failed: Redis unavailable")


async def _tokens_invalidated_since(username: str, iat: Any) -> bool:
    if not username or iat is None:
        return False
    try:
        from .redis_client import get_redis
        redis = await get_redis()
        epoch = await redis.get(f"pwd_epoch:{username}")
        if not epoch:
            return False
        return int(iat) < int(float(epoch))
    except Exception:
        # Fail-closed for auth, same posture as _is_token_revoked.
        return not settings.debug


async def _decode_token_to_user(token: str, db: AsyncSession) -> User:
    """Decode a JWT and resolve to a User. Rejects revoked or malformed tokens.

    The password-file fallback path has been removed — every authenticated
    request must resolve to an Admin row in the database.
    """
    from .models import Admin
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Pin the algorithm explicitly — guards against alg-confusion / "none".
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[_JWT_ALG],
            options={"require": ["exp", "iat", "sub", "nbf"]},
        )
        username: Optional[str] = payload.get("sub")
        is_admin: bool = bool(payload.get("is_admin", False))
        jti: Optional[str] = payload.get("jti")
        iat = payload.get("iat")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    if jti and await _is_token_revoked(jti):
        raise credentials_exception

    if await _tokens_invalidated_since(username, iat):
        raise credentials_exception

    result = await db.execute(select(Admin).where(Admin.username == username))
    admin = result.scalar_one_or_none()
    if admin is None:
        # No password-file fallback — explicitly fail.
        raise credentials_exception
    # Brief lockout / disabled-account check (the model carries `locked_until`).
    locked_until = getattr(admin, "locked_until", None)
    if locked_until is not None:
        now = datetime.now(timezone.utc)
        # Tolerate naive timestamps (sqlite legacy rows).
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > now:
            raise credentials_exception
    # Resolve role → is_admin. Deny if role is missing/unknown; only explicit
    # admin/superadmin roles grant admin access. This prevents a NULL role from
    # accidentally granting elevated privileges.
    role = getattr(admin, "role", None)
    if role is None:
        role_is_admin = False
    else:
        role_is_admin = str(getattr(role, "value", role)).lower() in ("admin", "superadmin")
    return User(
        id=admin.id,
        username=admin.username,
        is_admin=is_admin and role_is_admin,
        totp_secret=admin.totp_secret,
    )


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """Get the current user from JWT token (Authorization: Bearer)."""
    return await _decode_token_to_user(token, db)


async def get_current_user_cookie(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """Get the current user from either cookie or Authorization header."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    if not token:
        raise credentials_exception
    return await _decode_token_to_user(token, db)


async def get_current_admin_cookie(
    current_user: User = Depends(get_current_user_cookie),
) -> User:
    """Cookie-based admin guard for legacy panel endpoints."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


async def get_optional_user_cookie(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> Optional[User]:
    """Get the current user from cookie/header, or None if not authenticated."""
    try:
        token = request.cookies.get("access_token")
        if not token:
            auth = request.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                token = auth.split(" ", 1)[1].strip()
        if not token:
            return None
        return await _decode_token_to_user(token, db)
    except Exception:
        return None


async def get_current_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get the current admin user."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

async def rate_limit_dependency(
    request: Request,
    max_requests: int = 30,
    window_seconds: int = 60,
):
    """Redis-based sliding-window rate limiting dependency."""
    from .redis_client import get_redis
    client_ip = request.client.host if request.client else "unknown"
    try:
        redis = await get_redis()
        key = f"ratelimit:{client_ip}:{request.url.path}"
        current = await redis.incr(key)
        if current == 1:
            await redis.expire(key, window_seconds)
        if current > max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {max_requests} requests per {window_seconds}s.",
            )
    except HTTPException:
        raise
    except Exception:
        logger.warning("rate-limit Redis unavailable, allowing request through for %s %s", client_ip, request.url.path)
    return client_ip