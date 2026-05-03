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
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import pyotp
import logging
from pydantic import BaseModel

from .config import settings
from .database import AsyncSession, get_async_db
from sqlalchemy import select

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
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=settings.session_lifetime_hours)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key, algorithm="HS256"
    )
    return encoded_jwt

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
async def _decode_token_to_user(token: str, db: AsyncSession) -> User:
    """Decode a JWT and resolve to a User. Falls back to password-file admin."""
    from .models import Admin
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        username: Optional[str] = payload.get("sub")
        is_admin: bool = payload.get("is_admin", False)
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(Admin).where(Admin.username == username))
    admin = result.scalar_one_or_none()
    if admin is not None:
        return User(
            id=admin.id,
            username=admin.username,
            is_admin=is_admin,
            totp_secret=admin.totp_secret,
        )

    # Fallback for installs that authenticate via vpn-panel-password file.
    # No DB Admin row exists yet, but the JWT was issued by /api/login.
    return User(id=0, username=username, is_admin=is_admin, totp_secret=None)


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
    db: AsyncSession = Depends(get_async_db)
):
    """Rate limiting dependency."""
    # In a real implementation, this would use Redis
    client_ip = request.client.host
    # Check rate limits in database/Redis
    # Raise HTTPException if rate limit exceeded
    return client_ip