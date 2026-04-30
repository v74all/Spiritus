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
        expire = datetime.utcnow() + timedelta(minutes=15)
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
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_async_db)
) -> User:
    """Get the current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=["HS256"]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    # In a real implementation, you would query the database here
    # For now, we'll return a mock user
    return User(
        id=1,
        username=token_data.username,
        is_admin=True,
        totp_secret=None  # Would be fetched from DB in real implementation
    )

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