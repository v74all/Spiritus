"""
Users API router for V7LTHRONYX VPN Panel.

Endpoints:
- GET    /users - List all users
- POST   /users - Create a new user
- GET    /users/{user_id} - Get user details
- PUT    /users/{user_id} - Update user
- DELETE  /users/{user_id} - Delete user
- POST   /users/{user_id}/reset-traffic - Reset traffic
- GET    /users/{user_id}/config - Get user config
- GET    /users/{user_id}/qr - Get QR code
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import uuid as uuid_lib
import logging

from ..auth import get_current_admin, User
from ..database import get_async_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["users"])

# Models
class UserCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    traffic_limit_gb: float = Field(10.0, ge=0)
    expire_at: Optional[str] = None
    agent_id: Optional[int] = None
    speed_limit_up: int = Field(200, ge=0)
    speed_limit_down: int = Field(200, ge=0)
    note: str = ""

class UserUpdate(BaseModel):
    name: Optional[str] = None
    traffic_limit_gb: Optional[float] = None
    expire_at: Optional[str] = None
    active: Optional[int] = None
    speed_limit_up: Optional[int] = None
    speed_limit_down: Optional[int] = None
    note: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    name: str
    uuid: str
    traffic_limit_gb: float
    traffic_used_gb: float
    expire_at: Optional[str]
    active: int
    created_at: str
    agent_id: Optional[int]
    speed_limit_up: int
    speed_limit_down: int
    note: str

class MessageResponse(BaseModel):
    message: str
    success: bool = True

@router.get("", response_model=List[UserResponse])
async def list_users(
    search: Optional[str] = Query(None, description="Search by name"),
    active: Optional[int] = Query(None, description="Filter by active status"),
    admin: User = Depends(get_current_admin)
):
    """List all VPN users."""
    # TODO: Query from database
    return []

@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    admin: User = Depends(get_current_admin)
):
    """Create a new VPN user."""
    user_uuid = str(uuid_lib.uuid4())
    # TODO: Save to database
    return UserResponse(
        id=1,
        name=user.name,
        uuid=user_uuid,
        traffic_limit_gb=user.traffic_limit_gb,
        traffic_used_gb=0.0,
        expire_at=user.expire_at,
        active=1,
        created_at=datetime.utcnow().isoformat(),
        agent_id=user.agent_id,
        speed_limit_up=user.speed_limit_up,
        speed_limit_down=user.speed_limit_down,
        note=user.note
    )

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    admin: User = Depends(get_current_admin)
):
    """Get user details."""
    # TODO: Query from database
    raise HTTPException(status_code=404, detail="User not found")

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user: UserUpdate,
    admin: User = Depends(get_current_admin)
):
    """Update user details."""
    # TODO: Update in database
    raise HTTPException(status_code=404, detail="User not found")

@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: int,
    admin: User = Depends(get_current_admin)
):
    """Delete a user."""
    # TODO: Delete from database
    return MessageResponse(message="User deleted")

@router.post("/{user_id}/reset-traffic", response_model=MessageResponse)
async def reset_traffic(
    user_id: int,
    admin: User = Depends(get_current_admin)
):
    """Reset user traffic counter."""
    # TODO: Reset in database
    return MessageResponse(message="Traffic reset")

@router.get("/{user_id}/config")
async def get_user_config(
    user_id: int,
    protocol: str = Query("vmess", description="Protocol type"),
    admin: User = Depends(get_current_admin)
):
    """Get user configuration for a specific protocol."""
    # TODO: Generate config using protocols.py
    return {"config": "", "protocol": protocol}

@router.get("/{user_id}/qr")
async def get_user_qr(
    user_id: int,
    protocol: str = Query("vmess", description="Protocol type"),
    admin: User = Depends(get_current_admin)
):
    """Get QR code for user configuration."""
    # TODO: Generate QR code
    return {"qr_data": ""}