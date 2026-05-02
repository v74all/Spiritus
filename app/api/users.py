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
from ..models import VpnUser, Agent
from ..orchestrator import orchestrator
from ..protocol_engine import ClientConfigGenerator, PROTOCOLS

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["users"])

# Models
class UserCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    traffic_limit_gb: float = Field(10.0, ge=0)
    expire_at: Optional[str] = None
    agent_id: Optional[int] = None
    speed_limit_up: int = Field(0, ge=0)
    speed_limit_down: int = Field(0, ge=0)
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

def _user_to_response(u: VpnUser) -> UserResponse:
    return UserResponse(
        id=u.id,
        name=u.name,
        uuid=u.uuid,
        traffic_limit_gb=u.traffic_limit / (1024**3) if u.traffic_limit else 0,
        traffic_used_gb=u.traffic_used / (1024**3) if u.traffic_used else 0,
        expire_at=u.expire_at.isoformat() if u.expire_at else None,
        active=u.active,
        created_at=u.created_at.isoformat() if u.created_at else "",
        agent_id=u.agent_id,
        speed_limit_up=u.speed_limit_up,
        speed_limit_down=u.speed_limit_down,
        note=u.note or "",
    )

@router.get("", response_model=List[UserResponse])
async def list_users(
    search: Optional[str] = Query(None, description="Search by name"),
    active: Optional[int] = Query(None, description="Filter by active status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """List all VPN users."""
    query = select(VpnUser).order_by(VpnUser.id.desc()).limit(limit).offset(offset)

    if search:
        query = query.where(VpnUser.name.ilike(f"%{search}%"))
    if active is not None:
        query = query.where(VpnUser.active == active)

    result = await db.execute(query)
    users = result.scalars().all()
    return [_user_to_response(u) for u in users]

@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a new VPN user."""
    user_uuid = str(uuid_lib.uuid4())
    expire_at = None
    if user.expire_at:
        try:
            expire_at = datetime.fromisoformat(user.expire_at)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid expire_at format. Use ISO 8601.")

    db_user = VpnUser(
        uuid=user_uuid,
        name=user.name,
        traffic_limit=int(user.traffic_limit_gb * 1024 * 1024 * 1024),
        traffic_used=0,
        expire_at=expire_at,
        active=1,
        agent_id=user.agent_id,
        speed_limit_up=user.speed_limit_up,
        speed_limit_down=user.speed_limit_down,
        note=user.note,
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    # Add user to backend agent if assigned
    if db_user.agent_id:
        agent_result = await db.execute(select(Agent).where(Agent.id == db_user.agent_id))
        agent = agent_result.scalar_one_or_none()
        if agent:
            try:
                await orchestrator.add_user_to_agent(db_user, agent, None)
            except Exception as e:
                logger.warning(f"Failed to add user to agent: {e}")

    return _user_to_response(db_user)

@router.get("/count/total")
async def get_user_count(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Get total user count."""
    result = await db.execute(select(func.count(VpnUser.id)))
    total = result.scalar() or 0
    active_result = await db.execute(select(func.count(VpnUser.id)).where(VpnUser.active == 1))
    active = active_result.scalar() or 0
    return {"total": total, "active": active}

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Get user details."""
    result = await db.execute(select(VpnUser).where(VpnUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user: UserUpdate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Update user details."""
    result = await db.execute(select(VpnUser).where(VpnUser.id == user_id))
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.name is not None:
        db_user.name = user.name
    if user.traffic_limit_gb is not None:
        db_user.traffic_limit = int(user.traffic_limit_gb * 1024 * 1024 * 1024)
    if user.expire_at is not None:
        try:
            db_user.expire_at = datetime.fromisoformat(user.expire_at)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid expire_at format")
    if user.active is not None:
        db_user.active = user.active
    if user.speed_limit_up is not None:
        db_user.speed_limit_up = user.speed_limit_up
    if user.speed_limit_down is not None:
        db_user.speed_limit_down = user.speed_limit_down
    if user.note is not None:
        db_user.note = user.note

    await db.commit()
    await db.refresh(db_user)
    return _user_to_response(db_user)

@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Delete a user."""
    result = await db.execute(select(VpnUser).where(VpnUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Remove from backend
    if user.agent_id:
        agent_result = await db.execute(select(Agent).where(Agent.id == user.agent_id))
        agent = agent_result.scalar_one_or_none()
        if agent:
            try:
                await orchestrator.remove_user_from_agent(user, agent)
            except Exception as e:
                logger.warning(f"Failed to remove user from agent: {e}")

    await db.delete(user)
    await db.commit()
    return MessageResponse(message="User deleted")

@router.post("/{user_id}/reset-traffic", response_model=MessageResponse)
async def reset_traffic(
    user_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Reset user traffic counter."""
    result = await db.execute(select(VpnUser).where(VpnUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.traffic_used = 0
    user.traffic_upload = 0
    user.traffic_download = 0
    await db.commit()
    return MessageResponse(message="Traffic reset")

@router.get("/{user_id}/config")
async def get_user_config(
    user_id: int,
    protocol: str = Query("vless_vision_reality", description="Protocol type"),
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Get user configuration for a specific protocol."""
    result = await db.execute(select(VpnUser).where(VpnUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get server address from agent
    server_address = ""
    if user.agent_id:
        agent_result = await db.execute(select(Agent).where(Agent.id == user.agent_id))
        agent = agent_result.scalar_one_or_none()
        if agent:
            server_address = agent.address

    share_url = ""
    if protocol.startswith("vless"):
        share_url = ClientConfigGenerator.generate_vless_share_url(
            uuid=user.uuid,
            address=server_address,
            port=2058,
            security="reality",
            sni="objects.githubusercontent.com",
            fp="chrome",
            flow="xtls-rprx-vision" if "vision" in protocol else "",
            network="xhttp" if "xhttp" in protocol else "tcp",
        )
    elif protocol == "vmess_ws_tls":
        share_url = ClientConfigGenerator.generate_vmess_share_url(
            uuid=user.uuid,
            address=server_address,
            port=443,
        )
    elif protocol.startswith("trojan"):
        share_url = ClientConfigGenerator.generate_trojan_share_url(
            password=user.uuid,
            address=server_address,
            port=2083,
        )
    elif protocol == "hysteria2":
        share_url = ClientConfigGenerator.generate_hysteria2_share_url(
            password=user.uuid,
            address=server_address,
            port=8443,
        )

    return {"config": share_url, "protocol": protocol, "qr_data": share_url}

@router.get("/{user_id}/qr")
async def get_user_qr(
    user_id: int,
    protocol: str = Query("vless_vision_reality", description="Protocol type"),
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Get QR code for user configuration."""
    result = await db.execute(select(VpnUser).where(VpnUser.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Reuse config endpoint logic
    config_result = await get_user_config(user_id, protocol, admin, db)
    return {"qr_data": config_result.get("config", ""), "protocol": protocol}