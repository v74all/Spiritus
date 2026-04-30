"""
Agent (Multi-Backend) API router for V7LTHRONYX VPN Panel.

Endpoints:
- CRUD for agents (Xray/sing-box/WG/OpenVPN)
- Agent health monitoring
- ECH setup
- Config deployment
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from ..auth import get_current_admin, User
from ..database import get_async_db
from ..models import Agent, AgentBackend, AgentStatus, ProtocolConfig
from ..orchestrator import orchestrator

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/agents", tags=["agents"])


# ── Models ────────────────────────────────────────────────

class AgentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    backend: str = Field(..., description="xray|singbox|wireguard|openvpn")
    address: str = Field(..., min_length=1)
    api_port: int = Field(10085)
    api_key: Optional[str] = None
    config_path: Optional[str] = None
    bin_path: Optional[str] = None
    service_name: Optional[str] = None
    # WireGuard fields
    wg_interface: Optional[str] = None
    wg_private_key: Optional[str] = None
    wg_public_key: Optional[str] = None
    wg_address: Optional[str] = None
    wg_dns: Optional[str] = None
    wg_listen_port: Optional[int] = None
    wg_mtu: Optional[int] = 1280

class AgentUpdate(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    api_port: Optional[int] = None
    api_key: Optional[str] = None
    config_path: Optional[str] = None
    bin_path: Optional[str] = None
    service_name: Optional[str] = None
    ech_enabled: Optional[bool] = None
    ech_config: Optional[Dict[str, Any]] = None

class AgentResponse(BaseModel):
    id: int
    name: str
    backend: str
    status: str
    address: str
    api_port: int
    ech_enabled: bool
    last_heartbeat: Optional[str] = None
    cpu_usage: float = 0
    mem_usage: float = 0
    active_connections: int = 0
    created_at: Optional[str] = None

class ECHSetupRequest(BaseModel):
    public_name: str = Field("cloudflare-ech.com", description="ECH public name for DNS record")

class MessageResponse(BaseModel):
    message: str
    success: bool = True


# ── CRUD ──────────────────────────────────────────────────

@router.get("", response_model=List[AgentResponse])
async def list_agents(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """List all agents."""
    result = await db.execute(select(Agent).order_by(Agent.id))
    agents = result.scalars().all()
    return [
        AgentResponse(
            id=a.id,
            name=a.name,
            backend=a.backend.value,
            status=a.status.value,
            address=a.address,
            api_port=a.api_port,
            ech_enabled=a.ech_enabled,
            last_heartbeat=a.last_heartbeat.isoformat() if a.last_heartbeat else None,
            cpu_usage=a.cpu_usage,
            mem_usage=a.mem_usage,
            active_connections=a.active_connections,
            created_at=a.created_at.isoformat() if a.created_at else None,
        )
        for a in agents
    ]


@router.post("", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def create_agent(
    data: AgentCreate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Create a new agent."""
    try:
        backend = AgentBackend(data.backend)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid backend: {data.backend}")

    agent = Agent(
        name=data.name,
        backend=backend,
        status=AgentStatus.offline,
        address=data.address,
        api_port=data.api_port,
        api_key=data.api_key,
        config_path=data.config_path,
        bin_path=data.bin_path,
        service_name=data.service_name,
        wg_interface=data.wg_interface,
        wg_private_key=data.wg_private_key,
        wg_public_key=data.wg_public_key,
        wg_address=data.wg_address,
        wg_dns=data.wg_dns,
        wg_listen_port=data.wg_listen_port,
        wg_mtu=data.wg_mtu,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)

    return AgentResponse(
        id=agent.id,
        name=agent.name,
        backend=agent.backend.value,
        status=agent.status.value,
        address=agent.address,
        api_port=agent.api_port,
        ech_enabled=agent.ech_enabled,
        last_heartbeat=None,
        created_at=agent.created_at.isoformat() if agent.created_at else None,
    )


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Get agent details."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    return AgentResponse(
        id=agent.id,
        name=agent.name,
        backend=agent.backend.value,
        status=agent.status.value,
        address=agent.address,
        api_port=agent.api_port,
        ech_enabled=agent.ech_enabled,
        last_heartbeat=agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
        cpu_usage=agent.cpu_usage,
        mem_usage=agent.mem_usage,
        active_connections=agent.active_connections,
        created_at=agent.created_at.isoformat() if agent.created_at else None,
    )


@router.put("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: int,
    data: AgentUpdate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Update agent configuration."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if data.name is not None:
        agent.name = data.name
    if data.address is not None:
        agent.address = data.address
    if data.api_port is not None:
        agent.api_port = data.api_port
    if data.api_key is not None:
        agent.api_key = data.api_key
    if data.config_path is not None:
        agent.config_path = data.config_path
    if data.bin_path is not None:
        agent.bin_path = data.bin_path
    if data.service_name is not None:
        agent.service_name = data.service_name
    if data.ech_enabled is not None:
        agent.ech_enabled = data.ech_enabled
    if data.ech_config is not None:
        agent.ech_config = data.ech_config

    await db.commit()
    await db.refresh(agent)

    return AgentResponse(
        id=agent.id,
        name=agent.name,
        backend=agent.backend.value,
        status=agent.status.value,
        address=agent.address,
        api_port=agent.api_port,
        ech_enabled=agent.ech_enabled,
        last_heartbeat=agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
        cpu_usage=agent.cpu_usage,
        mem_usage=agent.mem_usage,
        active_connections=agent.active_connections,
        created_at=agent.created_at.isoformat() if agent.created_at else None,
    )


@router.delete("/{agent_id}", response_model=MessageResponse)
async def delete_agent(
    agent_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Delete an agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    await db.delete(agent)
    await db.commit()
    return MessageResponse(message=f"Agent '{agent.name}' deleted")


# ── Agent Operations ─────────────────────────────────────

@router.post("/{agent_id}/health-check")
async def check_agent_health(
    agent_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Check agent health status."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    healthy = await orchestrator._get_backend(agent).conn.health_check()
    agent.status = AgentStatus.online if healthy else AgentStatus.offline
    agent.last_heartbeat = datetime.utcnow() if healthy else agent.last_heartbeat
    await db.commit()

    return {
        "agent_id": agent_id,
        "healthy": healthy,
        "status": agent.status.value,
    }


@router.post("/health-check-all")
async def check_all_agents_health(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Check health of all agents."""
    statuses = await orchestrator.health_check_all(db)
    return {"agents": statuses}


@router.post("/{agent_id}/restart")
async def restart_agent(
    agent_id: int,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Restart an agent's service."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    success = await orchestrator.restart_agent(agent)
    return {"success": success, "message": "Agent restarted" if success else "Failed to restart agent"}


@router.post("/{agent_id}/ech-setup")
async def setup_ech(
    agent_id: int,
    data: ECHSetupRequest,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Setup ECH (Encrypted Client Hello) for an agent."""
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    ech_result = await orchestrator.setup_ech(agent, data.public_name)
    await db.commit()

    return ech_result