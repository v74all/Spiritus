"""
Protocols API router for V7LTHRONYX VPN Panel.

Endpoints:
- GET    /protocols - List all protocols
- GET    /protocols/{key} - Get protocol details
- POST   /protocols/{key}/enable - Enable a protocol
- POST   /protocols/{key}/disable - Disable a protocol
- PUT    /protocols/{key}/config - Update protocol config
- GET    /protocols/{key}/status - Get protocol status
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
import logging

from ..auth import get_current_admin, User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/protocols", tags=["protocols"])

# Import protocol registry
try:
    from protocols import ProtocolRegistry
    _registry = ProtocolRegistry()
    PROTOCOLS_AVAILABLE = True
except ImportError:
    PROTOCOLS_AVAILABLE = False
    logger.warning("Protocol registry not available")

class ProtocolConfig(BaseModel):
    config: Dict[str, Any]

class MessageResponse(BaseModel):
    message: str
    success: bool = True

@router.get("")
async def list_protocols(admin: User = Depends(get_current_admin)):
    """List all available protocols."""
    if not PROTOCOLS_AVAILABLE:
        return {"protocols": [], "error": "Protocol registry not available"}
    
    protocols = []
    for key, spec in _registry.all_protocols.items():
        protocols.append({
            "key": spec.key,
            "name": spec.name,
            "name_fa": spec.name_fa,
            "category": spec.category.value,
            "backend": spec.backend.value,
            "description": spec.description,
            "description_fa": spec.description_fa,
            "config_fields": spec.config_fields,
            "enabled": False  # TODO: Check from settings
        })
    
    return {"protocols": protocols}

@router.get("/{key}")
async def get_protocol(
    key: str,
    admin: User = Depends(get_current_admin)
):
    """Get details for a specific protocol."""
    if not PROTOCOLS_AVAILABLE:
        raise HTTPException(status_code=500, detail="Protocol registry not available")
    
    spec = _registry.all_protocols.get(key)
    if not spec:
        raise HTTPException(status_code=404, detail=f"Protocol '{key}' not found")
    
    return {
        "key": spec.key,
        "name": spec.name,
        "name_fa": spec.name_fa,
        "category": spec.category.value,
        "backend": spec.backend.value,
        "description": spec.description,
        "description_fa": spec.description_fa,
        "config_fields": spec.config_fields,
        "enabled": False  # TODO: Check from settings
    }

@router.post("/{key}/enable", response_model=MessageResponse)
async def enable_protocol(
    key: str,
    admin: User = Depends(get_current_admin)
):
    """Enable a protocol."""
    if not PROTOCOLS_AVAILABLE:
        raise HTTPException(status_code=500, detail="Protocol registry not available")
    
    spec = _registry.all_protocols.get(key)
    if not spec:
        raise HTTPException(status_code=404, detail=f"Protocol '{key}' not found")
    
    # TODO: Update settings in database
    return MessageResponse(message=f"Protocol '{spec.name}' enabled")

@router.post("/{key}/disable", response_model=MessageResponse)
async def disable_protocol(
    key: str,
    admin: User = Depends(get_current_admin)
):
    """Disable a protocol."""
    if not PROTOCOLS_AVAILABLE:
        raise HTTPException(status_code=500, detail="Protocol registry not available")
    
    spec = _registry.all_protocols.get(key)
    if not spec:
        raise HTTPException(status_code=404, detail=f"Protocol '{key}' not found")
    
    # TODO: Update settings in database
    return MessageResponse(message=f"Protocol '{spec.name}' disabled")

@router.put("/{key}/config")
async def update_protocol_config(
    key: str,
    config: ProtocolConfig,
    admin: User = Depends(get_current_admin)
):
    """Update protocol configuration."""
    if not PROTOCOLS_AVAILABLE:
        raise HTTPException(status_code=500, detail="Protocol registry not available")
    
    spec = _registry.all_protocols.get(key)
    if not spec:
        raise HTTPException(status_code=404, detail=f"Protocol '{key}' not found")
    
    # TODO: Save config to database
    return {"message": f"Protocol '{spec.name}' config updated", "success": True}

@router.get("/{key}/status")
async def get_protocol_status(
    key: str,
    admin: User = Depends(get_current_admin)
):
    """Get protocol runtime status."""
    if not PROTOCOLS_AVAILABLE:
        raise HTTPException(status_code=500, detail="Protocol registry not available")
    
    spec = _registry.all_protocols.get(key)
    if not spec:
        raise HTTPException(status_code=404, detail=f"Protocol '{key}' not found")
    
    # TODO: Check actual runtime status
    return {
        "key": key,
        "running": False,
        "enabled": False,
        "connections": 0,
        "uptime": None
    }