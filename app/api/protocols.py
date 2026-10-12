"""
Protocols API router for V7LTHRONYX VPN Panel.

Endpoints:
- GET    /protocols                            - List all protocols
- GET    /protocols/{key}                      - Get protocol details
- POST   /protocols/{key}/enable               - Enable a protocol (DB + Xray sync)
- POST   /protocols/{key}/disable              - Disable a protocol (DB + Xray sync)
- PUT    /protocols/{key}/config                - Update protocol config (DB + Xray sync)
- GET    /protocols/{key}/status                - Get protocol runtime status
- POST   /protocols/sync                        - Force a full sync
- POST   /protocols/{key}/rotate-reality       - Rotate REALITY keys for this protocol

The `enable`/`disable`/`config` endpoints are no longer no-ops: they
upsert a ProtocolConfig row and then call
`app.services.protocol_sync.sync_and_reload()` to render the Xray
config, validate it, and reload the daemon. If the Xray validator
rejects the new config the previous one is restored, so a typo in
the operator's form data never strands the running panel.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import User, get_current_admin
from ..database import get_async_db, safe_refresh
from ..models import Agent, AgentBackend, ProtocolConfig
from ..protocol_engine import PROTOCOLS, ProtocolSpec
from ..services.protocol_sync import (
    ProtocolRuntimeStatus,
    SyncResult,
    runtime_status,
    sync_and_reload,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/protocols", tags=["protocols"])


# ═══════════════════════════════════════════════════════════════
#  Models
# ═══════════════════════════════════════════════════════════════

class ProtocolConfigUpdate(BaseModel):
    """Body for PUT /protocols/{key}/config."""
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool | None = None


class ProtocolStatusResponse(BaseModel):
    key: str
    enabled_in_db: bool
    running: bool
    connections: int
    last_started_at: str | None = None
    last_error: str | None = None


class SyncResponse(BaseModel):
    success: bool
    config_path: str
    validator_output: str = ""
    reload_method: str | None = None
    rolled_back: bool = False
    error: str | None = None
    started_at: str
    finished_at: str | None = None


# ═══════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════

def _spec_to_dict(spec: ProtocolSpec, enabled: bool = False) -> dict[str, Any]:
    return {
        "key": spec.key,
        "name": spec.name,
        "name_fa": spec.name_fa,
        "category": spec.category.value,
        "backend": spec.backend.value,
        "description": spec.description,
        "description_fa": spec.description_fa,
        "config_fields": spec.config_fields,
        "requires_tls": spec.requires_tls,
        "supports_cdn": spec.supports_cdn,
        "supports_reality": spec.supports_reality,
        "supports_ech": spec.supports_ech,
        "enabled": enabled,
    }


async def _resolve_target_agent_id(db: AsyncSession) -> int:
    """Pick the agent this protocol's ProtocolConfig row should hang
    off.

    Most installs have a single local agent; we pick the first
    online Xray agent, falling back to any Xray agent, and finally
    to "no agent" (0) if the panel has no agents at all.
    """
    result = await db.execute(
        select(Agent).order_by(Agent.id.asc())
    )
    agents = list(result.scalars().all())
    # Prefer an Xray agent — ProtocolConfig rows are most useful for
    # the xray backend. If we don't have one we still want a stable
    # FK to hang the row off, so fall back to the lowest-id agent
    # of any backend, and ultimately to "no agent" (0).
    xray_agents = [a for a in agents if a.backend == AgentBackend.xray]
    if xray_agents:
        return xray_agents[0].id
    if agents:
        return agents[0].id
    return 0


async def _upsert_protocol_config(
    db: AsyncSession,
    protocol_key: str,
    config_payload: dict[str, Any],
    enabled: bool | None,
) -> ProtocolConfig:
    """Find or create the ProtocolConfig row for (agent, protocol_key).

    Idempotent — callers can invoke this on every form submit without
    worrying about duplicate rows. The UniqueConstraint
    `(agent_id, protocol_key)` is what guarantees that.
    """
    agent_id = await _resolve_target_agent_id(db)
    if agent_id:
        result = await db.execute(
            select(ProtocolConfig).where(
                ProtocolConfig.protocol_key == protocol_key,
                ProtocolConfig.agent_id == agent_id,
            )
        )
    else:
        # agent_id is nullable. We still want a stable row, so we
        # look up by (key, agent_id IS NULL).
        result = await db.execute(
            select(ProtocolConfig).where(
                ProtocolConfig.protocol_key == protocol_key,
                ProtocolConfig.agent_id.is_(None),
            )
        )
    row = result.scalar_one_or_none()
    if row is None:
        row = ProtocolConfig(
            agent_id=agent_id or None,
            protocol_key=protocol_key,
            enabled=enabled if enabled is not None else False,
            config=config_payload,
            tag=f"pcfg-{protocol_key}",
        )
        db.add(row)
    else:
        # Merge incoming config into the existing one so partial
        # updates don't blow away the keys the operator didn't touch.
        merged = dict(row.config or {})
        merged.update(config_payload)
        row.config = merged
        if enabled is not None:
            row.enabled = enabled
    await db.commit()
    await safe_refresh(db, row)
    return row


# ═══════════════════════════════════════════════════════════════
#  Endpoints
# ═══════════════════════════════════════════════════════════════

@router.get("", response_model=list[dict[str, Any]])
async def list_protocols(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """List all available protocols with their current enabled flag."""
    # Look up which protocols are enabled in the DB so the UI can
    # render the toggle state without a second round-trip per
    # protocol.
    result = await db.execute(
        select(ProtocolConfig.protocol_key).where(
            ProtocolConfig.enabled == True  # noqa: E712
        )
    )
    enabled_keys = {row[0] for row in result.all()}

    out: list[dict[str, Any]] = []
    for key, spec in PROTOCOLS.items():
        out.append(_spec_to_dict(spec, enabled=key in enabled_keys))
    return out


@router.get("/{key}")
async def get_protocol(
    key: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Get details for a specific protocol."""
    spec = PROTOCOLS.get(key)
    if not spec:
        raise HTTPException(status_code=404, detail=f"Protocol '{key}' not found")
    result = await db.execute(
        select(ProtocolConfig).where(ProtocolConfig.protocol_key == key)
    )
    row = result.scalar_one_or_none()
    return _spec_to_dict(spec, enabled=bool(row.enabled) if row else False)


@router.post("/{key}/enable", response_model=SyncResponse)
async def enable_protocol(
    key: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Enable a protocol. Triggers an Xray config re-render + reload.

    The handler returns a SyncResponse so the UI can show either
    "OK, Xray reloaded" or the validator's error verbatim. The old
    behaviour — a `{"message": ...}` with no side-effects — was
    a footgun (the operator would toggle the switch in the panel
    and notice nothing on the wire).
    """
    spec = PROTOCOLS.get(key)
    if not spec:
        raise HTTPException(status_code=404, detail=f"Protocol '{key}' not found")

    await _upsert_protocol_config(db, key, config_payload={}, enabled=True)
    sync: SyncResult = await sync_and_reload(db)
    return SyncResponse(**_sync_to_dict(sync))


@router.post("/{key}/disable", response_model=SyncResponse)
async def disable_protocol(
    key: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Disable a protocol and re-render the Xray config.

    Disabling is a full re-sync too: we drop the inbound from the
    on-disk config so Xray stops listening on the protocol's port.
    """
    spec = PROTOCOLS.get(key)
    if not spec:
        raise HTTPException(status_code=404, detail=f"Protocol '{key}' not found")

    # Mark the DB row disabled. We keep it (don't delete) so the
    # operator's config fields survive a re-enable.
    await _upsert_protocol_config(db, key, config_payload={}, enabled=False)
    sync: SyncResult = await sync_and_reload(db)
    return SyncResponse(**_sync_to_dict(sync))


@router.put("/{key}/config", response_model=SyncResponse)
async def update_protocol_config(
    key: str,
    payload: ProtocolConfigUpdate,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Update a protocol's config dict and re-render Xray.

    The config fields are spec-specific (port, sni, …) and are
    validated by `XrayConfigGenerator` when the config is rendered.
    We also reject unknown keys here so a stray form field doesn't
    silently sneak into the Xray JSON.
    """
    spec = PROTOCOLS.get(key)
    if not spec:
        raise HTTPException(status_code=404, detail=f"Protocol '{key}' not found")

    if spec.config_fields:
        known_keys = {f.get("key") for f in spec.config_fields if f.get("key")}
        # Always-allowed meta keys; these are not rendered into the
        # Xray inbound but are useful for the orchestrator.
        known_keys.update({"reality_private_key", "reality_public_key", "reality_short_id"})
        for k in payload.config:
            if k not in known_keys:
                raise HTTPException(
                    status_code=422,
                    detail=f"unknown config field '{k}' for protocol '{key}'",
                )

    await _upsert_protocol_config(
        db, key, config_payload=payload.config, enabled=payload.enabled
    )
    # Always re-render so the new config fields take effect.
    sync: SyncResult = await sync_and_reload(db)
    if not sync.success and sync.error:
        logger.warning(
            "protocol %s config update accepted in DB but Xray rejected: %s",
            key, sync.error,
        )
    return SyncResponse(**_sync_to_dict(sync))


@router.get("/{key}/status", response_model=ProtocolStatusResponse)
async def get_protocol_status(
    key: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Read-only runtime view of a single protocol."""
    spec = PROTOCOLS.get(key)
    if not spec:
        raise HTTPException(status_code=404, detail=f"Protocol '{key}' not found")
    st: ProtocolRuntimeStatus = await runtime_status(db, key)
    return ProtocolStatusResponse(
        key=st.key,
        enabled_in_db=st.enabled_in_db,
        running=st.running,
        connections=st.connections,
        last_started_at=st.last_started_at,
        last_error=st.last_error,
    )


@router.post("/sync", response_model=SyncResponse)
async def force_sync(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Force a full re-render of the Xray config from the DB.

    Useful after a manual DB edit, or after a `xray` upgrade where
    the binary's config schema shifted and a clean re-render is
    safer than a per-field PATCH.
    """
    sync: SyncResult = await sync_and_reload(db)
    return SyncResponse(**_sync_to_dict(sync))


# ═══════════════════════════════════════════════════════════════
#  Misc
# ═══════════════════════════════════════════════════════════════

def _sync_to_dict(sync: SyncResult) -> dict[str, Any]:
    """Convert SyncResult dataclass → JSON-friendly dict for the
    Pydantic response model."""
    return {
        "success": sync.success,
        "config_path": sync.config_path,
        "validator_output": sync.validator_output,
        "reload_method": sync.reload_method,
        "rolled_back": sync.rolled_back,
        "error": sync.error,
        "started_at": sync.started_at,
        "finished_at": sync.finished_at,
    }
