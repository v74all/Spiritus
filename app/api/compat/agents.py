from __future__ import annotations

from fastapi import APIRouter

from ._core import *  # noqa: F403
from .legacy_users import (
    BulkCreateRequest,
    BulkDeleteRequest,
    LegacyAddTrafficRequest,
    LegacyRenewRequest,
    LegacyUserCreate,
    legacy_bulk_export_zip,
)
from .monitor import legacy_server_info

router = APIRouter(tags=["compat"])


# ─────────────────────────────────────────────────────────────────────────────
#  Agents (legacy shape)
# ─────────────────────────────────────────────────────────────────────────────

class LegacyAgentCreate(BaseModel):
    name: str
    password: str
    traffic_quota_gb: float = 100
    speed_limit_default: int = 200


def _agent_to_legacy(a: Agent, user_count: int = 0) -> dict[str, Any]:
    meta = a.ech_config if isinstance(a.ech_config, dict) else {}
    return {
        "id": a.id,
        "name": a.name,
        "active": a.status.value != "offline" if hasattr(a, "status") and a.status else True,
        "traffic_quota_gb": float(meta.get("traffic_quota_gb") or 0),
        "traffic_used_gb": float(meta.get("traffic_used_gb") or 0),
        "user_count": user_count,
    }


def _agent_meta(agent: Agent) -> dict[str, Any]:
    return dict(agent.ech_config) if isinstance(agent.ech_config, dict) else {}


def _set_agent_meta(agent: Agent, **updates: Any) -> None:
    meta = _agent_meta(agent)
    meta.update(updates)
    agent.ech_config = meta


async def _agent_used_gb(agent_id: int, db: AsyncSession) -> float:
    result = await db.execute(
        select(func.coalesce(func.sum(VpnUser.traffic_used), 0)).where(
            VpnUser.agent_id == agent_id
        )
    )
    used = result.scalar() or 0
    return float(used) / (1024**3)


async def _get_current_agent_cookie(
    request: Request,
    db: AsyncSession = Depends(get_async_db),
) -> Agent:
    token = request.cookies.get("agent_access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        # Tokens are signed with jwt_secret_key (same as all other JWTs in the app).
        # Using secret_key here was a bug — it's the app secret, not the JWT key.
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    if payload.get("role") != "agent":
        raise HTTPException(status_code=403, detail="Agent privileges required")

    agent_id = payload.get("agent_id") or payload.get("user_id")
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=401, detail="Agent not found")
    return agent


@router.get("/agents")
async def legacy_list_agents(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(Agent))
    agents = result.scalars().all()
    user_counts: dict[int, int] = {}
    traffic_used: dict[int, float] = {}
    if agents:
        cnt_result = await db.execute(
            select(VpnUser.agent_id, func.count(VpnUser.id))
            .where(VpnUser.agent_id.in_([a.id for a in agents]))
            .group_by(VpnUser.agent_id)
        )
        user_counts = {row[0]: row[1] for row in cnt_result.all()}
        traffic_result = await db.execute(
            select(VpnUser.agent_id, func.coalesce(func.sum(VpnUser.traffic_used), 0))
            .where(VpnUser.agent_id.in_([a.id for a in agents]))
            .group_by(VpnUser.agent_id)
        )
        traffic_used = {row[0]: float(row[1] or 0) / (1024**3) for row in traffic_result.all()}
    out = []
    for a in agents:
        item = _agent_to_legacy(a, user_counts.get(a.id, 0))
        item["traffic_used_gb"] = round(traffic_used.get(a.id, 0), 2)
        out.append(item)
    return out


@router.post("/agents")
async def legacy_create_agent(
    body: LegacyAgentCreate,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    if not body.name:
        return {"ok": False, "error": "Name required"}
    if len(body.password) < 6:
        return {"ok": False, "error": "Password too short"}
    from ...models import AgentBackend, AgentStatus
    try:
        agent = Agent(
            name=body.name,
            backend=AgentBackend.xray,
            status=AgentStatus.offline,
            address="127.0.0.1",
            api_port=10085,
            api_key=get_password_hash(body.password),
            ech_config={
                "traffic_quota_gb": body.traffic_quota_gb,
                "speed_limit_default": body.speed_limit_default,
                "brand_name": "",
            },
        )
        db.add(agent)
        await db.commit()
        await safe_refresh(db, agent)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "agent": _agent_to_legacy(agent)}


@router.post("/agents/{agent_id}/edit")
async def legacy_edit_agent(
    agent_id: int,
    body: dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        return {"ok": False, "error": "Agent not found"}
    if "active" in body:
        from ...models import AgentStatus
        agent.status = AgentStatus.online if body["active"] else AgentStatus.offline
    meta_updates: dict[str, Any] = {}
    if "traffic_quota_gb" in body:
        meta_updates["traffic_quota_gb"] = float(body["traffic_quota_gb"] or 0)
    if "speed_limit_default" in body:
        meta_updates["speed_limit_default"] = int(body["speed_limit_default"] or 0)
    if meta_updates:
        _set_agent_meta(agent, **meta_updates)
    await db.commit()
    return {"ok": True}


@router.post("/agents/{agent_id}/reset-password")
async def legacy_reset_agent_password(
    agent_id: int,
    body: dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    pw = body.get("password", "")
    if len(pw) < 6:
        return {"ok": False, "error": "Password too short"}
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        return {"ok": False, "error": "Agent not found"}
    agent.api_key = get_password_hash(pw)
    await db.commit()
    return {"ok": True}


@router.delete("/agents/{agent_id}")
async def legacy_delete_agent(
    agent_id: int,
    body: dict[str, Any] | None = None,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        return {"ok": False, "error": "Agent not found"}
    delete_users = bool((body or {}).get("delete_users"))
    if delete_users:
        users_result = await db.execute(
            select(VpnUser).where(VpnUser.agent_id == agent_id)
        )
        for u in users_result.scalars().all():
            await db.delete(u)
    else:
        await db.execute(
            select(VpnUser).where(VpnUser.agent_id == agent_id)
        )
        users_result = await db.execute(
            select(VpnUser).where(VpnUser.agent_id == agent_id)
        )
        for u in users_result.scalars().all():
            u.agent_id = None
    await db.delete(agent)
    await db.commit()
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
#  Agent panel API (/api/agent/*)
# ─────────────────────────────────────────────────────────────────────────────

class LegacyAgentLoginRequest(BaseModel):
    name: str
    password: str


@router.post("/agent/login")
async def legacy_agent_login(
    body: LegacyAgentLoginRequest,
    req: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(Agent).where(Agent.name == body.name.strip()))
    agent = result.scalar_one_or_none()
    if agent is None or not agent.api_key or not verify_password(body.password, agent.api_key):
        return {"ok": False, "error": "Invalid credentials"}
    if agent.status and agent.status.value == "offline":
        return {"ok": False, "error": "Account is disabled"}

    token = create_access_token(
        data={
            "sub": agent.name,
            "role": "agent",
            "agent_id": agent.id,
            "is_admin": False,
        }
    )
    from ...middleware.csrf import is_secure_request
    response.set_cookie(
        key="agent_access_token",
        value=token,
        httponly=True,
        secure=is_secure_request(req),
        samesite="strict",
        max_age=settings.session_lifetime_hours * 3600,
        path="/",
    )
    return {"ok": True, "name": agent.name}


@router.post("/agent/logout")
async def legacy_agent_logout(response: Response):
    response.delete_cookie("agent_access_token", path="/")
    return {"ok": True}


@router.get("/agents/{agent_id}/mobile-profile")
async def legacy_agent_mobile_profile_admin(
    agent_id: int,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Import link the admin hands to an agent for the mobile app."""
    from ..users import build_import_uri

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "profile_uri": await build_import_uri(request, db, role="agent", agent=agent.name)
    }


@router.get("/agent/mobile-profile")
async def legacy_agent_mobile_profile_self(
    request: Request,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """The logged-in agent's own mobile-app import link."""
    from ..users import build_import_uri

    return {
        "profile_uri": await build_import_uri(request, db, role="agent", agent=agent.name)
    }


@router.get("/agent/me")
async def legacy_agent_me(
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    meta = _agent_meta(agent)
    quota = float(meta.get("traffic_quota_gb") or 0)
    used = await _agent_used_gb(agent.id, db)
    return {
        "name": agent.name,
        "traffic_quota_gb": quota,
        "traffic_used_gb": round(used, 2),
        "traffic_remaining_gb": round(max(0, quota - used), 2) if quota else 0,
        "active": agent.status.value != "offline" if agent.status else True,
        "brand_name": meta.get("brand_name", ""),
        "speed_limit_default": int(meta.get("speed_limit_default") or 0),
    }


@router.post("/agent/brand")
async def legacy_agent_brand(
    body: dict[str, Any],
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    brand = str(body.get("brand_name") or "").strip()[:40]
    _set_agent_meta(agent, brand_name=brand)
    await db.commit()
    return {"ok": True, "brand_name": brand}


async def _check_agent_quota(agent: Agent, requested_gb: float, db: AsyncSession) -> str | None:
    quota = float(_agent_meta(agent).get("traffic_quota_gb") or 0)
    if quota <= 0:
        return None
    used = await _agent_used_gb(agent.id, db)
    if used + requested_gb > quota:
        return f"Quota exceeded. Remaining: {max(0, quota - used):.1f} GB"
    return None


@router.get("/agent/users")
async def legacy_agent_users(
    request: Request,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(
        select(VpnUser)
        .where(VpnUser.agent_id == agent.id)
        .order_by(VpnUser.active.desc(), VpnUser.name)
    )
    server_ip = _request_config_host(request)
    return [_user_to_legacy(u, server_ip=server_ip) for u in result.scalars().all()]


@router.post("/agent/users")
async def legacy_agent_create_user(
    body: LegacyUserCreate,
    request: Request,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    quota_error = await _check_agent_quota(agent, body.traffic, db)
    if quota_error:
        return {"ok": False, "error": quota_error}

    if await taken_vpn_user_names(db, [body.name]):
        return {"ok": False, "error": f"User '{body.name}' already exists"}
    expire_at = _utcnow() + timedelta(days=body.days) if body.days else None
    default_speed = int(_agent_meta(agent).get("speed_limit_default") or 0)
    db_user = VpnUser(
        uuid=str(uuid_lib.uuid4()),
        name=body.name,
        traffic_limit=int(body.traffic * (1024**3)),
        traffic_used=0,
        expire_at=expire_at,
        active=1,
        agent_id=agent.id,
        speed_limit_up=body.speed_limit_up or default_speed,
        speed_limit_down=body.speed_limit_down or default_speed,
        note=body.note,
    )
    db.add(db_user)
    try:
        await db.commit()
        await safe_refresh(db, db_user)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    await _load_legacy_settings(db)
    links = _user_to_legacy(db_user, server_ip=_request_config_host(request))
    return {"ok": True, "user": links, "vmess": links.get("vmess", "")}


@router.post("/agent/bulk-users")
async def legacy_agent_bulk_users(
    body: BulkCreateRequest,
    request: Request,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    quota_error = await _check_agent_quota(agent, body.traffic * body.count, db)
    if quota_error:
        return {"ok": False, "error": quota_error}

    if body.numbered:
        names = [f"{body.prefix}-{str(body.start + i).zfill(body.pad)}" for i in range(body.count)]
        taken = await taken_vpn_user_names(db, names)
        if taken:
            return {"ok": False, "error": "Users already exist: " + ", ".join(sorted(taken))}
    expire_at = _utcnow() + timedelta(days=body.days) if body.days else None
    created_users: list[VpnUser] = []
    default_speed = int(_agent_meta(agent).get("speed_limit_default") or 0)
    for i in range(body.count):
        name = (
            f"{body.prefix}-{str(body.start + i).zfill(body.pad)}"
            if body.numbered
            else f"{body.prefix}-{uuid_lib.uuid4().hex[:8]}"
        )
        u = VpnUser(
            uuid=str(uuid_lib.uuid4()),
            name=name,
            traffic_limit=int(body.traffic * (1024**3)),
            traffic_used=0,
            expire_at=expire_at,
            active=1,
            agent_id=agent.id,
            speed_limit_up=body.speed_limit_up or default_speed,
            speed_limit_down=body.speed_limit_down or default_speed,
            note="",
        )
        db.add(u)
        created_users.append(u)
    try:
        await db.commit()
        for u in created_users:
            await safe_refresh(db, u)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    await _load_legacy_settings(db)
    server_ip = _request_config_host(request)
    return {
        "ok": True,
        "created": len(created_users),
        "users": [_user_to_legacy(u, server_ip=server_ip) for u in created_users],
        "numbered": body.numbered,
        "start": body.start,
        "pad": body.pad,
        "traffic_gb": body.traffic,
        "days": body.days,
        "note": "",
        "apply": body.apply,
    }


@router.post("/agent/bulk-delete")
async def legacy_agent_bulk_delete(
    body: BulkDeleteRequest,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    query = select(VpnUser).where(VpnUser.agent_id == agent.id)
    if body.names:
        query = query.where(VpnUser.name.in_(body.names))
    elif body.prefix:
        safe_prefix = body.prefix.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        query = query.where(VpnUser.name.like(f"{safe_prefix}%", escape="\\"))
    else:
        return {"ok": False, "error": "Provide names or prefix"}
    result = await db.execute(query)
    count = 0
    for u in result.scalars().all():
        await db.delete(u)
        count += 1
    await db.commit()
    return {"ok": True, "deleted": count, "apply": body.apply}


@router.post("/agent/bulk-export-zip")
async def legacy_agent_bulk_export_zip(
    body: dict[str, Any],
    agent: Agent = Depends(_get_current_agent_cookie),
):
    return await legacy_bulk_export_zip(body, admin=User(id=0, username=agent.name, is_admin=False))


@router.delete("/agent/users/{name}")
async def legacy_agent_delete_user(
    name: str,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).where(VpnUser.name == name, VpnUser.agent_id == agent.id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found or not yours"}
    await db.delete(user)
    await db.commit()
    return {"ok": True}


@router.post("/agent/users/{name}/toggle")
async def legacy_agent_toggle_user(
    name: str,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).where(VpnUser.name == name, VpnUser.agent_id == agent.id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found or not yours"}
    user.active = 0 if user.active else 1
    await db.commit()
    return {"ok": True, "active": bool(user.active)}


@router.post("/agent/users/{name}/renew")
async def legacy_agent_renew_user(
    name: str,
    body: LegacyRenewRequest,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).where(VpnUser.name == name, VpnUser.agent_id == agent.id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found or not yours"}
    extra_gb = max(0, body.traffic - ((user.traffic_limit or 0) / (1024**3)))
    quota_error = await _check_agent_quota(agent, extra_gb, db)
    if quota_error:
        return {"ok": False, "error": quota_error}
    user.traffic_limit = int(body.traffic * (1024**3))
    user.traffic_used = 0
    user.expire_at = _utcnow() + timedelta(days=body.days)
    user.active = 1
    await db.commit()
    return {"ok": True}


@router.post("/agent/users/{name}/add-traffic")
async def legacy_agent_add_traffic(
    name: str,
    body: LegacyAddTrafficRequest,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    quota_error = await _check_agent_quota(agent, body.gb, db)
    if quota_error:
        return {"ok": False, "error": quota_error}
    result = await db.execute(
        select(VpnUser).where(VpnUser.name == name, VpnUser.agent_id == agent.id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found or not yours"}
    user.traffic_limit = (user.traffic_limit or 0) + int(body.gb * (1024**3))
    await db.commit()
    return {"ok": True, "traffic_limit_gb": (user.traffic_limit or 0) / (1024**3)}


@router.get("/agent/live")
async def legacy_agent_live(agent: Agent = Depends(_get_current_agent_cookie)):
    return {}


@router.get("/agent/server-info")
async def legacy_agent_server_info(
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    return await legacy_server_info(admin=User(id=0, username=agent.name, is_admin=False), db=db)


@router.post("/agent/sync")
async def legacy_agent_sync(
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    now = _utcnow()
    result = await db.execute(
        select(VpnUser).where(
            VpnUser.agent_id == agent.id,
            VpnUser.expire_at.is_not(None),
            VpnUser.active == 1,
        )
    )
    disabled = 0
    for u in result.scalars().all():
        if u.expire_at and u.expire_at < now:
            u.active = 0
            disabled += 1
    if disabled:
        await db.commit()
    return {"ok": True, "disabled": disabled}


@router.get("/agent/groups")
async def legacy_agent_groups(
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.agent_id == agent.id))
    users = result.scalars().all()
    groups: dict[str, dict[str, Any]] = {}
    for u in users:
        prefix = u.name.split("-")[0] if "-" in u.name else u.name
        g = groups.setdefault(
            prefix,
            {"id": prefix, "count": 0, "active": 0, "disabled": 0, "traffic_gb": 0},
        )
        g["count"] += 1
        if u.active:
            g["active"] += 1
        else:
            g["disabled"] += 1
        if u.traffic_limit and not g["traffic_gb"]:
            g["traffic_gb"] = round(u.traffic_limit / (1024**3), 2)
    return list(groups.values())


@router.get("/agent/groups/{group_id}/users")
async def legacy_agent_group_users(
    group_id: str,
    request: Request,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(
        select(VpnUser).where(
            VpnUser.agent_id == agent.id,
            VpnUser.name.like(f"{group_id}%"),
        )
    )
    server_ip = _request_config_host(request)
    return {
        "ok": True,
        "users": [_user_to_legacy(u, server_ip=server_ip) for u in result.scalars().all()],
    }


__all__ = [_n for _n in list(globals()) if not _n.startswith("__")]
