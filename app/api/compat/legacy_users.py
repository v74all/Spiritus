from __future__ import annotations

from fastapi import APIRouter

from ._core import *  # noqa: F403

router = APIRouter(tags=["compat"])


# ─────────────────────────────────────────────────────────────────────────────
#  Users (legacy shape)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/users")
async def legacy_list_users(
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(select(VpnUser).order_by(VpnUser.id.desc()))
    server_ip = _request_config_host(request)
    return [_user_to_legacy(u, server_ip=server_ip) for u in result.scalars().all()]


class LegacyUserCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    traffic: float = Field(10.0, ge=0)
    days: int = Field(30, ge=0)
    speed_limit_up: int = Field(0, ge=0)
    speed_limit_down: int = Field(0, ge=0)
    note: str = ""


@router.post("/users")
async def legacy_create_user(
    body: LegacyUserCreate,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    from ...services.user_names import display_name_error

    user_name = body.name.strip()
    name_error = display_name_error(user_name)
    if name_error:
        return {"ok": False, "error": name_error}
    if await taken_vpn_user_names(db, [user_name]):
        return {"ok": False, "error": f"User '{user_name}' already exists"}
    expire_at = _utcnow() + timedelta(days=body.days) if body.days else None
    db_user = VpnUser(
        uuid=str(uuid_lib.uuid4()),
        name=user_name,
        traffic_limit=int(body.traffic * (1024**3)),
        traffic_used=0,
        expire_at=expire_at,
        active=1,
        speed_limit_up=body.speed_limit_up,
        speed_limit_down=body.speed_limit_down,
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
    return {
        "ok": True,
        "user": _user_to_legacy(db_user, server_ip=_request_config_host(request)),
    }


@router.delete("/users/{name}")
async def legacy_delete_user(
    name: str,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    await db.delete(user)
    await db.commit()
    return {"ok": True}


@router.post("/users/{name}/toggle")
async def legacy_toggle_user(
    name: str,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.active = 0 if user.active else 1
    await db.commit()
    return {
        "ok": True,
        "message": f"User {name} {'enabled' if user.active else 'disabled'}",
        "active": bool(user.active),
    }


class LegacyRenewRequest(BaseModel):
    traffic: float = Field(..., ge=0)
    days: int = Field(..., ge=0)


@router.post("/users/{name}/renew")
async def legacy_renew_user(
    name: str,
    body: LegacyRenewRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.traffic_limit = int(body.traffic * (1024**3))
    user.traffic_used = 0
    user.expire_at = _utcnow() + timedelta(days=body.days)
    user.active = 1
    await db.commit()
    return {"ok": True}


class LegacyAddTrafficRequest(BaseModel):
    gb: float = Field(..., gt=0)


@router.post("/users/{name}/add-traffic")
async def legacy_add_traffic(
    name: str,
    body: LegacyAddTrafficRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.traffic_limit = (user.traffic_limit or 0) + int(body.gb * (1024**3))
    await db.commit()
    return {"ok": True}


class LegacyNoteRequest(BaseModel):
    note: str


@router.post("/users/{name}/update-note")
async def legacy_update_note(
    name: str,
    body: LegacyNoteRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.note = body.note
    await db.commit()
    return {"ok": True}


class LegacySpeedRequest(BaseModel):
    speed_limit_down: int = Field(0, ge=0)
    speed_limit_up: int = Field(0, ge=0)


@router.post("/users/{name}/speed-limit")
async def legacy_speed_limit(
    name: str,
    body: LegacySpeedRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.speed_limit_down = body.speed_limit_down
    user.speed_limit_up = body.speed_limit_up
    await db.commit()
    return {"ok": True}


@router.post("/users/{name}/reset-traffic")
async def legacy_reset_traffic(
    name: str,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser).where(VpnUser.name == name))
    user = result.scalar_one_or_none()
    if user is None:
        return {"ok": False, "error": "User not found"}
    user.traffic_used = 0
    await db.commit()
    return {"ok": True}


@router.get("/users/{name}/activity")
async def legacy_user_activity(
    name: str,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Per-user activity view.

    Deep per-connection / per-site analytics need a DPI connection log
    that this panel does not collect, so those fields stay empty and the
    verdict is honest ("No deep data"). What we CAN report truthfully is
    the user's real traffic accounting (up/down/total and last-seen),
    which the dashboard's summary panel uses.
    """
    user = (
        await db.execute(select(VpnUser).where(VpnUser.name == name))
    ).scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=404, detail="user not found")

    up = int(user.traffic_upload or 0)
    down = int(user.traffic_download or 0)
    total = int(user.traffic_used or 0) or (up + down)
    last_seen = _user_last_seen.get(user.name, 0)

    summary = [
        {"label": "Upload", "bytes": up},
        {"label": "Download", "bytes": down},
        {"label": "Total", "bytes": total},
    ]

    return {
        "summary": summary,
        "categories": [],
        "services": [],
        "deep": {
            "verdict": "No deep data (DPI logging disabled)",
            "verdict_level": "safe",
            "total_connections": 0,
            "unique_destinations": 0,
            "activities": [],
            "ports": [],
            "hourly": [],
        },
        "sites": [],
        "recent": [],
        "total": total,
        "upload": up,
        "download": down,
        "last_seen": last_seen,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Bulk operations
# ─────────────────────────────────────────────────────────────────────────────

class BulkCreateRequest(BaseModel):
    prefix: str = "group"
    count: int = Field(1, ge=1, le=500)
    traffic: float = 1
    days: int = 30
    numbered: bool = True
    start: int = 1
    pad: int = 3
    apply: bool = False
    speed_limit_up: int = 0
    speed_limit_down: int = 0


@router.post("/bulk-users")
async def legacy_bulk_users(
    body: BulkCreateRequest,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    from ...services.user_names import display_name_error

    prefix = body.prefix.strip()
    prefix_error = display_name_error(prefix, label="Prefix")
    if prefix_error:
        return {"ok": False, "error": prefix_error}
    if body.numbered:
        names = [f"{prefix}-{str(body.start + i).zfill(body.pad)}" for i in range(body.count)]
        taken = await taken_vpn_user_names(db, names)
        if taken:
            return {"ok": False, "error": "Users already exist: " + ", ".join(sorted(taken))}
    expire_at = _utcnow() + timedelta(days=body.days) if body.days else None
    created_users: list[VpnUser] = []
    for i in range(body.count):
        if body.numbered:
            suffix = str(body.start + i).zfill(body.pad)
            name = f"{prefix}-{suffix}"
        else:
            name = f"{prefix}-{uuid_lib.uuid4().hex[:8]}"
        u = VpnUser(
            uuid=str(uuid_lib.uuid4()),
            name=name,
            traffic_limit=int(body.traffic * (1024**3)),
            traffic_used=0,
            expire_at=expire_at,
            active=1,
            speed_limit_up=body.speed_limit_up,
            speed_limit_down=body.speed_limit_down,
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
        "note": "",
        "apply": body.apply,
    }


class BulkDeleteRequest(BaseModel):
    prefix: str | None = None
    names: list[str] | None = None
    apply: bool = False


@router.post("/bulk-delete")
async def legacy_bulk_delete(
    body: BulkDeleteRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    query = select(VpnUser)
    if body.names:
        query = query.where(VpnUser.name.in_(body.names))
    elif body.prefix:
        safe_prefix = body.prefix.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        query = query.where(VpnUser.name.like(f"{safe_prefix}%", escape="\\"))
    else:
        return {"ok": False, "error": "Provide names or prefix"}

    result = await db.execute(query)
    users = result.scalars().all()
    count = 0
    for u in users:
        await db.delete(u)
        count += 1
    await db.commit()
    return {"ok": True, "deleted": count, "apply": body.apply}


_ZIP_STEM = re.compile(r"[^A-Za-z0-9._-]+")


def _download_stem(value: object) -> str:
    cleaned = _ZIP_STEM.sub("_", str(value or "bulk")).strip("._")[:40]
    return cleaned or "bulk"


def _zip_entry_name(value: object, used: set[str]) -> str:
    """A flat archive name. Client-supplied names must not be paths."""
    cleaned = _ZIP_STEM.sub("_", str(value or "user")).strip("._")[:80] or "user"
    candidate = f"{cleaned}.txt"
    n = 2
    while candidate in used:
        candidate = f"{cleaned}-{n}.txt"
        n += 1
    used.add(candidate)
    return candidate


@router.post("/bulk-export-zip")
async def legacy_bulk_export_zip(
    body: dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    import zipfile

    prefix = _download_stem(body.get("prefix", "bulk"))
    users = body.get("users", []) or []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        used_names: set[str] = set()
        for u in users:
            name = _zip_entry_name(u.get("name", "user"), used_names)
            text = "\n".join(
                f"{label}: {u.get(key, '')}"
                for key, label in [
                    ("vmess", "VMess"),
                    ("vless", "VLESS"),
                    ("cdn_vmess", "CDN"),
                    ("trojan", "Trojan"),
                    ("grpc_vmess", "gRPC"),
                    ("httpupgrade_vmess", "HU"),
                    ("ss2022", "SS2022"),
                    ("vless_ws", "VLESS-WS"),
                ]
                if u.get(key)
            )
            zf.writestr(name, text)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{prefix}-configs.zip"'},
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Groups
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/groups")
async def legacy_groups(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser))
    users = result.scalars().all()
    groups: dict[str, dict[str, Any]] = {}
    for u in users:
        prefix = u.name.split("-")[0] if "-" in u.name else u.name
        g = groups.setdefault(
            prefix,
            {
                "id": prefix,
                "count": 0,
                "active": 0,
                "disabled": 0,
                "traffic_gb": 0,
                "latest_expire": "",
            },
        )
        g["count"] += 1
        if u.active:
            g["active"] += 1
        else:
            g["disabled"] += 1
        if u.traffic_limit and not g["traffic_gb"]:
            g["traffic_gb"] = round(u.traffic_limit / (1024**3), 2)
        if u.expire_at:
            iso = u.expire_at.isoformat()
            if iso > g["latest_expire"]:
                g["latest_expire"] = iso
    return list(groups.values())


@router.get("/groups/{group_id}/users")
async def legacy_group_users(
    group_id: str,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    safe_group_id = group_id.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
    result = await db.execute(
        select(VpnUser).where(VpnUser.name.like(f"{safe_group_id}%", escape="\\"))
    )
    server_ip = _request_config_host(request)
    users = [_user_to_legacy(u, server_ip=server_ip) for u in result.scalars().all()]
    return {"ok": True, "users": users}


__all__ = [_n for _n in list(globals()) if not _n.startswith("__")]
