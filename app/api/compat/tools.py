from __future__ import annotations

from fastapi import APIRouter

from ._core import *  # noqa: F403

router = APIRouter(tags=["compat"])


# ─────────────────────────────────────────────────────────────────────────────
#  Export / Telegram test
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/export-csv")
async def legacy_export_csv(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(VpnUser))
    rows = [
        ["name", "uuid", "active", "traffic_limit_gb", "traffic_used_gb",
         "expire_at", "speed_limit_up", "speed_limit_down", "note"]
    ]
    for u in result.scalars().all():
        rows.append([
            u.name,
            u.uuid,
            u.active,
            (u.traffic_limit or 0) / (1024**3),
            (u.traffic_used or 0) / (1024**3),
            u.expire_at.isoformat() if u.expire_at else "",
            u.speed_limit_up or 0,
            u.speed_limit_down or 0,
            u.note or "",
        ])
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerows(rows)
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="users.csv"'},
    )


@router.get("/export-json")
async def legacy_export_json(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(select(VpnUser))
    payload = [_user_to_legacy(u) for u in result.scalars().all()]
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="users.json"'},
    )


@router.post("/telegram-test")
async def legacy_telegram_test(admin: User = Depends(get_current_admin_cookie)):
    if not (settings.telegram_bot_token and settings.telegram_chat_id):
        return {"ok": False, "error": "Telegram not configured"}
    try:
        from .. import telegram_bot
        if hasattr(telegram_bot, "send_test"):
            await telegram_bot.send_test()
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
#  Search, report, analytics, backup
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/search")
async def legacy_search(
    q: str = Query(..., min_length=1),
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).where(VpnUser.name.ilike(f"%{q}%")).limit(50)
    )
    users = []
    for u in result.scalars().all():
        users.append({
            "name": u.name,
            "active": bool(u.active),
            "traffic_used_gb": (u.traffic_used or 0) / (1024**3),
            "expire_at": u.expire_at.isoformat() if u.expire_at else None,
        })
    return {"users": users}


@router.get("/report")
async def legacy_report(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    total = (await db.execute(select(func.count(VpnUser.id)))).scalar() or 0
    active = (await db.execute(
        select(func.count(VpnUser.id)).where(VpnUser.active == 1)
    )).scalar() or 0
    total_used = (await db.execute(
        select(func.coalesce(func.sum(VpnUser.traffic_used), 0))
    )).scalar() or 0
    total_limit = (await db.execute(
        select(func.coalesce(func.sum(VpnUser.traffic_limit), 0))
    )).scalar() or 0

    week_ahead = _utcnow() + timedelta(days=7)
    expiring = (await db.execute(
        select(func.count(VpnUser.id)).where(
            VpnUser.active == 1,
            VpnUser.expire_at.is_not(None),
            VpnUser.expire_at < week_ahead,
        )
    )).scalar() or 0

    top_result = await db.execute(
        select(VpnUser).order_by(VpnUser.traffic_used.desc()).limit(10)
    )
    top_users = [
        {
            "name": u.name,
            "active": bool(u.active),
            "traffic_used_gb": (u.traffic_used or 0) / (1024**3),
        }
        for u in top_result.scalars().all()
    ]

    return {
        "total_users": total,
        "active_users": active,
        "inactive_users": total - active,
        "total_traffic_gb": total_used / (1024**3),
        "total_limit_gb": total_limit / (1024**3),
        "expiring_soon": expiring,
        "top_users": top_users,
    }


@router.get("/analytics")
async def legacy_analytics(
    days: int = Query(7, ge=1, le=90),
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    top_result = await db.execute(
        select(VpnUser).order_by(VpnUser.traffic_used.desc()).limit(10)
    )
    top_users = [
        {"name": u.name, "traffic_used_gb": (u.traffic_used or 0) / (1024**3)}
        for u in top_result.scalars().all()
    ]

    # Approximate daily traffic by grouping users' current usage by the
    # day their row was last updated (same approach as /traffic-history),
    # 0-filling the requested window so the chart always has a full series.
    cutoff = _utcnow() - timedelta(days=days)
    rows = (await db.execute(select(VpnUser).where(VpnUser.updated_at >= cutoff))).scalars().all()
    by_day: dict[str, int] = {}
    for u in rows:
        if u.updated_at:
            d = u.updated_at.strftime("%Y-%m-%d")
            by_day[d] = by_day.get(d, 0) + (u.traffic_used or 0)
    daily_traffic = [
        {"date": (_utcnow() - timedelta(days=i)).strftime("%Y-%m-%d"),
         "traffic_bytes": by_day.get((_utcnow() - timedelta(days=i)).strftime("%Y-%m-%d"), 0)}
        for i in range(days - 1, -1, -1)
    ]
    return {"daily_traffic": daily_traffic, "top_users": top_users}


@router.get("/backup/list")
async def legacy_backup_list(admin: User = Depends(get_current_admin_cookie)):
    backups: list[dict[str, Any]] = []
    backup_dir = _BACKUP_DIR
    if os.path.isdir(backup_dir):
        for name in sorted(os.listdir(backup_dir), reverse=True):
            if not _BACKUP_NAME_RE.fullmatch(name):
                continue
            path = os.path.join(backup_dir, name)
            try:
                st = os.stat(path)
                backups.append({
                    "name": name,
                    "path": path,
                    "size": st.st_size,
                    "created": datetime.fromtimestamp(st.st_mtime).isoformat(),
                })
            except OSError:
                continue
    return {"backups": backups}


_BACKUP_DIR = "/opt/v7lthronyx/backups"
_BACKUP_NAME_RE = re.compile(r"backup-\d{8}-\d{6}\.json(\.enc)?")


@router.post("/backup/create")
async def legacy_backup_create(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Write a JSON snapshot of users + settings to the backup dir.

    This is a logical (not pg_dump) backup: it captures the rows an
    operator actually needs to recover a panel — every VPN user and
    every key/value setting — in a portable, restorable form.
    """
    try:
        os.makedirs(_BACKUP_DIR, mode=0o700, exist_ok=True)

        users = (await db.execute(select(VpnUser))).scalars().all()
        settings_rows = (await db.execute(select(Setting))).scalars().all()

        snapshot = {
            "version": 1,
            "created_at": _utcnow().isoformat(),
            "users": [
                {
                    "uuid": u.uuid,
                    "name": u.name,
                    "traffic_limit": u.traffic_limit,
                    "traffic_used": u.traffic_used,
                    "traffic_upload": u.traffic_upload,
                    "traffic_download": u.traffic_download,
                    "speed_limit_up": u.speed_limit_up,
                    "speed_limit_down": u.speed_limit_down,
                    "expire_at": u.expire_at.isoformat() if u.expire_at else None,
                    "active": u.active,
                    "agent_id": u.agent_id,
                    "note": u.note,
                }
                for u in users
            ],
            "settings": [
                {"key": s.key, "value": s.value, "value_type": s.value_type}
                for s in settings_rows
            ],
        }

        # Snapshots hold client UUIDs and server keys: encrypt and keep 0600.
        fname = f"backup-{_utcnow().strftime('%Y%m%d-%H%M%S')}.json{ENCRYPTED_SUFFIX}"
        fpath = os.path.join(_BACKUP_DIR, fname)
        payload = encrypt_backup(json.dumps(snapshot, ensure_ascii=False).encode("utf-8"))
        fd = os.open(fpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        await record_audit(db, "backup_create", admin_id=getattr(admin, "id", None))

        return {
            "ok": True,
            "name": fname,
            "users": len(snapshot["users"]),
            "settings": len(snapshot["settings"]),
            "size": os.path.getsize(fpath),
        }
    except OSError as exc:
        logger.error("backup create failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"backup failed: {exc}")


@router.post("/backup/restore")
async def legacy_backup_restore(
    body: dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Restore a JSON snapshot: upsert settings and users by key/uuid."""
    name = (body or {}).get("name", "")
    if not isinstance(name, str) or not _BACKUP_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="invalid backup name")
    fpath = os.path.join(_BACKUP_DIR, name)
    if not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="backup not found")

    try:
        with open(fpath, "rb") as f:
            raw = f.read()
        if name.endswith(ENCRYPTED_SUFFIX):
            raw = decrypt_backup(raw)
        snapshot = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"cannot read backup: {exc}")

    restored_settings = 0
    for row in snapshot.get("settings", []):
        key = row.get("key")
        if not key:
            continue
        existing = (
            await db.execute(select(Setting).where(Setting.key == key))
        ).scalar_one_or_none()
        if existing:
            existing.value = row.get("value")
            existing.value_type = row.get("value_type", "string")
        else:
            db.add(Setting(key=key, value=row.get("value"), value_type=row.get("value_type", "string")))
        restored_settings += 1

    restored_users = 0
    for row in snapshot.get("users", []):
        uuid_val = row.get("uuid")
        if not uuid_val:
            continue
        existing = (
            await db.execute(select(VpnUser).where(VpnUser.uuid == uuid_val))
        ).scalar_one_or_none()
        expire_at = None
        if row.get("expire_at"):
            try:
                expire_at = datetime.fromisoformat(row["expire_at"])
            except ValueError:
                expire_at = None
        fields = {
            "name": row.get("name", uuid_val),
            "traffic_limit": row.get("traffic_limit", 0),
            "traffic_used": row.get("traffic_used", 0),
            "traffic_upload": row.get("traffic_upload", 0),
            "traffic_download": row.get("traffic_download", 0),
            "speed_limit_up": row.get("speed_limit_up", 0),
            "speed_limit_down": row.get("speed_limit_down", 0),
            "expire_at": expire_at,
            "active": row.get("active", 1),
            "note": row.get("note", ""),
        }
        if existing:
            for k, v in fields.items():
                setattr(existing, k, v)
        else:
            db.add(VpnUser(uuid=uuid_val, **fields))
        restored_users += 1

    await db.commit()
    await record_audit(
        db, "backup_restore", admin_id=getattr(admin, "id", None), details={"name": name}
    )
    return {"ok": True, "restored_users": restored_users, "restored_settings": restored_settings}


@router.post("/backup/cleanup")
async def legacy_backup_cleanup(
    body: dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    """Delete backups older than `keep_days` (default 30)."""
    keep_days = int((body or {}).get("keep_days", 30))
    removed = 0
    if os.path.isdir(_BACKUP_DIR):
        cutoff = time.time() - keep_days * 86400
        for name in os.listdir(_BACKUP_DIR):
            path = os.path.join(_BACKUP_DIR, name)
            try:
                if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                    os.unlink(path)
                    removed += 1
            except OSError:
                continue
    return {"ok": True, "removed": removed}


__all__ = [_n for _n in list(globals()) if not _n.startswith("__")]
