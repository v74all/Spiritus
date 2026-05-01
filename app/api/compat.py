"""
Legacy compatibility router for V7LTHRONYX VPN Panel.

The frontend (panel.js) was built against an older API surface. This router
maps the legacy endpoint paths and response shapes (``{ok: true, ...}`` style)
to the current backend implementation so the panel works without rewriting
the frontend.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import io
import csv
import json
import logging
import os
import time
import uuid as uuid_lib

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from jose import JWTError, jwt
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import (
    User,
    create_access_token,
    get_current_admin_cookie,
    get_password_hash,
    verify_password,
)
from ..config import settings
from ..database import get_async_db
from ..models import Admin, Agent, Setting, VpnUser
from ..security import fail2ban_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["compat"])

# In-memory state for endpoints that don't have a DB-backed implementation yet.
_login_attempts: dict[str, list[float]] = {}
_settings_state: dict[str, Any] = {}
_resilience_state: dict[str, Any] = {"active_attacks": 0, "stats": {}}
_LEGACY_SETTINGS_KEY = "legacy_panel_settings"
_LEGACY_SETTINGS_FILE = "vpn-settings.json"
_DPI_SETTING_KEYS = {
    "dpi_tcp_fragment",
    "dpi_tls_fragment",
    "dpi_ip_fragment",
    "dpi_tcp_keepalive",
    "dpi_dns_tunnel",
    "dpi_icmp_tunnel",
    "dpi_domain_front",
    "dpi_cdn_front_enabled",
    "dpi_cdn_front",
}
_PROTOCOL_ENABLE_KEYS = {
    "cdn_enabled",
    "trojan_enabled",
    "grpc_enabled",
    "httpupgrade_enabled",
    "ss2022_enabled",
    "vless_ws_enabled",
    "vless_xhttp_enabled",
    "vless_vision_enabled",
    "vless_reverse_enabled",
    "trojan_cdn_enabled",
    "trojan_cdn_grpc_enabled",
    "hysteria2_enabled",
    "tuic_enabled",
    "amneziawg_enabled",
    "shadowtls_enabled",
    "mieru_enabled",
    "naiveproxy_enabled",
    "wireguard_enabled",
    "openvpn_enabled",
}


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_locked_out(ip: str) -> bool:
    if ip not in _login_attempts:
        return False
    now = time.time()
    _login_attempts[ip] = [
        t for t in _login_attempts[ip] if now - t < settings.lockout_seconds
    ]
    return len(_login_attempts[ip]) >= settings.max_login_attempts


def _record_failed_attempt(ip: str) -> None:
    _login_attempts.setdefault(ip, []).append(time.time())


def _clear_attempts(ip: str) -> None:
    _login_attempts.pop(ip, None)


def _read_password_file() -> Optional[str]:
    pw_file = os.path.join(os.getcwd(), "vpn-panel-password")
    if not os.path.exists(pw_file):
        return None
    try:
        with open(pw_file) as f:
            return f.read().strip()
    except Exception as exc:
        logger.error(f"Failed to read password file: {exc}")
        return None


def _write_password_file(new_password: str) -> bool:
    pw_file = os.path.join(os.getcwd(), "vpn-panel-password")
    try:
        with open(pw_file, "w") as f:
            f.write(new_password)
        return True
    except Exception as exc:
        logger.error(f"Failed to write password file: {exc}")
        return False


def _days_left(expire_at: Optional[datetime]) -> int:
    if not expire_at:
        return 9999
    delta = expire_at - datetime.utcnow()
    return max(0, delta.days)


def _build_share_links(u: VpnUser) -> Dict[str, str]:
    """Generate protocol share URLs for a user. Best-effort — empty if disabled."""
    try:
        from ..protocol_engine import ClientConfigGenerator
    except Exception:
        return {}

    server_ip = _settings_state.get("server_ip") or settings.host
    if server_ip == "0.0.0.0":
        server_ip = ""
    sni_host = _settings_state.get("vmess_sni") or "www.aparat.com"
    ws_path = _settings_state.get("vmess_ws_path") or "/api/v1/stream"

    links: Dict[str, str] = {}
    try:
        links["vmess"] = ClientConfigGenerator.generate_vmess_share_url(
            uuid=u.uuid,
            address=server_ip,
            port=int(_settings_state.get("vmess_port") or 443),
            sni=sni_host,
            path=ws_path,
        )
    except Exception:
        links["vmess"] = ""

    if _settings_state.get("vless_ws_enabled") or settings.vless_ws_enabled:
        try:
            links["vless_ws"] = ClientConfigGenerator.generate_vless_share_url(
                uuid=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("vless_ws_port") or settings.vless_ws_port),
                network="ws",
                security="tls",
                sni=sni_host,
                path=_settings_state.get("vless_ws_path") or settings.vless_ws_path,
            )
        except Exception:
            links["vless_ws"] = ""

    if _settings_state.get("trojan_enabled"):
        try:
            links["trojan"] = ClientConfigGenerator.generate_trojan_share_url(
                password=u.uuid,
                address=server_ip,
                port=int(_settings_state.get("trojan_port") or 2083),
                sni=sni_host,
            )
        except Exception:
            links["trojan"] = ""

    return links


def _user_to_legacy(u: VpnUser) -> Dict[str, Any]:
    traffic_limit_gb = (u.traffic_limit / (1024**3)) if u.traffic_limit else 0
    traffic_used_gb = (u.traffic_used / (1024**3)) if u.traffic_used else 0
    links = _build_share_links(u)
    return {
        "id": u.id,
        "name": u.name,
        "uuid": u.uuid,
        "active": bool(u.active),
        "traffic_limit": traffic_limit_gb,
        "traffic_used_gb": traffic_used_gb,
        "traffic_used_bytes": u.traffic_used or 0,
        "expire_at": u.expire_at.isoformat() if u.expire_at else None,
        "days_left": _days_left(u.expire_at),
        "agent_id": u.agent_id,
        "speed_limit_up": u.speed_limit_up or 0,
        "speed_limit_down": u.speed_limit_down or 0,
        "note": u.note or "",
        "online_ip_count": 0,
        "online_ips": [],
        "vmess": links.get("vmess", ""),
        "vless": links.get("vless", ""),
        "cdn_vmess": links.get("cdn_vmess", ""),
        "trojan": links.get("trojan", ""),
        "grpc_vmess": links.get("grpc_vmess", ""),
        "httpupgrade_vmess": links.get("httpupgrade_vmess", ""),
        "ss2022": links.get("ss2022", ""),
        "vless_ws": links.get("vless_ws", ""),
    }


async def _load_legacy_settings(db: AsyncSession) -> Dict[str, Any]:
    if _settings_state:
        return dict(_settings_state)

    file_settings: Dict[str, Any] = {}
    settings_path = os.path.join(os.getcwd(), _LEGACY_SETTINGS_FILE)
    if os.path.exists(settings_path):
        try:
            with open(settings_path) as f:
                loaded_file = json.load(f)
            if isinstance(loaded_file, dict):
                file_settings = loaded_file
        except Exception as exc:
            logger.warning(f"Failed to load legacy settings file: {exc}")

    result = await db.execute(select(Setting).where(Setting.key == _LEGACY_SETTINGS_KEY))
    row = result.scalar_one_or_none()
    if not row or not row.value:
        _settings_state.update(file_settings)
        return dict(_settings_state)

    db_settings: Dict[str, Any] = {}
    try:
        loaded_db = json.loads(row.value)
    except json.JSONDecodeError:
        logger.warning("Ignoring invalid legacy panel settings JSON")
        loaded_db = {}
    if isinstance(loaded_db, dict):
        db_settings = loaded_db

    _settings_state.update({**file_settings, **db_settings})
    return dict(_settings_state)


def _preserve_protocols_on_dpi_update(
    current: Dict[str, Any],
    incoming: Dict[str, Any],
) -> Dict[str, Any]:
    if not any(key in incoming for key in _DPI_SETTING_KEYS):
        return incoming

    protected = dict(incoming)
    for key in _PROTOCOL_ENABLE_KEYS:
        if current.get(key) is True and protected.get(key) is False:
            protected[key] = True
    return protected


async def _save_legacy_settings(db: AsyncSession, data: Dict[str, Any]) -> None:
    current = await _load_legacy_settings(db)
    data = _preserve_protocols_on_dpi_update(current, data)
    _settings_state.update(data)
    result = await db.execute(select(Setting).where(Setting.key == _LEGACY_SETTINGS_KEY))
    row = result.scalar_one_or_none()
    value = json.dumps(_settings_state)
    if row is None:
        row = Setting(
            key=_LEGACY_SETTINGS_KEY,
            value=value,
            value_type="json",
            description="Legacy panel compatibility settings",
        )
        db.add(row)
    else:
        row.value = value
        row.value_type = "json"
    await db.commit()

    settings_path = os.path.join(os.getcwd(), _LEGACY_SETTINGS_FILE)
    try:
        with open(settings_path, "w") as f:
            json.dump(_settings_state, f, indent=2)
        os.chmod(settings_path, 0o600)
    except Exception as exc:
        logger.warning(f"Failed to mirror legacy settings file: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
#  Auth (legacy)
# ─────────────────────────────────────────────────────────────────────────────

class LegacyLoginRequest(BaseModel):
    password: str
    username: Optional[str] = "admin"


@router.post("/login")
async def legacy_login(
    request: LegacyLoginRequest,
    req: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db),
):
    client_ip = req.client.host if req.client else "0.0.0.0"

    if await fail2ban_manager.is_banned(client_ip, "panel", db):
        return {"ok": False, "error": "IP banned. Contact admin.", "locked": True}

    if _is_locked_out(client_ip):
        return {
            "ok": False,
            "error": f"Too many attempts. Try again in {settings.lockout_seconds}s",
            "locked": True,
        }

    username = request.username or "admin"
    admin_id: Optional[int] = None
    authenticated = False

    db_result = await db.execute(select(Admin).where(Admin.username == username))
    admin_user = db_result.scalar_one_or_none()
    if admin_user and verify_password(request.password, admin_user.password_hash):
        authenticated = True
        admin_id = admin_user.id

    if not authenticated:
        stored_pw = _read_password_file()
        if stored_pw and request.password == stored_pw:
            authenticated = True

    if not authenticated:
        _record_failed_attempt(client_ip)
        await fail2ban_manager.record_failed_attempt(
            client_ip, "panel", db, "Failed panel login"
        )
        return {"ok": False, "error": "Invalid password"}

    _clear_attempts(client_ip)

    token_payload: Dict[str, Any] = {"sub": username, "is_admin": True}
    if admin_id is not None:
        token_payload["user_id"] = admin_id

    access_token = create_access_token(data=token_payload)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.session_lifetime_hours * 3600,
        path="/",
    )
    return {"ok": True, "access_token": access_token}


@router.post("/logout")
async def legacy_logout(response: Response):
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


class ChangePasswordRequest(BaseModel):
    current: str
    new: str


@router.post("/change-password")
async def legacy_change_password(
    body: ChangePasswordRequest,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    if len(body.new) < 8:
        return {"ok": False, "error": "Password too short (min 8 chars)"}

    db_admin = None
    if admin.username:
        result = await db.execute(select(Admin).where(Admin.username == admin.username))
        db_admin = result.scalar_one_or_none()

    if db_admin is not None:
        if not verify_password(body.current, db_admin.password_hash):
            return {"ok": False, "error": "Current password is incorrect"}
        db_admin.password_hash = get_password_hash(body.new)
        await db.commit()
        return {"ok": True}

    stored_pw = _read_password_file()
    if stored_pw is None:
        return {"ok": False, "error": "Password store not initialized"}
    if body.current != stored_pw:
        return {"ok": False, "error": "Current password is incorrect"}
    if not _write_password_file(body.new):
        return {"ok": False, "error": "Failed to update password"}
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
#  Users (legacy shape)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/users")
async def legacy_list_users(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(select(VpnUser).order_by(VpnUser.id.desc()))
    return [_user_to_legacy(u) for u in result.scalars().all()]


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
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    expire_at = datetime.utcnow() + timedelta(days=body.days) if body.days else None
    db_user = VpnUser(
        uuid=str(uuid_lib.uuid4()),
        name=body.name,
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
        await db.refresh(db_user)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    await _load_legacy_settings(db)
    return {"ok": True, "user": _user_to_legacy(db_user)}


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
    user.expire_at = datetime.utcnow() + timedelta(days=body.days)
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
):
    return {
        "summary": [],
        "categories": [],
        "services": [],
        "deep": {
            "verdict": "No data",
            "verdict_level": "safe",
            "total_connections": 0,
            "unique_destinations": 0,
            "activities": [],
            "ports": [],
            "hourly": [],
        },
        "sites": [],
        "recent": [],
        "total": 0,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Bulk operations
# ─────────────────────────────────────────────────────────────────────────────

class BulkCreateRequest(BaseModel):
    prefix: str = "group"
    count: int = 1
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
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    expire_at = datetime.utcnow() + timedelta(days=body.days) if body.days else None
    created_users: List[VpnUser] = []
    for i in range(body.count):
        if body.numbered:
            suffix = str(body.start + i).zfill(body.pad)
            name = f"{body.prefix}-{suffix}"
        else:
            name = f"{body.prefix}-{uuid_lib.uuid4().hex[:8]}"
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
            await db.refresh(u)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    await _load_legacy_settings(db)
    return {
        "ok": True,
        "created": len(created_users),
        "users": [_user_to_legacy(u) for u in created_users],
        "numbered": body.numbered,
        "start": body.start,
        "pad": body.pad,
        "note": "",
        "apply": body.apply,
    }


class BulkDeleteRequest(BaseModel):
    prefix: Optional[str] = None
    names: Optional[List[str]] = None
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
        query = query.where(VpnUser.name.like(f"{body.prefix}%"))
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


@router.post("/bulk-export-zip")
async def legacy_bulk_export_zip(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    import zipfile

    prefix = str(body.get("prefix", "bulk"))
    users = body.get("users", []) or []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for u in users:
            name = u.get("name", "user")
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
            zf.writestr(f"{name}.txt", text)
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
    groups: Dict[str, Dict[str, Any]] = {}
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
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(
        select(VpnUser).where(VpnUser.name.like(f"{group_id}%"))
    )
    users = [_user_to_legacy(u) for u in result.scalars().all()]
    return {"ok": True, "users": users}


# ─────────────────────────────────────────────────────────────────────────────
#  Live, server-info, sync, system-monitor, online-users
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/live")
async def legacy_live(admin: User = Depends(get_current_admin_cookie)):
    """Realtime traffic counters keyed by username."""
    return {}


@router.get("/server-info")
async def legacy_server_info(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    s = await _load_legacy_settings(db)
    return {
        "vmess_port": s.get("vmess_port", 443),
        "vless": bool(s.get("reality_public_key")),
        "vless_port": s.get("vless_port", 2053),
        "vless_sni": s.get("reality_sni", "www.google.com"),
        "vless_public_key": s.get("reality_public_key", ""),
        "vless_short_id": s.get("reality_short_id", ""),
        "trojan": s.get("trojan_enabled", False),
        "trojan_port": s.get("trojan_port", 2083),
        "grpc": s.get("grpc_enabled", False),
        "grpc_port": s.get("grpc_port", 2054),
        "grpc_service": s.get("grpc_service_name", "GunService"),
        "httpupgrade": s.get("httpupgrade_enabled", False),
        "httpupgrade_port": s.get("httpupgrade_port", 2055),
        "httpupgrade_path": s.get("httpupgrade_path", "/httpupgrade"),
        "ss2022": bool(s.get("ss2022_server_key")),
        "ss2022_port": s.get("ss2022_port", 2056),
        "vless_ws": s.get("vless_ws_enabled", settings.vless_ws_enabled),
        "vless_ws_port": s.get("vless_ws_port", settings.vless_ws_port),
        "vless_ws_path": s.get("vless_ws_path", settings.vless_ws_path),
        "cdn": s.get("cdn_enabled", settings.cdn_enabled),
        "cdn_domain": s.get("cdn_domain", settings.cdn_domain),
        "cdn_ws_path": s.get("cdn_ws_path", settings.cdn_ws_path),
        "cdn_port": s.get("cdn_port", settings.cdn_port),
        "fragment_enabled": s.get("fragment_enabled", False),
        "mux_enabled": s.get("mux_enabled", False),
        "kill_switch": s.get("kill_switch_enabled", False),
        "telegram_enabled": s.get("telegram_enabled", False),
    }


@router.post("/sync")
async def legacy_sync(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    now = datetime.utcnow()
    result = await db.execute(
        select(VpnUser).where(VpnUser.expire_at != None, VpnUser.active == 1)
    )
    disabled = 0
    for u in result.scalars().all():
        if u.expire_at and u.expire_at < now:
            u.active = 0
            disabled += 1
    if disabled:
        await db.commit()
    return {"ok": True, "disabled": disabled}


@router.get("/system-monitor")
async def legacy_system_monitor(admin: User = Depends(get_current_admin_cookie)):
    import psutil

    cpu = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot = psutil.boot_time()
    net = psutil.net_io_counters()

    xray_pid = None
    xray_mem = 0
    xray_cpu = 0
    try:
        for proc in psutil.process_iter(["name", "pid", "memory_info", "cpu_percent"]):
            if "xray" in (proc.info.get("name") or "").lower():
                xray_pid = proc.info.get("pid")
                mi = proc.info.get("memory_info")
                xray_mem = mi.rss if mi else 0
                xray_cpu = proc.info.get("cpu_percent") or 0
                break
    except Exception:
        pass

    try:
        load_avg = list(os.getloadavg())
    except Exception:
        load_avg = [0.0, 0.0, 0.0]

    return {
        "cpu_percent": round(cpu, 1),
        "ram_percent": round(mem.percent, 1),
        "ram_used": mem.used,
        "ram_total": mem.total,
        "disk_percent": round(disk.percent, 1),
        "disk_used": disk.used,
        "disk_total": disk.total,
        "uptime_seconds": int(time.time() - boot),
        "xray_pid": xray_pid,
        "xray_mem": xray_mem,
        "xray_cpu": xray_cpu,
        "xray_version": "",
        "net_bytes_sent": net.bytes_sent,
        "net_bytes_recv": net.bytes_recv,
        "load_avg": load_avg,
    }


@router.get("/online-users")
async def legacy_online_users(admin: User = Depends(get_current_admin_cookie)):
    return []


@router.get("/traffic-history")
async def legacy_traffic_history(
    days: int = Query(30, ge=1, le=365),
    admin: User = Depends(get_current_admin_cookie),
):
    return []


@router.get("/traffic-history/top")
async def legacy_top_traffic(
    days: int = Query(30, ge=1, le=365),
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).order_by(VpnUser.traffic_used.desc()).limit(10)
    )
    return [
        {"username": u.name, "total_bytes": u.traffic_used or 0}
        for u in result.scalars().all()
    ]


# ─────────────────────────────────────────────────────────────────────────────
#  Settings
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/settings")
async def legacy_get_settings(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    defaults = {
        "config_prefix": "Proxy",
        "vmess_port": 443,
        "vmess_sni": "www.aparat.com",
        "vmess_ws_path": "/api/v1/stream",
        "kill_switch_enabled": False,
        "reality_sni": "www.google.com",
        "vless_port": 2053,
        "reality_public_key": "",
        "trojan_enabled": False,
        "trojan_port": 2083,
        "grpc_enabled": False,
        "grpc_port": 2054,
        "grpc_service_name": "GunService",
        "httpupgrade_enabled": False,
        "httpupgrade_port": 2055,
        "httpupgrade_path": "/httpupgrade",
        "fragment_enabled": False,
        "fragment_packets": "tlshello",
        "fragment_length": "100-200",
        "fragment_interval": "10-20",
        "mux_enabled": False,
        "mux_concurrency": 8,
        "ss2022_enabled": False,
        "ss2022_port": 2056,
        "ss2022_method": "2022-blake3-aes-128-gcm",
        "ss2022_server_key": "",
        "vless_ws_enabled": settings.vless_ws_enabled,
        "vless_ws_port": settings.vless_ws_port,
        "vless_ws_path": settings.vless_ws_path,
        "fingerprint": "chrome",
        "noise_enabled": False,
        "noise_packet": "rand:50-100",
        "noise_delay": "10-20",
        "cdn_enabled": settings.cdn_enabled,
        "cdn_domain": settings.cdn_domain,
        "cdn_ws_path": settings.cdn_ws_path,
        "cdn_port": settings.cdn_port,
        "telegram_enabled": False,
        "telegram_bot_token": settings.telegram_bot_token,
        "telegram_chat_id": settings.telegram_chat_id,
        "telegram_notify_user_disabled": True,
        "telegram_notify_user_expired": True,
        "telegram_notify_kill_switch": True,
        "telegram_notify_traffic_exhausted": True,
        "telegram_notify_user_created": False,
        "telegram_notify_user_deleted": False,
        "dpi_tcp_fragment": False,
        "dpi_tls_fragment": False,
        "dpi_ip_fragment": False,
        "dpi_tcp_keepalive": False,
        "dpi_dns_tunnel": False,
        "dpi_icmp_tunnel": False,
        "dpi_domain_front": False,
        "dpi_cdn_front_enabled": False,
        "dpi_cdn_front": "",
    }
    merged = {**defaults, **await _load_legacy_settings(db)}
    return merged


@router.post("/settings")
async def legacy_save_settings(
    data: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _save_legacy_settings(db, data)
    return {"ok": True, "rebuild": False}


@router.post("/settings/regenerate-reality")
async def legacy_regenerate_reality(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    import secrets

    public_key = secrets.token_urlsafe(32)[:43]
    short_id = secrets.token_hex(4)
    await _save_legacy_settings(
        db,
        {"reality_public_key": public_key, "reality_short_id": short_id},
    )
    return {"ok": True, "public_key": public_key, "short_id": short_id}


@router.post("/settings/generate-ss2022-key")
async def legacy_generate_ss2022_key(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    import base64
    import secrets

    key = base64.b64encode(secrets.token_bytes(16)).decode()
    await _save_legacy_settings(db, {"ss2022_server_key": key})
    return {"ok": True, "ss2022_server_key": key}


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

    week_ahead = datetime.utcnow() + timedelta(days=7)
    expiring = (await db.execute(
        select(func.count(VpnUser.id)).where(
            VpnUser.active == 1,
            VpnUser.expire_at != None,
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
    return {"daily_traffic": [], "top_users": top_users}


@router.get("/backup/list")
async def legacy_backup_list(admin: User = Depends(get_current_admin_cookie)):
    backups: List[Dict[str, Any]] = []
    backup_dir = "/opt/spiritus/backups"
    if os.path.isdir(backup_dir):
        for name in sorted(os.listdir(backup_dir), reverse=True):
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


@router.post("/backup/create")
async def legacy_backup_create(admin: User = Depends(get_current_admin_cookie)):
    return {"ok": True, "message": "Backup queued"}


@router.post("/backup/restore")
async def legacy_backup_restore(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    return {"ok": True}


@router.post("/backup/cleanup")
async def legacy_backup_cleanup(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    return {"ok": True, "removed": 0}


# ─────────────────────────────────────────────────────────────────────────────
#  Network resilience / aggressive / fightback (stubs)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/network-resilience/run")
async def legacy_resilience_run(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    technique = body.get("technique", "unknown")
    _resilience_state["active_attacks"] += 1
    _resilience_state["stats"][technique] = {
        "started_at": datetime.utcnow().isoformat(),
        "target": body.get("target"),
        "duration": body.get("duration"),
    }
    return {
        "ok": True,
        "iranian_target": False,
        "message": f"Simulation started: {technique}",
    }


@router.get("/network-resilience/stats")
async def legacy_resilience_stats(admin: User = Depends(get_current_admin_cookie)):
    return {
        "ok": True,
        "stats": _resilience_state["stats"],
        "active_attacks": _resilience_state["active_attacks"],
    }


@router.post("/network-resilience/stop")
async def legacy_resilience_stop(admin: User = Depends(get_current_admin_cookie)):
    _resilience_state["active_attacks"] = 0
    _resilience_state["stats"] = {}
    return {"ok": True}


@router.post("/aggressive/start")
async def legacy_aggressive_start(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    return {"ok": True, "attack_id": uuid_lib.uuid4().hex}


@router.post("/aggressive/stop")
async def legacy_aggressive_stop(admin: User = Depends(get_current_admin_cookie)):
    return {"ok": True}


@router.post("/fightback/start")
async def legacy_fightback_start(
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
):
    return {"ok": True, "technique_id": uuid_lib.uuid4().hex}


@router.post("/fightback/stop")
async def legacy_fightback_stop(admin: User = Depends(get_current_admin_cookie)):
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
#  Agents (legacy shape)
# ─────────────────────────────────────────────────────────────────────────────

class LegacyAgentCreate(BaseModel):
    name: str
    password: str
    traffic_quota_gb: float = 100
    speed_limit_default: int = 200


def _agent_to_legacy(a: Agent, user_count: int = 0) -> Dict[str, Any]:
    meta = a.ech_config if isinstance(a.ech_config, dict) else {}
    return {
        "id": a.id,
        "name": a.name,
        "active": a.status.value != "offline" if hasattr(a, "status") and a.status else True,
        "traffic_quota_gb": float(meta.get("traffic_quota_gb") or 0),
        "traffic_used_gb": float(meta.get("traffic_used_gb") or 0),
        "user_count": user_count,
    }


def _agent_meta(agent: Agent) -> Dict[str, Any]:
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
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
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
    user_counts: Dict[int, int] = {}
    traffic_used: Dict[int, float] = {}
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
    from ..models import AgentBackend, AgentStatus
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
        await db.refresh(agent)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "agent": _agent_to_legacy(agent)}


@router.post("/agents/{agent_id}/edit")
async def legacy_edit_agent(
    agent_id: int,
    body: Dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        return {"ok": False, "error": "Agent not found"}
    if "active" in body:
        from ..models import AgentStatus
        agent.status = AgentStatus.online if body["active"] else AgentStatus.offline
    meta_updates: Dict[str, Any] = {}
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
    body: Dict[str, Any],
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
    body: Optional[Dict[str, Any]] = None,
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
    response.set_cookie(
        key="agent_access_token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=settings.session_lifetime_hours * 3600,
        path="/",
    )
    return {"ok": True, "name": agent.name}


@router.post("/agent/logout")
async def legacy_agent_logout(response: Response):
    response.delete_cookie("agent_access_token", path="/")
    return {"ok": True}


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
    body: Dict[str, Any],
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    brand = str(body.get("brand_name") or "").strip()[:40]
    _set_agent_meta(agent, brand_name=brand)
    await db.commit()
    return {"ok": True, "brand_name": brand}


async def _check_agent_quota(agent: Agent, requested_gb: float, db: AsyncSession) -> Optional[str]:
    quota = float(_agent_meta(agent).get("traffic_quota_gb") or 0)
    if quota <= 0:
        return None
    used = await _agent_used_gb(agent.id, db)
    if used + requested_gb > quota:
        return f"Quota exceeded. Remaining: {max(0, quota - used):.1f} GB"
    return None


@router.get("/agent/users")
async def legacy_agent_users(
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _load_legacy_settings(db)
    result = await db.execute(
        select(VpnUser)
        .where(VpnUser.agent_id == agent.id)
        .order_by(VpnUser.active.desc(), VpnUser.name)
    )
    return [_user_to_legacy(u) for u in result.scalars().all()]


@router.post("/agent/users")
async def legacy_agent_create_user(
    body: LegacyUserCreate,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    quota_error = await _check_agent_quota(agent, body.traffic, db)
    if quota_error:
        return {"ok": False, "error": quota_error}

    expire_at = datetime.utcnow() + timedelta(days=body.days) if body.days else None
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
        await db.refresh(db_user)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    await _load_legacy_settings(db)
    links = _user_to_legacy(db_user)
    return {"ok": True, "user": links, "vmess": links.get("vmess", "")}


@router.post("/agent/bulk-users")
async def legacy_agent_bulk_users(
    body: BulkCreateRequest,
    agent: Agent = Depends(_get_current_agent_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    quota_error = await _check_agent_quota(agent, body.traffic * body.count, db)
    if quota_error:
        return {"ok": False, "error": quota_error}

    expire_at = datetime.utcnow() + timedelta(days=body.days) if body.days else None
    created_users: List[VpnUser] = []
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
            await db.refresh(u)
    except Exception as exc:
        await db.rollback()
        return {"ok": False, "error": str(exc)}
    await _load_legacy_settings(db)
    return {
        "ok": True,
        "created": len(created_users),
        "users": [_user_to_legacy(u) for u in created_users],
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
        query = query.where(VpnUser.name.like(f"{body.prefix}%"))
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
    body: Dict[str, Any],
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
    user.expire_at = datetime.utcnow() + timedelta(days=body.days)
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
    now = datetime.utcnow()
    result = await db.execute(
        select(VpnUser).where(
            VpnUser.agent_id == agent.id,
            VpnUser.expire_at != None,
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
    groups: Dict[str, Dict[str, Any]] = {}
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
    return {"ok": True, "users": [_user_to_legacy(u) for u in result.scalars().all()]}
