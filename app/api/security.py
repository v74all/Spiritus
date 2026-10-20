"""
Security API router for V7LTHRONYX VPN Panel.

Endpoints:
- WebAuthn registration/authentication
- mTLS certificate management
- Fail2ban management
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import verify_chain
from ..auth import User, create_access_token, get_current_admin, get_current_admin_cookie
from ..config import settings
from ..database import get_async_db
from ..models import Admin, AuditLog
from ..privileged_helper import PrivilegedHelperError, helper_request
from ..security import fail2ban_manager, mtls_manager, webauthn_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/security", tags=["security"])


# ── Models ────────────────────────────────────────────────

class WebAuthnRegistrationStart(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)

class WebAuthnRegistrationFinish(BaseModel):
    username: str
    client_data_json: str
    attestation_object: str
    credential_id: str
    transports: list[str] = Field(default_factory=list)

class WebAuthnAuthStart(BaseModel):
    username: str

class WebAuthnAuthFinish(BaseModel):
    username: str
    credential_id: str
    client_data_json: str
    authenticator_data: str
    signature: str
    user_handle: str | None = None

class MTLSGenerateCert(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    days: int = Field(365, ge=1, le=3650)

class Fail2banUnban(BaseModel):
    ip_address: str
    service: str = "panel"

class MessageResponse(BaseModel):
    message: str
    success: bool = True


# ── WebAuthn Endpoints ────────────────────────────────────

@router.get("/webauthn/options/{username}")
async def get_webauthn_registration_options(
    username: str,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Get WebAuthn registration options for a user."""
    if admin.username != username:
        raise HTTPException(status_code=403, detail="Passkeys can only be registered for the current account")
    # Get existing credentials
    result = await db.execute(select(Admin).where(Admin.username == username))
    admin_user = result.scalar_one_or_none()
    existing_creds = admin_user.webauthn_credentials if admin_user else []

    try:
        return await webauthn_manager.generate_registration_options(
            username=username,
            existing_credentials=existing_creds,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/webauthn/register")
async def complete_webauthn_registration(
    data: WebAuthnRegistrationFinish,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Complete WebAuthn registration."""
    if admin.username != data.username:
        raise HTTPException(status_code=403, detail="Passkeys can only be registered for the current account")
    try:
        credential = await webauthn_manager.verify_registration(
            username=data.username,
            client_data_json=data.client_data_json,
            attestation_object=data.attestation_object,
            credential_id=data.credential_id,
            transports=data.transports,
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Save credential to admin
    db_result = await db.execute(select(Admin).where(Admin.username == data.username))
    admin_user = db_result.scalar_one_or_none()

    if admin_user:
        creds = admin_user.webauthn_credentials or []
        creds = [c for c in creds if c.get("id") != credential["id"]]
        creds.append(credential)
        admin_user.webauthn_credentials = creds
        await db.commit()

    return {"success": True, "credential_id": credential["id"]}


@router.post("/webauthn/authenticate")
async def webauthn_authenticate_start(
    data: WebAuthnAuthStart,
    db: AsyncSession = Depends(get_async_db),
):
    """Start WebAuthn authentication."""
    result = await db.execute(select(Admin).where(Admin.username == data.username))
    admin_user = result.scalar_one_or_none()

    if not admin_user or not admin_user.webauthn_credentials:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No passkeys registered for this user"
        )

    try:
        return await webauthn_manager.generate_authentication_options(
            username=data.username,
            credentials=admin_user.webauthn_credentials,
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/webauthn/authenticate/complete")
async def webauthn_authenticate_complete(
    data: WebAuthnAuthFinish,
    db: AsyncSession = Depends(get_async_db),
):
    """Verify the assertion and issue the same revocable JWT used by password login."""
    result = await db.execute(select(Admin).where(Admin.username == data.username))
    admin_user = result.scalar_one_or_none()
    if not admin_user:
        raise HTTPException(status_code=401, detail="Authentication failed")
    try:
        verified = await webauthn_manager.verify_authentication(
            username=data.username,
            credential_id=data.credential_id,
            client_data_json=data.client_data_json,
            authenticator_data=data.authenticator_data,
            signature=data.signature,
            user_handle=data.user_handle,
            stored_credentials=admin_user.webauthn_credentials or [],
        )
    except (RuntimeError, ValueError) as exc:
        logger.warning("webauthn authentication rejected for %s: %s", data.username, type(exc).__name__)
        raise HTTPException(status_code=401, detail="Authentication failed") from exc

    credentials = list(admin_user.webauthn_credentials or [])
    for credential in credentials:
        if credential.get("id") == verified["credential_id"]:
            credential["sign_count"] = verified["sign_count"]
    admin_user.webauthn_credentials = credentials
    role = getattr(admin_user, "role", None)
    role_value = str(getattr(role, "value", role) or "").lower()
    if role_value not in {"admin", "superadmin"}:
        await db.commit()
        raise HTTPException(status_code=403, detail="Admin privileges required")
    await db.commit()
    token = create_access_token(
        {
            "sub": admin_user.username,
            "user_id": admin_user.id,
            "is_admin": True,
            "role": role_value,
        }
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.session_lifetime_hours * 3600,
    }


# ── mTLS Endpoints ────────────────────────────────────────

@router.post("/mtls/init-ca")
async def init_mtls_ca(
    admin: User = Depends(get_current_admin),
):
    """Initialize the mTLS Certificate Authority."""
    result = mtls_manager.init_ca()
    return result


@router.post("/mtls/generate-cert")
async def generate_mtls_cert(
    data: MTLSGenerateCert,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Generate a client certificate for an admin user."""
    result = mtls_manager.generate_client_cert(username=data.username, days=data.days)

    if result.get("cn"):
        # Update admin's mTLS CN
        db_result = await db.execute(select(Admin).where(Admin.username == data.username))
        admin_user = db_result.scalar_one_or_none()
        if admin_user:
            admin_user.mtls_cn = result["cn"]
            await db.commit()

    return result


@router.get("/mtls/nginx-config")
async def get_mtls_nginx_config(
    admin: User = Depends(get_current_admin),
):
    """Get nginx mTLS configuration snippet."""
    config = mtls_manager.generate_nginx_config()
    return {"nginx_config": config}


# ── Fail2ban Endpoints ────────────────────────────────────

@router.post("/fail2ban/install")
async def install_fail2ban(
    admin: User = Depends(get_current_admin),
):
    """Install fail2ban filters and jails."""
    try:
        result = await helper_request("fail2ban.install", {})
    except PrivilegedHelperError as exc:
        raise HTTPException(status_code=503, detail="Privileged helper unavailable") from exc
    if not result.ok:
        raise HTTPException(status_code=500, detail="Fail2ban installation failed")
    return {"results": result.data or {"installed": True}}


@router.get("/fail2ban/bans")
async def get_fail2ban_bans(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Get all active fail2ban bans."""
    bans = await fail2ban_manager.get_all_bans(db)
    return {"bans": bans}


@router.post("/fail2ban/unban")
async def unban_ip(
    data: Fail2banUnban,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Remove a ban for an IP address."""
    jail = f"v7lthronyx-{data.service}" if data.service in {"panel", "xray"} else data.service
    try:
        result = await helper_request(
            "fail2ban.unban", {"jail": jail, "address": data.ip_address}
        )
    except PrivilegedHelperError as exc:
        raise HTTPException(status_code=503, detail="Privileged helper unavailable") from exc
    if not result.ok:
        return MessageResponse(message="Failed to unban IP", success=False)
    success = await fail2ban_manager.unban(data.ip_address, data.service, db)
    if not success:
        raise HTTPException(status_code=404, detail="Ban not found")
    return MessageResponse(message=f"IP {data.ip_address} unbanned")


# ── Audit log ─────────────────────────────────────────────

@router.get("/audit")
async def list_audit_log(
    limit: int = 100,
    offset: int = 0,
    action: str | None = None,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    from sqlalchemy import select

    query = select(AuditLog).order_by(AuditLog.id.desc())
    if action:
        query = query.where(AuditLog.action == action[:100])
    rows = (
        await db.execute(query.limit(max(1, min(limit, 500))).offset(max(0, offset)))
    ).scalars().all()
    return [
        {
            "id": r.id,
            "admin_id": r.admin_id,
            "action": r.action,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "details": r.details,
            "ip_address": r.ip_address,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "entry_hash": r.entry_hash,
        }
        for r in rows
    ]


@router.get("/audit/verify")
async def verify_audit_log(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Re-compute the audit hash chain; ``ok=false`` means the log was tampered with."""
    return await verify_chain(db)
