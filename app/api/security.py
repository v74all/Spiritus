"""
Security API router for V7LTHRONYX VPN Panel.

Endpoints:
- WebAuthn registration/authentication
- mTLS certificate management
- Fail2ban management
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from typing import Optional, List
import logging

from ..auth import get_current_admin, get_current_user, User
from ..database import get_async_db
from ..security import webauthn_manager, mtls_manager, fail2ban_manager
from ..models import Admin

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

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

class WebAuthnAuthStart(BaseModel):
    username: str

class WebAuthnAuthFinish(BaseModel):
    username: str
    credential_id: str
    client_data_json: str
    authenticator_data: str
    signature: str

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
    # Get existing credentials
    result = await db.execute(select(Admin).where(Admin.username == username))
    admin_user = result.scalar_one_or_none()
    existing_creds = admin_user.webauthn_credentials if admin_user else []

    options = webauthn_manager.generate_registration_options(
        username=username,
        existing_credentials=existing_creds,
    )
    return options


@router.post("/webauthn/register")
async def complete_webauthn_registration(
    data: WebAuthnRegistrationFinish,
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Complete WebAuthn registration."""
    result = webauthn_manager.verify_registration(
        username=data.username,
        client_data_json=data.client_data_json,
        attestation_object=data.attestation_object,
        credential_id=data.credential_id,
    )

    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("error", "Registration failed")
        )

    # Save credential to admin
    db_result = await db.execute(select(Admin).where(Admin.username == data.username))
    admin_user = db_result.scalar_one_or_none()

    if admin_user:
        creds = admin_user.webauthn_credentials or []
        creds.append(result["credential"])
        admin_user.webauthn_credentials = creds
        await db.commit()

    return {"success": True, "credential_id": result.get("credential_id")}


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

    options = webauthn_manager.generate_authentication_options(
        username=data.username,
        credentials=admin_user.webauthn_credentials,
    )
    return options


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
    results = fail2ban_manager.install_all()
    return {"results": results}


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
    success = await fail2ban_manager.unban(data.ip_address, data.service, db)
    if not success:
        raise HTTPException(status_code=404, detail="Ban not found")
    return MessageResponse(message=f"IP {data.ip_address} unbanned")