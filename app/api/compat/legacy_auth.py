from __future__ import annotations

from fastapi import APIRouter

from ...auth import dummy_password_hash
from ._core import *  # noqa: F403

router = APIRouter(tags=["compat"])


# ─────────────────────────────────────────────────────────────────────────────
#  Auth (legacy)
# ─────────────────────────────────────────────────────────────────────────────

class LegacyLoginRequest(BaseModel):
    password: str
    username: str | None = "admin"
    totp_code: str | None = None


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

    if await _is_locked_out(client_ip):
        return {
            "ok": False,
            "error": f"Too many attempts. Try again in {settings.lockout_seconds}s",
            "locked": True,
        }

    username = request.username or "admin"
    admin_id: int | None = None
    authenticated = False

    db_result = await db.execute(select(Admin).where(Admin.username == username))
    admin_user = db_result.scalar_one_or_none()
    password_hash = admin_user.password_hash if admin_user is not None else dummy_password_hash()
    if admin_user and verify_password(request.password, password_hash):
        authenticated = True
        admin_id = admin_user.id

    # NOTE: the legacy plaintext password-file fallback has been intentionally
    # removed. First-run installs are bootstrapped via the ADMIN_BOOTSTRAP_*
    # env vars (see app/api/auth.py:bootstrap_initial_admin).

    if not authenticated:
        await _record_failed_attempt(client_ip)
        await fail2ban_manager.record_failed_attempt(
            client_ip, "panel", db, "Failed panel login"
        )
        await record_audit(db, "login_failed", details={"username": username[:100]}, request=req)
        # Constant message — no user enumeration.
        return {"ok": False, "error": "Invalid credentials"}

    # ── Second factor ────────────────────────────────────────────────────
    # If this admin has TOTP enabled, the password alone MUST NOT mint a
    # session. Previously this legacy endpoint skipped 2FA entirely, so a
    # stolen/guessed password bypassed the second factor completely.
    if admin_user.totp_enabled and admin_user.totp_secret:
        from ...auth import verify_totp
        from ..auth import _check_2fa_lockout, _clear_2fa_attempts, _record_failed_2fa

        code = (request.totp_code or "").strip()
        if not code:
            # First phase: password OK, ask the client for the 6-digit code.
            # No token issued, failed-attempt counter untouched (password was
            # valid) — but keep the 2FA brute-force lockout separate.
            return {"ok": False, "totp_required": True}

        await _check_2fa_lockout(client_ip, username)
        if not verify_totp(admin_user.totp_secret, code):
            await _record_failed_2fa(client_ip, username)
            logger.warning("legacy_login.2fa_failure ip=%s user=%s", client_ip, username)
            await record_audit(db, "login_2fa_failed", admin_id=admin_id, request=req)
            return {"ok": False, "error": "Invalid 2FA code"}
        await _clear_2fa_attempts(client_ip, username)

    await _clear_attempts(client_ip)

    token_payload: dict[str, Any] = {"sub": username, "is_admin": True}
    if admin_id is not None:
        token_payload["user_id"] = admin_id

    access_token = create_access_token(data=token_payload)
    # Cookie hardening: HttpOnly + SameSite=strict, plus Secure when the
    # request actually arrived over HTTPS. Hard-coding Secure=True bricks the
    # panel when it's reached over plain HTTP — the browser silently drops
    # the cookie, the very next /api/me request looks unauthenticated, and
    # the UI bounces back to the login screen.
    from ...middleware.csrf import is_secure_request
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=is_secure_request(req),
        samesite="strict",
        max_age=settings.session_lifetime_hours * 3600,
        path="/",
    )
    await record_audit(
        db, "login", admin_id=admin_id,
        details={"2fa": bool(admin_user.totp_enabled and admin_user.totp_secret), "legacy": True},
        request=req,
    )
    return {"ok": True, "access_token": access_token}


@router.post("/logout")
async def legacy_logout(req: Request, response: Response):
    # Deleting the cookie alone leaves a stolen copy valid until expiry.
    await revoke_request_token(req)
    response.delete_cookie("access_token", path="/")
    return {"ok": True}


class ChangePasswordRequest(BaseModel):
    current: str
    new: str


@router.post("/change-password")
async def legacy_change_password(
    body: ChangePasswordRequest,
    req: Request,
    response: Response,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    from ...auth import invalidate_sessions, validate_password_strength

    err = validate_password_strength(body.new)
    if err:
        return {"ok": False, "error": err}

    if not admin.username:
        return {"ok": False, "error": "Session invalid"}

    result = await db.execute(select(Admin).where(Admin.username == admin.username))
    db_admin = result.scalar_one_or_none()
    if db_admin is None:
        return {"ok": False, "error": "User not found"}

    if not verify_password(body.current, db_admin.password_hash):
        return {"ok": False, "error": "Current password is incorrect"}

    db_admin.password_hash = get_password_hash(body.new)
    await db.commit()
    logger.info("password.change user=%s", admin.username)
    await record_audit(db, "password_change", admin_id=db_admin.id, request=req)

    # Kill every token issued before this instant — a stolen/leaked token
    # must not keep working just because the operator "changed the
    # password". Then mint a fresh one so the current session survives
    # (its iat is now, so it isn't caught by its own invalidation).
    await invalidate_sessions(admin.username)
    access_token = create_access_token(data={"sub": admin.username, "is_admin": True})
    from ...middleware.csrf import is_secure_request
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=is_secure_request(req),
        samesite="strict",
        max_age=settings.session_lifetime_hours * 3600,
        path="/",
    )
    return {"ok": True}


__all__ = [_n for _n in list(globals()) if not _n.startswith("__")]
