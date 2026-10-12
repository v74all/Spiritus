"""Decoy endpoints. No legitimate client ever requests these paths, so any hit
is scanner/intruder activity: it is audited and counted toward a fail2ban ban."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import record_audit
from ..database import get_async_db
from ..security import fail2ban_manager

router = APIRouter(include_in_schema=False)

HONEYPOT_PATHS = (
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/phpmyadmin/",
    "/api/admin/backup.sql",
    "/api/v1/admin/export",
)


async def _trip(request: Request, db: AsyncSession = Depends(get_async_db)):
    ip = request.client.host if request.client else "unknown"
    await record_audit(db, "honeypot_hit", details={"path": request.url.path[:200]}, request=request)
    await fail2ban_manager.record_failed_attempt(ip, "panel", db, "Honeypot hit")
    return JSONResponse({"detail": "Not Found"}, status_code=404)


for _path in HONEYPOT_PATHS:
    router.add_api_route(_path, _trip, methods=["GET", "POST", "HEAD"])
