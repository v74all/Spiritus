"""
System API router for V7LTHRONYX VPN Panel.

Endpoints:
- GET  /system/status - System status
- GET  /system/stats - Traffic stats
- GET  /system/xray-status - Xray status
- POST /system/restart-xray - Restart Xray
- GET  /system/logs - System logs
- GET  /system/metrics - Prometheus metrics
"""

import hmac
import logging
import os
import subprocess

import psutil
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import User, get_current_admin
from ..config import settings
from ..database import get_async_db
from ..models import VpnUser
from ..privileged_helper import PrivilegedHelperError, helper_request

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/system", tags=["system"])

class SystemStatus(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    uptime_seconds: float
    xray_running: bool
    xray_version: str | None
    active_users: int
    total_users: int

class XrayStatus(BaseModel):
    running: bool
    version: str | None
    config_valid: bool
    uptime: float | None

class MessageResponse(BaseModel):
    message: str
    success: bool = True

@router.get("/status", response_model=SystemStatus)
async def get_system_status(
    admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_async_db),
):
    """Get system status information."""
    # CPU & Memory
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    # Xray status. `xray version` only proves the binary exists; the
    # dashboard used to report the service as up when nothing was listening.
    xray_running = False
    xray_version = None
    try:
        for proc in psutil.process_iter(["name"]):
            if "xray" in (proc.info.get("name") or "").lower():
                xray_running = True
                break
        result = subprocess.run(
            [settings.xray_bin_path, "version"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            xray_version = result.stdout.strip().split('\n')[0]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("xray version probe failed: %s", exc)

    # Uptime
    boot_time = psutil.boot_time()
    import time
    uptime = time.time() - boot_time

    # User counts from DB
    total_res = await db.execute(select(func.count(VpnUser.id)))
    total_users = total_res.scalar() or 0
    active_res = await db.execute(
        select(func.count(VpnUser.id)).where(VpnUser.active == 1)
    )
    active_users = active_res.scalar() or 0

    return SystemStatus(
        cpu_percent=cpu,
        memory_percent=mem.percent,
        disk_percent=disk.percent,
        uptime_seconds=uptime,
        xray_running=xray_running,
        xray_version=xray_version,
        active_users=active_users,
        total_users=total_users,
    )

@router.get("/xray-status", response_model=XrayStatus)
async def get_xray_status(admin: User = Depends(get_current_admin)):
    """Get Xray service status."""
    running = False
    version = None
    config_valid = False
    uptime = None

    try:
        # Check if xray process is running
        for proc in psutil.process_iter(['name', 'cmdline', 'create_time']):
            if 'xray' in proc.info.get('name', '').lower():
                running = True
                import time
                uptime = time.time() - proc.info.get('create_time', time.time())
                break

        # Get version
        result = subprocess.run(
            [settings.xray_bin_path, "version"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            version = result.stdout.strip().split('\n')[0]

        # Validate config
        result = subprocess.run(
            [settings.xray_bin_path, "-test", "-config", settings.xray_config_path],
            capture_output=True, text=True, timeout=10
        )
        config_valid = result.returncode == 0
    except Exception as e:
        logger.error(f"Error checking Xray status: {e}")

    return XrayStatus(
        running=running,
        version=version,
        config_valid=config_valid,
        uptime=uptime
    )

@router.post("/restart-xray", response_model=MessageResponse)
async def restart_xray(admin: User = Depends(get_current_admin)):
    """Restart Xray service."""
    try:
        result = await helper_request("service.restart", {"service": "xray"}, timeout=35)
        if result.ok:
            return MessageResponse(message="Xray restarted successfully")
        return MessageResponse(message="Xray restart failed", success=False)
    except PrivilegedHelperError:
        logger.error("privileged helper unavailable during Xray restart")
        return MessageResponse(message="Privileged helper unavailable", success=False)

@router.get("/logs")
async def get_logs(
    lines: int = Query(100, ge=1, le=1000),
    log_type: str = Query("panel", description="panel|xray|access"),
    admin: User = Depends(get_current_admin)
):
    """Get system logs. Path is whitelisted — no user-controlled file paths."""
    # Use absolute paths so a manipulated CWD can't redirect reads to a
    # different file. The dict acts as a strict allowlist.
    log_files = {
        "panel": os.path.abspath("vpn-panel.log"),
        "xray": "/var/log/xray/error.log",
        "access": os.path.abspath("access.log"),
    }
    if log_type not in log_files:
        raise HTTPException(status_code=404, detail="Unknown log type")

    log_file = log_files[log_type]
    if not os.path.isfile(log_file):
        return {"logs": []}

    try:
        with open(log_file, errors="replace") as f:
            all_lines = f.readlines()
            return {"logs": all_lines[-lines:]}
    except Exception as e:
        logger.error("logs.read failure type=%s", type(e).__name__)
        return {"logs": [], "error": "Failed to read log"}

@router.get("/metrics")
async def get_metrics(request: Request):
    """Prometheus-compatible metrics endpoint."""
    configured = settings.metrics_bearer_token
    auth = request.headers.get("authorization", "")
    supplied = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not configured:
        raise HTTPException(status_code=404, detail="Metrics endpoint disabled")
    if not supplied or not hmac.compare_digest(supplied, configured):
        raise HTTPException(
            status_code=401,
            detail="Invalid metrics token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    import psutil
    cpu = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    # System metrics
    system_metrics = f"""# HELP vpn_panel_cpu_percent CPU usage percentage
# TYPE vpn_panel_cpu_percent gauge
vpn_panel_cpu_percent {cpu}
# HELP vpn_panel_memory_percent Memory usage percentage
# TYPE vpn_panel_memory_percent gauge
vpn_panel_memory_percent {mem.percent}
# HELP vpn_panel_disk_percent Disk usage percentage
# TYPE vpn_panel_disk_percent gauge
vpn_panel_disk_percent {disk.percent}
# HELP vpn_panel_memory_total_bytes Total memory
# TYPE vpn_panel_memory_total_bytes gauge
vpn_panel_memory_total_bytes {mem.total}
# HELP vpn_panel_memory_available_bytes Available memory
# TYPE vpn_panel_memory_available_bytes gauge
vpn_panel_memory_available_bytes {mem.available}
"""
    # Custom VPN metrics
    from ..observability import prometheus_metrics
    custom_metrics = prometheus_metrics.generate_metrics()

    return PlainTextResponse(
        system_metrics + custom_metrics,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
