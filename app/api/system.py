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

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import psutil
import subprocess
import os
import logging

from ..auth import get_current_admin, User
from ..config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/system", tags=["system"])

class SystemStatus(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    uptime_seconds: float
    xray_running: bool
    xray_version: Optional[str]
    active_users: int
    total_users: int

class XrayStatus(BaseModel):
    running: bool
    version: Optional[str]
    config_valid: bool
    uptime: Optional[float]

class MessageResponse(BaseModel):
    message: str
    success: bool = True

@router.get("/status", response_model=SystemStatus)
async def get_system_status(admin: User = Depends(get_current_admin)):
    """Get system status information."""
    # CPU & Memory
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Xray status
    xray_running = False
    xray_version = None
    try:
        result = subprocess.run(
            [settings.xray_bin_path, "version"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            xray_running = True
            xray_version = result.stdout.strip().split('\n')[0]
    except Exception:
        pass
    
    # Uptime
    boot_time = psutil.boot_time()
    import time
    uptime = time.time() - boot_time
    
    return SystemStatus(
        cpu_percent=cpu,
        memory_percent=mem.percent,
        disk_percent=disk.percent,
        uptime_seconds=uptime,
        xray_running=xray_running,
        xray_version=xray_version,
        active_users=0,  # TODO: Query from DB
        total_users=0    # TODO: Query from DB
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
            [settings.xray_bin_path, "test", "-config", settings.xray_config_path],
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
        subprocess.run(
            ["systemctl", "restart", "xray"],
            capture_output=True, text=True, timeout=30
        )
        return MessageResponse(message="Xray restarted successfully")
    except Exception as e:
        logger.error(f"Error restarting Xray: {e}")
        return MessageResponse(message=f"Failed to restart Xray: {e}", success=False)

@router.get("/logs")
async def get_logs(
    lines: int = Query(100, ge=1, le=1000),
    log_type: str = Query("panel", description="panel|xray|access"),
    admin: User = Depends(get_current_admin)
):
    """Get system logs."""
    log_files = {
        "panel": "vpn-panel.log",
        "xray": "/var/log/xray/error.log",
        "access": "access.log"
    }
    
    log_file = log_files.get(log_type, "vpn-panel.log")
    
    try:
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                all_lines = f.readlines()
                return {"logs": all_lines[-lines:]}
        return {"logs": []}
    except Exception as e:
        return {"logs": [], "error": str(e)}

@router.get("/metrics")
async def get_metrics():
    """Prometheus-compatible metrics endpoint."""
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

    return {"metrics": system_metrics + custom_metrics}