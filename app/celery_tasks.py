"""
Celery module for V7LTHRONYX VPN Panel.

Background tasks:
- Traffic monitoring
- User expiration checks
- Auto-backup
- Xray config reload
- Anomaly detection
"""

from celery import Celery
from .config import settings
import logging

logger = logging.getLogger(__name__)

# Initialize Celery
celery_app = Celery(
    "v7lthronyx",
    broker=str(settings.redis_url),
    backend=str(settings.redis_url),
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "monitor-traffic": {
            "task": "app.celery_tasks.monitor_traffic",
            "schedule": 30.0,  # Every 30 seconds
        },
        "check-expirations": {
            "task": "app.celery_tasks.check_expirations",
            "schedule": 300.0,  # Every 5 minutes
        },
        "auto-backup": {
            "task": "app.celery_tasks.auto_backup",
            "schedule": 86400.0,  # Every 24 hours
        },
        "anomaly-detection": {
            "task": "app.celery_tasks.run_anomaly_detection",
            "schedule": 60.0,  # Every minute
        },
        # DPI Evasion tasks
        "dpi-flow-rate-check": {
            "task": "app.celery_tasks.dpi_flow_rate_check",
            "schedule": 30.0,  # Every 30 seconds
        },
        "dpi-sni-validation": {
            "task": "app.celery_tasks.dpi_sni_validation",
            "schedule": 21600.0,  # Every 6 hours
        },
        "dpi-ip-reputation": {
            "task": "app.celery_tasks.dpi_ip_reputation_check",
            "schedule": 21600.0,  # Every 6 hours
        },
        "dpi-reality-key-check": {
            "task": "app.celery_tasks.dpi_reality_key_rotation_check",
            "schedule": 86400.0,  # Every 24 hours
        },
    },
)

@celery_app.task(name="app.celery_tasks.monitor_traffic")
def monitor_traffic():
    """Monitor user traffic from Xray API."""
    logger.info("Monitoring traffic...")
    # TODO: Query Xray API and update user traffic in DB
    return {"status": "ok"}

@celery_app.task(name="app.celery_tasks.check_expirations")
def check_expirations():
    """Check for expired users and deactivate them."""
    logger.info("Checking user expirations...")
    # TODO: Query DB for expired users and deactivate
    return {"status": "ok"}

@celery_app.task(name="app.celery_tasks.auto_backup")
def auto_backup():
    """Create automatic backup."""
    logger.info("Running auto-backup...")
    # TODO: Create backup of DB and config
    return {"status": "ok"}

@celery_app.task(name="app.celery_tasks.run_anomaly_detection")
def run_anomaly_detection():
    """Run anomaly detection on traffic patterns."""
    logger.info("Running anomaly detection...")
    # TODO: Analyze traffic patterns for anomalies
    return {"status": "ok"}

@celery_app.task(name="app.celery_tasks.reload_xray_config")
def reload_xray_config():
    """Reload Xray configuration."""
    logger.info("Reloading Xray config...")
    import subprocess
    try:
        subprocess.run(
            ["systemctl", "reload", "xray"],
            capture_output=True, text=True, timeout=30
        )
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Failed to reload Xray: {e}")
        return {"status": "error", "message": str(e)}


# ═══ DPI Evasion Background Tasks ═══

@celery_app.task(name="app.celery_tasks.dpi_sni_validation")
def dpi_sni_validation():
    """Periodically validate SNIs in the pool for TLS 1.3 + H2 support.

    Runs every 6 hours to ensure SNI pool is up-to-date.
    """
    import asyncio
    logger.info("Running DPI SNI validation...")

    async def _validate():
        from .dpi_evasion import sni_manager
        pool = await sni_manager.get_sni_pool_status()
        validated = 0
        blocked = 0
        for entry in pool:
            if not entry.get("blocked"):
                result = await sni_manager.validate_sni(entry["domain"])
                if result.get("tls13") and result.get("reachable"):
                    validated += 1
                else:
                    await sni_manager.mark_sni_blocked(entry["domain"])
                    blocked += 1
        return {"validated": validated, "blocked": blocked}

    try:
        result = asyncio.run(_validate())
        logger.info(f"DPI SNI validation complete: {result}")
        return {"status": "ok", **result}
    except Exception as e:
        logger.error(f"DPI SNI validation failed: {e}")
        return {"status": "error", "message": str(e)}

@celery_app.task(name="app.celery_tasks.dpi_flow_rate_check")
def dpi_flow_rate_check():
    """Check per-user flow rates and enforce throttling.

    Runs every 30 seconds to detect long-flow patterns.
    """
    from .dpi_evasion import flow_rate_limiter
    rates = flow_rate_limiter.get_all_rates()
    throttled = [r for r in rates if r.get("throttled")]
    if throttled:
        logger.warning(f"Flow rate throttling active for {len(throttled)} users")
    return {
        "status": "ok",
        "monitored_users": len(rates),
        "throttled_users": len(throttled),
    }


@celery_app.task(name="app.celery_tasks.dpi_ip_reputation_check")
def dpi_ip_reputation_check():
    """Check server IP reputation against blacklists.

    Runs every 6 hours.
    """
    import asyncio

    async def _check():
        from .dpi_evasion import ip_reputation_monitor
        return await ip_reputation_monitor.check_ip_reputation()

    try:
        result = asyncio.run(_check())
        is_clean = result.get("is_clean", True)
        if not is_clean:
            logger.warning("Server IP reputation degraded!")
        return {"status": "ok", "is_clean": is_clean}
    except Exception as e:
        logger.error(f"IP reputation check failed: {e}")
        return {"status": "error", "message": str(e)}


@celery_app.task(name="app.celery_tasks.dpi_reality_key_rotation_check")
def dpi_reality_key_rotation_check():
    """Check if REALITY keys need rotation.

    Runs daily to check key expiration.
    """
    from .dpi_evasion import reality_key_manager
    active = reality_key_manager.get_active_keys()
    expiring = []
    for key in active:
        from datetime import datetime, timezone
        expires = datetime.fromisoformat(key["expires_at"])
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left <= 7:
            expiring.append({
                "key_id": key["key_id"],
                "agent_id": key["agent_id"],
                "days_left": days_left,
            })

    if expiring:
        logger.warning(f"REALITY keys expiring soon: {len(expiring)}")

    return {
        "status": "ok",
        "active_keys": len(active),
        "expiring_soon": len(expiring),
        "expiring_keys": expiring,
    }