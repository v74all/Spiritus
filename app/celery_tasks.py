"""
Celery module for V7LTHRONYX VPN Panel.

Background tasks:
- Traffic monitoring
- User expiration checks
- Auto-backup
- Xray config reload
- Anomaly detection
- Ops automation (alerts, edge-node checks, automatic Emergency Cloak)
"""

import logging
from datetime import UTC

from celery import Celery

from .config import settings
from .privileged_helper import PrivilegedHelperError, helper_request_sync

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
        "ops-monitor": {
            "task": "app.celery_tasks.ops_monitor",
            "schedule": 60.0,  # Every minute
            "options": {"expires": 55},  # drop a run that waited past the next one
        },
    },
)

@celery_app.task(name="app.celery_tasks.monitor_traffic")
def monitor_traffic():
    """Count per-user traffic from the local Xray and apply quota / expiry.

    Same cycle the panel runs in-process (app/user_runtime.py). Stats are
    read with reset, so the two runners split the bytes, never double them.
    """
    import asyncio

    from .user_runtime import run_cycle

    try:
        result = asyncio.run(run_cycle())
        logger.info(f"Traffic sync complete: {result}")
        return {"status": "ok", **result}
    except Exception as e:
        logger.error(f"Traffic monitoring failed: {e}")
        return {"status": "error", "message": str(e)}

@celery_app.task(name="app.celery_tasks.check_expirations")
def check_expirations():
    """Expire users past their date and stop serving them (see monitor_traffic)."""
    import asyncio

    from .user_runtime import run_cycle

    try:
        result = asyncio.run(run_cycle())
        if result["status_changes"]:
            logger.info(f"User status changes: {result['status_changes']}")
        return {"status": "ok", "expired_count": result["status_changes"], **result}
    except Exception as e:
        logger.error(f"Expiration check failed: {e}")
        return {"status": "error", "message": str(e)}

@celery_app.task(name="app.celery_tasks.auto_backup")
def auto_backup():
    """Create automatic backup of database and configuration.

    Uses pg_dump for PostgreSQL backup with rotation
    (keeps last N days based on settings).
    """
    import glob as globmod
    import os
    import subprocess
    from datetime import datetime

    backup_dir = os.path.join(os.getcwd(), "backups")
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    db_backup = os.path.join(backup_dir, f"vpnpanel_{timestamp}.sql.gz")

    try:
        # pg_dump piped to gzip. Pass DSN via env (PG* vars or
        # pg_dump's recognised PGSERVICE/PGDATABASE/...) — better still,
        # parse it once and feed the connection string via stdin-safe args.
        # Using a shell pipeline here, but the DSN is passed via env to avoid
        # leaking credentials in `ps` output.
        import gzip as _gzip
        env = os.environ.copy()
        env["PG_DUMP_DSN"] = settings.database_url.replace("+asyncpg", "")
        with _gzip.open(db_backup, "wb") as gz:
            proc = subprocess.run(
                ["pg_dump", "--dbname", env["PG_DUMP_DSN"]],
                stdout=gz, stderr=subprocess.PIPE, timeout=300,
            )
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            logger.error(f"Backup failed: {err}")
            try:
                os.remove(db_backup)
            except OSError:
                pass
            return {"status": "error", "message": err[:200]}
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        return {"status": "error", "message": str(e)[:200]}

    # Backup Xray config
    config_backup = os.path.join(backup_dir, f"xray_config_{timestamp}.json")
    try:
        import shutil
        if os.path.exists(settings.xray_config_path):
            shutil.copy2(settings.xray_config_path, config_backup)
    except Exception as e:
        logger.warning(f"Config backup failed: {e}")

    # Rotation: keep last 7 days
    retention_days = 7
    cutoff = datetime.now(UTC).timestamp() - (retention_days * 86400)
    removed = 0
    for f in globmod.glob(os.path.join(backup_dir, "vpnpanel_*.sql.gz")):
        if os.path.getmtime(f) < cutoff:
            os.remove(f)
            removed += 1
    for f in globmod.glob(os.path.join(backup_dir, "xray_config_*.json")):
        if os.path.getmtime(f) < cutoff:
            os.remove(f)
            removed += 1

    logger.info(f"Backup complete: {db_backup} (rotated {removed} old backups)")
    return {"status": "ok", "backup_file": db_backup, "rotated": removed}

@celery_app.task(name="app.celery_tasks.run_anomaly_detection")
def run_anomaly_detection():
    """Run anomaly detection on traffic patterns.

    Checks for unusual traffic spikes, port scans, and
    brute force attempts using the abuse_prevention module.
    """
    from .abuse_prevention import anomaly_detector, port_scan_detector

    # Check for traffic anomalies
    anomaly_count = len(anomaly_detector.alerts)
    scan_count = len(port_scan_detector._scan_alerts)

    if anomaly_count > 0:
        logger.warning(f"Anomaly detection: {anomaly_count} alerts active")
    if scan_count > 0:
        logger.warning(f"Port scan detection: {scan_count} alerts active")

    return {
        "status": "ok",
        "anomaly_alerts": anomaly_count,
        "port_scan_alerts": scan_count,
    }

@celery_app.task(name="app.celery_tasks.reload_xray_config")
def reload_xray_config():
    """Reload Xray configuration."""
    logger.info("Reloading Xray config...")
    try:
        result = helper_request_sync("service.reload", {"service": "xray"}, timeout=35)
        if not result.ok:
            return {"status": "error", "message": result.message}
        return {"status": "ok"}
    except PrivilegedHelperError as e:
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
        from datetime import datetime
        expires = datetime.fromisoformat(key["expires_at"])
        days_left = (expires - datetime.now(UTC)).days
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


@celery_app.task(name="app.celery_tasks.ops_monitor")
def ops_monitor():
    """Ops automation tick: edge-node checks, Telegram alerts, auto Emergency Cloak.

    See app/ops_automation.py. Uses its own NullPool engine: each task runs
    in a fresh event loop (asyncio.run), and pooled asyncpg connections
    cannot be reused across loops.
    """
    import asyncio

    async def _run():
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
        from sqlalchemy.pool import NullPool

        from .database import async_engine
        from .ops_automation import run_monitor

        engine = create_async_engine(async_engine.url, poolclass=NullPool)
        try:
            async with async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)() as db:
                return await run_monitor(db)
        finally:
            await engine.dispose()

    try:
        result = asyncio.run(_run())
        if result.get("events"):
            logger.info("Ops monitor: %s", result)
        return {"status": "ok", **result}
    except Exception as e:
        logger.error(f"Ops monitor failed: {e}")
        return {"status": "error", "message": str(e)}
