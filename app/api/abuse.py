"""
Abuse Prevention API router for V7LTHRONYX VPN Panel.

Endpoints:
- GET  /abuse/status - Get abuse prevention status
- POST /abuse/egress-filtering/apply - Apply egress filtering
- POST /abuse/egress-filtering/remove - Remove egress filtering
- GET  /abuse/anomalies - Get anomaly alerts
- GET  /abuse/port-scans - Get port scan alerts
"""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import List, Optional
import logging

from ..auth import get_current_admin, User
from ..abuse_prevention import (
    apply_egress_filtering, remove_egress_filtering,
    generate_egress_iptables_rules, BLOCKED_PORTS,
    anomaly_detector, port_scan_detector, AnomalyAlert
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/abuse", tags=["abuse-prevention"])

class MessageResponse(BaseModel):
    message: str
    success: bool = True

@router.get("/status")
async def get_abuse_status(admin: User = Depends(get_current_admin)):
    """Get abuse prevention status."""
    return {
        "egress_filtering": {
            "blocked_ports": {str(k): v for k, v in BLOCKED_PORTS.items()},
            "rules": generate_egress_iptables_rules()
        },
        "anomaly_detection": {
            "baselines_tracked": len(anomaly_detector.baselines),
            "total_alerts": len(anomaly_detector.alerts)
        },
        "port_scan_detection": {
            "total_alerts": len(port_scan_detector._scan_alerts)
        }
    }

@router.post("/egress-filtering/apply")
async def apply_egress(admin: User = Depends(get_current_admin)):
    """Apply egress filtering to block dangerous ports."""
    results = apply_egress_filtering()
    return {"results": results, "success": True}

@router.post("/egress-filtering/remove")
async def remove_egress(admin: User = Depends(get_current_admin)):
    """Remove egress filtering rules."""
    results = remove_egress_filtering()
    return {"results": results, "success": True}

@router.get("/anomalies")
async def get_anomalies(
    since: float = Query(0, description="Get alerts since Unix timestamp"),
    admin: User = Depends(get_current_admin)
):
    """Get anomaly alerts."""
    alerts = anomaly_detector.get_alerts(since=since)
    return {"alerts": [
        {
            "user_id": a.user_id,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "details": a.details,
            "timestamp": a.timestamp
        }
        for a in alerts
    ]}

@router.get("/port-scans")
async def get_port_scans(
    since: float = Query(0, description="Get alerts since Unix timestamp"),
    admin: User = Depends(get_current_admin)
):
    """Get port scan alerts."""
    alerts = port_scan_detector.get_scan_alerts(since=since)
    return {"alerts": alerts}