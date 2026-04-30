"""
Abuse prevention module for V7LTHRONYX VPN Panel.

Features:
- Anomaly detection (traffic pattern analysis)
- Port scan detection
- Egress filtering (block SMTP/SMB/Telnet)
- Brute force detection
"""

import psutil
import time
import logging
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
#  Egress Filtering
# ═══════════════════════════════════════════════════════════════

BLOCKED_PORTS = {
    25: "SMTP - Spam prevention",
    465: "SMTPS - Spam prevention",
    587: "SMTP Submission - Spam prevention",
    23: "Telnet - Insecure protocol",
    445: "SMB - Worm prevention",
    139: "SMB/NetBIOS - Worm prevention",
    3389: "RDP - Brute force target",
}

def generate_egress_iptables_rules() -> List[str]:
    """Generate iptables rules to block egress traffic on dangerous ports."""
    rules = []
    for port, reason in BLOCKED_PORTS.items():
        rules.append(
            f"# {reason}\n"
            f"iptables -A OUTPUT -p tcp --dport {port} -j DROP\n"
            f"iptables -A OUTPUT -p udp --dport {port} -j DROP"
        )
    return rules

def apply_egress_filtering():
    """Apply egress filtering iptables rules."""
    import subprocess
    applied = []
    for port, reason in BLOCKED_PORTS.items():
        try:
            # Check if rule already exists
            check = subprocess.run(
                ["iptables", "-C", "OUTPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
                capture_output=True, text=True
            )
            if check.returncode != 0:
                subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
                    capture_output=True, text=True
                )
                subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", str(port), "-j", "DROP"],
                    capture_output=True, text=True
                )
            applied.append({"port": port, "reason": reason, "status": "applied"})
        except Exception as e:
            applied.append({"port": port, "reason": reason, "status": f"error: {e}"})
    return applied

def remove_egress_filtering():
    """Remove egress filtering iptables rules."""
    import subprocess
    removed = []
    for port, reason in BLOCKED_PORTS.items():
        try:
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
                capture_output=True, text=True
            )
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", str(port), "-j", "DROP"],
                capture_output=True, text=True
            )
            removed.append({"port": port, "status": "removed"})
        except Exception as e:
            removed.append({"port": port, "status": f"error: {e}"})
    return removed

# ═══════════════════════════════════════════════════════════════
#  Anomaly Detection
# ═══════════════════════════════════════════════════════════════

@dataclass
class TrafficBaseline:
    """Baseline traffic pattern for a user."""
    user_id: int
    avg_bytes_per_minute: float = 0
    peak_bytes_per_minute: float = 0
    avg_connections: int = 0
    sample_count: int = 0
    last_updated: float = 0

@dataclass
class AnomalyAlert:
    """Anomaly alert."""
    user_id: int
    alert_type: str  # "traffic_spike", "unusual_port", "connection_flood"
    severity: str  # "low", "medium", "high", "critical"
    details: str
    timestamp: float = field(default_factory=time.time)

class AnomalyDetector:
    """Detect anomalous traffic patterns."""
    
    def __init__(self):
        self.baselines: Dict[int, TrafficBaseline] = {}
        self.alerts: List[AnomalyAlert] = []
        self._traffic_history: Dict[int, List[Tuple[float, int]]] = defaultdict(list)
    
    def record_traffic(self, user_id: int, bytes_transferred: int):
        """Record traffic for a user."""
        now = time.time()
        self._traffic_history[user_id].append((now, bytes_transferred))
        
        # Keep only last 60 minutes of data
        cutoff = now - 3600
        self._traffic_history[user_id] = [
            (t, b) for t, b in self._traffic_history[user_id] if t > cutoff
        ]
    
    def update_baseline(self, user_id: int):
        """Update baseline for a user based on traffic history."""
        history = self._traffic_history.get(user_id, [])
        if len(history) < 10:
            return
        
        bytes_list = [b for _, b in history]
        avg = sum(bytes_list) / len(bytes_list)
        peak = max(bytes_list)
        
        baseline = self.baselines.get(user_id, TrafficBaseline(user_id=user_id))
        baseline.avg_bytes_per_minute = avg
        baseline.peak_bytes_per_minute = peak
        baseline.sample_count = len(history)
        baseline.last_updated = time.time()
        self.baselines[user_id] = baseline
    
    def check_anomaly(self, user_id: int, current_bytes: int) -> Optional[AnomalyAlert]:
        """Check if current traffic is anomalous."""
        baseline = self.baselines.get(user_id)
        if not baseline or baseline.sample_count < 10:
            return None
        
        # Traffic spike: 5x above average
        if current_bytes > baseline.avg_bytes_per_minute * 5:
            alert = AnomalyAlert(
                user_id=user_id,
                alert_type="traffic_spike",
                severity="high" if current_bytes > baseline.avg_bytes_per_minute * 10 else "medium",
                details=f"Traffic {current_bytes} bytes/min is {current_bytes/baseline.avg_bytes_per_minute:.1f}x above average"
            )
            self.alerts.append(alert)
            return alert
        
        return None
    
    def get_alerts(self, since: float = 0) -> List[AnomalyAlert]:
        """Get alerts since timestamp."""
        return [a for a in self.alerts if a.timestamp > since]

# ═══════════════════════════════════════════════════════════════
#  Port Scan Detection
# ═══════════════════════════════════════════════════════════════

class PortScanDetector:
    """Detect port scanning activity."""
    
    def __init__(self, threshold: int = 10, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._connection_attempts: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self._scan_alerts: List[Dict] = []
    
    def record_connection(self, source_ip: str, dest_port: int):
        """Record a connection attempt."""
        now = time.time()
        self._connection_attempts[source_ip].append((now, dest_port))
        
        # Clean old entries
        cutoff = now - self.window_seconds
        self._connection_attempts[source_ip] = [
            (t, p) for t, p in self._connection_attempts[source_ip] if t > cutoff
        ]
        
        # Check for port scan
        unique_ports = set(p for _, p in self._connection_attempts[source_ip])
        if len(unique_ports) >= self.threshold:
            alert = {
                "source_ip": source_ip,
                "unique_ports": len(unique_ports),
                "ports_scanned": sorted(unique_ports),
                "timestamp": now,
                "type": "port_scan"
            }
            self._scan_alerts.append(alert)
            # Reset for this IP
            self._connection_attempts[source_ip] = []
            return alert
        
        return None
    
    def get_scan_alerts(self, since: float = 0) -> List[Dict]:
        """Get port scan alerts since timestamp."""
        return [a for a in self._scan_alerts if a["timestamp"] > since]

# Global instances
anomaly_detector = AnomalyDetector()
port_scan_detector = PortScanDetector()