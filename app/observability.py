"""
Observability module for V7LTHRONYX VPN Panel.

OpenTelemetry:
- Distributed tracing with OTLP export
- Auto-instrumented FastAPI, SQLAlchemy, Redis, HTTPX
- Trace context propagation

Prometheus/Grafana:
- Custom metrics (active users, traffic, connections)
- Grafana dashboard provisioning
- Alert rules
"""

import logging
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass

from .config import settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  OpenTelemetry Setup
# ═══════════════════════════════════════════════════════════════

def setup_opentelemetry(app=None):
    """Initialize OpenTelemetry instrumentation.

    Requires: opentelemetry-api, opentelemetry-sdk,
              opentelemetry-instrumentation-fastapi,
              opentelemetry-instrumentation-sqlalchemy,
              opentelemetry-instrumentation-redis,
              opentelemetry-instrumentation-httpx,
              opentelemetry-exporter-otlp
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        # Create resource
        resource = Resource.create({
            SERVICE_NAME: "v7lthronyx-vpn-panel",
            "service.version": "2.0.0",
            "deployment.environment": "production",
        })

        # Create tracer provider
        provider = TracerProvider(resource=resource)

        # OTLP exporter (sends to Jaeger/Tempo/Signoz)
        otlp_endpoint = os.environ.get(
            "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317"
        )
        otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(otlp_exporter))

        trace.set_tracer_provider(provider)

        # Auto-instrument FastAPI
        if app is not None:
            try:
                from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
                FastAPIInstrumentor.instrument_app(app)
                logger.info("OpenTelemetry: FastAPI instrumented")
            except ImportError:
                logger.warning("OpenTelemetry: fastapi instrumentation not available")

        # Auto-instrument SQLAlchemy
        try:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
            SQLAlchemyInstrumentor().instrument()
            logger.info("OpenTelemetry: SQLAlchemy instrumented")
        except ImportError:
            logger.warning("OpenTelemetry: sqlalchemy instrumentation not available")

        # Auto-instrument Redis
        try:
            from opentelemetry.instrumentation.redis import RedisInstrumentor
            RedisInstrumentor().instrument()
            logger.info("OpenTelemetry: Redis instrumented")
        except ImportError:
            logger.warning("OpenTelemetry: redis instrumentation not available")

        # Auto-instrument HTTPX
        try:
            from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
            HTTPXClientInstrumentor().instrument()
            logger.info("OpenTelemetry: HTTPX instrumented")
        except ImportError:
            logger.warning("OpenTelemetry: httpx instrumentation not available")

        logger.info(f"OpenTelemetry initialized (endpoint: {otlp_endpoint})")
        return True

    except ImportError:
        logger.warning("OpenTelemetry packages not installed. Tracing disabled.")
        return False
    except Exception as e:
        logger.error(f"Failed to initialize OpenTelemetry: {e}")
        return False


# ═══════════════════════════════════════════════════════════════
#  Custom Prometheus Metrics
# ═══════════════════════════════════════════════════════════════

class PrometheusMetrics:
    """Custom Prometheus metrics for VPN panel.

    These are exposed at /api/system/metrics alongside the
    standard system metrics.
    """

    def __init__(self):
        self._active_users = 0
        self._total_users = 0
        self._total_traffic_bytes = 0
        self._active_connections = 0
        self._failed_logins = 0
        self._banned_ips = 0
        self._anomaly_alerts = 0
        self._payments_total = 0
        self._payments_amount_total = 0

    def set_active_users(self, count: int):
        self._active_users = count

    def set_total_users(self, count: int):
        self._total_users = count

    def add_traffic(self, bytes_count: int):
        self._total_traffic_bytes += bytes_count

    def set_active_connections(self, count: int):
        self._active_connections = count

    def inc_failed_logins(self):
        self._failed_logins += 1

    def set_banned_ips(self, count: int):
        self._banned_ips = count

    def inc_anomaly_alerts(self):
        self._anomaly_alerts += 1

    def inc_payments(self, amount: int = 0):
        self._payments_total += 1
        self._payments_amount_total += amount

    def generate_metrics(self) -> str:
        """Generate Prometheus-compatible metrics text."""
        return f"""
# HELP vpn_active_users Number of active VPN users
# TYPE vpn_active_users gauge
vpn_active_users {self._active_users}

# HELP vpn_total_users Total number of VPN users
# TYPE vpn_total_users gauge
vpn_total_users {self._total_users}

# HELP vpn_total_traffic_bytes Total traffic in bytes
# TYPE vpn_total_traffic_bytes counter
vpn_total_traffic_bytes {self._total_traffic_bytes}

# HELP vpn_active_connections Number of active connections
# TYPE vpn_active_connections gauge
vpn_active_connections {self._active_connections}

# HELP vpn_failed_logins_total Total failed login attempts
# TYPE vpn_failed_logins_total counter
vpn_failed_logins_total {self._failed_logins}

# HELP vpn_banned_ips Number of currently banned IPs
# TYPE vpn_banned_ips gauge
vpn_banned_ips {self._banned_ips}

# HELP vpn_anomaly_alerts_total Total anomaly detection alerts
# TYPE vpn_anomaly_alerts_total counter
vpn_anomaly_alerts_total {self._anomaly_alerts}

# HELP vpn_payments_total Total number of payments
# TYPE vpn_payments_total counter
vpn_payments_total {self._payments_total}

# HELP vpn_payments_amount_total Total payment amount (IRR)
# TYPE vpn_payments_amount_total counter
vpn_payments_amount_total {self._payments_amount_total}
"""


# ═══════════════════════════════════════════════════════════════
#  Grafana Dashboard Provisioning
# ═══════════════════════════════════════════════════════════════

GRAFANA_DASHBOARD_JSON = {
    "dashboard": {
        "id": None,
        "title": "V7LTHRONYX VPN Panel",
        "description": "VPN Panel monitoring dashboard",
        "tags": ["vpn", "v7lthronyx"],
        "timezone": "browser",
        "panels": [
            {
                "id": 1,
                "title": "Active Users",
                "type": "stat",
                "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0},
                "targets": [
                    {"expr": "vpn_active_users", "refId": "A"}
                ],
                "fieldConfig": {
                    "defaults": {
                        "color": {"mode": "thresholds"},
                        "thresholds": {
                            "steps": [
                                {"color": "green", "value": None},
                                {"color": "yellow", "value": 50},
                                {"color": "red", "value": 100},
                            ]
                        }
                    }
                },
            },
            {
                "id": 2,
                "title": "Total Traffic",
                "type": "stat",
                "gridPos": {"h": 8, "w": 6, "x": 6, "y": 0},
                "targets": [
                    {"expr": "vpn_total_traffic_bytes", "refId": "A"}
                ],
                "fieldConfig": {
                    "defaults": {
                        "unit": "bytes",
                    }
                },
            },
            {
                "id": 3,
                "title": "Active Connections",
                "type": "graph",
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
                "targets": [
                    {"expr": "vpn_active_connections", "refId": "A", "legendFormat": "connections"}
                ],
            },
            {
                "id": 4,
                "title": "Failed Logins",
                "type": "graph",
                "gridPos": {"h": 8, "w": 6, "x": 0, "y": 16},
                "targets": [
                    {"expr": "rate(vpn_failed_logins_total[5m])", "refId": "A", "legendFormat": "failed/s"}
                ],
            },
            {
                "id": 5,
                "title": "Anomaly Alerts",
                "type": "graph",
                "gridPos": {"h": 8, "w": 6, "x": 6, "y": 16},
                "targets": [
                    {"expr": "rate(vpn_anomaly_alerts_total[5m])", "refId": "A", "legendFormat": "alerts/s"}
                ],
            },
            {
                "id": 6,
                "title": "System Resources",
                "type": "graph",
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 24},
                "targets": [
                    {"expr": "vpn_panel_cpu_percent", "refId": "A", "legendFormat": "CPU %"},
                    {"expr": "vpn_panel_memory_percent", "refId": "B", "legendFormat": "Memory %"},
                    {"expr": "vpn_panel_disk_percent", "refId": "C", "legendFormat": "Disk %"},
                ],
            },
            {
                "id": 7,
                "title": "Payments",
                "type": "stat",
                "gridPos": {"h": 8, "w": 6, "x": 0, "y": 32},
                "targets": [
                    {"expr": "vpn_payments_total", "refId": "A"},
                ],
            },
            {
                "id": 8,
                "title": "Banned IPs",
                "type": "stat",
                "gridPos": {"h": 8, "w": 6, "x": 6, "y": 32},
                "targets": [
                    {"expr": "vpn_banned_ips", "refId": "A"},
                ],
            },
        ],
        "refresh": "30s",
        "schemaVersion": 27,
        "version": 0,
    },
    "overwrite": True,
}

GRAFANA_DATASOURCE = {
    "apiVersion": 1,
    "datasources": [
        {
            "name": "Prometheus",
            "type": "prometheus",
            "access": "proxy",
            "url": "http://localhost:9090",
            "isDefault": True,
        },
        {
            "name": "Loki",
            "type": "loki",
            "access": "proxy",
            "url": "http://localhost:3100",
        },
    ],
}

GRAFANA_ALERT_RULES = """
groups:
  - name: v7lthronyx-alerts
    rules:
      - alert: HighCPUUsage
        expr: vpn_panel_cpu_percent > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on V7LTHRONYX panel"
          description: "CPU usage is {{ $value }}%"

      - alert: HighMemoryUsage
        expr: vpn_panel_memory_percent > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on V7LTHRONYX panel"

      - alert: HighFailedLogins
        expr: rate(vpn_failed_logins_total[5m]) > 10
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Brute force attack detected"
          description: "{{ $value }} failed logins per second"

      - alert: AnomalyDetected
        expr: rate(vpn_anomaly_alerts_total[5m]) > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Traffic anomaly detected"

      - alert: AgentDown
        expr: up{job="v7lthronyx-agents"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "VPN agent is down"
"""


def generate_grafana_provisioning(
    output_dir: str = "/opt/spiritus/grafana",
) -> Dict[str, str]:
    """Generate Grafana provisioning configuration files."""
    import json
    os.makedirs(output_dir, exist_ok=True)

    files = {}

    # Datasources
    ds_path = os.path.join(output_dir, "provisioning", "datasources", "datasources.yaml")
    os.makedirs(os.path.dirname(ds_path), exist_ok=True)
    try:
        import yaml as _yaml
    except ImportError:
        _yaml = None

    if _yaml is not None:
        with open(ds_path, 'w') as f:
            _yaml.dump(GRAFANA_DATASOURCE, f, default_flow_style=False)
        files["datasources"] = ds_path
    else:
        ds_json_path = ds_path.replace(".yaml", ".json")
        with open(ds_json_path, 'w') as f:
            json.dump(GRAFANA_DATASOURCE, f, indent=2)
        files["datasources"] = ds_json_path

    # Dashboard
    db_path = os.path.join(output_dir, "provisioning", "dashboards", "v7lthronyx.json")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with open(db_path, 'w') as f:
        json.dump(GRAFANA_DASHBOARD_JSON, f, indent=2)
    files["dashboard"] = db_path

    # Alert rules
    alerts_path = os.path.join(output_dir, "alert_rules.yml")
    with open(alerts_path, 'w') as f:
        f.write(GRAFANA_ALERT_RULES)
    files["alerts"] = alerts_path

    # Dashboard provider config
    provider_path = os.path.join(output_dir, "provisioning", "dashboards", "provider.yaml")
    provider_config = {
        "apiVersion": 1,
        "providers": [
            {
                "name": "V7LTHRONYX",
                "orgId": 1,
                "folder": "",
                "type": "file",
                "disableDeletion": False,
                "editable": True,
                "options": {
                    "path": os.path.dirname(db_path),
                    "foldersFromFilesStructure": False,
                },
            }
        ],
    }
    if _yaml is not None:
        with open(provider_path, 'w') as f:
            _yaml.dump(provider_config, f, default_flow_style=False)
        files["dashboard_provider"] = provider_path

    return files


# Global metrics instance
prometheus_metrics = PrometheusMetrics()