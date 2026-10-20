"""Operations panel API: live overview, emergency actions, protocol health,
edge-node reachability, in-country probes and the billing summary.

Everything here is measured on this server or read from the database. Where
the panel cannot know something on its own (reachability from inside Iran
needs a probe there), the response leaves it empty rather than inventing it.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import platform
import re
import secrets
import socket
import ssl
import statistics
import time
from collections import deque
from datetime import timedelta
from typing import Any

import httpx
import psutil
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import record_audit
from ..auth import User, get_current_admin_cookie
from ..config import settings
from ..database import get_async_db
from ..evasion_rotation import protocol_rotator
from ..models import (
    AuditLog,
    EdgeNode,
    Fail2banBan,
    Payment,
    PaymentStatus,
    ProbeAgent,
    ProbeReport,
    Reseller,
    ResellerLedger,
    VpnUser,
)
from ..payments import payment_manager
from ..privileged_helper import PrivilegedHelperError, helper_request
from ..timeutil import utcnow as _utcnow
from .compat._core import (
    _is_placeholder_host,
    _load_legacy_settings,
    _save_legacy_settings,
    _settings_state,
    _user_last_seen,
)
from .compat.monitor import legacy_server_info
from .compat.panel_settings import _schedule_xray_sync

router = APIRouter(prefix="/ops", tags=["ops"])
probe_router = APIRouter(prefix="/probe", tags=["probe"])

ONLINE_WINDOW_SECONDS = 90
PROBE_REPORT_RETENTION_DAYS = 30
PROBE_MIN_REPORT_INTERVAL_SECONDS = 30
MAX_EDGE_NODES = 200
MAX_PROBES = 50


# ═══════════════════════════════════════════════════════════════
#  Protocol catalog
# ═══════════════════════════════════════════════════════════════

# key, label, enabled flag in server-info (None = always on), port key,
# transport, settings key holding the camouflage SNI (TLS probe target).
# Only REALITY and ShadowTLS get a TLS test: both relay the handshake to a
# real site under the configured SNI, so a completed handshake from inside
# Iran means the SNI and port passed DPI. The rest get a TCP connect.
_PROTOCOLS: tuple[tuple[str, str, str | None, str, str, str | None], ...] = (
    ("vmess", "VMess WS", None, "vmess_port", "tcp", None),
    ("vless_reality", "VLESS REALITY", "vless_enabled", "vless_port", "tcp", "reality_sni"),
    ("vless_xhttp_reality", "VLESS XHTTP REALITY", "vless_xhttp_enabled", "vless_xhttp_port", "tcp", "vless_xhttp_reality_sni"),
    ("vless_vision_reality", "VLESS Vision REALITY", "vless_vision_enabled", "vless_vision_port", "tcp", "vless_vision_reality_sni"),
    ("vless_reverse_reality", "VLESS Reverse REALITY", "vless_reverse_enabled", "vless_reverse_port", "tcp", "vless_reverse_reality_sni"),
    ("trojan", "Trojan", "trojan_enabled", "trojan_port", "tcp", None),
    ("trojan_cdn", "Trojan CDN", "trojan_cdn_enabled", "trojan_cdn_port", "tcp", None),
    ("grpc", "gRPC", "grpc_enabled", "grpc_port", "tcp", None),
    ("httpupgrade", "HTTPUpgrade", "httpupgrade_enabled", "httpupgrade_port", "tcp", None),
    ("ss2022", "Shadowsocks 2022", "ss2022_enabled", "ss2022_port", "tcp", None),
    ("vless_ws", "VLESS WS", "vless_ws_enabled", "vless_ws_port", "tcp", None),
    ("vless_ws_plain_front", "VLESS WS Front", "vless_ws_plain_front_enabled", "vless_ws_plain_front_port", "tcp", None),
    ("hysteria2", "Hysteria2", "hysteria2_enabled", "hysteria2_port", "udp", None),
    ("tuic", "TUIC v5", "tuic_enabled", "tuic_port", "udp", None),
    ("amneziawg", "AmneziaWG", "amneziawg_enabled", "amneziawg_port", "udp", None),
    ("shadowtls", "ShadowTLS v3", "shadowtls_enabled", "shadowtls_port", "tcp", "shadowtls_sni"),
    ("mieru", "Mieru", "mieru_enabled", "mieru_port", "tcp", None),
    ("naiveproxy", "NaiveProxy", "naiveproxy_enabled", "naiveproxy_port", "tcp", None),
    ("wireguard", "WireGuard", "wireguard_enabled", "wireguard_port", "udp", None),
    ("openvpn", "OpenVPN", "openvpn_enabled", "openvpn_port", "udp", None),
)
PROTOCOL_KEYS = frozenset(p[0] for p in _PROTOCOLS)

# Explicit REALITY dest per protocol; otherwise the dest is <sni>:443.
_DEST_KEYS = {
    "vless_reality": "reality_dest",
    "vless_xhttp_reality": "vless_xhttp_reality_dest",
    "vless_vision_reality": "vless_vision_reality_dest",
    "vless_reverse_reality": "vless_reverse_reality_dest",
}

# Clients reach these through a CDN, not this server's IP, so a direct probe
# of server:port would measure the wrong path.
_CDN_FRONTED = frozenset({"trojan_cdn"})

# Probe protocol key -> evasion_rotation.ProtocolRotator key.
_ROTATOR_ALIASES = {"vless_ws": "vless_ws_tls"}

_SINGBOX_PROTOCOLS = frozenset({"hysteria2", "tuic", "shadowtls", "naiveproxy"})


def _catalog(server_info: dict[str, Any], s: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key, label, flag, port_key, transport, sni_key in _PROTOCOLS:
        enabled = True if flag is None else bool(server_info.get(flag))
        try:
            port = int(server_info.get(port_key) or 0)
        except (TypeError, ValueError):
            port = 0
        sni = str(s.get(sni_key) or "").strip() if sni_key else ""
        if transport == "udp":
            method = "udp"
        elif sni:
            method = "tls"
        else:
            method = "tcp"
        dest = ""
        if sni:
            dest = str(s.get(_DEST_KEYS.get(key, ""), "") or "").strip() or f"{sni}:443"
        rows.append({
            "key": key, "name": label, "enabled": enabled, "port": port,
            "transport": transport, "method": method, "sni": sni, "dest": dest,
        })
    return rows


async def _load_catalog(admin: User, db: AsyncSession) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    s = await _load_legacy_settings(db)
    server_info = await legacy_server_info(admin=admin, db=db)
    return _catalog(server_info, s), s


# ═══════════════════════════════════════════════════════════════
#  Network measurement helpers
# ═══════════════════════════════════════════════════════════════

def _short_error(exc: BaseException) -> str:
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "timeout"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "certificate verification failed"
    msg = getattr(exc, "strerror", None) or str(exc) or type(exc).__name__
    return msg[:120]


async def _resolve(host: str, port: int, timeout: float) -> tuple[Any, ...]:
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout
    )
    if not infos:
        raise OSError("no address")
    return infos[0][4]


async def _connect_ms(host: str, port: int, *, sni: str = "", timeout: float = 3.0) -> float:
    """Time a TCP connect (plus a verified TLS handshake when ``sni`` is set).

    DNS is resolved first so it is not counted in the RTT.
    """
    addr = await _resolve(host, port, timeout)
    ctx = ssl.create_default_context() if sni else None
    start = time.perf_counter()
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(addr[0], addr[1], ssl=ctx, server_hostname=sni or None),
        timeout,
    )
    elapsed = (time.perf_counter() - start) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return round(elapsed, 1)


async def _measure(host: str, port: int, *, sni: str = "", attempts: int = 1) -> dict[str, Any]:
    samples: list[float] = []
    error = None
    for _ in range(attempts):
        try:
            samples.append(await _connect_ms(host, port, sni=sni))
        except Exception as exc:  # noqa: BLE001 - every failure is reported, none raised
            error = _short_error(exc)
    return {
        "ok": bool(samples),
        "ms": round(statistics.median(samples), 1) if samples else None,
        "error": None if samples else error,
    }


def _listening_ports() -> tuple[set[int], set[int]] | None:
    try:
        tcp = {
            c.laddr.port for c in psutil.net_connections(kind="tcp")
            if c.status == psutil.CONN_LISTEN and c.laddr
        }
        udp = {c.laddr.port for c in psutil.net_connections(kind="udp") if c.laddr}
    except (psutil.AccessDenied, OSError):
        return None
    return tcp, udp


def _process_running(name: str) -> bool:
    for proc in psutil.process_iter(["name"]):
        try:
            if proc.info["name"] == name:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


async def _redis_ok() -> bool:
    try:
        from ..redis_client import get_redis

        return bool(await asyncio.wait_for((await get_redis()).ping(), 1.0))
    except Exception:  # noqa: BLE001 - "unavailable" is the answer
        return False


# Rolling NIC counters so the overview can report rates, not totals.
_NET_SAMPLES: deque[tuple[float, int, int]] = deque(maxlen=90)


def _net_history() -> list[dict[str, float]]:
    now = time.time()
    io = psutil.net_io_counters()
    if not _NET_SAMPLES or now - _NET_SAMPLES[-1][0] >= 2:
        _NET_SAMPLES.append((now, io.bytes_sent, io.bytes_recv))
    history = []
    samples = list(_NET_SAMPLES)
    for (t0, sent0, recv0), (t1, sent1, recv1) in zip(samples, samples[1:]):
        dt = t1 - t0
        if dt <= 0:
            continue
        history.append({
            "t": round(t1, 1),
            # Counter wrap/reset shows up as a negative delta; drop it to 0.
            "in_bps": max(0, recv1 - recv0) * 8 / dt,
            "out_bps": max(0, sent1 - sent0) * 8 / dt,
        })
    return history


# ═══════════════════════════════════════════════════════════════
#  Overview (topbar, Mission Control, War-Room)
# ═══════════════════════════════════════════════════════════════

_SECURITY_ACTIONS = (
    "honeypot_hit", "login_failed", "login_2fa_failed", "login",
    "panic_flush", "emergency_cloak_on", "emergency_cloak_off",
    "probe_created", "probe_deleted", "edge_node_added", "edge_node_deleted",
    "automation_updated",
)
_CLOAK_KEYS = (
    "fragment_enabled", "fragment_packets", "fragment_length", "fragment_interval",
    "noise_enabled", "noise_packet", "noise_delay",
)
_CLOAK_VALUES: dict[str, Any] = {
    "fragment_enabled": True,
    "fragment_packets": "tlshello",
    "fragment_length": "100-200",
    "fragment_interval": "10-20",
    "noise_enabled": True,
    "noise_packet": "rand:50-100",
    "noise_delay": "10-20",
}


def _event_summary(row: AuditLog) -> str:
    details = row.details or {}
    if row.action == "honeypot_hit":
        return str(details.get("path", ""))[:120]
    if row.action in ("login_failed", "login_2fa_failed"):
        return str(details.get("username", ""))[:60]
    if row.action in ("probe_created", "probe_deleted", "edge_node_added", "edge_node_deleted"):
        return str(details.get("name", ""))[:60]
    if row.action in ("emergency_cloak_on", "emergency_cloak_off"):
        return str(details.get("reason") or ("automatic" if details.get("source") == "auto" else ""))[:120]
    return ""


@router.get("/overview")
async def ops_overview(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    catalog, s = await _load_catalog(admin, db)
    now = _utcnow()
    since = now - timedelta(hours=24)

    async def _count(stmt) -> int:
        return int((await db.execute(stmt)).scalar() or 0)

    honeypot = await _count(
        select(func.count(AuditLog.id)).where(AuditLog.action == "honeypot_hit", AuditLog.created_at >= since)
    )
    failed_logins = await _count(
        select(func.count(AuditLog.id)).where(
            AuditLog.action.in_(("login_failed", "login_2fa_failed")), AuditLog.created_at >= since
        )
    )
    active_bans = await _count(select(func.count(Fail2banBan.id)).where(Fail2banBan.banned_until > now))
    total_users = await _count(select(func.count(VpnUser.id)))
    active_users = await _count(select(func.count(VpnUser.id)).where(VpnUser.active == 1))

    events = (
        await db.execute(
            select(AuditLog).where(AuditLog.action.in_(_SECURITY_ACTIONS))
            .order_by(AuditLog.id.desc()).limit(20)
        )
    ).scalars().all()

    cutoff = time.time() - ONLINE_WINDOW_SECONDS
    history = _net_history()
    latest = history[-1] if history else {"in_bps": None, "out_bps": None}

    enabled_keys = {p["key"] for p in catalog if p["enabled"]}
    return {
        "admin": admin.username,
        "singbox": {
            "needed": bool(enabled_keys & _SINGBOX_PROTOCOLS),
            "running": _process_running("sing-box"),
        },
        "redis_ok": await _redis_ok(),
        "host": {
            "hostname": socket.gethostname(),
            "arch": platform.machine(),
            "uptime_seconds": int(time.time() - psutil.boot_time()),
        },
        "xray_running": _process_running("xray"),
        "protocols": {
            "enabled": sum(1 for p in catalog if p["enabled"]),
            "total": len(catalog),
        },
        "users": {
            "total": total_users,
            "active": active_users,
            "online": sum(1 for ts in _user_last_seen.values() if ts >= cutoff),
        },
        "network": {"in_bps": latest["in_bps"], "out_bps": latest["out_bps"], "history": history[-30:]},
        "security_24h": {"honeypot_hits": honeypot, "failed_logins": failed_logins, "active_bans": active_bans},
        "posture": {
            "cloak_active": bool(s.get("emergency_cloak_active")),
            "cloak_source": s.get("emergency_cloak_source"),
            "fragment": bool(s.get("fragment_enabled")),
            "noise": bool(s.get("noise_enabled")),
            "mux": bool(s.get("mux_enabled")),
            "fingerprint": s.get("fingerprint") or "chrome",
        },
        "events": [
            {
                "at": e.created_at.isoformat() if e.created_at else None,
                "action": e.action,
                "ip": e.ip_address,
                "detail": _event_summary(e),
            }
            for e in events
        ],
    }


# ═══════════════════════════════════════════════════════════════
#  Emergency actions
# ═══════════════════════════════════════════════════════════════

@router.post("/panic-flush")
async def panic_flush(
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Restart every proxy service in use, dropping all live client connections."""
    catalog, _ = await _load_catalog(admin, db)
    enabled = {p["key"] for p in catalog if p["enabled"]}
    services = ["xray"]
    if enabled & _SINGBOX_PROTOCOLS:
        services.append(settings.singbox_service_name or "sing-box")
    if "mieru" in enabled:
        services.append(settings.mieru_service_name or "mita")

    results = {}
    for service in services:
        try:
            res = await helper_request("service.restart", {"service": service}, timeout=35)
            results[service] = {"ok": res.ok, "message": res.message}
        except PrivilegedHelperError:
            results[service] = {"ok": False, "message": "privileged helper unavailable"}

    ok = all(r["ok"] for r in results.values())
    if results["xray"]["ok"]:
        _user_last_seen.clear()
    await record_audit(db, "panic_flush", admin_id=admin.id, details={"services": results}, request=request)
    return {"ok": ok, "services": results}


class CloakRequest(BaseModel):
    active: bool


def _cloak_state(s: dict[str, Any]) -> dict[str, Any]:
    return {
        "active": bool(s.get("emergency_cloak_active")),
        "since": s.get("emergency_cloak_since"),
        "source": s.get("emergency_cloak_source"),
        "values": {k: s.get(k) for k in _CLOAK_KEYS},
    }


async def apply_cloak(db: AsyncSession, active: bool, source: str) -> tuple[bool, dict[str, Any]]:
    """Switch Emergency Cloak on/off. Returns (changed, state).

    On: force maximum client-side fragmentation + noise and snapshot the
    operator's own values. Off: restore that snapshot. Idempotent: setting
    the current state again changes nothing (and never overwrites the
    snapshot). ``source`` is "manual" or "auto"; automation only ever
    releases a cloak it engaged itself.

    Fragment/noise live in client configs, so clients pick the change up on
    their next subscription refresh.
    """
    s = await _load_legacy_settings(db)
    if active == bool(s.get("emergency_cloak_active")):
        return False, _cloak_state(s)

    now = _utcnow().isoformat()
    if active:
        update: dict[str, Any] = dict(_CLOAK_VALUES)
        update["emergency_cloak_snapshot"] = {k: s.get(k) for k in _CLOAK_KEYS}
        update["emergency_cloak_since"] = now
        update["emergency_cloak_source"] = source
    else:
        snapshot = s.get("emergency_cloak_snapshot") or {}
        update = {k: snapshot.get(k) for k in _CLOAK_KEYS}
        update["emergency_cloak_snapshot"] = None
        update["emergency_cloak_since"] = None
        update["emergency_cloak_source"] = None
        if source == "manual":
            # Keeps automation from re-engaging right after an operator said no.
            update["emergency_cloak_manual_off_at"] = now
    update["emergency_cloak_active"] = active
    await _save_legacy_settings(db, update)
    return True, _cloak_state({**s, **update})


@router.get("/cloak")
async def get_cloak(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    return _cloak_state(await _load_legacy_settings(db))


@router.post("/cloak")
async def set_cloak(
    data: CloakRequest,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Manual Emergency Cloak switch; see ``apply_cloak``."""
    changed, state = await apply_cloak(db, data.active, "manual")
    if changed:
        _schedule_xray_sync()
        await record_audit(
            db, "emergency_cloak_on" if data.active else "emergency_cloak_off",
            admin_id=admin.id, details={"source": "manual"}, request=request,
        )
    return state


# ═══════════════════════════════════════════════════════════════
#  Protocol health
# ═══════════════════════════════════════════════════════════════

async def _probe_stats(db: AsyncSession, since) -> dict[str, dict[str, Any]]:
    rows = (
        await db.execute(
            select(ProbeReport.protocol, ProbeReport.ok, ProbeReport.latency_ms)
            .where(ProbeReport.created_at >= since)
        )
    ).all()
    acc: dict[str, dict[str, Any]] = {}
    for protocol, ok, latency in rows:
        a = acc.setdefault(protocol, {"attempts": 0, "ok": 0, "latencies": []})
        a["attempts"] += 1
        if ok:
            a["ok"] += 1
            if latency is not None:
                a["latencies"].append(latency)
    return {
        k: {
            "attempts": v["attempts"],
            "ok_rate": round(v["ok"] / v["attempts"], 3),
            "median_ms": round(statistics.median(v["latencies"]), 1) if v["latencies"] else None,
        }
        for k, v in acc.items()
    }


@router.get("/protocols")
async def ops_protocols(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    catalog, _ = await _load_catalog(admin, db)
    enabled = [p for p in catalog if p["enabled"]]
    ports = _listening_ports()
    probes = await _probe_stats(db, _utcnow() - timedelta(hours=24))

    async def _dest(p: dict[str, Any]) -> dict[str, Any] | None:
        if not p["dest"]:
            return None
        host, _, port = p["dest"].rpartition(":")
        if not host or not port.isdigit():
            return {"ok": False, "ms": None, "error": "invalid dest"}
        return await _measure(host.strip("[]"), int(port), sni=p["sni"])

    dests = await asyncio.gather(*(_dest(p) for p in enabled))
    rotation = protocol_rotator.status()
    blocked = set(rotation["blocked"])

    rows = []
    for p, dest in zip(enabled, dests):
        listening = None
        if ports is not None and p["port"]:
            listening = p["port"] in (ports[0] if p["transport"] == "tcp" else ports[1])
        rows.append({
            **p,
            "listening": listening,
            "dest_check": dest,
            "probe_24h": probes.get(p["key"]),
            "rotation_blocked": _ROTATOR_ALIASES.get(p["key"], p["key"]) in blocked,
        })
    return {
        "protocols": rows,
        "disabled": [p["name"] for p in catalog if not p["enabled"]],
        "rotation": rotation,
    }


# ═══════════════════════════════════════════════════════════════
#  Subscription ordering from probe results
# ═══════════════════════════════════════════════════════════════

RANK_MIN_ATTEMPTS = 3
RANK_WORKING = 0.5
_RANK_CACHE: dict[str, Any] = {"at": -1e9, "rank": {}}
_RANK_CACHE_TTL = 60.0


async def protocol_rank(db: AsyncSession) -> dict[str, tuple[int, float, float]]:
    """Sort key per protocol from the last 24 h of in-country probe tests.

    Each carrier counts equally (the mean of per-carrier success rates), so
    one busy probe cannot outvote the others. Tier 0 = working (>= 50%),
    tier 2 = mostly failing; protocols with too little data are absent and
    the caller keeps them in their default place (tier 1).
    """
    now = time.monotonic()
    if now - _RANK_CACHE["at"] < _RANK_CACHE_TTL:
        return _RANK_CACHE["rank"]
    rows = (
        await db.execute(
            select(ProbeReport.protocol, ProbeReport.carrier, ProbeReport.ok, ProbeReport.latency_ms)
            .where(ProbeReport.created_at >= _utcnow() - timedelta(hours=24))
        )
    ).all()
    per: dict[str, dict[str, list[int]]] = {}
    latencies: dict[str, list[float]] = {}
    for protocol, carrier, ok, latency in rows:
        cell = per.setdefault(protocol, {}).setdefault(carrier, [0, 0])
        cell[0] += 1
        if ok:
            cell[1] += 1
            if latency is not None:
                latencies.setdefault(protocol, []).append(latency)
    rank: dict[str, tuple[int, float, float]] = {}
    for protocol, carriers in per.items():
        if sum(a for a, _ in carriers.values()) < RANK_MIN_ATTEMPTS:
            continue
        score = statistics.mean(ok / attempts for attempts, ok in carriers.values())
        median = statistics.median(latencies[protocol]) if latencies.get(protocol) else 1e9
        rank[protocol] = (0 if score >= RANK_WORKING else 2, -score, median)
    _RANK_CACHE.update(at=now, rank=rank)
    return rank


def rank_sort_key(protocol: str | None, rank: dict[str, tuple[int, float, float]], base_index: int):
    r = rank.get(protocol or "")
    return (1, 0.0, 0.0, base_index) if r is None else (*r, base_index)


# ═══════════════════════════════════════════════════════════════
#  Edge nodes
# ═══════════════════════════════════════════════════════════════

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class EdgeNodeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    address: str = Field(..., min_length=1, max_length=255)
    port: int = Field(443, ge=1, le=65535)
    location: str | None = Field(None, max_length=100)

    @field_validator("address")
    @classmethod
    def _valid_address(cls, v: str) -> str:
        v = v.strip().strip("[]")
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        if not _HOSTNAME_RE.match(v):
            raise ValueError("address must be an IP address or hostname")
        return v.lower()

    @field_validator("name", "location")
    @classmethod
    def _strip(cls, v: str | None) -> str | None:
        return v.strip() if isinstance(v, str) else v


def _node_dict(n: EdgeNode) -> dict[str, Any]:
    return {
        "id": n.id, "name": n.name, "address": n.address, "port": n.port,
        "location": n.location, "reachable": n.reachable, "rtt_ms": n.rtt_ms,
        "last_error": n.last_error,
        "last_checked_at": n.last_checked_at.isoformat() if n.last_checked_at else None,
    }


async def _check_nodes(db: AsyncSession, nodes: list[EdgeNode]) -> None:
    sem = asyncio.Semaphore(10)

    async def one(n: EdgeNode):
        async with sem:
            return await _measure(n.address, n.port, attempts=3)

    results = await asyncio.gather(*(one(n) for n in nodes))
    now = _utcnow()
    for n, r in zip(nodes, results):
        n.reachable = r["ok"]
        n.rtt_ms = r["ms"]
        n.last_error = r["error"]
        n.last_checked_at = now
    await db.commit()


@router.get("/nodes")
async def list_nodes(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    nodes = (await db.execute(select(EdgeNode).order_by(EdgeNode.id))).scalars().all()
    return {"nodes": [_node_dict(n) for n in nodes]}


@router.post("/nodes", status_code=201)
async def add_node(
    data: EdgeNodeCreate,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    count = (await db.execute(select(func.count(EdgeNode.id)))).scalar() or 0
    if count >= MAX_EDGE_NODES:
        raise HTTPException(400, f"At most {MAX_EDGE_NODES} edge nodes")
    node = EdgeNode(name=data.name, address=data.address, port=data.port, location=data.location or None)
    db.add(node)
    await db.commit()
    await record_audit(db, "edge_node_added", admin_id=admin.id, target_type="edge_node",
                       target_id=node.id, details={"name": node.name}, request=request)
    await _check_nodes(db, [node])
    return _node_dict(node)


@router.delete("/nodes/{node_id}")
async def delete_node(
    node_id: int,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    node = await db.get(EdgeNode, node_id)
    if not node:
        raise HTTPException(404, "Edge node not found")
    name = node.name
    await db.delete(node)
    await db.commit()
    await record_audit(db, "edge_node_deleted", admin_id=admin.id, target_type="edge_node",
                       target_id=node_id, details={"name": name}, request=request)
    return {"ok": True}


@router.post("/nodes/check")
async def check_nodes(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    nodes = list((await db.execute(select(EdgeNode).order_by(EdgeNode.id))).scalars().all())
    await _check_nodes(db, nodes)
    return {"nodes": [_node_dict(n) for n in nodes]}


# ═══════════════════════════════════════════════════════════════
#  In-country probes
# ═══════════════════════════════════════════════════════════════

# Well-known Iranian access networks by ASN. Anything else falls back to the
# ISP name returned by the lookup.
IR_CARRIERS = {
    "197207": "MCI (Hamrah-e Aval)",
    "44244": "MTN Irancell",
    "57218": "Rightel",
    "58224": "TCI (Mokhaberat)",
    "31549": "Shatel",
    "16322": "ParsOnline",
    "43754": "Asiatech",
    "50810": "Mobinnet",
    "25184": "Afranet",
}
_CARRIER_CACHE: dict[str, tuple[float, str | None, str]] = {}
_CARRIER_CACHE_TTL = 24 * 3600


async def _carrier_for_ip(ip: str) -> tuple[str | None, str]:
    """(asn, carrier) for a probe's public IP. The IP itself is never stored;
    it is only held in this in-memory cache for a day."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, "Unknown"
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return None, "Unknown (private address)"
    cached = _CARRIER_CACHE.get(ip)
    if cached and time.time() - cached[0] < _CARRIER_CACHE_TTL:
        return cached[1], cached[2]
    asn, carrier = None, "Unknown"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}", params={"fields": "status,as,isp"})
        data = resp.json() if resp.status_code == 200 else {}
        if data.get("status") == "success":
            match = re.match(r"AS(\d+)", str(data.get("as") or ""))
            asn = match.group(1) if match else None
            carrier = IR_CARRIERS.get(asn or "") or str(data.get("isp") or "Unknown")[:100]
    except Exception:  # noqa: BLE001 - lookup is best effort
        pass
    _CARRIER_CACHE[ip] = (time.time(), asn, carrier)
    return asn, carrier


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class ProbeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


def _probe_dict(p: ProbeAgent, stats: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": p.id, "name": p.name, "token_prefix": p.token_prefix, "active": p.active,
        "last_seen_at": p.last_seen_at.isoformat() if p.last_seen_at else None,
        "last_carrier": p.last_carrier, "last_asn": p.last_asn,
        "reports_24h": (stats or {}).get("attempts", 0),
        "ok_rate_24h": (stats or {}).get("ok_rate"),
    }


@router.get("/probes")
async def list_probes(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    probes = (await db.execute(select(ProbeAgent).order_by(ProbeAgent.id))).scalars().all()
    since = _utcnow() - timedelta(hours=24)
    rows = (
        await db.execute(
            select(ProbeReport.probe_id, func.count(ProbeReport.id), func.sum(case((ProbeReport.ok, 1), else_=0)))
            .where(ProbeReport.created_at >= since)
            .group_by(ProbeReport.probe_id)
        )
    ).all()
    stats = {pid: {"attempts": n, "ok_rate": round((ok or 0) / n, 3) if n else None} for pid, n, ok in rows}
    return {"probes": [_probe_dict(p, stats.get(p.id)) for p in probes]}


@router.post("/probes", status_code=201)
async def create_probe(
    data: ProbeCreate,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    count = (await db.execute(select(func.count(ProbeAgent.id)))).scalar() or 0
    if count >= MAX_PROBES:
        raise HTTPException(400, f"At most {MAX_PROBES} probes")
    token = "spr_" + secrets.token_urlsafe(32)
    probe = ProbeAgent(name=data.name.strip(), token_hash=_hash_token(token), token_prefix=token[:8])
    db.add(probe)
    await db.commit()
    await record_audit(db, "probe_created", admin_id=admin.id, target_type="probe",
                       target_id=probe.id, details={"name": probe.name}, request=request)
    # The token is shown exactly once; only its hash is kept.
    return {**_probe_dict(probe), "token": token}


@router.delete("/probes/{probe_id}")
async def delete_probe(
    probe_id: int,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    probe = await db.get(ProbeAgent, probe_id)
    if not probe:
        raise HTTPException(404, "Probe not found")
    name = probe.name
    # Explicit: SQLite does not enforce ON DELETE CASCADE without a pragma.
    await db.execute(delete(ProbeReport).where(ProbeReport.probe_id == probe_id))
    await db.delete(probe)
    await db.commit()
    await record_audit(db, "probe_deleted", admin_id=admin.id, target_type="probe",
                       target_id=probe_id, details={"name": name}, request=request)
    return {"ok": True}


@router.get("/carriers")
async def carrier_matrix(
    hours: int = 24,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Per carrier and protocol: success rate and median latency of probe tests."""
    hours = max(1, min(hours, 24 * PROBE_REPORT_RETENTION_DAYS))
    since = _utcnow() - timedelta(hours=hours)
    rows = (
        await db.execute(
            select(ProbeReport.carrier, ProbeReport.protocol, ProbeReport.ok,
                   ProbeReport.latency_ms, ProbeReport.created_at)
            .where(ProbeReport.created_at >= since)
        )
    ).all()
    labels = {p[0]: p[1] for p in _PROTOCOLS}
    acc: dict[str, dict[str, dict[str, Any]]] = {}
    last_seen: dict[str, Any] = {}
    for carrier, protocol, ok, latency, at in rows:
        cell = acc.setdefault(carrier, {}).setdefault(protocol, {"attempts": 0, "ok": 0, "latencies": []})
        cell["attempts"] += 1
        if ok:
            cell["ok"] += 1
            if latency is not None:
                cell["latencies"].append(latency)
        if at and (carrier not in last_seen or at > last_seen[carrier]):
            last_seen[carrier] = at

    carriers = []
    for carrier, protocols in sorted(acc.items()):
        cells = []
        for protocol, c in protocols.items():
            cells.append({
                "protocol": protocol,
                "name": labels.get(protocol, protocol),
                "attempts": c["attempts"],
                "ok_rate": round(c["ok"] / c["attempts"], 3),
                "median_ms": round(statistics.median(c["latencies"]), 1) if c["latencies"] else None,
            })
        cells.sort(key=lambda c: (-c["ok_rate"], c["median_ms"] if c["median_ms"] is not None else 1e9))
        best = cells[0] if cells and cells[0]["ok_rate"] > 0 else None
        carriers.append({
            "carrier": carrier,
            "last_report_at": last_seen[carrier].isoformat() if carrier in last_seen else None,
            "best": best,
            "protocols": cells,
        })
    return {"hours": hours, "carriers": carriers, "rotation": protocol_rotator.status()}


# ── Probe-facing endpoints (Bearer probe token, not an admin session) ──

async def _current_probe(request: Request, db: AsyncSession = Depends(get_async_db)) -> ProbeAgent:
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not token.startswith("spr_"):
        raise HTTPException(401, "Probe token required")
    probe = (
        await db.execute(select(ProbeAgent).where(ProbeAgent.token_hash == _hash_token(token)))
    ).scalar_one_or_none()
    if not probe or not probe.active:
        raise HTTPException(401, "Invalid probe token")
    return probe


def _probe_server_host(request: Request) -> str:
    host = str(_settings_state.get("server_ip") or settings.vpn_server_ip or settings.host or "")
    if _is_placeholder_host(host):
        # The probe reached the panel at this name, so it can reach the server there.
        host = request.url.hostname or ""
    return host


@probe_router.get("/targets")
async def probe_targets(
    request: Request,
    probe: ProbeAgent = Depends(_current_probe),
    db: AsyncSession = Depends(get_async_db),
):
    s = await _load_legacy_settings(db)
    server_info = await legacy_server_info(admin=User(id=0, username="probe", is_admin=True), db=db)
    targets = [
        {"protocol": p["key"], "name": p["name"], "port": p["port"], "method": p["method"], "sni": p["sni"]}
        for p in _catalog(server_info, s)
        if p["enabled"] and p["method"] in ("tcp", "tls") and p["port"] and p["key"] not in _CDN_FRONTED
    ]
    return {"server": _probe_server_host(request), "targets": targets, "min_interval_seconds": PROBE_MIN_REPORT_INTERVAL_SECONDS}


class ProbeResult(BaseModel):
    protocol: str = Field(..., max_length=40)
    method: str = Field(..., pattern="^(tcp|tls)$")
    ok: bool
    latency_ms: float | None = Field(None, ge=0, le=60000)
    error: str | None = Field(None, max_length=120)


class ProbeReportIn(BaseModel):
    results: list[ProbeResult] = Field(..., min_length=1, max_length=64)
    carrier: str | None = Field(None, max_length=100, description="Manual override of the detected carrier")


@probe_router.post("/report")
async def probe_report(
    data: ProbeReportIn,
    request: Request,
    probe: ProbeAgent = Depends(_current_probe),
    db: AsyncSession = Depends(get_async_db),
):
    now = _utcnow()
    if probe.last_seen_at and (now - probe.last_seen_at).total_seconds() < PROBE_MIN_REPORT_INTERVAL_SECONDS:
        raise HTTPException(429, f"Report at most every {PROBE_MIN_REPORT_INTERVAL_SECONDS}s")

    results = [r for r in data.results if r.protocol in PROTOCOL_KEYS]
    if not results:
        raise HTTPException(422, "No known protocol in results")

    asn, carrier = await _carrier_for_ip(request.client.host if request.client else "")
    if data.carrier and data.carrier.strip():
        carrier = data.carrier.strip()[:100]

    for r in results:
        db.add(ProbeReport(
            probe_id=probe.id, carrier=carrier, asn=asn, protocol=r.protocol, method=r.method,
            ok=r.ok, latency_ms=r.latency_ms if r.ok else None, error=None if r.ok else (r.error or "failed"),
        ))
        protocol_rotator.report(_ROTATOR_ALIASES.get(r.protocol, r.protocol), r.ok)
    probe.last_seen_at = now
    probe.last_carrier = carrier
    probe.last_asn = asn
    await db.execute(
        delete(ProbeReport).where(ProbeReport.created_at < now - timedelta(days=PROBE_REPORT_RETENTION_DAYS))
    )
    await db.commit()
    return {"ok": True, "stored": len(results), "carrier": carrier}


@probe_router.get("/script")
async def probe_script():
    """The probe itself, so an operator in Iran can fetch it from the panel."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts", "spiritus-probe.py")
    if not os.path.isfile(path):
        raise HTTPException(404, "Probe script not installed")
    return FileResponse(path, media_type="text/x-python", filename="spiritus-probe.py")


# ═══════════════════════════════════════════════════════════════
#  Financials
# ═══════════════════════════════════════════════════════════════

_GATEWAYS = (
    ("zarinpal", "Zarinpal", "IRR"),
    ("idpay", "IDPay", "IRR"),
    ("usdt_trc20", "USDT (TRC-20)", "USDT"),
)


def _major_units(amount: int, currency: str) -> float:
    # Payment.amount is Rial for IRR and cents for USDT (see PaymentManager.create_payment).
    return amount / 100 if (currency or "").upper() == "USDT" else float(amount)


@router.get("/financials")
async def ops_financials(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    since = _utcnow() - timedelta(days=30)

    async def _totals(*where) -> dict[str, dict[str, Any]]:
        rows = (
            await db.execute(
                select(Payment.currency, func.count(Payment.id), func.coalesce(func.sum(Payment.amount), 0))
                .where(Payment.status == PaymentStatus.paid, *where)
                .group_by(Payment.currency)
            )
        ).all()
        return {(cur or "IRR"): {"count": n, "amount": _major_units(int(total), cur)} for cur, n, total in rows}

    pending = (
        await db.execute(select(func.count(Payment.id)).where(Payment.status == PaymentStatus.pending))
    ).scalar() or 0

    recent = (
        await db.execute(
            select(Payment, Reseller.username)
            .outerjoin(Reseller, Payment.reseller_id == Reseller.id)
            .order_by(Payment.id.desc()).limit(15)
        )
    ).all()

    reseller_count, balance_total = (
        await db.execute(select(func.count(Reseller.id), func.coalesce(func.sum(Reseller.balance), 0)))
    ).one()
    top = (
        await db.execute(select(Reseller).where(Reseller.balance > 0).order_by(Reseller.balance.desc()).limit(5))
    ).scalars().all()
    ledger = (
        await db.execute(
            select(ResellerLedger, Reseller.username)
            .join(Reseller, ResellerLedger.reseller_id == Reseller.id)
            .order_by(ResellerLedger.id.desc()).limit(10)
        )
    ).all()

    return {
        "paid_30d": await _totals(Payment.paid_at >= since),
        "paid_all": await _totals(),
        "pending": pending,
        "gateways": [
            {"id": gid, "name": name, "currency": cur, "configured": gid in payment_manager._gateways}
            for gid, name, cur in _GATEWAYS
        ],
        "recent_payments": [
            {
                "id": p.id, "gateway": p.gateway.value if p.gateway else None,
                "status": p.status.value if p.status else None,
                "amount": _major_units(int(p.amount or 0), p.currency), "currency": p.currency or "IRR",
                "reseller": reseller, "created_at": p.created_at.isoformat() if p.created_at else None,
            }
            for p, reseller in recent
        ],
        "resellers": {
            "count": int(reseller_count or 0),
            "balance_total_irr": int(balance_total or 0),
            "top": [{"username": r.username, "balance_irr": int(r.balance or 0)} for r in top],
        },
        "ledger": [
            {
                "reseller": username, "kind": e.kind, "amount_irr": int(e.amount),
                "note": e.note, "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e, username in ledger
        ],
    }


# ═══════════════════════════════════════════════════════════════
#  Automation (runs from Celery beat; see app/ops_automation.py)
# ═══════════════════════════════════════════════════════════════

class AutomationUpdate(BaseModel):
    auto_cloak_enabled: bool | None = None
    auto_protocol_order_enabled: bool | None = None
    ops_alerts_enabled: bool | None = None


async def _automation_status(db: AsyncSession) -> dict[str, Any]:
    from .. import ops_automation as auto

    s = await _load_legacy_settings(db)
    state = await auto.load_state(db)
    return {
        "settings": auto.automation_settings(s),
        "telegram_configured": auto.telegram_configured(s),
        "last_run_at": state.get("last_run_at"),
        "last_delivery_ok": state.get("last_delivery_ok"),
        "blocked": state.get("blocked") or [],
        "silent_probes": len(state.get("silent_probes") or []),
        "log": state.get("log") or [],
        "cloak": {**_cloak_state(s), "manual_off_at": s.get("emergency_cloak_manual_off_at")},
        "rules": {
            "engage": f"success < {round(auto.CLOAK_ENGAGE_MAX_OK * 100)}% over "
                      f"{int(auto.CLOAK_ENGAGE_WINDOW.total_seconds() // 60)} min "
                      f"(≥ {auto.CLOAK_MIN_RESULTS} tests, ≥ {auto.CLOAK_ENGAGE_MIN_PROBES} probes)",
            "release": f"success ≥ {round(auto.CLOAK_RELEASE_MIN_OK * 100)}% over "
                       f"{int(auto.CLOAK_RELEASE_WINDOW.total_seconds() // 60)} min, "
                       f"after ≥ {int(auto.CLOAK_MIN_ON.total_seconds() // 60)} min on",
            "manual_off_hold_hours": int(auto.MANUAL_OFF_COOLDOWN.total_seconds() // 3600),
        },
    }


@router.get("/automation")
async def get_automation(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    return await _automation_status(db)


@router.post("/automation")
async def update_automation(
    data: AutomationUpdate,
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    update = data.model_dump(exclude_none=True)
    if update:
        await _save_legacy_settings(db, update)
        await record_audit(db, "automation_updated", admin_id=admin.id, details=update, request=request)
    return await _automation_status(db)


@router.post("/automation/run")
async def run_automation_now(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Run one automation tick now (the same one Celery beat runs every minute)."""
    from ..ops_automation import run_monitor

    result = await run_monitor(db)
    return {**result, "status": await _automation_status(db)}


@router.post("/automation/test-alert")
async def test_alert(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    from ..ops_automation import send_telegram, telegram_configured

    s = await _load_legacy_settings(db)
    if not telegram_configured(s):
        raise HTTPException(400, "Telegram is not configured: enable it and set the bot token and chat ID in Settings")
    ok = await send_telegram(s, "🧪 <b>تست هشدار پنل</b>\n\nهشدارهای خودکار به این چت ارسال می‌شوند.\n\n🤖 V7LTHRONYX Panel")
    if not ok:
        raise HTTPException(502, "Telegram did not accept the message: check the bot token and chat ID")
    return {"ok": True}
