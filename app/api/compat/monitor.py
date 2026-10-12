from __future__ import annotations

from fastapi import APIRouter

from ._core import *  # noqa: F403

router = APIRouter(tags=["compat"])


# ─────────────────────────────────────────────────────────────────────────────
#  Live, server-info, sync, system-monitor, online-users
# ─────────────────────────────────────────────────────────────────────────────

def _query_xray_stats(reset: bool = False) -> dict:
    """Query xray stats API and return {username: {up, down}} for all users."""
    try:
        xray_api = f"127.0.0.1:{getattr(settings, 'api_port', 10085)}"
        args = [settings.xray_bin_path, "api", "statsquery",
                f"--server={xray_api}",
                "--pattern", "user>>>"]
        if reset:
            args.append("--reset")
        result = subprocess.run(args, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return {}
        data = json.loads(result.stdout)
        stats: dict = {}
        for stat in data.get("stat", []):
            name = stat.get("name", "")
            value = int(stat.get("value") or 0)
            # name format: user>>>username>>>traffic>>>uplink|downlink
            parts = name.split(">>>")
            if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
                user = parts[1]
                direction = parts[3]
                if user not in stats:
                    stats[user] = {"up": 0, "down": 0}
                if direction == "uplink":
                    stats[user]["up"] = value
                elif direction == "downlink":
                    stats[user]["down"] = value
        return stats
    except Exception as e:
        logger.warning("xray stats query failed: %s", e)
        return {}


@router.get("/live")
async def legacy_live(admin: User = Depends(get_current_admin_cookie)):
    """Realtime traffic counters keyed by username (from xray stats, reset each call)."""
    stats = _query_xray_stats(reset=True)
    now = time.time()
    for username, s in stats.items():
        if (s.get("up") or 0) + (s.get("down") or 0) > 0:
            _user_last_seen[username] = now
    return stats


@router.get("/server-info")
async def legacy_server_info(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    # Auth required: this exposes the full server topology — every
    # protocol's port, SNI, REALITY dest/short-id and public keys.
    # It used to allow unauthenticated access (get_optional_user_cookie),
    # which handed an anonymous visitor a complete reconnaissance map.
    # The agent panel uses a separate /agent/server-info route, and the
    # internal agent call passes its own User object directly, so neither
    # is affected by tightening the HTTP guard here.
    s = await _load_legacy_settings(db)
    return {
        # VMess (always-on)
        "vmess_port": s.get("vmess_port", 443),
        "vmess_sni": s.get("vmess_sni", "www.aparat.com"),
        "vmess_ws_path": s.get("vmess_ws_path", "/api/v1/stream"),
        # VLESS Reality (Vision)
        "vless": bool(s.get("reality_public_key")) or _as_bool(s.get("vless_xhttp_enabled", False)) or _as_bool(s.get("vless_vision_enabled", False)),
        "vless_enabled": bool(s.get("reality_public_key")) or _as_bool(s.get("vless_xhttp_enabled", False)) or _as_bool(s.get("vless_vision_enabled", False)),
        "vless_port": s.get("vless_port", 2053),
        "vless_sni": s.get("reality_sni", "chat.deepseek.com"),
        "vless_public_key": s.get("reality_public_key", ""),
        "vless_short_id": s.get("reality_short_id", ""),
        # VLESS xHTTP REALITY
        "vless_xhttp": _as_bool(s.get("vless_xhttp_enabled", False)),
        "vless_xhttp_enabled": _as_bool(s.get("vless_xhttp_enabled", False)),
        "vless_xhttp_port": s.get("vless_xhttp_port", 2053),
        "vless_xhttp_mode": s.get("vless_xhttp_mode", "auto"),
        "vless_xhttp_path": s.get("vless_xhttp_path", "/xhttp"),
        "vless_xhttp_reality_sni": s.get("vless_xhttp_reality_sni", "digikala.com"),
        "vless_xhttp_reality_dest": s.get("vless_xhttp_reality_dest", "digikala.com:443"),
        "vless_xhttp_reality_short_id": s.get("vless_xhttp_reality_short_id", ""),
        "vless_xhttp_reality_public_key": s.get("vless_xhttp_reality_public_key", s.get("reality_public_key", "")),
        # VLESS Vision REALITY
        "vless_vision": _as_bool(s.get("vless_vision_enabled", False)),
        "vless_vision_enabled": _as_bool(s.get("vless_vision_enabled", False)),
        "vless_vision_port": s.get("vless_vision_port", 2058),
        "vless_vision_reality_sni": s.get("vless_vision_reality_sni", "objects.githubusercontent.com"),
        "vless_vision_reality_dest": s.get("vless_vision_reality_dest", "objects.githubusercontent.com:443"),
        "vless_vision_reality_short_id": s.get("vless_vision_reality_short_id", ""),
        "vless_vision_reality_public_key": s.get("vless_vision_reality_public_key", s.get("reality_public_key", "")),
        # VLESS Reverse REALITY
        "vless_reverse": _as_bool(s.get("vless_reverse_enabled", False)),
        "vless_reverse_enabled": _as_bool(s.get("vless_reverse_enabled", False)),
        "vless_reverse_port": s.get("vless_reverse_port", 2059),
        # Trojan
        "trojan": _as_bool(s.get("trojan_enabled", False)),
        "trojan_enabled": _as_bool(s.get("trojan_enabled", False)),
        "trojan_port": s.get("trojan_port", 2083),
        # Trojan CDN
        "trojan_cdn_enabled": _as_bool(s.get("trojan_cdn_enabled", False)),
        "trojan_cdn_port": s.get("trojan_cdn_port", 2083),
        # gRPC
        "grpc": _as_bool(s.get("grpc_enabled", False)),
        "grpc_enabled": _as_bool(s.get("grpc_enabled", False)),
        "grpc_port": s.get("grpc_port", 2054),
        "grpc_service": s.get("grpc_service_name", "GunService"),
        # HTTPUpgrade
        "httpupgrade": _as_bool(s.get("httpupgrade_enabled", False)),
        "httpupgrade_enabled": _as_bool(s.get("httpupgrade_enabled", False)),
        "httpupgrade_port": s.get("httpupgrade_port", 2055),
        "httpupgrade_path": s.get("httpupgrade_path", "/httpupgrade"),
        # ShadowSocks 2022
        "ss2022": bool(s.get("ss2022_server_key")),
        "ss2022_enabled": _as_bool(s.get("ss2022_enabled", False)) and bool(s.get("ss2022_server_key")),
        "ss2022_port": s.get("ss2022_port", 2056),
        # VLESS WS
        "vless_ws": _as_bool(s.get("vless_ws_enabled", settings.vless_ws_enabled)),
        "vless_ws_enabled": _as_bool(s.get("vless_ws_enabled", settings.vless_ws_enabled)),
        "vless_ws_port": s.get("vless_ws_port", settings.vless_ws_port),
        "vless_ws_path": s.get("vless_ws_path", settings.vless_ws_path),
        # VLESS WS Plain Front (Iranian domain fronting, no TLS)
        "vless_ws_plain_front": _as_bool(s.get("vless_ws_plain_front_enabled", settings.vless_ws_plain_front_enabled)),
        "vless_ws_plain_front_enabled": _as_bool(s.get("vless_ws_plain_front_enabled", settings.vless_ws_plain_front_enabled)),
        "vless_ws_plain_front_port": s.get("vless_ws_plain_front_port", settings.vless_ws_plain_front_port),
        "vless_ws_plain_front_domain": s.get("vless_ws_plain_front_domain", settings.vless_ws_plain_front_domain),
        "vless_ws_plain_front_path": s.get("vless_ws_plain_front_path", settings.vless_ws_plain_front_path),
        # Hysteria2
        "hysteria2": _as_bool(s.get("hysteria2_enabled", False)),
        "hysteria2_enabled": _as_bool(s.get("hysteria2_enabled", False)),
        "hysteria2_port": s.get("hysteria2_port", 8443),
        # TUIC v5
        "tuic": _as_bool(s.get("tuic_enabled", False)),
        "tuic_enabled": _as_bool(s.get("tuic_enabled", False)),
        "tuic_port": s.get("tuic_port", 8444),
        # AmneziaWG
        "amneziawg": _as_bool(s.get("amneziawg_enabled", False)),
        "amneziawg_enabled": _as_bool(s.get("amneziawg_enabled", False)),
        "amneziawg_port": s.get("amneziawg_port", 51820),
        # ShadowTLS v3
        "shadowtls": _as_bool(s.get("shadowtls_enabled", False)),
        "shadowtls_enabled": _as_bool(s.get("shadowtls_enabled", False)),
        "shadowtls_port": s.get("shadowtls_port", 8445),
        # Mieru
        "mieru": _as_bool(s.get("mieru_enabled", False)),
        "mieru_enabled": _as_bool(s.get("mieru_enabled", False)),
        "mieru_port": s.get("mieru_port", 8446),
        # NaiveProxy
        "naiveproxy": _as_bool(s.get("naiveproxy_enabled", False)),
        "naiveproxy_enabled": _as_bool(s.get("naiveproxy_enabled", False)),
        "naiveproxy_port": s.get("naiveproxy_port", 8447),
        # WireGuard
        "wireguard": _as_bool(s.get("wireguard_enabled", False)),
        "wireguard_enabled": _as_bool(s.get("wireguard_enabled", False)),
        "wireguard_port": s.get("wireguard_port", 51821),
        # OpenVPN
        "openvpn": _as_bool(s.get("openvpn_enabled", False)),
        "openvpn_enabled": _as_bool(s.get("openvpn_enabled", False)),
        "openvpn_port": s.get("openvpn_port", 1194),
        # CDN
        "cdn": _as_bool(s.get("cdn_enabled", settings.cdn_enabled)),
        "cdn_enabled": _as_bool(s.get("cdn_enabled", settings.cdn_enabled)),
        "cdn_domain": s.get("cdn_domain", settings.cdn_domain),
        "cdn_ws_path": s.get("cdn_ws_path", settings.cdn_ws_path),
        "cdn_port": s.get("cdn_port", settings.cdn_port),
        # Misc
        "fragment_enabled": _as_bool(s.get("fragment_enabled", False)),
        "mux_enabled": _as_bool(s.get("mux_enabled", False)),
        "kill_switch": _as_bool(s.get("kill_switch_enabled", False)),
        "telegram_enabled": _as_bool(s.get("telegram_enabled", False)),
        # Host Header Spoofing
        "dpi_http_host_spoof_enabled": _as_bool(s.get("dpi_http_host_spoof_enabled", False)),
        "dpi_http_host_spoof_domain": s.get("dpi_http_host_spoof_domain", "chat.deepseek.com"),
        "dpi_ws_host_front_enabled": _as_bool(s.get("dpi_ws_host_front_enabled", False)),
        "dpi_ws_host_front_domain": s.get("dpi_ws_host_front_domain", "rubika.ir"),
        "dpi_cdn_host_front_enabled": _as_bool(s.get("dpi_cdn_host_front_enabled", False)),
        "dpi_cdn_host_front_domain": s.get("dpi_cdn_host_front_domain", "web.splus.ir"),
        "dpi_bug_host_enabled": _as_bool(s.get("dpi_bug_host_enabled", False)),
        "dpi_bug_host_domain": s.get("dpi_bug_host_domain", "chat.deepseek.com"),
        # Tunneling
        "dpi_dns_tunnel": _as_bool(s.get("dpi_dns_tunnel", False)),
        "dpi_icmp_tunnel": _as_bool(s.get("dpi_icmp_tunnel", False)),
        # Domain / CDN Fronting
        "dpi_domain_front": _as_bool(s.get("dpi_domain_front", False)),
        "dpi_cdn_front_enabled": _as_bool(s.get("dpi_cdn_front_enabled", False)),
        "dpi_cdn_front": s.get("dpi_cdn_front", ""),
        # Advanced Network Resilience
        "dpi_packet_reorder": _as_bool(s.get("dpi_packet_reorder", False)),
        "dpi_dynamic_port": _as_bool(s.get("dpi_dynamic_port", False)),
        "dpi_fake_http": _as_bool(s.get("dpi_fake_http", False)),
        "dpi_traffic_shape": _as_bool(s.get("dpi_traffic_shape", False)),
        "dpi_multi_path": _as_bool(s.get("dpi_multi_path", False)),
        "dpi_protocol_hop": _as_bool(s.get("dpi_protocol_hop", False)),
        "dpi_aggression_level": s.get("dpi_aggression_level", "medium"),
        # IPv6
        "ipv6_enabled": _as_bool(s.get("ipv6_enabled", settings.ipv6_enabled)),
        "server_ipv6": s.get("server_ipv6", settings.vpn_server_ipv6),
        # Emergency Relay
        "emergency_relay_enabled": _as_bool(s.get("emergency_relay_enabled", False)),
        "emergency_relay_address": s.get("emergency_relay_address", ""),
    }


@router.post("/sync")
async def legacy_sync(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    now = _utcnow()
    result = await db.execute(
        select(VpnUser).where(VpnUser.expire_at.is_not(None), VpnUser.active == 1)
    )
    disabled = 0
    for u in result.scalars().all():
        if u.expire_at and u.expire_at < now:
            u.active = 0
            disabled += 1
    if disabled:
        await db.commit()
    return {"ok": True, "disabled": disabled}


@router.get("/system-monitor")
async def legacy_system_monitor(admin: User = Depends(get_current_admin_cookie)):
    import psutil

    cpu = psutil.cpu_percent(interval=0)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot = psutil.boot_time()
    net = psutil.net_io_counters()

    xray_pid = None
    xray_mem = 0
    xray_cpu = 0
    try:
        for proc in psutil.process_iter(["name", "pid", "memory_info", "cpu_percent"]):
            if "xray" in (proc.info.get("name") or "").lower():
                xray_pid = proc.info.get("pid")
                mi = proc.info.get("memory_info")
                xray_mem = mi.rss if mi else 0
                xray_cpu = proc.info.get("cpu_percent") or 0
                break
    except Exception:
        pass

    try:
        load_avg = list(os.getloadavg())
    except Exception:
        load_avg = [0.0, 0.0, 0.0]

    return {
        "cpu_percent": round(cpu, 1),
        "ram_percent": round(mem.percent, 1),
        "ram_used": mem.used,
        "ram_total": mem.total,
        "disk_percent": round(disk.percent, 1),
        "disk_used": disk.used,
        "disk_total": disk.total,
        "uptime_seconds": int(time.time() - boot),
        "xray_pid": xray_pid,
        "xray_mem": xray_mem,
        "xray_cpu": xray_cpu,
        "xray_version": "",
        "net_bytes_sent": net.bytes_sent,
        "net_bytes_recv": net.bytes_recv,
        "load_avg": load_avg,
    }


@router.get("/online-users")
async def legacy_online_users(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Return users who have had traffic in the last 90 seconds."""
    cutoff = time.time() - 90
    # Seed last-seen from cumulative xray stats on first call (before any /live poll)
    if not _user_last_seen:
        for username, s in _query_xray_stats(reset=False).items():
            if (s.get("up") or 0) + (s.get("down") or 0) > 0:
                _user_last_seen[username] = time.time()

    recently_active = [u for u, ts in _user_last_seen.items() if ts >= cutoff]
    if not recently_active:
        return []

    result = await db.execute(
        select(VpnUser).where(VpnUser.name.in_(recently_active), VpnUser.active == 1)
    )
    users = result.scalars().all()

    # Get latest cumulative stats for display (no reset)
    stats = _query_xray_stats(reset=False)

    online = []
    for u in users:
        s = stats.get(u.name, {})
        online.append({
            "name": u.name,
            "uuid": u.uuid,
            "upload": s.get("up", 0),
            "download": s.get("down", 0),
            "total": (s.get("up") or 0) + (s.get("down") or 0),
            "last_seen": _user_last_seen.get(u.name, 0),
        })

    online.sort(key=lambda x: x["last_seen"], reverse=True)
    return online


@router.get("/traffic-history")
async def legacy_traffic_history(
    days: int = Query(30, ge=1, le=365),
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    # No time-series log table exists yet, so we approximate daily traffic
    # by grouping users' current traffic_used by the date their record was
    # last updated. This won't reflect intra-day changes but gives a real
    # picture of which days saw user activity rather than an empty chart.
    cutoff = _utcnow() - timedelta(days=days)
    result = await db.execute(
        select(VpnUser).where(VpnUser.updated_at >= cutoff)
    )
    users = result.scalars().all()

    # Aggregate traffic by date
    daily: dict[str, int] = {}
    for u in users:
        if u.updated_at:
            day = u.updated_at.strftime("%Y-%m-%d")
            daily[day] = daily.get(day, 0) + (u.traffic_used or 0)

    # Build a full list for the requested date range (0-fill missing days)
    out = []
    for i in range(days - 1, -1, -1):
        d = (_utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        out.append({"date": d, "traffic_bytes": daily.get(d, 0)})
    return out


@router.get("/traffic-history/top")
async def legacy_top_traffic(
    days: int = Query(30, ge=1, le=365),
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    result = await db.execute(
        select(VpnUser).order_by(VpnUser.traffic_used.desc()).limit(10)
    )
    return [
        {"username": u.name, "total_bytes": u.traffic_used or 0}
        for u in result.scalars().all()
    ]


__all__ = [_n for _n in list(globals()) if not _n.startswith("__")]
