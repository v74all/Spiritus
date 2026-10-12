from __future__ import annotations

from fastapi import APIRouter

from ._core import *  # noqa: F403

router = APIRouter(tags=["compat"])


# ─────────────────────────────────────────────────────────────────────────────
#  Settings
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/settings")
async def legacy_get_settings(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    defaults = {
        "config_prefix": "Proxy",
        "vmess_port": 443,
        "vmess_sni": "www.aparat.com",
        "vmess_ws_path": "/api/v1/stream",
        "kill_switch_enabled": False,
        "reality_sni": "chat.deepseek.com",
        "vless_port": 2053,
        "reality_public_key": settings.reality_public_key,
        "vless": True,
        "vless_enabled": True,
        "trojan_enabled": False,
        "trojan_port": 2083,
        "grpc_enabled": False,
        "grpc_port": 2054,
        "grpc_service_name": "GunService",
        "httpupgrade_enabled": False,
        "httpupgrade_port": 2055,
        "httpupgrade_path": "/httpupgrade",
        "fragment_enabled": False,
        "fragment_packets": "tlshello",
        "fragment_length": "100-200",
        "fragment_interval": "10-20",
        "mux_enabled": False,
        "mux_concurrency": 8,
        "ss2022_enabled": False,
        "ss2022_port": 2056,
        "ss2022_method": "2022-blake3-aes-128-gcm",
        "ss2022_server_key": "",
        "vless_ws_enabled": settings.vless_ws_enabled,
        "vless_ws_port": settings.vless_ws_port,
        "vless_ws_path": settings.vless_ws_path,
        "fingerprint": "chrome",
        "noise_enabled": False,
        "noise_packet": "rand:50-100",
        "noise_delay": "10-20",
        "cdn_enabled": settings.cdn_enabled,
        "cdn_domain": settings.cdn_domain,
        "cdn_ws_path": settings.cdn_ws_path,
        "cdn_port": settings.cdn_port,
        "telegram_enabled": False,
        "telegram_bot_token": getattr(settings, 'telegram_bot_token', ''),
        "telegram_chat_id": getattr(settings, 'telegram_chat_id', ''),
        "telegram_notify_user_disabled": True,
        "telegram_notify_user_expired": True,
        "telegram_notify_kill_switch": True,
        "telegram_notify_traffic_exhausted": True,
        "telegram_notify_user_created": False,
        "telegram_notify_user_deleted": False,
        "dpi_tcp_fragment": False,
        "dpi_tls_fragment": False,
        "dpi_ip_fragment": False,
        "dpi_tcp_keepalive": False,
        "dpi_dns_tunnel": False,
        "dpi_icmp_tunnel": False,
        "dpi_domain_front": False,
        "dpi_cdn_front_enabled": False,
        "dpi_cdn_front": "",
        # Host Header Spoofing
        "dpi_http_host_spoof_enabled": False,
        "dpi_http_host_spoof_domain": "chat.deepseek.com",
        "dpi_ws_host_front_enabled": False,
        "dpi_ws_host_front_domain": "rubika.ir",
        "dpi_cdn_host_front_enabled": False,
        "dpi_cdn_host_front_domain": "web.splus.ir",
        "dpi_bug_host_enabled": False,
        "dpi_bug_host_domain": "chat.deepseek.com",
        # Advanced Network Resilience
        "dpi_packet_reorder": False,
        "dpi_dynamic_port": False,
        "dpi_fake_http": False,
        "dpi_traffic_shape": False,
        "dpi_multi_path": False,
        "dpi_protocol_hop": False,
        "dpi_aggression_level": "medium",
        # VLESS XHTTP REALITY
        "vless_xhttp_enabled": True,
        "vless_xhttp_port": 2053,
        "vless_xhttp_mode": "auto",
        "vless_xhttp_path": "/xhttp",
        "vless_xhttp_reality_sni": "digikala.com",
        "vless_xhttp_reality_dest": "digikala.com:443",
        "vless_xhttp_reality_short_id": "",
        "vless_xhttp_reality_public_key": settings.reality_public_key,
        # VLESS Vision REALITY
        "vless_vision_enabled": True,
        "vless_vision_port": 2058,
        "vless_vision_reality_sni": "objects.githubusercontent.com",
        "vless_vision_reality_dest": "objects.githubusercontent.com:443",
        "vless_vision_reality_short_id": "",
        "vless_vision_reality_public_key": settings.reality_public_key,
        # VLESS Reverse REALITY
        "vless_reverse_enabled": True,
        "vless_reverse_port": 2059,
        # Hysteria2
        "hysteria2_enabled": True,
        "hysteria2_port": 8443,
        # TUIC
        "tuic_enabled": True,
        "tuic_port": 8444,
        # AmneziaWG
        "amneziawg_enabled": False,
        "amneziawg_port": 51820,
        # ShadowTLS
        "shadowtls_enabled": False,
        "shadowtls_port": 8445,
        # Mieru
        "mieru_enabled": False,
        "mieru_port": 8446,
        # NaiveProxy
        "naiveproxy_enabled": False,
        "naiveproxy_port": 8447,
        # WireGuard
        "wireguard_enabled": False,
        "wireguard_port": 51821,
        # OpenVPN
        "openvpn_enabled": False,
        "openvpn_port": 1194,
    }
    merged = _normalize_settings_types({**defaults, **await _load_legacy_settings(db)})
    return merged


def _get_active_vmess_clients() -> list:
    """Fetch active user UUIDs for VMess inbounds."""
    try:
        import asyncio

        from ...database import async_engine
        async def _fetch():
            async with async_engine.connect() as conn:
                result = await conn.execute(
                    select(VpnUser.uuid, VpnUser.name).where(VpnUser.active == 1)
                )
                return [{"id": row.uuid, "alterId": 0, "email": row.name} for row in result.all()]
        try:
            asyncio.get_running_loop()
            # Running inside async context — create new loop in new thread
            import concurrent.futures
            def _run_in_thread():
                new_loop = asyncio.new_event_loop()
                try:
                    return new_loop.run_until_complete(_fetch())
                finally:
                    new_loop.close()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(_run_in_thread).result(timeout=10)
        except RuntimeError:
            return asyncio.run(_fetch())
    except Exception as e:
        logger.warning(f"Failed to fetch VMess clients: {e}")
        return []


def _get_active_vless_clients() -> list:
    """Fetch active user UUIDs for VLESS inbounds."""
    try:
        import asyncio

        from ...database import async_engine
        async def _fetch():
            async with async_engine.connect() as conn:
                result = await conn.execute(
                    select(VpnUser.uuid, VpnUser.name).where(VpnUser.active == 1)
                )
                return [{"id": row.uuid, "email": row.name} for row in result.all()]
        try:
            asyncio.get_running_loop()
            import concurrent.futures
            def _run_in_thread():
                new_loop = asyncio.new_event_loop()
                try:
                    return new_loop.run_until_complete(_fetch())
                finally:
                    new_loop.close()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(_run_in_thread).result(timeout=10)
        except RuntimeError:
            return asyncio.run(_fetch())
    except Exception as e:
        logger.warning(f"Failed to fetch VLESS clients: {e}")
        return []


def _get_active_trojan_clients() -> list:
    """Fetch active user passwords (UUIDs) for Trojan inbounds."""
    try:
        import asyncio

        from ...database import async_engine
        async def _fetch():
            async with async_engine.connect() as conn:
                result = await conn.execute(
                    select(VpnUser.uuid, VpnUser.name).where(VpnUser.active == 1)
                )
                return [{"password": row.uuid, "email": row.name} for row in result.all()]
        try:
            asyncio.get_running_loop()
            import concurrent.futures
            def _run_in_thread():
                new_loop = asyncio.new_event_loop()
                try:
                    return new_loop.run_until_complete(_fetch())
                finally:
                    new_loop.close()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(_run_in_thread).result(timeout=10)
        except RuntimeError:
            return asyncio.run(_fetch())
    except Exception as e:
        logger.warning(f"Failed to fetch Trojan clients: {e}")
        return []


async def _fetch_clients_async() -> tuple:
    """Async-safe user fetch for use inside a running event loop."""
    try:
        from ...database import async_engine
        async with async_engine.connect() as conn:
            result = await conn.execute(
                select(VpnUser.uuid, VpnUser.name).where(VpnUser.active == 1)
            )
            rows = result.all()
        vmess   = [{"id": r.uuid, "alterId": 0, "email": r.name} for r in rows]
        vless   = [{"id": r.uuid, "email": r.name} for r in rows]
        trojan  = [{"password": r.uuid, "email": r.name} for r in rows]
        return vmess, vless, trojan
    except Exception as e:
        logger.warning("_fetch_clients_async failed: %s", e)
        return [], [], []


def _generate_xray_server_config(
    vmess_clients: list | None = None,
    vless_clients: list | None = None,
    trojan_clients: list | None = None,
) -> dict:
    """Generate the server-side Xray config with inbounds for all enabled protocols.

    Optionally accepts pre-fetched client lists so callers running inside an
    async context can avoid the sync thread-pool fallback.
    """
    s = _settings_state
    inbounds = []
    sni = s.get("vmess_sni") or "www.aparat.com"
    fp = s.get("fingerprint") or "chrome"
    reality_pk = s.get("reality_private_key") or settings.reality_private_key
    s.get("reality_public_key") or settings.reality_public_key
    reality_sid = s.get("reality_short_id") or ""
    # IPv6 dual-stack: "::" accepts both v4+v6 on Linux (IPV6_V6ONLY=false)
    listen_addr = "::" if _as_bool(s.get("ipv6_enabled")) else "0.0.0.0"

    cert_file = settings.tls_cert_file
    key_file = settings.tls_key_file

    # Xray runs as 'nobody' by default. If the cert/key files exist but are not
    # world-readable, xray crashes with "permission denied". We copy them to the
    # xray config dir (which is already accessible to xray) and use those copies.
    _XRAY_CERT = "/usr/local/etc/xray/server.crt"
    _XRAY_KEY  = "/usr/local/etc/xray/server.key"

    def _ensure_xray_readable(src_cert: str, src_key: str) -> tuple:
        """Return (cert_path, key_path) that xray can read, copying if needed."""
        import shutil
        try:
            os.makedirs("/usr/local/etc/xray", exist_ok=True)
            for src, dst in [(src_cert, _XRAY_CERT), (src_key, _XRAY_KEY)]:
                if os.path.exists(src):
                    shutil.copy2(src, dst)
                    os.chmod(dst, 0o644)
            return _XRAY_CERT, _XRAY_KEY
        except Exception as exc:
            logger.warning("Could not copy TLS certs to xray dir: %s", exc)
            return src_cert, src_key

    # If the cert files are missing, ALL TLS-bearing inbounds (VMess-WS, VLESS-
    # WS, Trojan, gRPC, HTTPUpgrade, SS2022, CDN-WS, WS-Plain-Front, ...) would
    # crash-loop Xray with "open: no such file or directory". We detect that
    # here once and gate every TLS inbound on the result. REALITY-mode inbounds
    # (VLESS-Reality / Vision / XHTTP) don't need cert files and stay enabled.
    _tls_ready = bool(cert_file) and bool(key_file) \
        and os.path.exists(cert_file) and os.path.exists(key_file)
    if _tls_ready:
        cert_file, key_file = _ensure_xray_readable(cert_file, key_file)
    else:
        logger.warning(
            "Xray sync: TLS cert/key missing (cert=%s, key=%s). "
            "Skipping TLS-bearing inbounds; only REALITY inbounds will start.",
            cert_file, key_file,
        )

    # Fetch active user UUIDs for client authentication (use provided lists or
    # fall back to the sync thread-pool helper when called from sync context).
    if vmess_clients is None:
        vmess_clients = _get_active_vmess_clients()
    if vless_clients is None:
        vless_clients = _get_active_vless_clients()
    if trojan_clients is None:
        trojan_clients = _get_active_trojan_clients()

    # VMess WS+TLS (always-on when TLS is available; skipped otherwise)
    if _tls_ready:
        inbounds.append({
            "tag": "in-vmess-ws",
            "port": int(s.get("vmess_port") or 443),
            "listen": listen_addr,
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": s.get("vmess_ws_path") or "/api/v1/stream"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                    "minVersion": "1.2",
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        })

    # VLESS REALITY (Vision)
    if s.get("reality_public_key"):
        inbounds.append({
            "tag": "in-vless-reality",
            "port": int(s.get("vless_port") or 2053),
            "listen": listen_addr,
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [s.get("reality_sni") or "chat.deepseek.com"],
                    "dest": s.get("reality_dest") or "chat.deepseek.com:443",
                    "privateKey": reality_pk,
                    "shortIds": [reality_sid] if reality_sid else [""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS XHTTP REALITY (use distinct port to avoid collision with VLESS Reality)
    if _as_bool(s.get("vless_xhttp_enabled")):
        xhttp_sni = s.get("vless_xhttp_reality_sni") or "digikala.com"
        xhttp_dest = s.get("vless_xhttp_reality_dest") or "digikala.com:443"
        xhttp_pk = s.get("vless_xhttp_reality_private_key") or reality_pk
        xhttp_sid = s.get("vless_xhttp_reality_short_id") or ""
        raw_xhttp_port = int(s.get("vless_xhttp_port") or 0)
        vless_port_val = int(s.get("vless_port") or 2053)
        # Avoid port collision with standard VLESS Reality inbound
        xhttp_port = (
            raw_xhttp_port
            if raw_xhttp_port and raw_xhttp_port != vless_port_val
            else 8449  # Safe default for XHTTP Reality
        )
        inbounds.append({
            "tag": "in-vless-xhttp",
            "port": xhttp_port,
            "listen": listen_addr,
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "xhttpSettings": {
                    "mode": s.get("vless_xhttp_mode") or "auto",
                    "path": s.get("vless_xhttp_path") or "/xhttp",
                    "host": xhttp_sni,
                },
                "realitySettings": {
                    "serverNames": [xhttp_sni],
                    "dest": xhttp_dest,
                    "privateKey": xhttp_pk,
                    "shortIds": [xhttp_sid] if xhttp_sid else [""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS Vision REALITY
    if _as_bool(s.get("vless_vision_enabled")):
        vision_sni = s.get("vless_vision_reality_sni") or "objects.githubusercontent.com"
        vision_dest = s.get("vless_vision_reality_dest") or "objects.githubusercontent.com:443"
        inbounds.append({
            "tag": "in-vless-vision",
            "port": int(s.get("vless_vision_port") or 2058),
            "listen": listen_addr,
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [vision_sni],
                    "dest": vision_dest,
                    "privateKey": reality_pk,
                    "shortIds": [s.get("vless_vision_reality_short_id") or ""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS Reverse REALITY (backhaul-tunneled)
    if _as_bool(s.get("vless_reverse_enabled")):
        rev_sni = s.get("vless_reverse_reality_sni") or "digikala.com"
        rev_dest = s.get("vless_reverse_reality_dest") or "digikala.com:443"
        rev_sid = s.get("vless_reverse_reality_short_id") or ""
        inbounds.append({
            "tag": "in-vless-reverse",
            "port": int(s.get("vless_reverse_port") or 2059),
            "listen": listen_addr,
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [rev_sni],
                    "dest": rev_dest,
                    "privateKey": reality_pk,
                    "shortIds": [rev_sid] if rev_sid else [""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # Trojan TCP+TLS
    if _as_bool(s.get("trojan_enabled")) and _tls_ready:
        inbounds.append({
            "tag": "in-trojan",
            "port": int(s.get("trojan_port") or 2083),
            "listen": listen_addr,
            "protocol": "trojan",
            "settings": {"clients": trojan_clients},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # gRPC
    if _as_bool(s.get("grpc_enabled")) and _tls_ready:
        inbounds.append({
            "tag": "in-grpc",
            "port": int(s.get("grpc_port") or 2054),
            "listen": listen_addr,
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {"serviceName": s.get("grpc_service_name") or "GunService"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # HTTPUpgrade
    if _as_bool(s.get("httpupgrade_enabled")) and _tls_ready:
        inbounds.append({
            "tag": "in-httpupgrade",
            "port": int(s.get("httpupgrade_port") or 2055),
            "listen": listen_addr,
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "httpupgradeSettings": {"path": s.get("httpupgrade_path") or "/httpupgrade"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS WS+TLS
    if _as_bool(s.get("vless_ws_enabled")) and _tls_ready:
        inbounds.append({
            "tag": "in-vless-ws",
            "port": int(s.get("vless_ws_port") or 2057),
            "listen": listen_addr,
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": s.get("vless_ws_path") or "/vless-ws"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS WS+TLS Domain Fronting — TLS with spoofed SNI
    # Client connects directly to our server with TLS, SNI shows a trusted domain
    # (e.g. chat.deepseek.com) to bypass DPI. Server terminates TLS with its own cert.
    if _as_bool(s.get("vless_ws_plain_front_enabled")) and _tls_ready:
        _front_host = s.get("vless_ws_plain_front_domain") or "chat.deepseek.com"
        _front_port = int(s.get("vless_ws_plain_front_port") or 2052)
        inbounds.append({
            "tag": "in-vless-ws-plain",
            "port": _front_port,
            "listen": listen_addr,
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "path": s.get("vless_ws_plain_front_path") or "/",
                },
                "tlsSettings": {
                    "serverName": _front_host,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # ShadowSocks 2022
    if _as_bool(s.get("ss2022_enabled")) and s.get("ss2022_server_key") and _tls_ready:
        inbounds.append({
            "tag": "in-ss2022",
            "port": int(s.get("ss2022_port") or 2056),
            "listen": listen_addr,
            "protocol": "shadowsocks",
            "settings": {
                "method": s.get("ss2022_method") or "2022-blake3-aes-128-gcm",
                "password": s.get("ss2022_server_key"),
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # ── Google Apps Script Relay HTTP Proxy (emergency — always on) ──
    inbounds.append({
        "tag": "in-http-relay",
        "port": 8080,
        "listen": listen_addr,
        "protocol": "http",
        "settings": {"auth": "noauth"},
        "sniffing": {"enabled": True, "destOverride": ["http"]},
    })

    # CDN WS+TLS
    if _as_bool(s.get("cdn_enabled")) and s.get("cdn_domain") and _tls_ready:
        cdn_domain = s.get("cdn_domain")
        inbounds.append({
            "tag": "in-cdn-ws",
            "port": int(s.get("cdn_port") or 2082),
            "listen": listen_addr,
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": s.get("cdn_ws_path") or "/cdn-ws"},
                "tlsSettings": {
                    "serverName": cdn_domain,
                    "certificates": [{"certificateFile": cert_file, "keyFile": key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


def _schedule_xray_sync():
    """Schedule a background Xray config sync after settings change."""
    try:
        import asyncio
        loop = asyncio.get_running_loop()
        loop.create_task(_sync_xray_config_async())
    except RuntimeError:
        # No running loop (e.g., called from thread) — fall back to thread
        import threading
        t = threading.Thread(target=_sync_xray_config_now, daemon=True)
        t.start()
    except Exception:
        pass


async def _sync_xray_config_async():
    """Generate and write the Xray server config (async, runs in main event loop)."""
    try:
        await asyncio.sleep(0.5)  # Small delay to let settings settle

        # Fetch users via async-safe path — avoids the thread+new-loop approach
        # that conflicts with asyncpg's connection pool during startup.
        vmess_clients, vless_clients, trojan_clients = await _fetch_clients_async()

        config = _generate_xray_server_config(vmess_clients, vless_clients, trojan_clients)
        installed = await helper_request(
            "config.install",
            {"target": "xray", "content": json.dumps(config, indent=2)},
        )
        if not installed.ok:
            raise RuntimeError(installed.message or "config install failed")
        restarted = await helper_request("service.restart", {"service": "xray"}, timeout=35)
        if not restarted.ok:
            raise RuntimeError(restarted.message or "Xray restart failed")
        logger.info("Xray config auto-synced (%d inbounds, %d users)",
                    len(config.get("inbounds", [])), len(vmess_clients))
    except Exception as e:
        logger.warning(f"Async Xray sync failed: {e}")


def _sync_xray_config_now():
    """Generate and write the Xray server config (sync, for thread fallback)."""
    try:
        import time
        time.sleep(0.5)
        config = _generate_xray_server_config()
        installed = helper_request_sync(
            "config.install",
            {"target": "xray", "content": json.dumps(config, indent=2)},
        )
        if not installed.ok:
            raise RuntimeError(installed.message or "config install failed")
        restarted = helper_request_sync("service.restart", {"service": "xray"}, timeout=35)
        if not restarted.ok:
            raise RuntimeError(restarted.message or "Xray restart failed")
        logger.info(f"Xray config synced ({len(config.get('inbounds', []))} inbounds)")
    except Exception as e:
        logger.warning(f"Xray sync failed: {e}")


@router.post("/settings")
async def legacy_save_settings(
    data: dict[str, Any],
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    await _save_legacy_settings(db, data)
    _schedule_xray_sync()
    return {"ok": True, "rebuild": True}


@router.post("/settings/regenerate-reality")
async def legacy_regenerate_reality(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    import secrets

    private_key = ""
    public_key = ""
    try:
        result = subprocess.run(
            [settings.xray_bin_path, "x25519"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.strip().splitlines():
            if line.startswith("PrivateKey:"):
                private_key = line.split(":", 1)[1].strip()
            elif line.startswith("PublicKey:"):
                public_key = line.split(":", 1)[1].strip()
    except Exception:
        private_key = ""
        public_key = ""

    if not private_key or not public_key:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519

        key = x25519.X25519PrivateKey.generate()
        private_raw = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_raw = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        private_key = base64.urlsafe_b64encode(private_raw).decode().rstrip("=")
        public_key = base64.urlsafe_b64encode(public_raw).decode().rstrip("=")

    short_id = secrets.token_hex(4)
    await _save_legacy_settings(
        db,
        {
            "reality_private_key": private_key,
            "reality_public_key": public_key,
            "reality_short_id": short_id,
        },
    )
    return {"ok": True, "public_key": public_key, "short_id": short_id}


@router.post("/settings/generate-ss2022-key")
async def legacy_generate_ss2022_key(
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    import base64
    import secrets

    key = base64.b64encode(secrets.token_bytes(16)).decode()
    await _save_legacy_settings(db, {"ss2022_server_key": key})
    return {"ok": True, "ss2022_server_key": key}


__all__ = [_n for _n in list(globals()) if not _n.startswith("__")]
