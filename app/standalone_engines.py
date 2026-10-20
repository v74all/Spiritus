"""sing-box and mita servers for the protocols Xray does not serve:
Hysteria2, TUIC v5, ShadowTLS v3 and NaiveProxy on sing-box, Mieru on mita.

Rendered from the panel settings and the active users, with the credentials
the share links and subscriptions carry (see client_credentials): the two
sides must always agree. A password set in the settings is shared by every
user; left empty, each user signs in with their own UUID, which is what lets
one user be cut off without touching the others.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
from typing import Any

from .config import settings
from .protocol_engine import _parse_mbps, ss2022_key_length, ss2022_user_key

logger = logging.getLogger(__name__)

SHADOWTLS_SS_METHOD = "2022-blake3-aes-128-gcm"
CLASH_API = "127.0.0.1:9095"  # sing-box connection stats, loopback only

_EMPTY_SINGBOX = {
    "log": {"level": "warn"},
    "inbounds": [],
    "outbounds": [{"type": "direct", "tag": "direct"}],
}


def _on(state: dict, key: str) -> bool:
    v = state.get(key)
    return v is True or str(v).lower() in ("1", "true", "yes", "on")


def shadowtls_server_key(method: str = SHADOWTLS_SS_METHOD) -> str:
    """Server PSK of the Shadowsocks layer inside ShadowTLS: stable, secret,
    and never stored — derived from the panel's secret key."""
    digest = hmac.new(settings.secret_key.encode(), b"spiritus-shadowtls-ss", hashlib.sha256).digest()
    return base64.b64encode(digest[: ss2022_key_length(method)]).decode()


def client_credentials(state: dict, user) -> dict[str, dict[str, str]]:
    """Per-protocol credentials for one user, as server and client see them."""
    uid = user.uuid
    return {
        "hysteria2": {"password": state.get("hysteria2_password") or uid},
        "tuic": {"uuid": uid, "password": state.get("tuic_password") or uid},
        "shadowtls": {
            "password": state.get("shadowtls_password") or uid,
            "ss_method": SHADOWTLS_SS_METHOD,
            "ss_password": f"{shadowtls_server_key()}:{ss2022_user_key(uid, SHADOWTLS_SS_METHOD)}",
        },
        "naiveproxy": {
            "username": state.get("naiveproxy_user") or user.name,
            "password": state.get("naiveproxy_password") or uid,
        },
        "mieru": {
            "username": state.get("mieru_user") or user.name,
            "password": state.get("mieru_password") or uid,
        },
    }


def standalone_settings(state: dict) -> dict[str, Any]:
    """The values both the server and the client configs read."""
    sni_host = state.get("vmess_sni") or "www.aparat.com"
    return {
        "hysteria2_port": int(state.get("hysteria2_port") or 8443),
        "hysteria2_obfs": (state.get("hysteria2_salamander_password") or "")
        if _on(state, "hysteria2_salamander_enabled") else "",
        "hysteria2_up": _parse_mbps(state.get("hysteria2_bandwidth_up") or ""),
        "hysteria2_down": _parse_mbps(state.get("hysteria2_bandwidth_down") or ""),
        "hysteria2_hop": (state.get("hysteria2_port_hop_ports") or "")
        if _on(state, "hysteria2_port_hop_enabled") else "",
        "tuic_port": int(state.get("tuic_port") or 8444),
        "tuic_cc": state.get("tuic_congestion_control") or "bbr",
        "tuic_zero_rtt": _on(state, "tuic_zero_rtt"),
        "shadowtls_port": int(state.get("shadowtls_port") or 8445),
        "shadowtls_sni": state.get("shadowtls_sni") or sni_host,
        "naive_port": int(state.get("naiveproxy_port") or 8447),
        "naive_sni": state.get("naiveproxy_sni") or sni_host,
        "wireguard_port": int(state.get("wireguard_port") or 51821),
        "wireguard_address": state.get("wireguard_address") or "10.9.0.1/16",
        "wireguard_dns": state.get("wireguard_dns") or "1.1.1.1",
        "wireguard_mtu": int(state.get("wireguard_mtu") or 1280),
        "mieru_port": int(state.get("mieru_port") or 8446),
        "mieru_transport": "UDP" if str(state.get("mieru_transport") or "").upper() == "UDP" else "TCP",
        "mieru_mtu": int(state.get("mieru_mtu") or 1400),
    }


# ── WireGuard (a sing-box endpoint) ──
# Keys come from the panel's secret key, so nothing is stored: the server's
# from a fixed label, each user's from their UUID.

def _wg_keypair(label: bytes) -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    seed = hmac.new(settings.secret_key.encode(), b"spiritus-wireguard:" + label, hashlib.sha256).digest()
    key = X25519PrivateKey.from_private_bytes(seed)
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode(), base64.b64encode(pub).decode()


def wireguard_server_keys() -> tuple[str, str]:
    return _wg_keypair(b"server")


def wireguard_user_keys(user) -> tuple[str, str]:
    return _wg_keypair(b"user:" + user.uuid.encode())


def wireguard_user_address(state: dict, user) -> str | None:
    """The user's tunnel address: host number id + 1 in the configured
    network (the server holds .1). None when the network is full."""
    import ipaddress

    try:
        iface = ipaddress.ip_interface(standalone_settings(state)["wireguard_address"])
    except ValueError:
        return None
    host = int(iface.network.network_address) + 1 + int(user.id)
    if host >= int(iface.network.broadcast_address) or host == int(iface.ip):
        return None
    return str(ipaddress.ip_address(host))


def wireguard_client_conf(state: dict, user, server_ip: str) -> str | None:
    address = wireguard_user_address(state, user)
    if not address:
        return None
    st = standalone_settings(state)
    priv, _ = wireguard_user_keys(user)
    _, server_pub = wireguard_server_keys()
    host = f"[{server_ip}]" if ":" in server_ip else server_ip
    return (
        "[Interface]\n"
        f"PrivateKey = {priv}\n"
        f"Address = {address}/32\n"
        f"DNS = {st['wireguard_dns']}\n"
        f"MTU = {st['wireguard_mtu']}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_pub}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {host}:{st['wireguard_port']}\n"
        "PersistentKeepalive = 25\n"
    )


# Chromium's TLS stack (inside every Naive client) refuses certificates
# valid for more than 200 days, even one the client is told to trust.
NAIVE_CERT_DAYS = 180
NAIVE_RENEW_DAYS = 30


def naive_certificate(state: dict, server_ip: str) -> tuple[str, str, bool]:
    """(cert_pem, key_pem, is_new) for Naive on a server without a publicly
    trusted certificate: self-signed, short-lived, for the server's IP,
    renewed a month before it runs out. Profiles carry the certificate."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.UTC)
    cert_pem, key_pem = state.get("naive_cert_pem") or "", state.get("naive_key_pem") or ""
    if cert_pem and key_pem:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            ips = {str(a) for a in san.get_values_for_type(x509.IPAddress)}
            if cert.not_valid_after_utc - now > datetime.timedelta(days=NAIVE_RENEW_DAYS) and server_ip in ips:
                return cert_pem, key_pem, False
        except Exception:  # noqa: BLE001 - unreadable: make a new one
            pass
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "spiritus-naive")])
    sans: list[x509.GeneralName] = []
    try:
        sans.append(x509.IPAddress(ipaddress.ip_address(server_ip)))
    except ValueError:
        sans.append(x509.DNSName(server_ip))
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=NAIVE_CERT_DAYS))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode(),
        True,
    )


def _dedupe(entries: list[dict]) -> list[dict]:
    seen, out = set(), []
    for e in entries:
        key = json.dumps(e, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(e)
    return out


def singbox_server_config(state: dict, users: list, cert_file: str, key_file: str,
                          naive_pem: tuple[str, str] | None = None, mark_users: bool = True) -> dict | None:
    """sing-box config for every enabled standalone protocol, or None."""
    st = standalone_settings(state)
    have_cert = bool(cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file))
    creds = [(u, client_credentials(state, u)) for u in users]

    def tls(alpn: list[str]) -> dict:
        return {"enabled": True, "certificate_path": cert_file, "key_path": key_file, "alpn": alpn}

    inbounds: list[dict[str, Any]] = []
    if _on(state, "hysteria2_enabled") and have_cert:
        hy2: dict[str, Any] = {
            "type": "hysteria2", "tag": "hysteria2-in", "listen": "::", "listen_port": st["hysteria2_port"],
            "users": _dedupe([{"name": u.name, "password": c["hysteria2"]["password"]} for u, c in creds]),
            "tls": tls(["h3"]),
        }
        if st["hysteria2_up"]:
            hy2["up_mbps"] = st["hysteria2_up"]
        if st["hysteria2_down"]:
            hy2["down_mbps"] = st["hysteria2_down"]
        if st["hysteria2_obfs"]:
            hy2["obfs"] = {"type": "salamander", "password": st["hysteria2_obfs"]}
        inbounds.append(hy2)
    if _on(state, "tuic_enabled") and have_cert:
        inbounds.append({
            "type": "tuic", "tag": "tuic-in", "listen": "::", "listen_port": st["tuic_port"],
            "users": _dedupe([{"name": u.name, **c["tuic"]} for u, c in creds]),
            "congestion_control": st["tuic_cc"],
            "zero_rtt_handshake": st["tuic_zero_rtt"],
            "tls": tls(["h3"]),
        })
    if _on(state, "shadowtls_enabled"):
        # ShadowTLS v3 borrows a real site's TLS handshake (no certificate
        # of ours); the proxying is the multi-user SS-2022 layer it wraps.
        inbounds.append({
            "type": "shadowtls", "tag": "shadowtls-in", "listen": "::", "listen_port": st["shadowtls_port"],
            "version": 3, "strict_mode": True,
            "users": _dedupe([{"name": u.name, "password": c["shadowtls"]["password"]} for u, c in creds]),
            "handshake": {"server": st["shadowtls_sni"], "server_port": 443},
            "detour": "shadowtls-ss-in",
        })
        inbounds.append({
            "type": "shadowsocks", "tag": "shadowtls-ss-in", "listen": "127.0.0.1",
            "method": SHADOWTLS_SS_METHOD, "password": shadowtls_server_key(),
            "users": [{"name": u.name, "password": ss2022_user_key(u.uuid, SHADOWTLS_SS_METHOD)} for u in users],
        })
    if _on(state, "naiveproxy_enabled") and (have_cert or naive_pem):
        naive_tls = tls(["h2", "http/1.1"])
        if naive_pem:  # its own short-lived certificate, inline
            naive_tls.pop("certificate_path"), naive_tls.pop("key_path")
            naive_tls["certificate"] = naive_pem[0].strip().splitlines()
            naive_tls["key"] = naive_pem[1].strip().splitlines()
        inbounds.append({
            "type": "naive", "tag": "naive-in", "listen": "::", "listen_port": st["naive_port"],
            "users": _dedupe([{"username": c["naiveproxy"]["username"], "password": c["naiveproxy"]["password"]} for u, c in creds]),
            "tls": naive_tls,
        })
    endpoints: list[dict[str, Any]] = []
    wg_rules: list[dict[str, Any]] = []
    if _on(state, "wireguard_enabled"):
        server_priv, _ = wireguard_server_keys()
        peers = []
        for u in users:
            addr = wireguard_user_address(state, u)
            if addr:
                peers.append({"public_key": wireguard_user_keys(u)[1], "allowed_ips": [f"{addr}/32"]})
                wg_rules.append({"source_ip_cidr": [f"{addr}/32"], "outbound": f"u{u.id}"})
        endpoints.append({
            "type": "wireguard", "tag": "wireguard-in", "system": False,
            "mtu": st["wireguard_mtu"], "address": [st["wireguard_address"]],
            "private_key": server_priv, "listen_port": st["wireguard_port"], "peers": peers,
        })
    if not inbounds and not endpoints:
        return None
    # Each user leaves through a direct outbound carrying their mark: the
    # kernel counts their bytes and applies their speed limit there
    # (app/traffic_control.py). sing-box itself keeps no per-user counts.
    from .traffic_control import singbox_mark

    if not mark_users:  # sing-box without CAP_NET_ADMIN: marking would fail every dial
        marked, rules = [], []
    else:
        marked = [{"type": "direct", "tag": f"u{u.id}", "routing_mark": singbox_mark(u.id)} for u in users]
        rules = [{"auth_user": [u.name], "outbound": f"u{u.id}"} for u in users] + wg_rules
    config: dict[str, Any] = {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": [{"type": "direct", "tag": "direct"}, *marked],
        "route": {"rules": rules, "final": "direct"},
        "experimental": {"clash_api": {"external_controller": CLASH_API}},
    }
    if endpoints:
        config["endpoints"] = endpoints
    return config


def mieru_server_config(state: dict, users: list) -> dict | None:
    if not _on(state, "mieru_enabled") or not users:
        return None
    st = standalone_settings(state)
    return {
        "portBindings": [{"port": st["mieru_port"], "protocol": st["mieru_transport"]}],
        "users": _dedupe([
            {"name": c["mieru"]["username"], "password": c["mieru"]["password"]}
            for c in (client_credentials(state, u) for u in users)
        ]),
        "loggingLevel": "WARN",
        "mtu": st["mieru_mtu"],
    }


def engine_installed(name: str) -> bool:
    if name == "sing-box":
        paths = (settings.singbox_bin_path,)
    else:  # the mita .deb installs /usr/bin/mita
        paths = (settings.mieru_bin_path, "/usr/bin/mita", "/usr/local/bin/mita")
    return any(p and os.access(p, os.X_OK) for p in paths)


# What each worker last installed, so an unchanged config is not reloaded.
_installed: dict[str, str] = {}


async def apply_standalone_engines(db) -> dict[str, str]:
    """Render, install and (re)load sing-box and mita when their config changed."""
    from sqlalchemy import select

    from .api.compat import _load_legacy_settings
    from .api.compat._core import _save_legacy_settings, _settings_state
    from .models import VpnUser
    from .privileged_helper import PrivilegedHelperError, helper_request
    from .tls_trust import load_cert_info

    await _load_legacy_settings(db)
    state = dict(_settings_state)
    users = (await db.execute(select(VpnUser).where(VpnUser.active == 1))).scalars().all()
    status: dict[str, str] = {}

    naive_pem = None
    server_ip = state.get("server_ip") or settings.vpn_server_ip or ""
    cert = load_cert_info()
    if _on(state, "naiveproxy_enabled") and server_ip and (cert is None or cert.self_signed):
        cert_pem, key_pem, is_new = naive_certificate(state, server_ip)
        if is_new:
            await _save_legacy_settings(db, {"naive_cert_pem": cert_pem, "naive_key_pem": key_pem})
            logger.info("Made a %d-day certificate for NaiveProxy", NAIVE_CERT_DAYS)
        naive_pem = (cert_pem, key_pem)

    from .tls_trust import tls_files
    from .traffic_control import engine_can_mark

    can_mark = engine_can_mark("sing-box")
    if not can_mark:
        logger.warning("sing-box lacks CAP_NET_ADMIN: its users are not counted per user nor speed limited")
    sb = singbox_server_config(state, users, *tls_files(), naive_pem, mark_users=can_mark)
    mieru = mieru_server_config(state, users)
    plans = (
        ("sing-box", sb, _EMPTY_SINGBOX),
        ("mieru", mieru, None),
    )
    for name, config, idle in plans:
        engine = "sing-box" if name == "sing-box" else "mita"
        if not engine_installed(engine):
            status[name] = f"{engine} is not installed" if config is not None else "off"
            if config is not None:
                logger.warning("%s protocols are enabled but %s is not installed", name, engine)
            continue
        target = config if config is not None else idle
        if target is None:
            if _installed.get(name) not in (None, "stopped"):
                try:
                    await helper_request("mieru.stop", {}, timeout=20)
                except PrivilegedHelperError:
                    pass
                _installed[name] = "stopped"
            status[name] = "off"
            continue
        content = json.dumps(target, sort_keys=True)
        if _installed.get(name) == content:
            status[name] = "unchanged"
            continue
        try:
            installed = await helper_request("config.install", {"target": name, "content": content})
            if not installed.ok:
                raise PrivilegedHelperError(installed.message)
            if name == "sing-box":
                done = await helper_request("service.reload", {"service": "sing-box"}, timeout=35)
                if not done.ok:
                    done = await helper_request("service.restart", {"service": "sing-box"}, timeout=35)
            else:
                done = await helper_request("mieru.apply", {}, timeout=35)
            if not done.ok:
                raise PrivilegedHelperError(done.message)
        except PrivilegedHelperError as exc:
            status[name] = f"failed: {exc}"
            logger.warning("Could not apply %s config: %s", name, exc)
            continue
        _installed[name] = content
        status[name] = "applied"

    # Hysteria2 port hopping: clients hop across a UDP range that the
    # kernel redirects to the listener.
    st = standalone_settings(state)
    hop = st["hysteria2_hop"] if (_on(state, "hysteria2_enabled") and engine_installed("sing-box")) else ""
    hop_key = f"{hop}->{st['hysteria2_port']}"
    if _installed.get("hy2-hop", "->") != hop_key and (hop or "hy2-hop" in _installed):
        try:
            out = await helper_request("hysteria2.port_hop", {"ports": hop, "target": st["hysteria2_port"]})
            status["hysteria2-port-hop"] = out.message if out.ok else f"failed: {out.message}"
            if out.ok:
                _installed["hy2-hop"] = hop_key
        except PrivilegedHelperError as exc:
            status["hysteria2-port-hop"] = f"failed: {exc}"
    return status
