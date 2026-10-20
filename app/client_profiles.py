"""sing-box and Clash (mihomo) subscription profiles.

Built from the user's share links (compat._core._build_share_links), so a
profile can never disagree with the links or the servers. ShadowTLS, which
has no share link, is added straight from the settings.

- sing-box JSON: Hiddify, NekoBox, the sing-box apps (SFA / SFI / SFM).
  Covers every protocol except XHTTP and Mieru (sing-box has neither).
- Clash JSON-as-YAML (YAML is a superset of JSON): Clash Meta / mihomo,
  Clash Verge, FlClash. Covers everything except NaiveProxy.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from typing import Any

from .standalone_engines import client_credentials, standalone_settings


def _q(qs: dict, key: str, default: str = "") -> str:
    v = qs.get(key)
    return v[0] if v else default


def parse_link(link: str) -> dict[str, Any] | None:
    """A share link as a neutral node description; None when unknown."""
    scheme, _, rest = link.partition("://")
    if scheme == "vmess":
        j = json.loads(base64.b64decode(rest + "=" * (-len(rest) % 4)))
        return {
            "proto": "vmess", "name": j.get("ps", "VMess"), "server": j["add"], "port": int(j["port"]),
            "uuid": j["id"], "network": j.get("net") or "tcp", "security": j.get("tls") or "none",
            "sni": j.get("sni", ""), "host": j.get("host", ""), "path": j.get("path", ""),
            "fp": j.get("fp", ""), "alpn": j.get("alpn", ""), "pcs": j.get("pcs", ""), "vcn": j.get("vcn", ""),
        }
    u = urllib.parse.urlsplit(link)
    qs = urllib.parse.parse_qs(u.query)
    name = urllib.parse.unquote(u.fragment) or scheme
    base = {"name": name, "server": u.hostname, "port": u.port}
    user = urllib.parse.unquote(u.username or "")
    pw = urllib.parse.unquote(u.password or "")
    common = {k: _q(qs, k) for k in ("sni", "fp", "alpn", "path", "host", "pcs", "vcn", "pbk", "sid", "flow", "mode")}
    if scheme in ("vless", "trojan"):
        node = {**base, **common, "proto": scheme, "network": _q(qs, "type", "tcp"),
                "security": _q(qs, "security", "tls" if scheme == "trojan" else "none")}
        node["uuid" if scheme == "vless" else "password"] = user
        node["service_name"] = _q(qs, "serviceName") or common["path"]
        return node
    if scheme == "ss":
        try:
            method, password = base64.urlsafe_b64decode(user + "=" * (-len(user) % 4)).decode().split(":", 1)
        except Exception:
            method, password = user, pw
        return {**base, "proto": "ss", "method": method, "password": password}
    if scheme == "hysteria2":
        return {**base, "proto": "hysteria2", "password": user, "sni": _q(qs, "sni"),
                "obfs_password": _q(qs, "obfs-password") if _q(qs, "obfs") == "salamander" else "",
                "pin": _q(qs, "pinSHA256"), "insecure": _q(qs, "insecure") == "1", "ports": _q(qs, "mport")}
    if scheme == "tuic":
        return {**base, "proto": "tuic", "uuid": user, "password": pw, "sni": _q(qs, "sni"),
                "alpn": _q(qs, "alpn", "h3"), "cc": _q(qs, "congestion_control", "bbr"),
                "udp_relay_mode": _q(qs, "udp_relay_mode", "native"), "insecure": _q(qs, "allow_insecure") == "1"}
    if scheme == "naive+https":
        return {**base, "proto": "naive", "username": user, "password": pw}
    if scheme == "mierus":  # the simple link carries no name
        return {**base, "name": "V7LTHRONYX-Mieru", "proto": "mieru", "port": int(_q(qs, "port") or 0), "username": user, "password": pw,
                "transport": _q(qs, "protocol", "TCP"), "multiplexing": _q(qs, "multiplexing", "MULTIPLEXING_LOW")}
    return None


def shadowtls_node(state: dict, user, server_ip: str) -> dict[str, Any] | None:
    from .standalone_engines import engine_installed

    if not (state.get("shadowtls_enabled") and engine_installed("sing-box")):
        return None
    st = standalone_settings(state)
    c = client_credentials(state, user)["shadowtls"]
    return {"proto": "shadowtls", "name": "V7LTHRONYX-ShadowTLS", "server": server_ip, "port": st["shadowtls_port"],
            "sni": st["shadowtls_sni"], "password": c["password"], "method": c["ss_method"],
            "ss_password": c["ss_password"]}


def naive_node(state: dict, user, server_ip: str, cert_pem: str) -> dict[str, Any] | None:
    """Naive on a self-signed certificate: no link (Chromium-based clients
    accept no pin), but sing-box can trust the certificate itself."""
    from .standalone_engines import engine_installed

    if not (state.get("naiveproxy_enabled") and cert_pem and engine_installed("sing-box")):
        return None
    st = standalone_settings(state)
    c = client_credentials(state, user)["naiveproxy"]
    return {"proto": "naive", "name": "V7LTHRONYX-Naive", "server": server_ip, "port": st["naive_port"],
            "username": c["username"], "password": c["password"], "cert_pem": cert_pem}


def nodes_for(user, server_ip: str, links: dict[str, str], state: dict, cert_pem: str = "") -> list[dict[str, Any]]:
    nodes = []
    for key, link in links.items():
        if not link or key.endswith("_ipv6") or key == "wireguard":
            continue
        node = parse_link(link)
        if node:
            node["key"] = key
            nodes.append(node)
    stls = shadowtls_node(state, user, server_ip)
    if stls:
        stls["key"] = "shadowtls"
        nodes.append(stls)
    if links.get("wireguard"):
        from .standalone_engines import (
            wireguard_server_keys,
            wireguard_user_address,
            wireguard_user_keys,
        )

        st = standalone_settings(state)
        nodes.append({"proto": "wireguard", "key": "wireguard", "name": "V7LTHRONYX-WireGuard",
                      "server": server_ip, "port": st["wireguard_port"],
                      "address": wireguard_user_address(state, user), "private_key": wireguard_user_keys(user)[0],
                      "peer_public_key": wireguard_server_keys()[1], "mtu": st["wireguard_mtu"]})
    if not links.get("naiveproxy"):
        naive = naive_node(state, user, server_ip, cert_pem)
        if naive:
            naive["key"] = "naiveproxy"
            nodes.append(naive)
    seen: dict[str, int] = {}
    for n in nodes:  # tags must be unique
        seen[n["name"]] = seen.get(n["name"], 0) + 1
        if seen[n["name"]] > 1:
            n["name"] = f"{n['name']}-{seen[n['name']]}"
    return nodes


# ── sing-box ────────────────────────────────────────────────────────────

def _sb_tls(n: dict, spki_pin: str, alpn: list[str] | None = None) -> dict:
    tls: dict[str, Any] = {"enabled": True, "server_name": n.get("vcn") or n.get("sni") or n["server"]}
    if n.get("pcs") or n.get("pin"):
        tls["certificate_public_key_sha256"] = [spki_pin]
    elif n.get("insecure"):
        tls["insecure"] = True
    if alpn:
        tls["alpn"] = alpn
    if n.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": n["fp"]}
    return tls


def _sb_transport(n: dict) -> dict | None:
    net = n.get("network") or "tcp"
    if net == "ws":
        t: dict[str, Any] = {"type": "ws", "path": n.get("path") or "/"}
        if n.get("host"):
            t["headers"] = {"Host": n["host"]}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": n.get("service_name") or n.get("path") or ""}
    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": n.get("path") or "/"}
        if n.get("host"):
            t["host"] = n["host"]
        return t
    return None


def singbox_outbounds(nodes: list[dict], spki_pin: str) -> list[dict]:
    out: list[dict] = []
    for n in nodes:
        p, tag = n["proto"], n["name"]
        base = {"tag": tag, "server": n["server"], "server_port": n["port"]}
        if p in ("vmess", "vless", "trojan"):
            if n.get("network") not in (None, "tcp", "ws", "grpc", "httpupgrade"):
                continue  # XHTTP: not a sing-box transport
            ob: dict[str, Any] = {"type": p, **base}
            if p == "vmess":
                ob.update(uuid=n["uuid"], security="auto", alter_id=0)
            elif p == "vless":
                ob["uuid"] = n["uuid"]
                if n.get("flow"):
                    ob["flow"] = n["flow"]
            else:
                ob["password"] = n["password"]
            if n.get("security") == "reality":
                ob["tls"] = {"enabled": True, "server_name": n["sni"],
                             "utls": {"enabled": True, "fingerprint": n.get("fp") or "chrome"},
                             "reality": {"enabled": True, "public_key": n["pbk"], "short_id": n.get("sid", "")}}
            elif n.get("security") == "tls":
                ob["tls"] = _sb_tls(n, spki_pin)
            tr = _sb_transport(n)
            if tr:
                ob["transport"] = tr
            out.append(ob)
        elif p == "ss":
            out.append({"type": "shadowsocks", **base, "method": n["method"], "password": n["password"]})
        elif p == "hysteria2":
            ob = {"type": "hysteria2", **base, "password": n["password"], "tls": _sb_tls(n, spki_pin, ["h3"])}
            if n.get("obfs_password"):
                ob["obfs"] = {"type": "salamander", "password": n["obfs_password"]}
            if n.get("ports"):
                ob["server_ports"] = [n["ports"].replace("-", ":")]
            out.append(ob)
        elif p == "tuic":
            out.append({"type": "tuic", **base, "uuid": n["uuid"], "password": n["password"],
                        "congestion_control": n["cc"], "udp_relay_mode": n["udp_relay_mode"],
                        "tls": _sb_tls(n, spki_pin, [n.get("alpn") or "h3"])})
        elif p == "naive":
            tls = {"enabled": True, "server_name": n["server"]}
            if n.get("cert_pem"):
                tls["certificate"] = n["cert_pem"].strip().splitlines()
            out.append({"type": "naive", **base, "username": n["username"], "password": n["password"], "tls": tls})
        elif p == "wireguard":  # an endpoint in sing-box 1.11+
            out.append({"type": "wireguard", "tag": tag, "address": [f"{n['address']}/32"],
                        "private_key": n["private_key"], "mtu": n["mtu"],
                        "peers": [{"address": n["server"], "port": n["port"], "public_key": n["peer_public_key"],
                                   "allowed_ips": ["0.0.0.0/0", "::/0"], "persistent_keepalive_interval": 25}]})
        elif p == "shadowtls":
            out.append({"type": "shadowsocks", "tag": tag, "method": n["method"], "password": n["ss_password"],
                        "detour": tag + "-shadowtls"})
            out.append({"type": "shadowtls", **base, "tag": tag + "-shadowtls", "version": 3,
                        "password": n["password"],
                        "tls": {"enabled": True, "server_name": n["sni"],
                                "utls": {"enabled": True, "fingerprint": "chrome"}}})
    return out


def singbox_profile(user, server_ip: str, links: dict[str, str], state: dict, spki_pin: str,
                    cert_pem: str = "") -> dict:
    nodes = singbox_outbounds(nodes_for(user, server_ip, links, state, cert_pem), spki_pin)
    names = [o["tag"] for o in nodes if not o["tag"].endswith("-shadowtls")]
    endpoints = [o for o in nodes if o["type"] == "wireguard"]
    nodes = [o for o in nodes if o["type"] != "wireguard"]
    profile = {
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True, "strict_route": True},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto", *names], "default": "auto"},
            {"type": "urltest", "tag": "auto", "outbounds": names,
             "url": "https://www.gstatic.com/generate_204", "interval": "5m"},
            *nodes,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {"final": "proxy", "auto_detect_interface": True},
    }
    if endpoints:
        profile["endpoints"] = endpoints
    return profile


# ── Clash / mihomo ──────────────────────────────────────────────────────

def _clash_tls(n: dict, leaf_pin: str, cp: dict) -> None:
    cp["tls"] = True
    cp["servername" if n["proto"] in ("vmess", "vless") else "sni"] = n.get("vcn") or n.get("sni") or n["server"]
    if n.get("pcs") or n.get("pin"):
        cp["fingerprint"] = leaf_pin
    elif n.get("insecure"):
        cp["skip-cert-verify"] = True
    if n.get("fp"):
        cp["client-fingerprint"] = n["fp"]


def clash_proxies(nodes: list[dict], leaf_pin: str) -> list[dict]:
    out: list[dict] = []
    for n in nodes:
        p = n["proto"]
        cp: dict[str, Any] = {"name": n["name"], "server": n["server"], "port": n["port"], "udp": True}
        if p in ("vmess", "vless", "trojan"):
            net = n.get("network") or "tcp"
            cp["type"] = p
            if p == "vmess":
                cp.update(uuid=n["uuid"], alterId=0, cipher="auto")
            elif p == "vless":
                cp["uuid"] = n["uuid"]
                if n.get("flow"):
                    cp["flow"] = n["flow"]
            else:
                cp["password"] = n["password"]
            if n.get("security") == "reality":
                cp.update({"tls": True, "servername": n["sni"], "client-fingerprint": n.get("fp") or "chrome",
                           "reality-opts": {"public-key": n["pbk"], "short-id": n.get("sid", "")}})
            elif n.get("security") == "tls":
                _clash_tls(n, leaf_pin, cp)
            if net == "ws" or net == "httpupgrade":
                opts: dict[str, Any] = {"path": n.get("path") or "/"}
                if n.get("host"):
                    opts["headers"] = {"Host": n["host"]}
                if net == "httpupgrade":
                    opts["v2ray-http-upgrade"] = True
                cp["network"] = "ws"
                cp["ws-opts"] = opts
            elif net == "grpc":
                cp["network"] = "grpc"
                cp["grpc-opts"] = {"grpc-service-name": n.get("service_name") or n.get("path") or ""}
            elif net == "xhttp":
                cp["network"] = "xhttp"
                cp["xhttp-opts"] = {"path": n.get("path") or "/", "mode": n.get("mode") or "auto"}
                if n.get("host"):
                    cp["xhttp-opts"]["host"] = n["host"]
            else:
                cp["network"] = "tcp"
            out.append(cp)
        elif p == "ss":
            out.append({**cp, "type": "ss", "cipher": n["method"], "password": n["password"]})
        elif p == "shadowtls":
            out.append({**cp, "type": "ss", "cipher": n["method"], "password": n["ss_password"],
                        "plugin": "shadow-tls", "client-fingerprint": "chrome",
                        "plugin-opts": {"host": n["sni"], "password": n["password"], "version": 3}})
        elif p == "hysteria2":
            cp.update(type="hysteria2", password=n["password"], alpn=["h3"])
            _clash_tls(n, leaf_pin, cp)
            cp.pop("tls", None)
            if n.get("obfs_password"):
                cp.update({"obfs": "salamander", "obfs-password": n["obfs_password"]})
            if n.get("ports"):
                cp["ports"] = n["ports"]
            out.append(cp)
        elif p == "tuic":
            cp.update({"type": "tuic", "uuid": n["uuid"], "password": n["password"], "alpn": [n.get("alpn") or "h3"],
                       "congestion-controller": n["cc"], "udp-relay-mode": n["udp_relay_mode"]})
            _clash_tls(n, leaf_pin, cp)
            cp.pop("tls", None)
            out.append(cp)
        elif p == "wireguard":
            out.append({**cp, "type": "wireguard", "ip": n["address"], "private-key": n["private_key"],
                        "public-key": n["peer_public_key"], "mtu": n["mtu"]})
        elif p == "mieru":
            out.append({**cp, "type": "mieru", "transport": n["transport"], "username": n["username"],
                        "password": n["password"], "multiplexing": n["multiplexing"]})
    return out


def clash_profile(user, server_ip: str, links: dict[str, str], state: dict, leaf_pin: str) -> dict:
    proxies = clash_proxies(nodes_for(user, server_ip, links, state), leaf_pin)
    names = [p["name"] for p in proxies]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["AUTO", *names]},
            {"name": "AUTO", "type": "url-test", "proxies": names,
             "url": "https://www.gstatic.com/generate_204", "interval": 300},
        ],
        "rules": ["MATCH,PROXY"],
    }


