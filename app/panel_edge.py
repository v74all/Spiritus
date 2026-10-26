"""Publish the panel on the active domain without taking VPN traffic.

Port 443 stays the public door. TLS with the panel's own name goes to the
panel over HTTPS. Every other name on 443 (the camouflage SNI in client
configs) still goes to Xray. Plain IP access on the panel port is unchanged.

The SNI split hands both backends a loopback connection, so it speaks the
PROXY protocol to them: without it every visitor reached the panel as
127.0.0.1, which the admin IP allowlist always lets in and which put every
visitor in one login rate-limit bucket.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

XRAY_LOOPBACK_PORT = 10443
PANEL_TLS_PORT = 18443
ACME_WEBROOT = "/etc/v7lthronyx/acme-web"
_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
# The cert paths are written into nginx.conf, which root's nginx master
# parses: a ';', '{' or newline in a file name would add directives.
_SAFE_PATH = re.compile(r"/[A-Za-z0-9._/-]{1,250}")
# Only the TLS directories: root-owned, and holding nothing but certificates.
_CERT_ROOTS = (Path("/etc/v7lthronyx/tls"), Path("/opt/v7lthronyx/tls"))


def retarget_shared_443(inbounds: list) -> list:
    """When a domain is active, Xray must not bind the public 443."""
    from .domain_manager import cached_active_domain

    if not cached_active_domain():
        return inbounds
    for inbound in inbounds:
        try:
            port = int(inbound.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if port == 443 and inbound.get("listen") != "127.0.0.1":
            inbound["listen"] = "127.0.0.1"
            inbound["port"] = XRAY_LOOPBACK_PORT
            # nginx's stream proxy announces the real client (see _write_configs).
            stream = inbound.setdefault("streamSettings", {})
            stream.setdefault("sockopt", {})["acceptProxyProtocol"] = True
    return inbounds


def apply_edge(domain: str, cert: str, key: str) -> dict:
    domain = (domain or "").strip().lower()
    if not _DOMAIN.fullmatch(domain):
        return {"ok": False, "message": "invalid domain"}
    cert_path, key_path = _allowed_cert(cert), _allowed_cert(key)
    if cert_path is None or key_path is None:
        return {"ok": False, "message": "certificate path is not allowed"}
    if not cert_path.is_file() or not key_path.is_file():
        return {"ok": False, "message": "certificate files are missing"}
    if not _nginx_installed():
        return {"ok": False, "message": "nginx is not installed"}
    _write_configs(domain, cert_path, key_path)
    reload = subprocess.run(
        ["systemctl", "reload", "nginx"], capture_output=True, text=True, timeout=20, check=False,
    )
    if reload.returncode != 0:
        start = subprocess.run(
            ["systemctl", "enable", "--now", "nginx"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if start.returncode != 0:
            return {"ok": False, "message": (start.stderr or start.stdout or "nginx start failed")[-400:]}
    return {"ok": True, "message": f"panel https://{domain}"}


def remove_edge() -> dict:
    for path in (
        Path("/etc/nginx/sites-enabled/spiritus-panel.conf"),
        Path("/etc/nginx/sites-available/spiritus-panel.conf"),
        Path("/etc/nginx/spiritus-stream.conf"),
    ):
        path.unlink(missing_ok=True)
    if _nginx_installed():
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=20, check=False)
    return {"ok": True, "message": "panel edge removed"}


def ensure_challenge_location(domain: str) -> None:
    """Let Let's Encrypt read the HTTP-01 token before the HTTPS redirect."""
    site = Path("/etc/nginx/sites-available/spiritus-panel.conf")
    if not site.is_file() or "acme-challenge" in site.read_text(encoding="utf-8"):
        return
    old = "    return 301 https://$host$request_uri;\n"
    new = (
        "    location ^~ /.well-known/acme-challenge/ {\n"
        f"        root {ACME_WEBROOT};\n"
        "        default_type text/plain;\n"
        "    }\n"
        "    location / {\n"
        "        return 301 https://$host$request_uri;\n"
        "    }\n"
    )
    text = site.read_text(encoding="utf-8")
    if old not in text:
        return
    site.write_text(text.replace(old, new, 1), encoding="utf-8")
    subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=20, check=False)


def _nginx_installed() -> bool:
    return Path("/usr/sbin/nginx").is_file()


def _allowed_cert(path: str) -> Path | None:
    """The resolved path when it is a plain file name inside a TLS directory."""
    if not _SAFE_PATH.fullmatch(path or ""):
        return None
    try:
        resolved = Path(path).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not _SAFE_PATH.fullmatch(str(resolved)):
        return None
    if not any(resolved.is_relative_to(root) for root in _CERT_ROOTS):
        return None
    return resolved


def _write_configs(domain: str, cert: Path, key: Path) -> None:
    stream = Path("/etc/nginx/spiritus-stream.conf")
    stream.write_text(
        "stream {\n"
        "    map $ssl_preread_server_name $spiritus_edge {\n"
        f"        {domain} 127.0.0.1:{PANEL_TLS_PORT};\n"
        f"        default 127.0.0.1:{XRAY_LOOPBACK_PORT};\n"
        "    }\n"
        "    server {\n"
        "        listen 443 reuseport;\n"
        "        listen [::]:443 reuseport;\n"
        "        proxy_pass $spiritus_edge;\n"
        "        proxy_protocol on;\n"
        "        ssl_preread on;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    nginx_conf = Path("/etc/nginx/nginx.conf")
    if nginx_conf.is_file() and "spiritus-stream.conf" not in nginx_conf.read_text(encoding="utf-8"):
        with nginx_conf.open("a", encoding="utf-8") as handle:
            handle.write("\ninclude /etc/nginx/spiritus-stream.conf;\n")
    site = (
        "server {\n"
        "    listen 80;\n"
        "    listen [::]:80;\n"
        f"    server_name {domain};\n"
        "    location ^~ /.well-known/acme-challenge/ {\n"
        f"        root {ACME_WEBROOT};\n"
        "        default_type text/plain;\n"
        "    }\n"
        "    location / {\n"
        "        return 301 https://$host$request_uri;\n"
        "    }\n"
        "}\n"
        "server {\n"
        f"    listen 127.0.0.1:{PANEL_TLS_PORT} ssl proxy_protocol;\n"
        f"    server_name {domain};\n"
        f"    ssl_certificate {cert};\n"
        f"    ssl_certificate_key {key};\n"
        "    location / {\n"
        "        proxy_pass http://127.0.0.1:38471;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Forwarded-Proto https;\n"
        # Replaces any X-Forwarded-For the client sent.
        "        proxy_set_header X-Forwarded-For $proxy_protocol_addr;\n"
        "        proxy_set_header X-Real-IP $proxy_protocol_addr;\n"
        "    }\n"
        "}\n"
    )
    available = Path("/etc/nginx/sites-available")
    enabled = Path("/etc/nginx/sites-enabled")
    available.mkdir(parents=True, exist_ok=True)
    enabled.mkdir(parents=True, exist_ok=True)
    (available / "spiritus-panel.conf").write_text(site, encoding="utf-8")
    link = enabled / "spiritus-panel.conf"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(available / "spiritus-panel.conf")
    default = enabled / "default"
    if default.exists() or default.is_symlink():
        default.unlink()
