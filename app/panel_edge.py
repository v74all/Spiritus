"""Publish the panel on the active domain without taking VPN traffic.

Port 443 stays the public door. TLS with the panel's own name goes to the
panel over HTTPS. Every other name on 443 (the camouflage SNI in client
configs) still goes to Xray. Plain IP access on the panel port is unchanged.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

XRAY_LOOPBACK_PORT = 10443
PANEL_TLS_PORT = 18443
_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)


def retarget_shared_443(config: dict) -> dict:
    """When a domain is active, Xray must not bind the public 443."""
    from .domain_manager import cached_active_domain

    if not cached_active_domain():
        return config
    for inbound in config.get("inbounds") or []:
        try:
            port = int(inbound.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if port == 443 and inbound.get("listen") != "127.0.0.1":
            inbound["listen"] = "127.0.0.1"
            inbound["port"] = XRAY_LOOPBACK_PORT
    return config


def apply_edge(domain: str, cert: str, key: str) -> dict:
    domain = (domain or "").strip().lower()
    if not _DOMAIN.fullmatch(domain):
        return {"ok": False, "message": "invalid domain"}
    cert_path, key_path = Path(cert), Path(key)
    if not _allowed_cert(cert_path) or not _allowed_cert(key_path):
        return {"ok": False, "message": "certificate path is not allowed"}
    if not cert_path.is_file() or not key_path.is_file():
        return {"ok": False, "message": "certificate files are missing"}
    if not _nginx_installed():
        return {"ok": False, "message": "nginx is not installed"}
    _write_configs(domain, cert_path, key_path)
    proc = subprocess.run(
        ["nginx", "-t"], capture_output=True, text=True, timeout=20, check=False,
    )
    if proc.returncode != 0:
        return {"ok": False, "message": (proc.stderr or proc.stdout or "nginx -t failed")[-400:]}
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


def _nginx_installed() -> bool:
    return Path("/usr/sbin/nginx").is_file()


def _allowed_cert(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    allowed = (Path("/etc/v7lthronyx"), Path("/opt/v7lthronyx"))
    return any(resolved.is_relative_to(root) for root in allowed)


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
        "    return 301 https://$host$request_uri;\n"
        "}\n"
        "server {\n"
        f"    listen 127.0.0.1:{PANEL_TLS_PORT} ssl;\n"
        f"    server_name {domain};\n"
        f"    ssl_certificate {cert};\n"
        f"    ssl_certificate_key {key};\n"
        "    location / {\n"
        "        proxy_pass http://127.0.0.1:38471;\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Forwarded-Proto https;\n"
        "        proxy_set_header X-Forwarded-For $remote_addr;\n"
        "    }\n"
        "}\n"
    )
    available = Path("/etc/nginx/sites-available")
    enabled = Path("/etc/nginx/sites-enabled")
    available.mkdir(parents=True, exist_ok=True)
    enabled.mkdir(parents=True, exist_ok=True)
    (available / "spiritus-panel.conf").write_text(site, encoding="utf-8")
    link = enabled / "spiritus-panel.conf"
    if not link.exists():
        link.symlink_to(available / "spiritus-panel.conf")
    default = enabled / "default"
    if default.exists() or default.is_symlink():
        default.unlink()
