"""Root-owned allowlisted helper for system operations.

Install as its own systemd service. The socket is group-readable by
``vpnpanel``; SO_PEERCRED additionally rejects callers outside that group.
"""

from __future__ import annotations

import asyncio
import grp
import json
import os
import pwd
import socket
import struct
import subprocess
from pathlib import Path
from typing import Any

SOCKET_PATH = Path(os.environ.get("PRIVILEGED_HELPER_SOCKET", "/run/v7lthronyx/helper.sock"))
PANEL_USER = os.environ.get("PANEL_USER", "vpnpanel")
PANEL_GROUP = os.environ.get("PANEL_GROUP", "vpnpanel")
# A full Xray config carries every user on every inbound (~1.5 KB per user).
MAX_REQUEST = 32 * 1024 * 1024

SERVICES = {"xray", "sing-box", "mita", "fail2ban"}
EGRESS_BLOCKED_PORTS = (23, 25, 139, 445, 465, 587, 3389)
# The mita .deb installs /usr/bin/mita; a manual install may use /usr/local/bin.
MITA = next((p for p in ("/usr/bin/mita", "/usr/local/bin/mita") if os.path.exists(p)), "/usr/bin/mita")
CONFIG_TARGETS = {
    "xray": Path("/usr/local/etc/xray/config.json"),
    "sing-box": Path("/usr/local/etc/sing-box/config.json"),
    "mieru": Path("/usr/local/etc/mieru/server.json"),
}


def _resolve_argv(argv: list[str]) -> list[str]:
    """Find sbin tools such as nft when the unit's PATH omits /usr/sbin."""
    if not argv or os.path.isabs(argv[0]):
        return argv
    for directory in ("/usr/local/sbin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/bin", "/bin"):
        candidate = os.path.join(directory, argv[0])
        if os.access(candidate, os.X_OK):
            return [candidate, *argv[1:]]
    return argv


def _run(argv: list[str], timeout: int = 30) -> dict[str, Any]:
    proc = subprocess.run(_resolve_argv(argv), capture_output=True, text=True, timeout=timeout, check=False)
    output = (proc.stderr or proc.stdout or "").strip()[-2000:]
    return {"ok": proc.returncode == 0, "message": output, "code": proc.returncode}


def _atomic_config(target_name: str, content: str) -> dict[str, Any]:
    target = CONFIG_TARGETS.get(target_name)
    if target is None or len(content.encode("utf-8")) > MAX_REQUEST:
        return {"ok": False, "message": "invalid config target or size"}
    try:
        json.loads(content)
    except json.JSONDecodeError:
        return {"ok": False, "message": "config is not valid JSON"}
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    # Create with final permissions so secrets are never briefly world-readable.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(tmp, 0o640)
    os.replace(tmp, target)
    # root:panel-group 0640. The panel user can validate the file, and the
    # xray user reads it via SupplementaryGroups=vpnpanel. 0640 root:root
    # made /api/ready fail and left Xray unable to open its own config.
    try:
        os.chown(target, 0, grp.getgrnam(PANEL_GROUP).gr_gid)
    except KeyError:
        pass
    os.chmod(target, 0o640)
    return {"ok": True, "message": "config installed"}


def _install_fail2ban() -> dict[str, Any]:
    filters = Path("/etc/fail2ban/filter.d")
    jails = Path("/etc/fail2ban/jail.d")
    if not filters.is_dir() or not jails.is_dir():
        return {"ok": False, "message": "fail2ban is not installed"}
    (filters / "v7lthronyx-panel.conf").write_text(
        "[Definition]\nfailregex = ^.*Failed login attempt.*from <HOST>.*$\nignoreregex =\n",
        encoding="utf-8",
    )
    (filters / "v7lthronyx-xray.conf").write_text(
        "[Definition]\nfailregex = ^.*rejected.*from <HOST>.*$\nignoreregex =\n",
        encoding="utf-8",
    )
    (jails / "v7lthronyx.conf").write_text(
        "[v7lthronyx-panel]\n"
        "enabled=true\nfilter=v7lthronyx-panel\nport=38471\n"
        "logpath=/opt/v7lthronyx/vpn-panel.log\nmaxretry=3\nbantime=3600\nfindtime=600\n\n"
        "[v7lthronyx-xray]\n"
        "enabled=true\nfilter=v7lthronyx-xray\n"
        "port=443,2052:2059,2083,8443,8444,8449\n"
        "logpath=/var/log/xray/error.log\nmaxretry=3\nbantime=3600\nfindtime=600\n",
        encoding="utf-8",
    )
    for path in (
        filters / "v7lthronyx-panel.conf",
        filters / "v7lthronyx-xray.conf",
        jails / "v7lthronyx.conf",
    ):
        os.chmod(path, 0o640)
    result = _run(["systemctl", "reload", "fail2ban"])
    result["data"] = {"installed": result["ok"]}
    return result


def _update_egress_rules(action: str) -> dict[str, Any]:
    if action not in {"apply", "remove"}:
        return {"ok": False, "message": "invalid firewall action"}
    failures: list[str] = []
    for port in EGRESS_BLOCKED_PORTS:
        for protocol in ("tcp", "udp"):
            rule = ["OUTPUT", "-p", protocol, "--dport", str(port), "-j", "DROP"]
            check = _run(["iptables", "-C", *rule])
            if action == "apply" and not check["ok"]:
                result = _run(["iptables", "-A", *rule])
                if not result["ok"]:
                    failures.append(f"{protocol}/{port}: {result['message']}")
            elif action == "remove" and check["ok"]:
                result = _run(["iptables", "-D", *rule])
                if not result["ok"]:
                    failures.append(f"{protocol}/{port}: {result['message']}")
    return {
        "ok": not failures,
        "message": "; ".join(failures) if failures else f"egress rules {action}d",
        "data": {"ports": list(EGRESS_BLOCKED_PORTS), "action": action},
    }


def _dispatch(operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    if operation == "certificate.issue":
        domain = str(payload.get("domain", "")).lower()
        contact = str(payload.get("contact_email", ""))
        mode = str(payload.get("mode", "acme"))
        import re
        if not re.fullmatch(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", domain):
            return {"ok": False, "message": "invalid domain"}
        if len(contact) > 254 or mode not in {"acme", "self-signed"}:
            return {"ok": False, "message": "invalid certificate request"}
        from .domain_manager import _generate_self_signed_cert, _issue_letsencrypt_cert
        issued = (
            _generate_self_signed_cert(domain)
            if mode == "self-signed"
            else _issue_letsencrypt_cert(domain, contact)
        )
        return {
            "ok": issued.success,
            "message": issued.error or "certificate issued",
            "data": {"domain": domain, "steps": issued.steps, "issuer": mode},
        }
    if operation in {"service.reload", "service.restart"}:
        service = str(payload.get("service", ""))
        if service not in SERVICES:
            return {"ok": False, "message": "service is not allowlisted"}
        action = operation.rsplit(".", 1)[1]
        return _run(["systemctl", action, service])
    if operation == "config.install":
        return _atomic_config(str(payload.get("target", "")), str(payload.get("content", "")))
    if operation == "mieru.apply":
        # `replace`, not `apply`: apply merges, so removed users stayed.
        # `reload` keeps live sessions; it fails when mita is not started.
        replaced = _run([MITA, "replace", "config", str(CONFIG_TARGETS["mieru"])])
        if not replaced["ok"]:
            return replaced
        reloaded = _run([MITA, "reload"])
        return reloaded if reloaded["ok"] else _run([MITA, "start"])
    if operation == "mieru.stop":
        return _run([MITA, "stop"])
    # Per-user traffic (see app/traffic_kernel.py): counting, speed limits,
    # Mieru byte counts, Hysteria2 port hopping. All input is validated there.
    if operation == "traffic.accounting.read":
        from .traffic_kernel import read_accounting
        return read_accounting()
    if operation == "traffic.shaping.apply":
        from .traffic_kernel import apply_shaping
        return apply_shaping(payload.get("users", []))
    if operation == "traffic.mieru.read":
        from .traffic_kernel import mieru_traffic
        return mieru_traffic(MITA)
    if operation == "hysteria2.port_hop":
        from .traffic_kernel import hysteria2_port_hop
        target = payload.get("target")
        if not isinstance(target, int):
            return {"ok": False, "message": "invalid target port"}
        return hysteria2_port_hop(str(payload.get("ports", "")), target)
    if operation == "wireguard.remove_peer":
        import re
        interface = str(payload.get("interface", ""))
        public_key = str(payload.get("public_key", ""))
        if not re.fullmatch(r"wg[0-9]{1,3}", interface) or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", public_key):
            return {"ok": False, "message": "invalid WireGuard request"}
        removed = _run(["wg", "set", interface, "peer", public_key, "remove"])
        if not removed["ok"]:
            return removed
        return _run(["wg-quick", "save", interface])
    if operation == "firewall.allow_port":
        port = payload.get("port")
        protocol = str(payload.get("protocol", "tcp"))
        if not isinstance(port, int) or not 1 <= port <= 65535 or protocol not in {"tcp", "udp"}:
            return {"ok": False, "message": "invalid firewall rule"}
        return _run(["ufw", "allow", f"{port}/{protocol}"])
    if operation == "firewall.egress.apply":
        return _update_egress_rules("apply")
    if operation == "firewall.egress.remove":
        return _update_egress_rules("remove")
    if operation == "fail2ban.install":
        return _install_fail2ban()
    if operation == "fail2ban.unban":
        jail, address = str(payload.get("jail", "")), str(payload.get("address", ""))
        if jail not in {"v7lthronyx-panel", "v7lthronyx-xray", "sshd"} or len(address) > 45:
            return {"ok": False, "message": "invalid fail2ban request"}
        import ipaddress
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return {"ok": False, "message": "invalid IP address"}
        return _run(["fail2ban-client", "set", jail, "unbanip", address])
    return {"ok": False, "message": "operation is not allowlisted"}


def _peer_allowed(writer: asyncio.StreamWriter) -> bool:
    sock = writer.get_extra_info("socket")
    if sock is None:
        return False
    pid, uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    del pid
    expected_uid = pwd.getpwnam(PANEL_USER).pw_uid
    expected_gid = grp.getgrnam(PANEL_GROUP).gr_gid
    return uid == expected_uid and gid == expected_gid


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        if not _peer_allowed(writer):
            result = {"ok": False, "message": "unauthorized peer"}
        else:
            raw = await asyncio.wait_for(reader.readline(), timeout=5)
            if not raw or len(raw) > MAX_REQUEST:
                result = {"ok": False, "message": "invalid request size"}
            else:
                request = json.loads(raw)
                operation = request.get("operation")
                payload = request.get("payload", {})
                if not isinstance(operation, str) or not isinstance(payload, dict):
                    result = {"ok": False, "message": "invalid request"}
                else:
                    result = await asyncio.to_thread(_dispatch, operation, payload)
    except (TimeoutError, ValueError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
        result = {"ok": False, "message": f"{type(exc).__name__}: {exc}"}
    writer.write(json.dumps(result, separators=(",", ":")).encode() + b"\n")
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def start_server(path: Path) -> asyncio.AbstractServer:
    # Requests are one JSON line. The stream's default line limit (64 KiB)
    # would refuse an Xray config past ~35 users, so match MAX_REQUEST.
    return await asyncio.start_unix_server(_handle, path=str(path), limit=MAX_REQUEST + 1)


async def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("privileged helper must run as root")
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()
    server = await start_server(SOCKET_PATH)
    os.chown(SOCKET_PATH, 0, grp.getgrnam(PANEL_GROUP).gr_gid)
    # Group-only socket (panel group); SO_PEERCRED additionally checks each caller.
    os.chmod(SOCKET_PATH, 0o660)  # nosec B103
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
