"""Kernel side of per-user traffic: runs as root inside the privileged helper.

The engines mark each user's outgoing connections (SO_MARK, see
app/traffic_control.py). Here:

- nftables counts bytes per mark for sing-box users (sing-box has no
  per-user statistics) and copies the mark onto the connection so replies
  can be matched too;
- tc shapes per mark: upload on the uplink interface's egress, download on
  its ingress, redirected through an IFB device where the connection's mark
  is restored first.

Everything is rebuilt from a declarative spec, so applying the same spec
twice is harmless. Nothing here is reachable except through the helper's
allowlisted operations, which validate their input.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Any

TABLE = "spiritus"
IFB = "spiritus-ifb"
MARK_KIND_MASK = 0x00F00000
SINGBOX_KIND = 0x00200000
MAX_LIMITED_USERS = 60000
_lock = threading.Lock()
MIERU_STATE = Path("/var/lib/v7lthronyx/mieru-traffic.json")

_NFT_RULESET = f"""
table inet {TABLE} {{
  set acct_up {{ type mark; flags dynamic; counter; size 1048576; }}
  set acct_down {{ type mark; flags dynamic; counter; size 1048576; }}
  chain out {{
    type filter hook output priority mangle; policy accept;
    meta mark and {MARK_KIND_MASK:#010x} != 0 ct mark set meta mark
    meta mark and {MARK_KIND_MASK:#010x} == {SINGBOX_KIND:#010x} update @acct_up {{ meta mark }}
  }}
  chain in {{
    type filter hook input priority mangle; policy accept;
    ct mark and {MARK_KIND_MASK:#010x} == {SINGBOX_KIND:#010x} update @acct_down {{ ct mark }}
  }}
}}
"""


def _run(argv: list[str], stdin: str | None = None, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout, check=False)


def uplink_interface() -> str:
    """The interface the default route leaves by."""
    for target in ("1.1.1.1", "2606:4700:4700::1111"):
        out = _run(["ip", "route", "get", target]).stdout
        m = re.search(r"\bdev (\S+)", out)
        if m:
            return m.group(1)
    raise RuntimeError("no default route")


def ensure_accounting() -> dict[str, Any]:
    """Create the counting table once; recreating it would zero the counters."""
    if _run(["nft", "list", "table", "inet", TABLE]).returncode == 0:
        return {"ok": True, "message": "accounting in place"}
    out = _run(["nft", "-f", "-"], stdin=_NFT_RULESET)
    return {"ok": out.returncode == 0, "message": (out.stderr or "accounting table created").strip()[-500:]}


def read_accounting() -> dict[str, Any]:
    """Bytes per mark since the last read, then zero the counters. Serialised,
    so concurrent readers each get their own bytes, never the same ones."""
    with _lock:
        ensured = ensure_accounting()
        if not ensured["ok"]:
            return ensured
        data: dict[str, dict[str, int]] = {}
        for direction in ("up", "down"):
            listed = _run(["nft", "-j", "list", "set", "inet", TABLE, f"acct_{direction}"])
            _run(["nft", "flush", "set", "inet", TABLE, f"acct_{direction}"])
            per_mark: dict[str, int] = {}
            try:
                for item in json.loads(listed.stdout or "{}").get("nftables", []):
                    for elem in (item.get("set") or {}).get("elem", []) or []:
                        e = elem.get("elem", elem)
                        per_mark[str(int(e["val"]))] = int(e.get("counter", {}).get("bytes", 0))
            except (ValueError, KeyError, TypeError):
                pass
            data[direction] = per_mark
        return {"ok": True, "message": "read", "data": data}


def _validate_limits(users: Any) -> list[dict[str, Any]]:
    if not isinstance(users, list) or len(users) > MAX_LIMITED_USERS:
        raise ValueError("invalid user list")
    clean = []
    for u in users:
        marks = [int(m) for m in u.get("marks", [])]
        if not marks or any(not (0 < m < 0x10000000) or not (m & MARK_KIND_MASK) for m in marks):
            raise ValueError("invalid mark")
        up, down = int(u.get("up_kbit") or 0), int(u.get("down_kbit") or 0)
        if not (0 <= up <= 100_000_000 and 0 <= down <= 100_000_000):
            raise ValueError("invalid rate")
        clean.append({"marks": marks, "up_kbit": up, "down_kbit": down})
    return clean


def _htb(dev: str, users: list[dict[str, Any]], key: str) -> list[str]:
    cmds = [
        f"qdisc add dev {dev} root handle 1: htb default 1",
        f"class add dev {dev} parent 1: classid 1:1 htb rate 100gbit",
    ]
    for i, u in enumerate(users, start=2):
        rate = u[key]
        if not rate:
            continue
        cls = f"1:{i:x}"
        cmds.append(f"class add dev {dev} parent 1: classid {cls} htb rate {rate}kbit ceil {rate}kbit")
        cmds.append(f"qdisc add dev {dev} parent {cls} fq_codel")
        for mark in u["marks"]:
            cmds.append(f"filter add dev {dev} parent 1: protocol all prio 1 handle {mark:#x} fw flowid {cls}")
    return cmds


def apply_shaping(users: Any, interface: str | None = None) -> dict[str, Any]:
    """Speed limits per user. Rebuilt from scratch on every call."""
    try:
        users = _validate_limits(users)
        dev = interface or uplink_interface()
    except (ValueError, RuntimeError) as exc:
        return {"ok": False, "message": str(exc)}
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", dev):
        return {"ok": False, "message": "invalid interface"}
    with _lock:
        ensure_accounting()  # the ct mark the download side matches on
        _run(["tc", "qdisc", "del", "dev", dev, "root"])
        _run(["tc", "qdisc", "del", "dev", dev, "ingress"])
        _run(["ip", "link", "del", IFB])
        users = [u for u in users if u["up_kbit"] or u["down_kbit"]]
        if not users:
            return {"ok": True, "message": f"no speed limits on {dev}", "data": {"interface": dev, "limited": 0}}
        batch = _htb(dev, users, "up_kbit")
        out = _run(["ip", "link", "add", IFB, "type", "ifb"])
        if out.returncode != 0:
            return {"ok": False, "message": "ifb: " + out.stderr.strip()}
        _run(["ip", "link", "set", IFB, "up"])
        batch += [
            f"qdisc add dev {dev} handle ffff: ingress",
            f"filter add dev {dev} parent ffff: protocol all prio 1 matchall action connmark action mirred egress redirect dev {IFB}",
        ]
        batch += _htb(IFB, users, "down_kbit")
        out = _run(["tc", "-force", "-batch", "-"], stdin="\n".join(batch) + "\n", timeout=120)
        if out.returncode != 0:
            return {"ok": False, "message": out.stderr.strip()[-500:]}
        return {"ok": True, "message": f"{len(users)} users limited on {dev}", "data": {"interface": dev, "limited": len(users)}}


def mieru_traffic(mita: str) -> dict[str, Any]:
    """Per-user bytes mita served since the last call. mita reports totals
    since it started; the last totals are kept on disk to take differences
    (a smaller total means mita restarted: all of it is new)."""
    with _lock:
        out = _run([mita, "get", "metrics"], timeout=15)
        if out.returncode != 0:
            return {"ok": False, "message": out.stderr.strip()[-300:]}
        try:
            users = json.loads(out.stdout).get("users", {}) or {}
        except json.JSONDecodeError:
            return {"ok": False, "message": "unreadable mita metrics"}
        try:
            last = json.loads(MIERU_STATE.read_text())
        except (OSError, json.JSONDecodeError):
            last = {}
        deltas, now = {}, {}
        for name, m in users.items():
            down, up = int(m.get("DownloadBytes") or 0), int(m.get("UploadBytes") or 0)
            prev_down, prev_up = last.get(name, [0, 0])
            deltas[name] = [down - prev_down if down >= prev_down else down,
                            up - prev_up if up >= prev_up else up]
            now[name] = [down, up]
        MIERU_STATE.parent.mkdir(parents=True, exist_ok=True)
        tmp = MIERU_STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(now))
        os.replace(tmp, MIERU_STATE)
        return {"ok": True, "message": "read", "data": {n: {"down": d, "up": u} for n, (d, u) in deltas.items() if d or u}}


HOP_TABLE = "spiritus_hop"


def hysteria2_port_hop(ports: str, target: int) -> dict[str, Any]:
    """Redirect a UDP port range to the Hysteria2 listener (clients hop
    across it). An empty range removes it. nftables, in a table of its own:
    no iptables lock file (the helper's /run is read-only), and removing it
    never touches the traffic counters."""
    with _lock:
        _run(["nft", "delete", "table", "inet", HOP_TABLE])
        if not ports:
            return {"ok": True, "message": "port hopping off"}
        m = re.fullmatch(r"(\d{4,5})-(\d{4,5})", ports)
        if not m:
            return {"ok": False, "message": "port range must look like 20000-50000"}
        lo, hi = int(m.group(1)), int(m.group(2))
        if not (1024 <= lo < hi <= 65535) or lo <= target <= hi or not (1 <= target <= 65535):
            return {"ok": False, "message": "invalid port range"}
        ruleset = (
            f"table inet {HOP_TABLE} {{\n"
            f"  chain prerouting {{ type nat hook prerouting priority dstnat; policy accept;\n"
            f"    udp dport {lo}-{hi} redirect to :{target}\n  }}\n}}\n"
        )
        out = _run(["nft", "-f", "-"], stdin=ruleset)
        if out.returncode != 0:
            return {"ok": False, "message": out.stderr.strip()[-300:]}
        return {"ok": True, "message": f"UDP {lo}-{hi} -> {target}"}
