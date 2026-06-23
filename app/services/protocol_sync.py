"""
Protocol sync service: bridges the panel's idea of "what should be
running" (ProtocolConfig rows + setting flags) with the actual state
on disk and in the Xray process.

This module is the SINGLE place that:
  - reads ProtocolConfig rows from the DB
  - composes them into an Xray config
  - writes that config to `settings.xray_config_path`
  - validates the config with `xray -test`
  - reloads Xray (or restarts it) so the new config takes effect
  - records what was actually applied so `/protocols/{key}/status`
    can report accurate runtime state

Why one module rather than scattered per-endpoint calls?
  - The four steps above (compose, write, validate, reload) must
    always run in that order and atomically. Splitting them across
    `/enable` and `/update` handlers invites half-applied state
    (config updated but Xray still serving the old one, or Xray
    reloaded with a broken config because the validator didn't run).
  - Recovery is a single concern: if `xray -test` rejects the
    config we need to keep the previous good config and surface
    the error uniformly regardless of which endpoint triggered it.
  - The audit log needs one place to record "protocol X toggled
    ON, config Y regenerated, Xray reloaded, validator said OK"
    for traceability.

Concurrency:
  - `xray_sync_lock` prevents two requests from racing the same
    generation (each generation does up to four filesystem writes).
  - The lock is in-process — a second uvicorn worker (if anyone
    ever runs gunicorn -w 2) would still race. We don't ship with
    multiple workers, so a per-process lock is enough.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import uuid as _uuid
import asyncio
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import secrets as _secrets
from ..config import settings
from ..models import Agent, AgentBackend, AgentStatus, ProtocolConfig
from ..protocol_engine import (
    PROTOCOLS,
    MieruConfigGenerator,
    ProtocolSpec,
    SingboxConfigGenerator,
    XrayConfigGenerator,
)
from ..timeutil import utcnow as _utcnow
from ..privileged_helper import helper_request, PrivilegedHelperError
from ..redis_client import get_redis

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  Public dataclasses
# ═══════════════════════════════════════════════════════════════

@dataclass
class ProtocolRuntimeStatus:
    """What a single protocol is doing right now."""
    key: str
    enabled_in_db: bool
    running: bool
    connections: int
    last_started_at: Optional[str]
    last_error: Optional[str] = None


@dataclass
class SyncResult:
    """Outcome of a sync attempt. Returned by sync_and_reload()."""
    success: bool
    config_path: str
    validator_output: str = ""
    reload_method: Optional[str] = None  # "reload" | "restart" | None
    rolled_back: bool = False
    error: Optional[str] = None
    started_at: str = field(default_factory=lambda: _utcnow().isoformat())
    finished_at: Optional[str] = None
    # sing-box sync outcome (standalone protocols). None when no
    # sing-box protocol was enabled, so we never touched sing-box.
    singbox_synced: Optional[bool] = None
    singbox_message: str = ""
    # Mieru (mita) sync outcome. None when Mieru was not enabled.
    mieru_synced: Optional[bool] = None
    mieru_message: str = ""


# ═══════════════════════════════════════════════════════════════
#  Concurrency
# ═══════════════════════════════════════════════════════════════

# Per-process serialiser. The async functions below also serialise
# through an asyncio.Lock where they make filesystem changes, so
# this is the belt; the asyncio lock is the braces.
_xray_sync_lock = threading.RLock()
_xray_async_lock = asyncio.Lock()


@asynccontextmanager
async def _distributed_sync_lock():
    """Serialize config deployment across all uvicorn workers."""
    token = secrets.token_urlsafe(24)
    redis = await get_redis()
    acquired = await redis.set("lock:protocol-sync", token, ex=120, nx=True)
    if not acquired:
        raise RuntimeError("another protocol sync is already running")
    try:
        async with _xray_async_lock:
            yield
    finally:
        await redis.eval(
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
            "return redis.call('del', KEYS[1]) else return 0 end",
            1,
            "lock:protocol-sync",
            token,
        )


# ═══════════════════════════════════════════════════════════════
#  Reading the "what should be running" state
# ═══════════════════════════════════════════════════════════════

async def _load_enabled_protocols(db: AsyncSession) -> List[ProtocolConfig]:
    """Return every ProtocolConfig row whose `enabled` flag is True.

    Tied to an agent via `agent_id`. An operator may enable the same
    protocol on multiple agents (e.g. enable VLESS+XHTTP on the
    Helsinki node and the Singapore node independently).
    """
    result = await db.execute(
        select(ProtocolConfig).where(ProtocolConfig.enabled == True)  # noqa: E712
    )
    return list(result.scalars().all())


async def _load_agent_for(db: AsyncSession, protocol_cfg: ProtocolConfig) -> Optional[Agent]:
    """Resolve the agent a ProtocolConfig belongs to. Returns None if
    the FK is dangling (e.g. the agent row was deleted while the
    protocol config was kept)."""
    if protocol_cfg.agent_id is None:
        return None
    result = await db.execute(
        select(Agent).where(Agent.id == protocol_cfg.agent_id)
    )
    return result.scalar_one_or_none()


# ═══════════════════════════════════════════════════════════════
#  Composing the Xray config
# ═══════════════════════════════════════════════════════════════

async def _resolve_domain_defaults(db: AsyncSession) -> Dict[str, str]:
    """Read the active domain + cert paths from the Setting table.

    Used as the default for every TLS-bearing inbound's SNI and
    every inbound that needs `certificateFile` /
    `keyFile`. Protocols that explicitly set their own
    `reality_sni` / `sni` / `domain` win — this is just the
    fallback so the operator doesn't have to type the same
    domain 14 times in the protocol form.

    Returns an empty dict if no domain is configured. Callers
    that REQUIRE a domain (Trojan-CDN, SNI-based VLESS-WS) use
    this signal to skip the inbound rather than emit a broken
    config.
    """
    from sqlalchemy import select as _select
    from ..models import Setting
    result = await db.execute(
        _select(Setting).where(Setting.key.in_([
            "domain_active",
            "domain_cert_path",
            "domain_key_path",
        ]))
    )
    rows = {row.key: row.value for row in result.scalars().all() if row.value}
    return {
        "domain": rows.get("domain_active", "").strip(),
        "cert_path": rows.get("domain_cert_path", "").strip(),
        "key_path": rows.get("domain_key_path", "").strip(),
    }


def _apply_domain_defaults(
    cfg: Dict[str, Any],
    domain: str,
    cert_path: str,
    key_path: str,
) -> Dict[str, Any]:
    """Fill in any unset SNI / cert fields with the active domain.

    Why a function and not a dict merge inline:
      - Different protocols use different keys for the same
        concept (some use `sni`, others `reality_sni`, others
        `domain`). The mapping is protocol-specific and lives
        in the inbound builders, not here.
      - The Xray config builders (XrayConfigGenerator) accept
        the per-protocol dict and figure out which keys map to
        what. We just need to seed the dict with `sni=domain`
        for protocols that don't override it.
      - We never overwrite a value the operator typed. A blank
        string in `cfg` triggers the default; any non-blank
        value wins.

    We also seed `tlsSettings.certificates[0].certFile` /
    `keyFile` for protocols that need an explicit cert path
    (e.g. VLESS-WS+TLS, Trojan-WS+TLS). Xray's inbound schema
    supports both the short form `security: tls` with a server-
    managed cert and the long form with explicit cert paths;
    we use the long form so the panel's cert always wins.
    """
    out = dict(cfg)
    if domain:
        # Per-protocol SNI keys. If the operator set one
        # explicitly, keep it. If not, default to the active
        # domain.
        for key in ("sni", "reality_sni", "domain", "front_domain"):
            if not out.get(key):
                out[key] = domain
        # reality_dest is "host:port" — if the operator didn't
        # set it, point at the active domain on 443.
        if not out.get("reality_dest"):
            out[f"reality_dest"] = f"{domain}:443"
    if cert_path and key_path:
        # Xray's TLS block. Some inbound builders read these
        # via `tlsSettings.certificates[0]`, others via a flat
        # `cert_file` / `key_file` on the inbound. We set both
        # so the builders can pick whichever schema they use.
        out.setdefault("cert_file", cert_path)
        out.setdefault("key_file", key_path)
        out.setdefault("tls_cert_path", cert_path)
        out.setdefault("tls_key_path", key_path)
    return out


# ═══════════════════════════════════════════════════════════════
#  Composing the Xray config
# ═══════════════════════════════════════════════════════════════

def _resolve_reality_keys(protocol_cfg: ProtocolConfig) -> Tuple[str, str, str]:
    """Pull REALITY key material from the DB config or the secrets
    manager. The DB config wins if the operator has explicitly set
    a per-protocol override; otherwise we fall back to whatever
    `app.secrets.reality_*` returns.

    Returns (private_key, public_key, short_id). The private key is
    needed for server-side Xray config; the public key and short id
    are echoed into client share URLs and (in the case of short id)
    into the server's `shortIds` array.

    Raises ValueError if the private key is empty — an empty key
    produces an invalid Xray config that will fail at `xray -test`.
    """
    cfg = protocol_cfg.config or {}
    private_key = (
        cfg.get("reality_private_key")
        or _secrets.reality_private_key()
    )
    public_key = (
        cfg.get("reality_public_key")
        or _secrets.reality_public_key()
    )
    short_id = (
        cfg.get("reality_short_id")
        or cfg.get("short_id")
        or _secrets.reality_short_id()
        or ""
    )
    if not private_key:
        raise ValueError(
            "REALITY private key is not set. Generate keys via Settings → "
            "Protocol Config or run: xray x25519"
        )
    if not public_key:
        raise ValueError(
            "REALITY public key is not set. Generate keys via Settings → "
            "Protocol Config or run: xray x25519"
        )
    return private_key, public_key, short_id


def _build_inbound_for(
    protocol_key: str,
    protocol_cfg: ProtocolConfig,
    user_uuid: str,
    domain_defaults: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    """Translate a ProtocolConfig row into an Xray inbound dict.

    Returns None when we don't know how to render the protocol — the
    orchestrator treats that as "skip" rather than "fail" so that a
    half-rolled-out spec doesn't break Xray startup.

    `domain_defaults` carries the active domain + cert paths from
    the DomainManager. Every protocol that needs an SNI or a
    cert path falls back to these when the operator hasn't set
    one explicitly. The fallback is the whole point of the
    Domain feature: the operator sets the domain ONCE and every
    protocol inherits it.
    """
    spec: Optional[ProtocolSpec] = PROTOCOLS.get(protocol_key)
    if spec is None:
        logger.warning("unknown protocol key %r in ProtocolConfig row", protocol_key)
        return None
    if spec.backend.value not in {"xray", "xray-core"}:
        # Standalone protocols (Hysteria2, TUIC, …) live in their own
        # binaries and are NOT Xray inbounds. The config-deployed flow
        # for those is a separate code path; for now the sync
        # service only handles xray.
        return None

    # Merge the operator's per-protocol config with the panel-wide
    # domain defaults. The per-protocol dict wins for any non-empty
    # value; the domain defaults fill in the blanks.
    raw_cfg = protocol_cfg.config or {}
    if domain_defaults and (domain_defaults.get("domain") or domain_defaults.get("cert_path")):
        cfg = _apply_domain_defaults(
            raw_cfg,
            domain=domain_defaults.get("domain", ""),
            cert_path=domain_defaults.get("cert_path", ""),
            key_path=domain_defaults.get("key_path", ""),
        )
    else:
        cfg = dict(raw_cfg)

    # Resolve REALITY keys lazily — only protocols that actually use them
    # call _resolve_reality_keys(). Calling it unconditionally would break
    # every non-REALITY protocol when keys are not yet generated.
    _reality_keys_cache: Optional[Tuple[str, str, str]] = None

    def _get_reality_keys() -> Tuple[str, str, str]:
        nonlocal _reality_keys_cache
        if _reality_keys_cache is None:
            _reality_keys_cache = _resolve_reality_keys(protocol_cfg)
        return _reality_keys_cache

    # We don't have a single global user UUID — pass a placeholder
    # that the Xray API will replace when a real client connects.
    # (Inbound-level `clients` is a template; per-user entries are
    # added through the StatsService / HandlerService at runtime.)
    placeholder_uuid = "00000000-0000-0000-0000-000000000000"

    if protocol_key == "vless_xhttp_reality":
        try:
            pk, _, sid = _get_reality_keys()
        except ValueError as exc:
            logger.warning("vless_xhttp_reality skipped: %s", exc)
            return None
        return XrayConfigGenerator.generate_vless_xhttp_reality(
            user_uuid=placeholder_uuid,
            port=int(cfg.get("port", 2053)),
            reality_private_key=pk,
            reality_short_id=sid,
            reality_dest=cfg.get("reality_dest", "digikala.com:443"),
            reality_sni=cfg.get("reality_sni", "digikala.com"),
            xhttp_path=cfg.get("xhttp_path", "/xhttp-stream"),
            xhttp_mode=cfg.get("xhttp_mode", "auto"),
        )
    if protocol_key == "vless_vision_reality":
        try:
            pk, _, sid = _get_reality_keys()
        except ValueError as exc:
            logger.warning("vless_vision_reality skipped: %s", exc)
            return None
        return XrayConfigGenerator.generate_vless_vision_reality(
            user_uuid=placeholder_uuid,
            port=int(cfg.get("port", 2058)),
            reality_private_key=pk,
            reality_short_id=sid,
            reality_dest=cfg.get("reality_dest", "objects.githubusercontent.com:443"),
            reality_sni=cfg.get("reality_sni", "objects.githubusercontent.com"),
            flow=cfg.get("flow", "xtls-rprx-vision"),
        )
    if protocol_key == "vmess_ws_tls":
        return XrayConfigGenerator.generate_vmess_ws_tls(
            user_uuid=placeholder_uuid,
            port=int(cfg.get("port", 443)),
            sni=cfg.get("sni", "www.aparat.com"),
            ws_path=cfg.get("ws_path", "/api/v1/stream"),
        )
    if protocol_key == "vless_ws_tls":
        return XrayConfigGenerator.generate_vless_ws_tls(
            user_uuid=placeholder_uuid,
            port=int(cfg.get("port", 2057)),
            ws_path=cfg.get("ws_path", "/vless-ws"),
            host=cfg.get("host", ""),
        )
    if protocol_key == "ss2022":
        server_key = cfg.get("server_key", "")
        user_key = cfg.get("user_key", "")
        if not server_key or not user_key:
            logger.warning(
                "ss2022: server_key or user_key is empty — skipping inbound. "
                "Set them via the protocol config page."
            )
            return None
        return XrayConfigGenerator.generate_ss2022(
            server_key=server_key,
            user_key=user_key,
            port=int(cfg.get("port", 2056)),
            method=cfg.get("method", "2022-blake3-aes-128-gcm"),
        )
    if protocol_key == "vless_reverse_reality":
        try:
            pk, _, sid = _get_reality_keys()
        except ValueError as exc:
            logger.warning("vless_reverse_reality skipped: %s", exc)
            return None
        return XrayConfigGenerator.generate_vless_reverse_reality(
            user_uuid=placeholder_uuid,
            port=int(cfg.get("port", 2059)),
            reality_private_key=pk,
            reality_short_id=sid,
            reality_dest=cfg.get("reality_dest", "digikala.com:443"),
            reality_sni=cfg.get("reality_sni", "digikala.com"),
            tunnel_port=int(cfg.get("tunnel_port", 0)),
            backhaul_mode=cfg.get("backhaul_mode", "rathole"),
        )
    if protocol_key == "trojan_cdn":
        return XrayConfigGenerator.generate_trojan_cdn(
            user_password=placeholder_uuid,
            port=int(cfg.get("port", 2083)),
            ws_path=cfg.get("ws_path", "/trojan-ws"),
            grpc_service=cfg.get("grpc_service", "TrojanService"),
            grpc_enabled=bool(cfg.get("grpc_enabled", False)),
            grpc_port=int(cfg.get("grpc_port", 2060)),
            sni=cfg.get("sni", ""),
            domain=cfg.get("domain", ""),
        )
    if protocol_key == "vless_ws_plain_front":
        return XrayConfigGenerator.generate_vless_ws_plain(
            user_uuid=placeholder_uuid,
            port=int(cfg.get("port", 2052)),
            ws_path=cfg.get("ws_path", "/"),
            host=cfg.get("front_domain", cfg.get("host", "")),
        )
    if protocol_key == "grpc_transport":
        return XrayConfigGenerator.generate_vless_grpc(
            user_uuid=placeholder_uuid,
            port=int(cfg.get("port", 2054)),
            service_name=cfg.get("service_name", "GunService"),
            sni=cfg.get("sni", cfg.get("domain", "")),
        )
    if protocol_key == "httpupgrade":
        return XrayConfigGenerator.generate_vless_httpupgrade(
            user_uuid=placeholder_uuid,
            port=int(cfg.get("port", 2055)),
            path=cfg.get("path", "/httpupgrade"),
            host=cfg.get("host", ""),
            sni=cfg.get("sni", cfg.get("domain", "")),
        )
    logger.info("protocol %r has no inbound builder; skipping Xray sync", protocol_key)
    return None


# ═══════════════════════════════════════════════════════════════
#  Composing the sing-box config (standalone protocols)
# ═══════════════════════════════════════════════════════════════

# Which protocol keys are hosted by sing-box rather than Xray.
SINGBOX_PROTOCOLS = {"hysteria2", "tuic", "shadowtls", "naiveproxy"}


def _build_singbox_inbounds_for(
    protocol_key: str,
    protocol_cfg: ProtocolConfig,
    domain_defaults: Optional[Dict[str, str]] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Translate a ProtocolConfig row into sing-box inbound dict(s).

    Returns a list of inbounds (ShadowTLS yields two: the camouflage
    inbound plus its Shadowsocks detour) or None when the protocol
    has no sing-box builder or is missing required secrets.
    """
    raw_cfg = protocol_cfg.config or {}
    if domain_defaults and (domain_defaults.get("domain") or domain_defaults.get("cert_path")):
        cfg = _apply_domain_defaults(
            raw_cfg,
            domain=domain_defaults.get("domain", ""),
            cert_path=domain_defaults.get("cert_path", ""),
            key_path=domain_defaults.get("key_path", ""),
        )
    else:
        cfg = dict(raw_cfg)

    sni = cfg.get("sni") or cfg.get("domain") or ""
    cert_path = cfg.get("cert_file") or cfg.get("tls_cert_path") or ""
    key_path = cfg.get("key_file") or cfg.get("tls_key_path") or ""

    if protocol_key == "hysteria2":
        password = cfg.get("password", "")
        if not password:
            logger.warning("hysteria2: password not set — skipping sing-box inbound")
            return None
        return SingboxConfigGenerator.generate_hysteria2(
            password=password,
            port=int(cfg.get("port", 8443)),
            sni=sni,
            cert_path=cert_path,
            key_path=key_path,
            salamander_enabled=bool(cfg.get("salamander_enabled", False)),
            salamander_password=cfg.get("salamander_password", ""),
            bandwidth_up=cfg.get("bandwidth_up", "100 mbps"),
            bandwidth_down=cfg.get("bandwidth_down", "200 mbps"),
        )
    if protocol_key == "tuic":
        password = cfg.get("password", "")
        if not password:
            logger.warning("tuic: password not set — skipping sing-box inbound")
            return None
        tuic_uuid = cfg.get("uuid", "")
        if not tuic_uuid:
            # Derive a stable UUID from the protocol row so the same
            # config renders identically across syncs.
            tuic_uuid = str(_uuid.uuid5(_uuid.NAMESPACE_DNS, f"tuic-{protocol_cfg.id}-{password}"))
        return SingboxConfigGenerator.generate_tuic(
            uuid=tuic_uuid,
            password=password,
            port=int(cfg.get("port", 8444)),
            sni=sni,
            cert_path=cert_path,
            key_path=key_path,
            congestion_control=cfg.get("congestion_control", "cubic"),
            udp_relay=cfg.get("udp_relay", "native"),
            zero_rtt=bool(cfg.get("zero_rtt", False)),
        )
    if protocol_key == "shadowtls":
        password = cfg.get("password", "")
        ss_password = cfg.get("ss_password") or cfg.get("server_key") or password
        if not password or not ss_password:
            logger.warning("shadowtls: password/ss_password not set — skipping sing-box inbound")
            return None
        return SingboxConfigGenerator.generate_shadowtls(
            password=password,
            ss_password=ss_password,
            port=int(cfg.get("port", 8445)),
            handshake_server=cfg.get("sni", "chat.deepseek.com"),
            handshake_port=int(cfg.get("handshake_port", 443)),
            version=int(cfg.get("version", 3)),
        )
    if protocol_key == "naiveproxy":
        password = cfg.get("password", "")
        if not password:
            logger.warning("naiveproxy: password not set — skipping sing-box inbound")
            return None
        return SingboxConfigGenerator.generate_naive(
            username=cfg.get("user", "panel"),
            password=password,
            port=int(cfg.get("port", 8447)),
            sni=sni,
            cert_path=cert_path,
            key_path=key_path,
        )
    logger.info("protocol %r has no sing-box inbound builder; skipping", protocol_key)
    return None


# ═══════════════════════════════════════════════════════════════
#  Filesystem + process interaction
# ═══════════════════════════════════════════════════════════════

def _write_xray_config(config: Dict[str, Any], path: str) -> None:
    """Atomically replace the Xray config file.

    Atomicity matters here: Xray's reload path opens the file,
    parses it, and only then does the new config take over. If we
    write in place and Xray re-reads mid-write, it sees a half-formed
    JSON and aborts to a no-proxy state.

    We write to a sibling temp file, fsync, then os.replace() so the
    rename is atomic on POSIX.
    """
    parent = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".xray-config-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        # Best-effort cleanup if the rename never happened.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _validate_xray_config(path: str) -> Tuple[bool, str]:
    """Run `xray -test -config <path>` and return (ok, output).

    The validator is what stops a typo in the inbound JSON from
    turning into a panel-wide outage. We surface its stderr in the
    SyncResult so the operator can see *what* Xray didn't like.
    """
    bin_path = settings.xray_bin_path or "/usr/local/bin/xray"
    try:
        # NOTE: the flag is `-test`, not a `test` subcommand. Recent
        # Xray (run is the default command) rejects `xray test -config`
        # with "unknown command", which would make every validation
        # fail. `xray -test -config` is the correct, version-stable form.
        proc = subprocess.run(
            [bin_path, "-test", "-config", path],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        # The xray binary is missing (e.g. dev machine without xray
        # installed). Treat as a soft failure — config is written
        # but we report the validator as missing.
        return False, f"xray binary not found at {bin_path}"
    except subprocess.TimeoutExpired:
        return False, "xray -test timed out after 15s"
    except Exception as exc:  # noqa: BLE001
        return False, f"xray -test failed to start: {exc}"

    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        return False, output.strip() or f"xray -test exited {proc.returncode}"
    return True, output.strip()


def _validate_singbox_config(path: str) -> Tuple[bool, str]:
    """Run `sing-box check -c <path>` and return (ok, output).

    Mirrors `_validate_xray_config` for the standalone protocols. When
    the sing-box binary is absent (dev machine), this is a soft failure
    so the rest of the sync still completes for Xray.
    """
    bin_path = settings.singbox_bin_path or "/usr/local/bin/sing-box"
    try:
        proc = subprocess.run(
            [bin_path, "check", "-c", path],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        return False, f"sing-box binary not found at {bin_path}"
    except subprocess.TimeoutExpired:
        return False, "sing-box check timed out after 15s"
    except Exception as exc:  # noqa: BLE001
        return False, f"sing-box check failed to start: {exc}"

    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        return False, output.strip() or f"sing-box check exited {proc.returncode}"
    return True, output.strip()


async def _reload_or_restart_xray(agent: Optional[Agent]) -> Tuple[bool, str, Optional[str]]:
    """Apply the new config to the running Xray.

    Returns (ok, message, method). `method` is "reload" if we
    successfully signalled Xray to re-read its config, "restart" if
    we had to bounce the systemd unit (e.g. SIGHUP not supported),
    or None if we couldn't touch the process at all.

    For the panel's local Xray (agent is None) we go through
    systemd. For a remote agent we'd shell out over the agent's API
    — that path is TODO and is logged as such.
    """
    if agent is not None and agent.id is not None:
        # Remote agent. The orchestrator owns this path; we call into
        # it so all reload-style actions go through the same audit
        # trail.
        from .orchestrator import orchestrator  # local import — avoids cycle
        if agent.address in ("127.0.0.1", "localhost", "::1"):
            return await _systemd_reload_or_restart(agent.service_name or "xray")
        try:
            ok = await orchestrator.restart_agent(agent)
        except Exception as exc:  # noqa: BLE001
            return False, f"remote agent restart failed: {type(exc).__name__}", None
        return ok, "ok", "restart"

    # Local Xray.
    return await _systemd_reload_or_restart("xray")


async def _systemd_reload_or_restart(unit: str) -> Tuple[bool, str, Optional[str]]:
    """Try `systemctl reload <unit>` first; fall back to `restart`.

    `reload` (which sends SIGHUP) is preferred because it preserves
    active connections. Not all builds of xray.service honour
    ExecReload though, so we try and fall back.
    """
    try:
        response = await helper_request("service.reload", {"service": unit}, timeout=35)
    except PrivilegedHelperError as exc:
        return False, str(exc), None
    if response.ok:
        return True, "reloaded", "reload"
    try:
        response = await helper_request("service.restart", {"service": unit}, timeout=65)
    except PrivilegedHelperError as exc:
        return False, str(exc), None
    if not response.ok:
        return False, response.message or f"restart {unit} failed", None
    return True, "restarted (no reload support on this unit)", "restart"


# ═══════════════════════════════════════════════════════════════
#  Status reporting
# ═══════════════════════════════════════════════════════════════

async def runtime_status(
    db: AsyncSession,
    protocol_key: str,
) -> ProtocolRuntimeStatus:
    """Read-only view of what a protocol is doing right now.

    Combines the DB row (`enabled_in_db`) with the on-disk config
    (`running`) and a best-effort process check.
    """
    result = await db.execute(
        select(ProtocolConfig).where(ProtocolConfig.protocol_key == protocol_key)
    )
    row = result.scalar_one_or_none()
    if row is None:
        return ProtocolRuntimeStatus(
            key=protocol_key,
            enabled_in_db=False,
            running=False,
            connections=0,
            last_started_at=None,
            last_error="no ProtocolConfig row",
        )

    # Cheap "is the protocol in the on-disk Xray config?" check.
    running = False
    try:
        cfg_path = settings.xray_config_path
        if os.path.isfile(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                on_disk = json.load(f)
            tags = [
                ib.get("tag", "")
                for ib in on_disk.get("inbounds", [])
                if isinstance(ib, dict)
            ]
            running = row.tag in tags if row.tag else any(
                row.protocol_key in t for t in tags
            )
    except (OSError, json.JSONDecodeError):
        running = False

    return ProtocolRuntimeStatus(
        key=protocol_key,
        enabled_in_db=bool(row.enabled),
        running=running,
        connections=int(row.connections or 0),
        last_started_at=row.last_started_at.isoformat() if row.last_started_at else None,
        last_error=None,
    )


# ═══════════════════════════════════════════════════════════════
#  Orchestration: the entrypoint called by the API
# ═══════════════════════════════════════════════════════════════

async def _sync_singbox(
    enabled: List[ProtocolConfig],
    domain_defaults: Dict[str, str],
) -> Tuple[Optional[bool], str]:
    """Render + write + validate + reload the sing-box config.

    Returns (synced, message):
      - (None, "...")  no sing-box protocol enabled — sing-box untouched
      - (True, "...")  config written, validated and reloaded
      - (False, "...") something failed (validation, write, reload)

    This runs alongside the Xray sync but is intentionally independent:
    a sing-box failure must not roll back a good Xray config and vice
    versa. Each backend owns its own file and unit.
    """
    sb_protocols = [p for p in enabled if p.protocol_key in SINGBOX_PROTOCOLS]
    if not sb_protocols:
        return None, "no sing-box protocol enabled"

    target = settings.singbox_config_path
    if not target:
        return False, "singbox_config_path is not configured"

    inbounds: List[Dict[str, Any]] = []
    for proto_cfg in sb_protocols:
        built = _build_singbox_inbounds_for(
            proto_cfg.protocol_key, proto_cfg, domain_defaults
        )
        if built:
            inbounds.extend(built)

    if not inbounds:
        return False, "sing-box protocols enabled but none produced a valid inbound (check passwords/keys)"

    full_config = SingboxConfigGenerator.generate_full_config(inbounds)

    fd, candidate_path = tempfile.mkstemp(prefix=".singbox-candidate-", suffix=".json")
    os.close(fd)
    try:
        _write_xray_config(full_config, candidate_path)
    except OSError as exc:
        return False, f"failed to write sing-box config: {exc}"

    ok, output = _validate_singbox_config(candidate_path)
    if not ok:
        try:
            os.unlink(candidate_path)
        except OSError:
            pass
        return False, f"sing-box check rejected the config: {output[:200]}"
    try:
        os.unlink(candidate_path)
    except OSError:
        pass

    try:
        installed = await helper_request(
            "config.install",
            {"target": "sing-box", "content": json.dumps(full_config, indent=2)},
        )
    except PrivilegedHelperError as exc:
        return False, str(exc)
    if not installed.ok:
        return False, f"failed to install sing-box config: {installed.message}"

    reload_ok, reload_msg, _ = await _systemd_reload_or_restart(
        settings.singbox_service_name or "sing-box"
    )
    if not reload_ok:
        return False, f"sing-box config validated but reload failed: {reload_msg}"
    return True, "sing-box synced and reloaded"


async def _sync_mieru(enabled: List[ProtocolConfig]) -> Tuple[Optional[bool], str]:
    """Render + write + apply the Mieru (mita) server config.

    Mieru runs its own daemon configured via `mita apply config <file>`,
    so the apply step differs from the systemd-reload used by Xray and
    sing-box. Returns the same (synced, message) tristate as
    `_sync_singbox`: None means Mieru was not enabled.
    """
    mieru_rows = [p for p in enabled if p.protocol_key == "mieru"]
    if not mieru_rows:
        return None, "mieru not enabled"

    proto_cfg = mieru_rows[0]
    cfg = proto_cfg.config or {}
    password = cfg.get("password", "")
    if not password:
        return False, "mieru: password not set — skipping"

    target = settings.mieru_config_path
    if not target:
        return False, "mieru_config_path is not configured"

    server_config = MieruConfigGenerator.generate_server_config(
        username=cfg.get("user", "panel"),
        password=password,
        port=int(cfg.get("port", 8446)),
        protocol=cfg.get("transport", "TCP"),
        mtu=int(cfg.get("mtu", 1400)),
    )

    try:
        installed = await helper_request(
            "config.install",
            {"target": "mieru", "content": json.dumps(server_config, indent=2)},
        )
        if not installed.ok:
            return False, f"failed to install mieru config: {installed.message}"
        applied = await helper_request("mieru.apply", timeout=35)
    except PrivilegedHelperError as exc:
        return False, str(exc)
    if not applied.ok:
        return False, f"mita apply config failed: {applied.message[:200]}"

    reload_ok, reload_msg, _ = await _systemd_reload_or_restart(
        settings.mieru_service_name or "mita"
    )
    if not reload_ok:
        return False, f"mieru config applied but service reload failed: {reload_msg}"
    return True, "mieru synced and reloaded"


async def sync_and_reload(
    db: AsyncSession,
    *,
    config_path: Optional[str] = None,
    dry_run: bool = False,
) -> SyncResult:
    """End-to-end sync: read DB → render config → write → validate → reload.

    Steps:
      1. Read every enabled ProtocolConfig from the DB.
      2. Resolve their agents and group by agent (one Xray config
         per agent; the local panel has one default agent and a
         single config).
      3. For each agent, render the Xray config, write it, run
         `xray -test`, and if it passes, reload Xray.
      4. If validation fails, restore the previous config file
         and report the validator output so the operator can fix
         the setting instead of guessing.

    The result is recorded into the corresponding ProtocolConfig
    rows (last_started_at, connections=0) so the runtime_status
    endpoint reflects the new state without a process query.
    """
    target_path = config_path or settings.xray_config_path
    if not target_path:
        return SyncResult(
            success=False,
            config_path="",
            error="xray_config_path is not configured (set XRAY_CONFIG_PATH)",
        )

    try:
        async with _distributed_sync_lock():
            # Pull the active domain + cert paths ONCE so every
            # inbound sees the same defaults. Reloading this per-
            # protocol would be 14 redundant DB hits on a full
            # sync and could produce inconsistent renders if the
            # operator toggles the domain mid-sync.
            domain_defaults = await _resolve_domain_defaults(db)

            enabled = await _load_enabled_protocols(db)
            if not enabled:
                # No protocol is enabled — write a minimal config with
                # only the API inbound so the orchestrator's restart
                # doesn't kill the gRPC API.
                full_config = XrayConfigGenerator.generate_full_config(
                    inbounds=[],
                    api_port=int(getattr(settings, "api_port", 10085) or 10085),
                )
            else:
                inbounds: List[Dict[str, Any]] = []
                for proto_cfg in enabled:
                    inbound = _build_inbound_for(
                        proto_cfg.protocol_key,
                        proto_cfg,
                        user_uuid="00000000-0000-0000-0000-000000000000",
                        domain_defaults=domain_defaults,
                    )
                    if inbound is not None:
                        inbounds.append(inbound)
                        proto_cfg.tag = str(inbound.get("tag") or "") or None
                full_config = XrayConfigGenerator.generate_full_config(
                    inbounds=inbounds,
                    api_port=int(getattr(settings, "api_port", 10085) or 10085),
                )

            if dry_run:
                return SyncResult(
                    success=True,
                    config_path=target_path,
                    validator_output="dry-run: config not written",
                )

            fd, candidate_path = tempfile.mkstemp(prefix=".xray-candidate-", suffix=".json")
            os.close(fd)
            try:
                _write_xray_config(full_config, candidate_path)
            except OSError as exc:
                return SyncResult(
                    success=False,
                    config_path=target_path,
                    error=f"failed to write config: {exc}",
                )

            ok, output = _validate_xray_config(candidate_path)
            if not ok:
                try:
                    os.unlink(candidate_path)
                except OSError:
                    pass
                return SyncResult(
                    success=False,
                    config_path=target_path,
                    validator_output=output,
                    error=f"xray -test rejected the new config: {output[:200]}",
                )
            try:
                os.unlink(candidate_path)
            except OSError:
                pass

            try:
                installed = await helper_request(
                    "config.install",
                    {"target": "xray", "content": json.dumps(full_config, indent=2)},
                )
            except PrivilegedHelperError as exc:
                return SyncResult(success=False, config_path=target_path, error=str(exc))
            if not installed.ok:
                return SyncResult(
                    success=False,
                    config_path=target_path,
                    error=f"failed to install config: {installed.message}",
                )

            # 4. Reload.
            agent = await _load_agent_for(db, enabled[0]) if enabled else None
            reload_ok, reload_msg, method = await _reload_or_restart_xray(agent)
            if not reload_ok:
                return SyncResult(
                    success=False,
                    config_path=target_path,
                    validator_output=output,
                    error=f"config validated but reload failed: {reload_msg}",
                )

            # 5. Mark ProtocolConfig rows as recently-started. We do
            # not have a per-protocol connection count here; the
            # background traffic monitor (`app.celery_tasks.monitor_traffic`)
            # fills that in within ~30 seconds.
            now = _utcnow()
            for proto_cfg in enabled:
                proto_cfg.last_started_at = now
                # Tag is stored on the row so `runtime_status` can
                # match it against the rendered Xray config without
                # parsing the spec by hand.
            await db.commit()

            # 6. Sync the standalone (sing-box) protocols. This is
            # independent of the Xray sync above — a sing-box failure
            # is surfaced in the result but does not fail the overall
            # sync, since the Xray config is already live and good.
            singbox_synced, singbox_message = await _sync_singbox(enabled, domain_defaults)
            if singbox_synced is False:
                logger.warning("sing-box sync issue: %s", singbox_message)

            # 7. Sync Mieru (mita) — also independent of Xray/sing-box.
            mieru_synced, mieru_message = await _sync_mieru(enabled)
            if mieru_synced is False:
                logger.warning("mieru sync issue: %s", mieru_message)

            return SyncResult(
                success=True,
                config_path=target_path,
                validator_output=output,
                reload_method=method,
                finished_at=_utcnow().isoformat(),
                singbox_synced=singbox_synced,
                singbox_message=singbox_message,
                mieru_synced=mieru_synced,
                mieru_message=mieru_message,
            )
    except Exception as exc:  # noqa: BLE001
        logger.exception("sync_and_reload failed")
        return SyncResult(
            success=False,
            config_path=target_path,
            error=f"{type(exc).__name__}: {exc}",
            finished_at=_utcnow().isoformat(),
        )
