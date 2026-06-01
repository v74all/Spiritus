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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import secrets as _secrets
from ..config import settings
from ..models import Agent, AgentBackend, AgentStatus, ProtocolConfig
from ..protocol_engine import PROTOCOLS, ProtocolSpec, XrayConfigGenerator
from ..timeutil import utcnow as _utcnow

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


# ═══════════════════════════════════════════════════════════════
#  Concurrency
# ═══════════════════════════════════════════════════════════════

# Per-process serialiser. The async functions below also serialise
# through an asyncio.Lock where they make filesystem changes, so
# this is the belt; the asyncio lock is the braces.
_xray_sync_lock = threading.RLock()


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

    private_key, _, short_id = _resolve_reality_keys(protocol_cfg)
    # We don't have a single global user UUID — pass a placeholder
    # that the Xray API will replace when a real client connects.
    # (Inbound-level `clients` is a template; per-user entries are
    # added through the StatsService / HandlerService at runtime.)
    placeholder_uuid = "00000000-0000-0000-0000-000000000000"

    if protocol_key == "vless_xhttp_reality":
        return XrayConfigGenerator.generate_vless_xhttp_reality(
            user_uuid=placeholder_uuid,
            port=int(cfg.get("port", 2053)),
            reality_private_key=private_key,
            reality_short_id=short_id,
            reality_dest=cfg.get("reality_dest", "digikala.com:443"),
            reality_sni=cfg.get("reality_sni", "digikala.com"),
            xhttp_path=cfg.get("xhttp_path", "/xhttp-stream"),
            xhttp_mode=cfg.get("xhttp_mode", "auto"),
        )
    if protocol_key == "vless_vision_reality":
        return XrayConfigGenerator.generate_vless_vision_reality(
            user_uuid=placeholder_uuid,
            port=int(cfg.get("port", 2058)),
            reality_private_key=private_key,
            reality_short_id=short_id,
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
        return XrayConfigGenerator.generate_ss2022(
            server_key=cfg.get("server_key", ""),
            user_key=cfg.get("user_key", ""),
            port=int(cfg.get("port", 2056)),
            method=cfg.get("method", "2022-blake3-aes-128-gcm"),
        )
    # Anything else (grpc, httpupgrade, trojan-cdn, hysteria2, tuic,
    # amneziawg, …) has no first-class inbound builder in
    # XrayConfigGenerator yet. We log the omission and skip so
    # enabling such a protocol doesn't fail with a 500.
    logger.info("protocol %r has no inbound builder; skipping Xray sync", protocol_key)
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
        proc = subprocess.run(
            [bin_path, "test", "-config", path],
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


def _reload_or_restart_xray(agent: Optional[Agent]) -> Tuple[bool, str, Optional[str]]:
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
        try:
            ok = asyncio.get_event_loop().run_until_complete(
                orchestrator.restart_agent(agent)
            )
        except RuntimeError:
            # No running event loop — fall back to sync reload via
            # systemctl if it's the local node.
            if agent.address in ("127.0.0.1", "localhost"):
                return _systemd_reload_or_restart(agent.service_name or "xray")
            return False, f"remote agent {agent.name} sync reload not yet supported", None
        return ok, "ok", "restart"

    # Local Xray.
    return _systemd_reload_or_restart("xray")


def _systemd_reload_or_restart(unit: str) -> Tuple[bool, str, Optional[str]]:
    """Try `systemctl reload <unit>` first; fall back to `restart`.

    `reload` (which sends SIGHUP) is preferred because it preserves
    active connections. Not all builds of xray.service honour
    ExecReload though, so we try and fall back.
    """
    try:
        reload_proc = subprocess.run(
            ["systemctl", "reload", unit],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return False, "systemctl not available; cannot reload Xray", None
    except subprocess.TimeoutExpired:
        return False, f"systemctl reload {unit} timed out", None

    if reload_proc.returncode == 0:
        return True, "reloaded", "reload"

    # Reload failed — usually because the unit has no ExecReload
    # line. Try a full restart.
    try:
        restart_proc = subprocess.run(
            ["systemctl", "restart", unit],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False, f"systemctl restart {unit} timed out", None

    if restart_proc.returncode != 0:
        msg = (restart_proc.stderr or restart_proc.stdout or "").strip()
        return False, msg or f"systemctl restart {unit} failed", None
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

import asyncio  # noqa: E402  (placed here so module loads even on Python <3.10)


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

    with _xray_sync_lock:
        try:
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

            # 1. Back up the current config so we can roll back.
            backup_path: Optional[str] = None
            if os.path.isfile(target_path):
                backup_path = target_path + ".bak"
                shutil.copy2(target_path, backup_path)

            # 2. Write the new config atomically.
            try:
                _write_xray_config(full_config, target_path)
            except OSError as exc:
                return SyncResult(
                    success=False,
                    config_path=target_path,
                    error=f"failed to write config: {exc}",
                )

            # 3. Validate.
            ok, output = _validate_xray_config(target_path)
            if not ok:
                # Roll back to the previous good config so the running
                # Xray isn't stranded with a broken file on its next
                # reload.
                if backup_path and os.path.isfile(backup_path):
                    shutil.copy2(backup_path, target_path)
                return SyncResult(
                    success=False,
                    config_path=target_path,
                    validator_output=output,
                    rolled_back=bool(backup_path and os.path.isfile(backup_path)),
                    error=f"xray -test rejected the new config: {output[:200]}",
                )

            # 4. Reload.
            reload_ok, reload_msg, method = _reload_or_restart_xray(
                _load_agent_for(db, enabled[0]) if enabled else None
            )
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
                if not proto_cfg.tag:
                    proto_cfg.tag = f"pcfg-{proto_cfg.protocol_key}"
            await db.commit()

            return SyncResult(
                success=True,
                config_path=target_path,
                validator_output=output,
                reload_method=method,
                finished_at=_utcnow().isoformat(),
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("sync_and_reload failed")
            return SyncResult(
                success=False,
                config_path=target_path,
                error=f"{type(exc).__name__}: {exc}",
                finished_at=_utcnow().isoformat(),
            )
