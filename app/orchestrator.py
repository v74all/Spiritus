"""
Multi-Backend Orchestrator for V7LTHRONYX VPN Panel.

Manages multiple backend agents:
- Xray-core (with API)
- sing-box
- WireGuard / AmneziaWG
- OpenVPN

Features:
- Agent registration and health monitoring
- Config generation and deployment
- User sync across backends
- ECH (Encrypted Client Hello) support
- Automatic failover
"""

import asyncio
import json
import os
import subprocess
import tempfile
import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
from .timeutil import utcnow as _utcnow
from enum import Enum

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Agent, AgentBackend, AgentStatus, ProtocolConfig, VpnUser
from .protocol_engine import XrayConfigGenerator, ech_mgr
from .privileged_helper import helper_request, PrivilegedHelperError

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  Agent Connection
# ═══════════════════════════════════════════════════════════════

class AgentConnection:
    """Manages connection to a backend agent."""

    def __init__(self, agent: Agent):
        self.agent = agent
        self._client: Optional[httpx.AsyncClient] = None
        self._last_heartbeat = 0

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            base_url = f"http://{self.agent.address}:{self.agent.api_port}"
            headers = {}
            if self.agent.api_key:
                headers["Authorization"] = f"Bearer {self.agent.api_key}"
            self._client = httpx.AsyncClient(
                base_url=base_url,
                headers=headers,
                timeout=10.0,
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def health_check(self) -> bool:
        """Check if agent is alive."""
        try:
            client = await self.get_client()
            resp = await client.get("/health")
            self._last_heartbeat = time.time()
            return resp.status_code == 200
        except Exception:
            return False

    async def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        try:
            client = await self.get_client()
            resp = await client.get("/stats")
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.error(f"Failed to get stats from agent {self.agent.name}: {e}")
        return {}


# ═══════════════════════════════════════════════════════════════
#  Xray Backend
# ═══════════════════════════════════════════════════════════════

class XrayBackend:
    """Xray-core backend manager."""

    def __init__(self, agent: Agent):
        self.agent = agent
        self.conn = AgentConnection(agent)

    async def restart(self) -> bool:
        """Restart Xray service on the agent."""
        try:
            result = await helper_request(
                "service.restart", {"service": self.agent.service_name or "xray"}, timeout=35
            )
            return result.ok
        except PrivilegedHelperError as e:
            logger.error(f"Failed to restart Xray on {self.agent.name}: {e}")
            return False

    async def reload_config(self) -> bool:
        """Reload Xray configuration."""
        try:
            result = await helper_request(
                "service.reload", {"service": self.agent.service_name or "xray"}, timeout=35
            )
            return result.ok
        except PrivilegedHelperError as e:
            logger.error(f"Failed to reload Xray config on {self.agent.name}: {e}")
            return False

    async def get_user_traffic(self, user_email: str) -> Dict[str, int]:
        """Get a user's traffic via `xray api statsquery`.

        Xray tracks per-user counters as `user>>>{email}>>>traffic>>>uplink`
        / `...>>>downlink` (the email is the user identity, not the uuid).
        We query both with one pattern call and sum by direction.
        """
        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                [
                    self._bin(), "api", "statsquery",
                    f"--server={self._api_server()}",
                    f"-pattern=user>>>{user_email}>>>traffic",
                ],
                capture_output=True, text=True, timeout=15,
            )
            if proc.returncode != 0:
                return {"upload": 0, "download": 0}
            data = json.loads(proc.stdout or "{}")
            up = down = 0
            for stat in data.get("stat", []):
                name = stat.get("name", "")
                value = int(stat.get("value", 0) or 0)
                if name.endswith("uplink"):
                    up += value
                elif name.endswith("downlink"):
                    down += value
            return {"upload": up, "download": down}
        except (json.JSONDecodeError, FileNotFoundError, subprocess.TimeoutExpired, ValueError) as e:
            logger.error("Failed to get traffic for %s: %s", user_email, e)
            return {"upload": 0, "download": 0}

    async def deploy_config(self, config: Dict[str, Any]) -> bool:
        """Deploy Xray configuration to agent."""
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as candidate:
                json.dump(config, candidate, indent=2)
                candidate_path = candidate.name
            result = subprocess.run(
                [self.agent.bin_path or "/usr/local/bin/xray", "-test", "-config", candidate_path],
                capture_output=True, text=True, timeout=10
            )
            os.unlink(candidate_path)
            if result.returncode != 0:
                logger.error(f"Xray config validation failed: {result.stderr}")
                return False
            installed = await helper_request(
                "config.install", {"target": "xray", "content": json.dumps(config, indent=2)}
            )
            if not installed.ok:
                return False
            return await self.reload_config()
        except Exception as e:
            logger.error(f"Failed to deploy Xray config: {e}")
            return False

    def _api_server(self) -> str:
        """Xray gRPC API address. The generated config puts the API
        inbound on 127.0.0.1:<api_port>. There is no separate agent
        daemon, so even a 'remote' agent's local Xray is reachable
        only on its own loopback — runtime user ops therefore target
        the local API server."""
        from .config import settings as _settings
        port = self.agent.api_port or getattr(_settings, "api_port", 10085) or 10085
        return f"127.0.0.1:{port}"

    def _bin(self) -> str:
        from .config import settings as _settings
        return self.agent.bin_path or _settings.xray_bin_path or "/usr/local/bin/xray"

    def _read_live_inbounds(self) -> List[Dict[str, Any]]:
        """Read non-API inbounds from the on-disk Xray config so we can
        target every enabled protocol when adding/removing a user."""
        from .config import settings as _settings
        path = self.agent.config_path or _settings.xray_config_path
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("xray add_user: cannot read config %s: %s", path, exc)
            return []
        return [
            ib for ib in cfg.get("inbounds", [])
            if isinstance(ib, dict) and ib.get("protocol") not in ("api", "dokodemo-door")
        ]

    @staticmethod
    def _client_entry(protocol: str, user: VpnUser) -> Optional[Dict[str, Any]]:
        """Build the settings.clients entry for `user` for a given
        inbound protocol. Returns None for protocols that don't take
        a per-user credential here."""
        email = user.name or user.uuid
        if protocol == "vmess":
            return {"id": user.uuid, "alterId": 0, "email": email}
        if protocol == "vless":
            return {"id": user.uuid, "email": email}
        if protocol == "trojan":
            return {"password": user.uuid, "email": email}
        if protocol == "shadowsocks":
            # SS-2022 multi-user: per-user PSK lives in clients[].
            return {"password": user.uuid, "email": email}
        return None

    async def add_user(self, user: VpnUser, protocol_config: ProtocolConfig) -> bool:
        """Add a user to every live Xray inbound via `xray api adu`.

        `xray api adu` reads a config-style JSON (an `inbounds` array of
        complete inbound objects) and injects each inbound's
        settings.clients into the matching running inbound by tag — no
        full restart, connections preserved.
        """
        inbounds = self._read_live_inbounds()
        if not inbounds:
            logger.warning("xray add_user: no live inbounds found; nothing to do")
            return False

        adu_inbounds: List[Dict[str, Any]] = []
        for ib in inbounds:
            entry = self._client_entry(ib.get("protocol", ""), user)
            if entry is None:
                continue
            clone = json.loads(json.dumps(ib))  # deep copy
            clone.setdefault("settings", {})["clients"] = [entry]
            adu_inbounds.append(clone)

        if not adu_inbounds:
            logger.info("xray add_user: no inbound accepts a per-user credential")
            return False

        payload = {"inbounds": adu_inbounds}
        fd, tmp = tempfile.mkstemp(prefix="xray-adu-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            proc = await asyncio.to_thread(
                subprocess.run,
                [self._bin(), "api", "adu", f"--server={self._api_server()}", tmp],
                capture_output=True, text=True, timeout=15,
            )
            ok = proc.returncode == 0 and "result: ok" in (proc.stdout + proc.stderr)
            if not ok:
                logger.error(
                    "xray adu for %s failed: %s",
                    user.name, (proc.stderr or proc.stdout or "").strip()[:200],
                )
            return ok
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.error("xray adu for %s errored: %s", user.name, exc)
            return False
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    async def remove_user(self, user_uuid: str, email: Optional[str] = None) -> bool:
        """Remove a user from every live Xray inbound via `xray api rmu`.

        rmu identifies users by email, so we remove `email` from each
        inbound tag. Falls back to the uuid as the email key when the
        caller didn't pass one (legacy behaviour)."""
        ident = email or user_uuid
        inbounds = self._read_live_inbounds()
        if not inbounds:
            return False
        all_ok = True
        for ib in inbounds:
            tag = ib.get("tag", "")
            if not tag:
                continue
            try:
                proc = await asyncio.to_thread(
                    subprocess.run,
                    [self._bin(), "api", "rmu", f"--server={self._api_server()}", f"-tag={tag}", ident],
                    capture_output=True, text=True, timeout=15,
                )
                # rmu exits 0 even when the user wasn't present, so we
                # treat a non-zero exit (e.g. unknown tag) as a per-tag
                # miss rather than a hard failure.
                if proc.returncode != 0:
                    all_ok = False
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                logger.error("xray rmu for %s on %s errored: %s", ident, tag, exc)
                all_ok = False
        return all_ok


# ═══════════════════════════════════════════════════════════════
#  sing-box Backend
# ═══════════════════════════════════════════════════════════════

class SingboxBackend:
    """sing-box backend manager."""

    def __init__(self, agent: Agent):
        self.agent = agent
        self.conn = AgentConnection(agent)

    async def restart(self) -> bool:
        try:
            result = await helper_request(
                "service.restart", {"service": self.agent.service_name or "sing-box"}, timeout=35
            )
            return result.ok
        except PrivilegedHelperError as e:
            logger.error(f"Failed to restart sing-box on {self.agent.name}: {e}")
            return False

    async def deploy_config(self, config: Dict[str, Any]) -> bool:
        """Deploy sing-box configuration."""
        try:
            installed = await helper_request(
                "config.install", {"target": "sing-box", "content": json.dumps(config, indent=2)}
            )
            if not installed.ok:
                return False
            return await self.restart()
        except Exception as e:
            logger.error(f"Failed to deploy sing-box config: {e}")
            return False

    async def add_user(self, user: VpnUser, protocol_config: ProtocolConfig) -> bool:
        """Add a user to the sing-box standalone protocols.

        sing-box has no runtime user-add API (unlike Xray's gRPC adu).
        In this panel the standalone protocols (Hysteria2/TUIC/ShadowTLS/
        NaiveProxy) authenticate every client with a single shared,
        per-protocol credential that is handed out in the user's share
        link — there is no per-UUID entry to inject. Adding a panel user
        therefore needs no change to the live sing-box config, so this is
        intentionally a no-op (we must NOT restart sing-box on every user
        create — that would drop all active QUIC sessions for nothing).

        The authoritative config is (re)generated by
        `app.services.protocol_sync._sync_singbox` whenever a protocol's
        settings change; that path owns writes + validation + reload.
        """
        return True

    async def remove_user(self, user_uuid: str) -> bool:
        """Remove a user — see add_user: shared-credential model, no-op."""
        return True


# ═══════════════════════════════════════════════════════════════
#  WireGuard Backend
# ═══════════════════════════════════════════════════════════════

class WireGuardBackend:
    """WireGuard/AmneziaWG backend manager."""

    def __init__(self, agent: Agent):
        self.agent = agent
        self.conn = AgentConnection(agent)

    async def add_user(self, user: VpnUser, protocol_config: ProtocolConfig) -> Dict[str, str]:
        """Add a WireGuard peer. Returns client config."""
        try:
            import subprocess as sp

            # Generate client keys
            priv_key_result = sp.run(
                ["wg", "genkey"], capture_output=True, text=True
            )
            client_private_key = priv_key_result.stdout.strip()

            pub_key_result = sp.run(
                ["wg", "pubkey"], input=client_private_key,
                capture_output=True, text=True
            )
            client_public_key = pub_key_result.stdout.strip()

            # Assign IP from subnet
            interface = self.agent.wg_interface or "wg0"
            base_addr = self.agent.wg_address or "10.8.0.1/24"
            subnet = base_addr.split("/")[0].rsplit(".", 1)[0]

            # Get next available IP
            show_result = sp.run(
                ["wg", "show", interface, "allowed-ips"],
                capture_output=True, text=True
            )
            used_ips = set()
            for line in show_result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        ip = parts[1].split("/")[0]
                        used_ips.add(ip.rsplit(".", 1)[1] if "." in ip else "1")

            client_ip_num = 2
            while str(client_ip_num) in used_ips:
                client_ip_num += 1
            client_ip = f"{subnet}.{client_ip_num}/24"

            # Add peer
            sp.run(
                ["wg", "set", interface, "peer", client_public_key,
                 "allowed-ips", client_ip],
                capture_output=True, text=True
            )

            # Save config
            sp.run(
                ["wg-quick", "save", interface],
                capture_output=True, text=True
            )

            # Pull AmneziaWG obfuscation parameters from the protocol
            # config. These junk-packet knobs (Jc/Jmin/Jmax/S1/S2/H1-H4)
            # are the entire reason to run AmneziaWG over plain WireGuard
            # — without them the DPI-evasion is a no-op. They must match
            # between server and client, so we echo the server's values
            # into the generated client config.
            pcfg = (protocol_config.config or {}) if protocol_config else {}
            is_amnezia = (
                protocol_config is not None
                and protocol_config.protocol_key == "amneziawg"
            )

            # Generate client config
            from .protocol_engine import ClientConfigGenerator
            config = ClientConfigGenerator.generate_wg_config(
                interface_private_key=client_private_key,
                interface_address=client_ip,
                server_public_key=self.agent.wg_public_key or "",
                server_endpoint=f"{self.agent.address}:{self.agent.wg_listen_port or 51820}",
                dns=self.agent.wg_dns or "1.1.1.1",
                mtu=int(pcfg.get("mtu", self.agent.wg_mtu or 1280)),
                jc=int(pcfg.get("jc", 0)) if is_amnezia else 0,
                jmin=int(pcfg.get("jmin", 0)) if is_amnezia else 0,
                jmax=int(pcfg.get("jmax", 0)) if is_amnezia else 0,
                s1=int(pcfg.get("s1", 0)) if is_amnezia else 0,
                s2=int(pcfg.get("s2", 0)) if is_amnezia else 0,
                h1=int(pcfg.get("h1", 0)) if is_amnezia else 0,
                h2=int(pcfg.get("h2", 0)) if is_amnezia else 0,
                h3=int(pcfg.get("h3", 0)) if is_amnezia else 0,
                h4=int(pcfg.get("h4", 0)) if is_amnezia else 0,
            )

            return {"config": config, "success": True, "public_key": client_public_key}
        except Exception as e:
            logger.error(f"Failed to add WG peer: {e}")
            return {"config": "", "success": False, "error": str(e)}

    async def remove_user(self, client_public_key: str) -> bool:
        """Remove a WireGuard peer."""
        try:
            interface = self.agent.wg_interface or "wg0"
            result = await helper_request(
                "wireguard.remove_peer",
                {"interface": interface, "public_key": client_public_key},
            )
            return result.ok
        except PrivilegedHelperError as e:
            logger.error(f"Failed to remove WG peer: {e}")
            return False


# ═══════════════════════════════════════════════════════════════
#  Orchestrator
# ═══════════════════════════════════════════════════════════════

class Orchestrator:
    """Multi-backend orchestrator.

    Routes user operations to the correct backend based on agent type.
    """

    def __init__(self):
        self._backends: Dict[int, Any] = {}  # agent_id -> backend instance

    def _get_backend(self, agent: Agent):
        """Get the appropriate backend for an agent."""
        if agent.id in self._backends:
            return self._backends[agent.id]

        if agent.backend == AgentBackend.xray:
            backend = XrayBackend(agent)
        elif agent.backend == AgentBackend.singbox:
            backend = SingboxBackend(agent)
        elif agent.backend == AgentBackend.wireguard:
            backend = WireGuardBackend(agent)
        else:
            backend = XrayBackend(agent)  # Default to Xray

        self._backends[agent.id] = backend
        return backend

    async def health_check_all(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Check health of all agents."""
        result = await db.execute(select(Agent))
        agents = result.scalars().all()

        statuses = []
        for agent in agents:
            backend = self._get_backend(agent)
            is_healthy = await backend.conn.health_check()

            # Update agent status
            agent.status = AgentStatus.online if is_healthy else AgentStatus.offline
            agent.last_heartbeat = _utcnow() if is_healthy else agent.last_heartbeat

            statuses.append({
                "id": agent.id,
                "name": agent.name,
                "backend": agent.backend.value,
                "status": agent.status.value,
                "healthy": is_healthy,
                "last_heartbeat": agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
            })

        await db.commit()
        return statuses

    async def add_user_to_agent(
        self, user: VpnUser, agent: Agent, protocol_config: ProtocolConfig
    ) -> Dict[str, Any]:
        """Add a user to the appropriate backend."""
        backend = self._get_backend(agent)
        result = await backend.add_user(user, protocol_config)
        return result if isinstance(result, dict) else {"success": result}

    async def remove_user_from_agent(
        self, user: VpnUser, agent: Agent
    ) -> bool:
        """Remove a user from the appropriate backend."""
        backend = self._get_backend(agent)
        if isinstance(backend, WireGuardBackend):
            # WG identifies peers by public key, not email.
            return await backend.remove_user(user.uuid)
        if isinstance(backend, XrayBackend):
            # Xray rmu keys off the user's email (== user.name).
            return await backend.remove_user(user.uuid, email=user.name)
        return await backend.remove_user(user.uuid)

    async def deploy_agent_config(
        self, agent: Agent, config: Dict[str, Any]
    ) -> bool:
        """Deploy configuration to an agent."""
        backend = self._get_backend(agent)
        return await backend.deploy_config(config)

    async def restart_agent(self, agent: Agent) -> bool:
        """Restart an agent's service."""
        backend = self._get_backend(agent)
        return await backend.restart()

    async def get_user_traffic(
        self, user: VpnUser, agent: Agent
    ) -> Dict[str, int]:
        """Get user traffic from the backend."""
        backend = self._get_backend(agent)
        if isinstance(backend, XrayBackend):
            # Xray stat counters key off the user's email (== user.name).
            return await backend.get_user_traffic(user.name or user.uuid)
        return {"upload": 0, "download": 0}

    async def setup_ech(
        self, agent: Agent, public_name: str = "cloudflare-ech.com"
    ) -> Dict[str, Any]:
        """Setup ECH (Encrypted Client Hello) for an agent."""
        keys = ech_mgr.generate_ech_keys()
        ech_config = ech_mgr.generate_ech_config(
            public_key=keys["public_key"],
            public_name=public_name,
        )
        dns_record = ech_mgr.generate_dns_https_record(ech_config)

        # Update agent ECH config
        agent.ech_enabled = True
        agent.ech_config = {
            "keys": [keys],
            "public_name": public_name,
            "ech_config": ech_config,
            "dns_record": dns_record,
        }

        return {
            "ech_keys": keys,
            "ech_config": ech_config,
            "dns_record": dns_record,
            "instructions": f"Publish the following DNS HTTPS record for your domain:\n{dns_record}"
        }


# Global orchestrator instance
orchestrator = Orchestrator()
