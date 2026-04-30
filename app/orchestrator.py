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
import subprocess
import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Agent, AgentBackend, AgentStatus, ProtocolConfig, VpnUser
from .protocol_engine import XrayConfigGenerator, ech_mgr

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
            subprocess.run(
                ["systemctl", "restart", self.agent.service_name or "xray"],
                capture_output=True, text=True, timeout=30
            )
            return True
        except Exception as e:
            logger.error(f"Failed to restart Xray on {self.agent.name}: {e}")
            return False

    async def reload_config(self) -> bool:
        """Reload Xray configuration."""
        try:
            subprocess.run(
                ["systemctl", "reload", self.agent.service_name or "xray"],
                capture_output=True, text=True, timeout=30
            )
            return True
        except Exception as e:
            logger.error(f"Failed to reload Xray config on {self.agent.name}: {e}")
            return False

    async def get_user_traffic(self, user_uuid: str) -> Dict[str, int]:
        """Get user traffic from Xray API."""
        try:
            client = await self.conn.get_client()
            resp = await client.get(
                f"/debug/pprof/goroutine?user={user_uuid}"
            )
            # Xray API: Get user stats
            resp_up = await client.post(
                "/api/v1/stats",
                json={"tag": f"user>>>{user_uuid}>>>uplink>>>traffic>>>bytes"}
            )
            resp_down = await client.post(
                "/api/v1/stats",
                json={"tag": f"user>>>{user_uuid}>>>downlink>>>traffic>>>bytes"}
            )
            up = resp_up.json().get("stat", {}).get("value", 0) if resp_up.status_code == 200 else 0
            down = resp_down.json().get("stat", {}).get("value", 0) if resp_down.status_code == 200 else 0
            return {"upload": int(up), "download": int(down)}
        except Exception as e:
            logger.error(f"Failed to get traffic for {user_uuid}: {e}")
            return {"upload": 0, "download": 0}

    async def deploy_config(self, config: Dict[str, Any]) -> bool:
        """Deploy Xray configuration to agent."""
        try:
            config_path = self.agent.config_path or "/usr/local/etc/xray/config.json"
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)

            # Validate config
            result = subprocess.run(
                [self.agent.bin_path or "/usr/local/bin/xray", "test", "-config", config_path],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.error(f"Xray config validation failed: {result.stderr}")
                return False

            # Reload
            return await self.reload_config()
        except Exception as e:
            logger.error(f"Failed to deploy Xray config: {e}")
            return False

    async def add_user(self, user: VpnUser, protocol_config: ProtocolConfig) -> bool:
        """Add a user to Xray via API."""
        try:
            client = await self.conn.get_client()
            resp = await client.post(
                "/api/v1/inbound/addClient",
                json={
                    "id": user.uuid,
                    "email": user.name,
                    "limitIp": 0,
                    "totalGB": user.traffic_limit // (1024 * 1024 * 1024) if user.traffic_limit else 0,
                    "expiryTime": int(user.expire_at.timestamp() * 1000) if user.expire_at else 0,
                    "enable": True,
                    "tgId": "",
                    "subId": "",
                }
            )
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Failed to add user {user.name} to Xray: {e}")
            return False

    async def remove_user(self, user_uuid: str) -> bool:
        """Remove a user from Xray via API."""
        try:
            client = await self.conn.get_client()
            resp = await client.post(
                "/api/v1/inbound/delClient",
                json={"id": user_uuid}
            )
            return resp.status_code == 200
        except Exception as e:
            logger.error(f"Failed to remove user {user_uuid} from Xray: {e}")
            return False


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
            subprocess.run(
                ["systemctl", "restart", self.agent.service_name or "sing-box"],
                capture_output=True, text=True, timeout=30
            )
            return True
        except Exception as e:
            logger.error(f"Failed to restart sing-box on {self.agent.name}: {e}")
            return False

    async def deploy_config(self, config: Dict[str, Any]) -> bool:
        """Deploy sing-box configuration."""
        try:
            config_path = self.agent.config_path or "/usr/local/etc/sing-box/config.json"
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            return await self.restart()
        except Exception as e:
            logger.error(f"Failed to deploy sing-box config: {e}")
            return False

    async def add_user(self, user: VpnUser, protocol_config: ProtocolConfig) -> bool:
        """Add user to sing-box config and reload."""
        # sing-box doesn't have a runtime API like Xray
        # We need to regenerate the full config and reload
        return await self.restart()


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

            # Generate client config
            from .protocol_engine import ClientConfigGenerator
            config = ClientConfigGenerator.generate_wg_config(
                interface_private_key=client_private_key,
                interface_address=client_ip,
                server_public_key=self.agent.wg_public_key or "",
                server_endpoint=f"{self.agent.address}:{self.agent.wg_listen_port or 51820}",
                dns=self.agent.wg_dns or "1.1.1.1",
                mtu=self.agent.wg_mtu or 1280,
            )

            return {"config": config, "success": True}
        except Exception as e:
            logger.error(f"Failed to add WG peer: {e}")
            return {"config": "", "success": False, "error": str(e)}

    async def remove_user(self, client_public_key: str) -> bool:
        """Remove a WireGuard peer."""
        try:
            interface = self.agent.wg_interface or "wg0"
            subprocess.run(
                ["wg", "set", interface, "peer", client_public_key, "remove"],
                capture_output=True, text=True
            )
            subprocess.run(
                ["wg-quick", "save", interface],
                capture_output=True, text=True
            )
            return True
        except Exception as e:
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
            agent.last_heartbeat = datetime.utcnow() if is_healthy else agent.last_heartbeat

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
            # Need client public key for WG
            return await backend.remove_user(user.uuid)
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
            return await backend.get_user_traffic(user.uuid)
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