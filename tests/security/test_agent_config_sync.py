import asyncio

from app.database import AsyncSessionLocal, init_db
from app.models import Agent, AgentBackend, AgentStatus
from app.orchestrator import Orchestrator


class FakeOrchestrator(Orchestrator):
    def __init__(self, failing=()):
        super().__init__()
        self.calls = []
        self.failing = set(failing)

    async def deploy_agent_config(self, agent, config):
        self.calls.append(agent.name)
        if agent.name in self.failing:
            raise RuntimeError("node down")
        return True


def test_sync_skips_unchanged_isolates_failures_and_ignores_offline():
    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            names = ["sync-a", "sync-b", "sync-off"]
            for n, st in zip(names, (AgentStatus.online, AgentStatus.online, AgentStatus.offline), strict=True):
                db.add(Agent(name=n, backend=AgentBackend.xray, address="10.0.0.1", status=st))
            await db.commit()

            orch = FakeOrchestrator(failing={"sync-b"})
            first = {r["name"]: r["status"] for r in await orch.sync_config_to_agents(db, {"x": 1})}
            assert first == {"sync-a": "synced", "sync-b": "failed"}
            assert "sync-off" not in orch.calls

            second = {r["name"]: r["status"] for r in await orch.sync_config_to_agents(db, {"x": 1})}
            assert second["sync-a"] == "unchanged" and second["sync-b"] == "failed"

            changed = {r["name"]: r["status"] for r in await orch.sync_config_to_agents(db, {"x": 2})}
            assert changed["sync-a"] == "synced"
            forced = {r["name"]: r["status"] for r in await orch.sync_config_to_agents(db, {"x": 2}, force=True)}
            assert forced["sync-a"] == "synced"

    asyncio.run(go())
