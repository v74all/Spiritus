"""Ops automation: auto Emergency Cloak, change-only alerts, subscription ordering."""

import asyncio
import base64
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

import app.api.compat as compat
import app.api.ops as ops
import app.ops_automation as auto
from app.api.compat._core import _load_legacy_settings, _save_legacy_settings
from app.auth import create_access_token, get_password_hash
from app.database import AsyncSessionLocal, init_db
from app.main import _subscription_json_config, app
from app.models import Admin, AuditLog, EdgeNode, ProbeAgent, ProbeReport, Setting, UserRole, VpnUser
from app.timeutil import utcnow

PASSWORD = "Sup3rStrong!Pass-1"
CLOAK_RESET = {
    "emergency_cloak_active": False, "emergency_cloak_source": None, "emergency_cloak_since": None,
    "emergency_cloak_snapshot": None, "emergency_cloak_manual_off_at": None,
    "fragment_enabled": False, "noise_enabled": False,
    "auto_cloak_enabled": True, "auto_protocol_order_enabled": True, "ops_alerts_enabled": True,
}


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # settings saves mirror to ./vpn-settings.json
    monkeypatch.setattr(ops, "_process_running", lambda name: True)
    ops._RANK_CACHE.update(at=-1e9, rank={})

    async def reset():
        await init_db()
        async with AsyncSessionLocal() as db:
            for model in (ProbeReport, ProbeAgent, EdgeNode):
                await db.execute(delete(model))
            await db.execute(delete(Setting).where(Setting.key == auto.STATE_KEY))
            await db.commit()
            await _save_legacy_settings(db, dict(CLOAK_RESET))

    _run(reset())


class Collector:
    def __init__(self):
        self.messages = []

    async def __call__(self, text):
        self.messages.append(text)
        return True


async def _probes(n):
    async with AsyncSessionLocal() as db:
        probes = [ProbeAgent(name=f"p{i}", token_hash=uuid.uuid4().hex * 2, token_prefix="spr_test") for i in range(n)]
        db.add_all(probes)
        await db.commit()
        return [p.id for p in probes]


async def _reports(probe_ids, ok, count, *, carrier="MCI (Hamrah-e Aval)", protocol="vless_vision_reality", age=timedelta(minutes=5)):
    async with AsyncSessionLocal() as db:
        at = utcnow() - age
        for i in range(count):
            db.add(ProbeReport(probe_id=probe_ids[i % len(probe_ids)], carrier=carrier, protocol=protocol,
                               method="tls", ok=ok, latency_ms=120.0 if ok else None, created_at=at))
        await db.commit()


async def _tick(collector, now=None):
    async with AsyncSessionLocal() as db:
        return await auto.run_monitor(db, notify=collector, now=now)


async def _settings(**values):
    async with AsyncSessionLocal() as db:
        if values:
            await _save_legacy_settings(db, values)
        return await _load_legacy_settings(db)


# ── Automatic Emergency Cloak ───────────────────────────────────

def test_cloak_engages_when_probes_from_several_devices_mostly_fail():
    async def go():
        ids = await _probes(2)
        await _reports(ids, ok=False, count=12)
        c = Collector()
        await _tick(c)
        s = await _settings()
        async with AsyncSessionLocal() as db:
            audits = (await db.execute(select(AuditLog).where(AuditLog.action == "emergency_cloak_on"))).scalars().all()
        return c, s, audits

    c, s, audits = _run(go())
    assert s["emergency_cloak_active"] is True and s["emergency_cloak_source"] == "auto"
    assert s["fragment_enabled"] is True and s["noise_enabled"] is True
    assert any(a.details.get("source") == "auto" for a in audits)
    assert any("Emergency Cloak خودکار روشن شد" in m for m in c.messages)


def test_cloak_needs_more_than_one_probe():
    async def go():
        ids = await _probes(1)
        await _reports(ids, ok=False, count=20)
        await _tick(Collector())
        return await _settings()

    assert _run(go())["emergency_cloak_active"] is False


def test_cloak_holds_back_after_a_manual_switch_off():
    async def go():
        await _settings(emergency_cloak_manual_off_at=(utcnow() - timedelta(hours=1)).isoformat())
        ids = await _probes(2)
        await _reports(ids, ok=False, count=12)
        await _tick(Collector())
        return await _settings()

    assert _run(go())["emergency_cloak_active"] is False


def test_auto_cloak_is_released_after_recovery_and_settings_restored():
    async def go():
        await _settings(fragment_length="5-10")
        async with AsyncSessionLocal() as db:
            await ops.apply_cloak(db, True, "auto")
        await _settings(emergency_cloak_since=(utcnow() - timedelta(hours=2)).isoformat())
        ids = await _probes(2)
        await _reports(ids, ok=True, count=12)
        c = Collector()
        await _tick(c)
        return c, await _settings()

    c, s = _run(go())
    assert s["emergency_cloak_active"] is False and s["fragment_enabled"] is False
    assert s["fragment_length"] == "5-10"
    assert any("خاموش شد" in m for m in c.messages)


def test_a_cloak_switched_on_by_hand_is_never_released_automatically():
    async def go():
        async with AsyncSessionLocal() as db:
            await ops.apply_cloak(db, True, "manual")
        await _settings(emergency_cloak_since=(utcnow() - timedelta(hours=5)).isoformat())
        ids = await _probes(2)
        await _reports(ids, ok=True, count=20)
        await _tick(Collector())
        return await _settings()

    s = _run(go())
    assert s["emergency_cloak_active"] is True and s["emergency_cloak_source"] == "manual"


def test_auto_cloak_can_be_switched_off():
    async def go():
        await _settings(auto_cloak_enabled=False)
        ids = await _probes(2)
        await _reports(ids, ok=False, count=12)
        await _tick(Collector())
        return await _settings()

    assert _run(go())["emergency_cloak_active"] is False


# ── Alerts on state changes only ─────────────────────────────────

def test_first_run_is_silent_then_each_change_is_announced_once(monkeypatch):
    state = {"xray": True, "node": True}
    monkeypatch.setattr(ops, "_process_running", lambda name: state["xray"])

    async def fake_measure(host, port, *, sni="", attempts=1):
        return {"ok": state["node"], "ms": 12.0 if state["node"] else None, "error": None if state["node"] else "timeout"}

    monkeypatch.setattr(ops, "_measure", fake_measure)

    async def go():
        async with AsyncSessionLocal() as db:
            db.add(EdgeNode(name="fra-1", address="203.0.113.5", port=443))
            await db.commit()
        c = Collector()
        t0 = utcnow()
        await _tick(c, now=t0)
        first = list(c.messages)
        state.update(xray=False, node=False)
        await _tick(c, now=t0 + timedelta(minutes=6))
        second = c.messages[len(first):]
        await _tick(c, now=t0 + timedelta(minutes=12))
        third = c.messages[len(first) + len(second):]
        return first, second, third

    first, second, third = _run(go())
    assert first == []
    assert any("Xray متوقف شده" in m for m in second)
    assert any("fra-1" in m and "از دسترس خارج شد" in m for m in second)
    assert third == []


def test_blocked_protocol_on_a_carrier_is_announced_and_its_recovery_too():
    async def go():
        ids = await _probes(1)
        c = Collector()
        await _tick(c)  # baseline
        await _reports(ids, ok=False, count=3, carrier="<b>Evil</b> ISP")
        await _tick(c)
        blocked = list(c.messages)
        await _reports(ids, ok=True, count=4, carrier="<b>Evil</b> ISP")
        await _tick(c)
        return blocked, c.messages[len(blocked):]

    blocked, recovered = _run(go())
    assert any("بسته شده" in m for m in blocked)
    # Probe-supplied carrier names are escaped before they reach Telegram HTML.
    assert all("<b>Evil</b>" not in m for m in blocked) and any("&lt;b&gt;Evil&lt;/b&gt;" in m for m in blocked)
    assert any("دوباره کار می‌کند" in m for m in recovered)


def test_alerts_can_be_switched_off():
    async def go():
        await _settings(ops_alerts_enabled=False)
        ids = await _probes(1)
        c = Collector()
        await _tick(c)
        await _reports(ids, ok=False, count=3)
        await _tick(c)
        async with AsyncSessionLocal() as db:
            state = await auto.load_state(db)
        return c, state

    c, state = _run(go())
    assert c.messages == []
    assert state["blocked"] and state["log"]  # still detected and logged in the panel


# ── Subscription ordering ────────────────────────────────────────

def test_subscription_lists_working_protocols_first(monkeypatch):
    monkeypatch.setattr(compat, "_user_to_legacy", lambda user, server_ip=None: {
        "vmess": "vmess://A", "vless_vision": "vless://VISION", "hysteria2": "hy2://H", "trojan": "trojan://T",
    })

    async def seed():
        ids = await _probes(1)
        await _reports(ids, ok=False, count=3, protocol="vmess")
        await _reports(ids, ok=True, count=3, protocol="vless_vision_reality")
        async with AsyncSessionLocal() as db:
            u = VpnUser(uuid=str(uuid.uuid4()), name=f"ord-{uuid.uuid4().hex[:6]}", active=1)
            db.add(u)
            await db.commit()
            return u.uuid

    with TestClient(app) as client:
        user_uuid = _run(seed())
        body = client.get(f"/sub-api/{user_uuid}").text
        ordered = base64.b64decode(body).decode().split("\n")
        _run(_settings(auto_protocol_order_enabled=False))
        ops._RANK_CACHE.update(at=-1e9, rank={})
        default = base64.b64decode(client.get(f"/sub-api/{user_uuid}").text).decode().split("\n")

    # Working first, untested (trojan, UDP hysteria2) keep default order, failing last.
    assert ordered == ["vless://VISION", "trojan://T", "hy2://H", "vmess://A"]
    assert default == ["vmess://A", "vless://VISION", "trojan://T", "hy2://H"]


def test_json_subscription_puts_the_best_protocol_first():
    user = SimpleNamespace(uuid=str(uuid.uuid4()), name="sara")
    s = {"vless_vision_enabled": True, "trojan_enabled": True, "config_prefix": "Proxy"}
    rank = {"vless_vision_reality": (0, -1.0, 90.0), "vmess": (2, -0.0, 1e9)}
    tags = [o["tag"] for o in _subscription_json_config(user, "203.0.113.10", s, rank)["outbounds"]]
    proxies = [t for t in tags if t.startswith("Proxy-")]
    assert proxies[0] == "Proxy-VLESS-Vision-sara" and proxies[-1] == "Proxy-VMess-sara"
    assert tags[-2:] == ["direct", "block"]


# ── Endpoints ────────────────────────────────────────────────────

@pytest.fixture
def admin_headers():
    async def setup():
        async with AsyncSessionLocal() as db:
            a = Admin(username=f"auto-{uuid.uuid4().hex[:8]}", password_hash=get_password_hash(PASSWORD), role=UserRole.admin)
            db.add(a)
            await db.commit()
            return a.username

    return {"Authorization": "Bearer " + create_access_token({"sub": _run(setup()), "is_admin": True})}


def test_automation_endpoints(admin_headers, monkeypatch):
    monkeypatch.setattr(ops, "_schedule_xray_sync", lambda: None)
    with TestClient(app) as client:
        st = client.get("/api/ops/automation", headers=admin_headers).json()
        assert st["last_run_at"] is None and st["settings"]["auto_cloak_enabled"] is True
        st = client.post("/api/ops/automation", json={"auto_cloak_enabled": False}, headers=admin_headers).json()
        assert st["settings"]["auto_cloak_enabled"] is False
        run = client.post("/api/ops/automation/run", headers=admin_headers).json()
        assert run["status"]["last_run_at"] is not None
        r = client.post("/api/ops/automation/test-alert", headers=admin_headers)
        assert r.status_code == 400 and "Telegram" in r.json()["detail"]
        assert client.get("/api/ops/automation").status_code == 401


def test_monitor_is_scheduled_every_minute():
    from app.celery_tasks import celery_app

    entry = celery_app.conf.beat_schedule["ops-monitor"]
    assert entry["task"] == "app.celery_tasks.ops_monitor" and entry["schedule"] == 60.0


def test_blocks_present_on_the_first_run_are_recorded_not_announced():
    async def go():
        ids = await _probes(1)
        await _reports(ids, ok=False, count=3)
        c = Collector()
        await _tick(c)
        async with AsyncSessionLocal() as db:
            return c, await auto.load_state(db)

    c, state = _run(go())
    assert c.messages == [] and state["blocked"] == ["MCI (Hamrah-e Aval)|vless_vision_reality"]
