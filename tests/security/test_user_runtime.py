"""Users reach the running engines, traffic is counted, limits are enforced.

Checked end to end against a live Xray 26 (create / disable / quota / expiry /
delete, all without a restart). These tests pin the logic with a fake
`xray api` so they run anywhere.
"""

import asyncio
import datetime
import json
import subprocess
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import user_runtime
from app.api.compat import monitor
from app.auth import create_access_token, get_password_hash
from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.models import Admin, TrafficDaily, UserRole, VpnUser
from app.user_runtime import ACTIVE, DISABLED, EXPIRED, QUOTA, status_for


def _run(coro):
    return asyncio.run(coro)


def _user(**kw):
    base = {"id": 1, "name": "ali", "uuid": str(uuid.uuid4()), "active": ACTIVE,
            "traffic_limit": 0, "traffic_used": 0, "expire_at": None}
    base.update(kw)
    return VpnUser(**base)


# ── Status rules ────────────────────────────────────────────────────────

def test_status_rules():
    now = datetime.datetime(2026, 10, 20)
    assert status_for(_user(), now) == ACTIVE
    assert status_for(_user(expire_at=now - datetime.timedelta(seconds=1)), now) == EXPIRED
    assert status_for(_user(traffic_limit=100, traffic_used=100), now) == QUOTA
    assert status_for(_user(traffic_limit=0, traffic_used=10**12), now) == ACTIVE  # 0 = unlimited
    # Switched off by hand stays off, whatever the dates say.
    assert status_for(_user(active=DISABLED), now) == DISABLED
    # Expired / limited users come back once renewed / given traffic.
    assert status_for(_user(active=EXPIRED, expire_at=now + datetime.timedelta(days=3)), now) == ACTIVE
    assert status_for(_user(active=QUOTA, traffic_limit=200, traffic_used=100), now) == ACTIVE


# ── Reconcile (fake `xray api`) ─────────────────────────────────────────

def _load(path):
    with open(path) as fh:
        return json.load(fh)


class FakeXray:
    def __init__(self, live):
        self.live = live  # tag -> {email: account}
        self.calls = []
        self.outbounds = {"direct", "block"}
        self.rules = []

    def __call__(self, command, *args, timeout=15):
        self.calls.append((command, args))
        out = {}
        if command == "lsi":
            out = {"inbounds": [{"tag": t} for t in self.live]}
        elif command == "inbounduser":
            tag = args[0].split("=", 1)[1]
            out = {"users": [{"email": e, "account": a} for e, a in self.live[tag].items()]}
        elif command == "lso":
            out = {"outbounds": [{"tag": t} for t in self.outbounds]}
        elif command == "lsrules":
            out = {"rules": [{"ruleTag": r["ruleTag"]} for r in self.rules]}
        elif command == "rmu":
            tag = args[0].split("=", 1)[1]
            for e in args[1:]:
                self.live[tag].pop(e, None)
        elif command == "adu":
            for ib in _load(args[0])["inbounds"]:
                for c in ib["settings"]["clients"]:
                    self.live[ib["tag"]][c["email"]] = {k: v for k, v in c.items() if k != "email"}
        elif command == "ado":
            self.outbounds |= {o["tag"] for o in _load(args[0])["outbounds"]}
        elif command == "adrules":
            self.rules = _load(args[0])["routing"]["rules"]
        elif command == "rmo":
            self.outbounds -= set(args)
        elif command == "rmrules":
            self.rules = [r for r in self.rules if r["ruleTag"] not in args]
        return subprocess.CompletedProcess([], 0, json.dumps(out), "")


def _config(clients, limits=()):
    return {
        "inbounds": [
            {"tag": "in-vless", "protocol": "vless", "settings": {"clients": clients}},
            {"tag": "in-http-relay", "protocol": "http", "settings": {}},
        ],
        "outbounds": [{"tag": "direct"}, {"tag": "block"}, *[{"tag": f"limit-{i}"} for i in limits]],
        "routing": {"rules": [{"user": ["x"], "outboundTag": f"limit-{i}", "ruleTag": f"limit-{i}"} for i in limits]},
    }


def test_reconcile_adds_removes_and_replaces_changed_users(monkeypatch):
    fake = FakeXray({"in-vless": {"old": {"id": "1"}, "keep": {"id": "2"}, "moved": {"id": "3"}}, "in-http-relay": {}})
    monkeypatch.setattr(user_runtime, "_xray_api", fake)
    wanted = [{"id": "2", "email": "keep"}, {"id": "33", "email": "moved"}, {"id": "4", "email": "new"}]
    result = user_runtime._reconcile_blocking(_config(wanted))
    assert result["ok"] and result["added"] == 2 and result["removed"] == 2
    assert fake.live["in-vless"] == {"keep": {"id": "2"}, "moved": {"id": "33"}, "new": {"id": "4"}}
    # A second pass has nothing to do.
    fake.calls.clear()
    assert user_runtime._reconcile_blocking(_config(wanted))["added"] == 0
    assert not [c for c in fake.calls if c[0] in ("adu", "rmu")]


def test_reconcile_keeps_speed_limit_outbounds_and_rules_in_step(monkeypatch):
    fake = FakeXray({"in-vless": {}, "in-http-relay": {}})
    monkeypatch.setattr(user_runtime, "_xray_api", fake)
    assert user_runtime._reconcile_blocking(_config([], limits=(7, 9)))["ok"]
    assert {"limit-7", "limit-9"} <= fake.outbounds and {r["ruleTag"] for r in fake.rules} == {"limit-7", "limit-9"}
    assert user_runtime._reconcile_blocking(_config([], limits=(9,)))["ok"]
    assert "limit-7" not in fake.outbounds and [r["ruleTag"] for r in fake.rules] == ["limit-9"]


def test_reconcile_asks_for_a_full_sync_when_inbounds_changed(monkeypatch):
    monkeypatch.setattr(user_runtime, "_xray_api", FakeXray({"in-other": {}}))
    assert user_runtime._reconcile_blocking(_config([]))["ok"] is False


def test_xray_api_puts_the_server_flag_before_positionals(monkeypatch):
    seen = {}
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: seen.setdefault("argv", argv) and subprocess.CompletedProcess(argv, 0, "", ""))
    user_runtime._xray_api("rmu", "-tag=x", "alice")
    argv = seen["argv"]
    # Go stops parsing flags at the first positional: a trailing --server=
    # was taken as a user to remove and the call went to the wrong port.
    assert argv.index(next(a for a in argv if a.startswith("--server="))) < argv.index("alice")


# ── Traffic + limits through the DB ─────────────────────────────────────

async def _make_users(*specs):
    await init_db()
    async with AsyncSessionLocal() as db:
        out = []
        for name, kw in specs:
            u = VpnUser(name=f"{name}-{uuid.uuid4().hex[:6]}", uuid=str(uuid.uuid4()), active=ACTIVE, **kw)
            db.add(u)
            out.append(u)
        await db.commit()
        return [(u.id, u.name) for u in out]


def test_collected_traffic_is_counted_daily_and_quota_enforced(monkeypatch):
    (uid, name), (uid2, name2) = _run(_make_users(("q", {"traffic_limit": 1000}), ("free", {})))
    reads = []

    def fake_stats(reset=False):
        reads.append(reset)
        return {name: {"up": 300, "down": 900}, name2: {"up": 5, "down": 5}}

    monkeypatch.setattr(user_runtime, "query_user_stats", fake_stats)

    async def cycle():
        async with AsyncSessionLocal() as db:
            await user_runtime.collect_traffic(db)
            changed = await user_runtime.enforce_limits(db)
        async with AsyncSessionLocal() as db:
            u = (await db.execute(select(VpnUser).where(VpnUser.id == uid))).scalar_one()
            daily = (await db.execute(select(TrafficDaily).where(TrafficDaily.user_id == uid))).scalars().all()
            return changed, u, daily

    changed, u, daily = _run(cycle())
    assert reads == [True]  # the collector reads with reset: each byte counted once
    assert (u.traffic_upload, u.traffic_download, u.traffic_used) == (300, 900, 1200)
    assert u.active == QUOTA and changed >= 1
    assert len(daily) == 1 and (daily[0].upload, daily[0].download) == (300, 900)
    _, u, daily = _run(cycle())
    assert u.traffic_used == 2400 and len(daily) == 1 and daily[0].download == 1800


def test_live_counters_are_read_without_reset(monkeypatch):
    calls = []
    monkeypatch.setattr(user_runtime, "query_user_stats", lambda reset=False: calls.append(reset) or {"a": {"up": 1, "down": 2}})
    stats = monitor._query_xray_stats(reset=False)
    assert stats == {"a": {"up": 1, "down": 2}} and calls == [False]


def test_user_changes_request_an_engine_sync(monkeypatch):
    requested = []
    monkeypatch.setattr(user_runtime, "request_sync", lambda: requested.append(1))
    monkeypatch.setattr(user_runtime.settings, "user_runtime_sync", True)
    (uid, _), = _run(_make_users(("hook", {})))
    assert requested  # creating the user

    async def toggle(field, value):
        async with AsyncSessionLocal() as db:
            u = (await db.execute(select(VpnUser).where(VpnUser.id == uid))).scalar_one()
            setattr(u, field, value)
            await db.commit()

    requested.clear()
    _run(toggle("note", "just a note"))
    assert not requested  # unrelated fields do not touch the engines
    _run(toggle("active", DISABLED))
    assert requested
    requested.clear()
    _run(toggle("speed_limit_down", 500))
    assert requested


# ── Admin routes ────────────────────────────────────────────────────────

@pytest.fixture
def admin_headers():
    async def setup():
        await init_db()
        async with AsyncSessionLocal() as db:
            admin = Admin(username=f"rt-{uuid.uuid4().hex[:8]}", password_hash=get_password_hash("Sup3rStrong!Pass-1"),
                          role=UserRole.admin)
            db.add(admin)
            await db.commit()
            return admin.username

    return {"Authorization": "Bearer " + create_access_token({"sub": _run(setup()), "is_admin": True})}


def test_toggle_renew_and_more_traffic_follow_the_rules(admin_headers, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (uid, name), = _run(_make_users(("route", {"traffic_limit": 100, "traffic_used": 500})))

    async def set_active(v):
        async with AsyncSessionLocal() as db:
            u = (await db.execute(select(VpnUser).where(VpnUser.id == uid))).scalar_one()
            u.active = v
            await db.commit()

    _run(set_active(QUOTA))
    with TestClient(app) as client:
        users = {u["name"]: u for u in client.get("/api/users", headers=admin_headers).json()}
        assert users[name]["status"] == "limited" and users[name]["active"] is False
        # Switching on a user still over quota keeps them limited.
        r = client.post(f"/api/users/{name}/toggle", headers=admin_headers).json()
        assert r["status"] == "disabled"
        r = client.post(f"/api/users/{name}/toggle", headers=admin_headers).json()
        assert r["status"] == "limited"
        client.post(f"/api/users/{name}/add-traffic", json={"gb": 1}, headers=admin_headers)
        users = {u["name"]: u for u in client.get("/api/users", headers=admin_headers).json()}
        assert users[name]["status"] == "active"
        # Renew with 0 days means "never expires", not "expires now".
        client.post(f"/api/users/{name}/renew", json={"traffic": 5, "days": 0}, headers=admin_headers)
        users = {u["name"]: u for u in client.get("/api/users", headers=admin_headers).json()}
        assert users[name]["status"] == "active" and users[name]["expire_at"] is None
