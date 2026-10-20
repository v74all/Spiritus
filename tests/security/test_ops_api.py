"""Ops panel API: cloak, panic flush, probes, carrier matrix, edge nodes, financials."""

import asyncio
import socket
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import app.api.ops as ops
from app.api.compat._core import _load_legacy_settings, _save_legacy_settings
from app.auth import create_access_token, get_password_hash
from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.middleware.ip_allowlist import _PUBLIC_PREFIXES
from app.models import (
    Admin,
    AuditLog,
    Payment,
    PaymentGateway,
    PaymentStatus,
    ProbeAgent,
    ProbeReport,
    UserRole,
)
from app.privileged_helper import HelperResponse, PrivilegedHelperError

PASSWORD = "Sup3rStrong!Pass-1"


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def admin_headers():
    async def setup():
        await init_db()
        async with AsyncSessionLocal() as db:
            admin = Admin(username=f"ops-{uuid.uuid4().hex[:8]}", password_hash=get_password_hash(PASSWORD),
                          role=UserRole.admin)
            db.add(admin)
            await db.commit()
            return admin.username

    name = _run(setup())
    return {"Authorization": "Bearer " + create_access_token({"sub": name, "is_admin": True})}


@pytest.fixture(autouse=True)
def no_xray_sync(monkeypatch, tmp_path):
    monkeypatch.setattr(ops, "_schedule_xray_sync", lambda: None)
    # Settings saves mirror to ./vpn-settings.json; keep that out of the repo.
    monkeypatch.chdir(tmp_path)


async def _settings(**values):
    async with AsyncSessionLocal() as db:
        if values:
            await _save_legacy_settings(db, values)
        return await _load_legacy_settings(db)


# ── Emergency cloak ──────────────────────────────────────────────

def test_cloak_forces_dpi_values_and_restores_the_operators_own(admin_headers):
    _run(_settings(emergency_cloak_active=False, fragment_enabled=False, fragment_length="5-10",
                   noise_enabled=False, noise_packet="str:hello"))
    with TestClient(app) as client:
        on = client.post("/api/ops/cloak", json={"active": True}, headers=admin_headers).json()
        assert on["active"] is True
        assert on["values"]["fragment_enabled"] is True and on["values"]["noise_enabled"] is True
        assert on["values"]["fragment_length"] == "100-200"

        # Enabling twice must not overwrite the snapshot with the cloak values.
        client.post("/api/ops/cloak", json={"active": True}, headers=admin_headers)

        off = client.post("/api/ops/cloak", json={"active": False}, headers=admin_headers).json()
        s = _run(_settings())
    assert off["active"] is False
    assert s["fragment_enabled"] is False and s["fragment_length"] == "5-10"
    assert s["noise_enabled"] is False and s["noise_packet"] == "str:hello"


# ── Panic flush ──────────────────────────────────────────────────

def test_panic_flush_restarts_xray_and_is_audited(admin_headers, monkeypatch):
    calls = []

    async def fake_helper(operation, payload=None, *, timeout=30.0):
        calls.append((operation, payload["service"]))
        return HelperResponse(ok=True, message="restarted")

    async def audited():
        async with AsyncSessionLocal() as db:
            return (await db.execute(select(AuditLog).where(AuditLog.action == "panic_flush"))).scalars().all()

    monkeypatch.setattr(ops, "helper_request", fake_helper)
    with TestClient(app) as client:
        r = client.post("/api/ops/panic-flush", headers=admin_headers).json()
        assert _run(audited())
    assert r["ok"] is True and r["services"]["xray"]["ok"] is True
    assert ("service.restart", "xray") in calls


def test_panic_flush_reports_failure_when_helper_is_down(admin_headers, monkeypatch):
    async def down(*_a, **_k):
        raise PrivilegedHelperError("down")

    monkeypatch.setattr(ops, "helper_request", down)
    with TestClient(app) as client:
        r = client.post("/api/ops/panic-flush", headers=admin_headers).json()
    assert r["ok"] is False
    assert r["services"]["xray"]["message"] == "privileged helper unavailable"


# ── Probes ───────────────────────────────────────────────────────

def _create_probe(client, headers, name="tehran-phone"):
    r = client.post("/api/ops/probes", json={"name": name}, headers=headers)
    assert r.status_code == 201
    return r.json()


def test_probe_token_is_shown_once_and_only_its_hash_is_stored(admin_headers):
    async def stored(probe_id):
        async with AsyncSessionLocal() as db:
            return await db.get(ProbeAgent, probe_id)

    with TestClient(app) as client:
        probe = _create_probe(client, admin_headers)
        listed = client.get("/api/ops/probes", headers=admin_headers).json()["probes"]
        row = _run(stored(probe["id"]))
    assert probe["token"].startswith("spr_")
    assert all("token" not in p for p in listed)
    assert row.token_hash == ops._hash_token(probe["token"]) and probe["token"] not in row.token_hash


def test_probe_endpoints_reject_missing_or_wrong_tokens():
    with TestClient(app) as client:
        assert client.get("/api/probe/targets").status_code == 401
        assert client.get("/api/probe/targets", headers={"Authorization": "Bearer spr_nope"}).status_code == 401
        # An admin session token is not a probe token.
        admin = {"Authorization": "Bearer " + create_access_token({"sub": "x", "is_admin": True})}
        assert client.post("/api/probe/report", json={"results": []}, headers=admin).status_code in (401, 422)


def test_probe_targets_only_include_enabled_directly_reachable_tcp_protocols(admin_headers):
    _run(_settings(vless_vision_enabled=True, vless_vision_reality_sni="objects.githubusercontent.com",
                   vless_vision_port=2058, hysteria2_enabled=True, trojan_cdn_enabled=True, server_ip="203.0.113.10"))
    with TestClient(app) as client:
        probe = _create_probe(client, admin_headers)
        plan = client.get("/api/probe/targets", headers={"Authorization": "Bearer " + probe["token"]}).json()
    keys = {t["protocol"]: t for t in plan["targets"]}
    assert plan["server"] == "203.0.113.10"
    assert keys["vless_vision_reality"]["method"] == "tls"
    assert keys["vless_vision_reality"]["sni"] == "objects.githubusercontent.com"
    assert "hysteria2" not in keys  # UDP: not testable by the probe
    assert "trojan_cdn" not in keys  # reached via CDN, not server:port


def test_reports_build_the_carrier_matrix_and_are_rate_limited(admin_headers, monkeypatch):
    async def fake_lookup(ip):
        return "44244", "MTN Irancell"

    monkeypatch.setattr(ops, "_carrier_for_ip", fake_lookup)
    with TestClient(app) as client:
        probe = _create_probe(client, admin_headers)
        h = {"Authorization": "Bearer " + probe["token"]}
        report = {"results": [
            {"protocol": "vless_vision_reality", "method": "tls", "ok": True, "latency_ms": 120.5},
            {"protocol": "vmess", "method": "tcp", "ok": False, "error": "connection reset"},
            {"protocol": "not-a-protocol", "method": "tcp", "ok": True},
        ]}
        ack = client.post("/api/probe/report", json=report, headers=h).json()
        assert ack == {"ok": True, "stored": 2, "carrier": "MTN Irancell"}
        assert client.post("/api/probe/report", json=report, headers=h).status_code == 429

        matrix = client.get("/api/ops/carriers", headers=admin_headers).json()["carriers"]
        mtn = next(c for c in matrix if c["carrier"] == "MTN Irancell")
        assert mtn["best"]["protocol"] == "vless_vision_reality"
        cells = {c["protocol"]: c for c in mtn["protocols"]}
        assert cells["vmess"]["ok_rate"] == 0 and cells["vless_vision_reality"]["median_ms"] == 120.5

        client.delete(f"/api/ops/probes/{probe['id']}", headers=admin_headers)

        async def remaining():
            async with AsyncSessionLocal() as db:
                return (await db.execute(select(ProbeReport).where(ProbeReport.probe_id == probe["id"]))).all()

        assert _run(remaining()) == []


def test_carrier_override_wins_over_lookup(admin_headers):
    with TestClient(app, client=("10.0.0.5", 50000)) as client:
        probe = _create_probe(client, admin_headers)
        ack = client.post(
            "/api/probe/report",
            json={"carrier": "Shatel", "results": [{"protocol": "vmess", "method": "tcp", "ok": True}]},
            headers={"Authorization": "Bearer " + probe["token"]},
        ).json()
    assert ack["carrier"] == "Shatel"


def test_private_probe_address_is_not_looked_up():
    assert _run(ops._carrier_for_ip("192.168.1.10")) == (None, "Unknown (private address)")
    assert _run(ops._carrier_for_ip("not-an-ip")) == (None, "Unknown")


def test_probe_endpoints_bypass_the_admin_ip_allowlist():
    assert "/api/probe/" in _PUBLIC_PREFIXES


# ── Edge nodes ───────────────────────────────────────────────────

def test_edge_node_reachability_is_measured(admin_headers):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    open_port = server.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        with TestClient(app) as client:
            up = client.post("/api/ops/nodes", json={"name": "fra-1", "address": "127.0.0.1", "port": open_port},
                             headers=admin_headers).json()
            down = client.post("/api/ops/nodes", json={"name": "dead", "address": "127.0.0.1", "port": closed_port},
                               headers=admin_headers).json()
            assert up["reachable"] is True and up["rtt_ms"] is not None
            assert down["reachable"] is False and down["last_error"]

            bad = client.post("/api/ops/nodes", json={"name": "x", "address": "bad host!"}, headers=admin_headers)
            assert bad.status_code == 422

            assert client.delete(f"/api/ops/nodes/{down['id']}", headers=admin_headers).json() == {"ok": True}
            assert client.delete(f"/api/ops/nodes/{down['id']}", headers=admin_headers).status_code == 404
    finally:
        server.close()


# ── Financials & overview ────────────────────────────────────────

def test_financials_report_stored_payments_in_major_units(admin_headers):
    async def seed():
        async with AsyncSessionLocal() as db:
            from app.timeutil import utcnow
            db.add(Payment(gateway=PaymentGateway.zarinpal, status=PaymentStatus.paid, amount=5_000_000,
                           currency="IRR", paid_at=utcnow()))
            db.add(Payment(gateway=PaymentGateway.usdt_trc20, status=PaymentStatus.paid, amount=1250,
                           currency="USDT", paid_at=utcnow()))
            db.add(Payment(gateway=PaymentGateway.idpay, status=PaymentStatus.pending, amount=1, currency="IRR"))
            await db.commit()

    before = None
    with TestClient(app) as client:
        before = client.get("/api/ops/financials", headers=admin_headers).json()
        _run(seed())
        after = client.get("/api/ops/financials", headers=admin_headers).json()

    def amt(d, cur):
        return d["paid_30d"].get(cur, {}).get("amount", 0)

    assert amt(after, "USDT") - amt(before, "USDT") == pytest.approx(12.5)
    assert amt(after, "IRR") - amt(before, "IRR") == 5_000_000
    assert after["pending"] - before["pending"] == 1
    assert {g["id"] for g in after["gateways"]} == {"zarinpal", "idpay", "usdt_trc20"}


def test_overview_counts_honeypot_hits_and_lists_them_as_events(admin_headers):
    with TestClient(app) as client:
        before = client.get("/api/ops/overview", headers=admin_headers).json()["security_24h"]["honeypot_hits"]
        client.get("/wp-login.php")
        data = client.get("/api/ops/overview", headers=admin_headers).json()
    assert data["security_24h"]["honeypot_hits"] == before + 1
    assert any(e["action"] == "honeypot_hit" and e["detail"] == "/wp-login.php" for e in data["events"])
    assert data["protocols"]["enabled"] >= 1
    assert "in_bps" in data["network"]


def test_ops_endpoints_require_an_admin():
    with TestClient(app) as client:
        for path in ("/api/ops/overview", "/api/ops/protocols", "/api/ops/nodes",
                     "/api/ops/probes", "/api/ops/carriers", "/api/ops/financials"):
            assert client.get(path).status_code == 401, path
