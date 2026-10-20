"""sing-box / mita servers, the sing-box and Clash profiles, speed limits.

The configs here were run for real (sing-box 1.14, mita 3.38, mihomo 1.19,
Xray 26) with real clients, inside a network namespace for speed limits and
kernel byte counts. These tests keep what made that work.
"""

import asyncio
import base64
import datetime
import json
import os
import shutil
import subprocess
import uuid

import pytest
from cryptography import x509

from app import standalone_engines, traffic_control, traffic_kernel
from app.api.compat import _core
from app.api.compat._core import _load_legacy_settings, _save_legacy_settings
from app.api.compat.panel_settings import ensure_ss2022_key
from app.client_profiles import clash_profile, parse_link, singbox_profile
from app.database import AsyncSessionLocal, init_db
from app.models import VpnUser
from app.privileged_helper_daemon import _dispatch
from app.tls_trust import load_cert_info

SERVER_IP = "203.0.113.7"


def _users():
    return [VpnUser(id=i, name=n, uuid=str(uuid.uuid4()), active=1, speed_limit_up=up, speed_limit_down=down)
            for i, (n, up, down) in enumerate((("ali", 50, 100), ("sara", 0, 0)), start=1)]


STATE = {"hysteria2_enabled": True, "tuic_enabled": True, "shadowtls_enabled": True, "naiveproxy_enabled": True,
         "mieru_enabled": True, "wireguard_enabled": True, "hysteria2_salamander_enabled": True,
         "hysteria2_salamander_password": "salt", "tuic_congestion_control": "bbr", "server_ip": SERVER_IP}


@pytest.fixture
def cert(tmp_path):
    c, k = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-days", "30", "-keyout", str(k), "-out", str(c), "-subj", "/CN=t",
                    "-addext", f"subjectAltName=IP:{SERVER_IP}"], check=True, capture_output=True)
    return str(c), str(k)


def test_every_user_gets_their_own_credentials_and_mark(cert):
    users = _users()
    cfg = standalone_engines.singbox_server_config(STATE, users, *cert)
    by_tag = {ib["tag"]: ib for ib in cfg["inbounds"]}
    assert {u["password"] for u in by_tag["hysteria2-in"]["users"]} == {u.uuid for u in users}
    assert by_tag["hysteria2-in"]["obfs"] == {"type": "salamander", "password": "salt"}
    assert {u["uuid"] for u in by_tag["tuic-in"]["users"]} == {u.uuid for u in users}
    assert by_tag["tuic-in"]["congestion_control"] == "bbr"
    ss = by_tag["shadowtls-ss-in"]
    assert len(base64.b64decode(ss["password"])) == 16 and len(ss["users"]) == 2
    # Each user leaves through their own marked outbound (counting, limits).
    marks = {o["tag"]: o["routing_mark"] for o in cfg["outbounds"] if "routing_mark" in o}
    assert marks == {f"u{u.id}": traffic_control.singbox_mark(u.id) for u in users}
    assert {r["outbound"] for r in cfg["route"]["rules"]} == set(marks)
    wg = cfg["endpoints"][0]
    assert wg["listen_port"] == 51821 and len(wg["peers"]) == 2


def test_links_match_the_server(cert, monkeypatch):
    monkeypatch.setattr(standalone_engines, "engine_installed", lambda name: True)
    monkeypatch.setattr(_core.settings, "tls_cert_file", cert[0])
    monkeypatch.setattr(_core, "_settings_state", dict(STATE))
    u = _users()[0]
    links = _core._build_share_links(u, server_ip=SERVER_IP)
    hy2 = parse_link(links["hysteria2"])
    assert hy2["password"] == u.uuid and hy2["obfs_password"] == "salt"
    tuic = parse_link(links["tuic"])
    assert tuic["uuid"] == u.uuid and tuic["cc"] == "bbr"
    assert links["mieru"].startswith(f"mierus://ali:{u.uuid}@{SERVER_IP}?")
    assert links["wireguard"].startswith("[Interface]\nPrivateKey = ")
    # The WireGuard keys are derived, so server and client agree without storage.
    pub = standalone_engines.wireguard_user_keys(u)[1]
    peers = standalone_engines.singbox_server_config(STATE, [u], *cert)["endpoints"][0]["peers"]
    assert peers[0]["public_key"] == pub


def test_naive_certificate_is_short_lived_and_for_the_server_ip():
    pem, key, new = standalone_engines.naive_certificate({}, SERVER_IP)
    c = x509.load_pem_x509_certificate(pem.encode())
    # Chromium (inside every Naive client) refuses anything valid > 200 days.
    assert (c.not_valid_after_utc - c.not_valid_before_utc) <= datetime.timedelta(days=200)
    assert SERVER_IP in [str(a) for a in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)]
    assert new
    # Kept while valid, renewed for a new IP.
    assert standalone_engines.naive_certificate({"naive_cert_pem": pem, "naive_key_pem": key}, SERVER_IP)[2] is False
    assert standalone_engines.naive_certificate({"naive_cert_pem": pem, "naive_key_pem": key}, "198.51.100.1")[2] is True


@pytest.mark.skipif(not shutil.which("sing-box") and not os.path.exists("/usr/local/bin/sing-box"),
                    reason="sing-box not installed")
def test_sing_box_accepts_server_and_profile(cert, monkeypatch, tmp_path):
    monkeypatch.setattr(standalone_engines, "engine_installed", lambda name: True)
    monkeypatch.setattr(_core.settings, "tls_cert_file", cert[0])
    monkeypatch.setattr(_core, "_settings_state", dict(STATE))
    sb = shutil.which("sing-box") or "/usr/local/bin/sing-box"
    u = _users()[0]
    links = _core._build_share_links(u, server_ip=SERVER_IP)
    for name, cfg in (("server", standalone_engines.singbox_server_config(STATE, [u], *cert)),
                      ("profile", singbox_profile(u, SERVER_IP, links, STATE, load_cert_info(cert[0]).spki_sha256))):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(cfg))
        r = subprocess.run([sb, "check", "-c", str(path)], capture_output=True, text=True)
        assert r.returncode == 0, (name, r.stderr[-400:])


def test_clash_profile_covers_mieru_and_shadowtls(cert, monkeypatch):
    monkeypatch.setattr(standalone_engines, "engine_installed", lambda name: True)
    monkeypatch.setattr(_core.settings, "tls_cert_file", cert[0])
    monkeypatch.setattr(_core, "_settings_state", dict(STATE))
    u = _users()[0]
    clash = clash_profile(u, SERVER_IP, _core._build_share_links(u, server_ip=SERVER_IP), STATE, "ab" * 32)
    types = {p["type"] for p in clash["proxies"]}
    assert {"hysteria2", "tuic", "mieru", "ss", "wireguard"} <= types
    assert any(p.get("plugin") == "shadow-tls" for p in clash["proxies"])


# ── Speed limits (panel side) and the kernel side's input checks ────────

def test_speed_limits_in_kb_per_second_become_kbit_per_mark(monkeypatch):
    monkeypatch.setattr(traffic_control, "engine_can_mark", lambda process, proc="/proc": True)
    spec = traffic_control.shaping_spec(_users())
    assert spec == [{"marks": [traffic_control.xray_mark(1), traffic_control.singbox_mark(1)],
                     "up_kbit": 400, "down_kbit": 800}]  # sara (0 = unlimited) is left out
    outbounds, rules = traffic_control.xray_limit_parts(_users())
    assert outbounds[0]["streamSettings"]["sockopt"]["mark"] == traffic_control.xray_mark(1)
    assert rules == [{"type": "field", "user": ["ali"], "outboundTag": "limit-1", "ruleTag": "limit-1"}]


def test_kernel_side_rejects_bad_input(monkeypatch):
    monkeypatch.setattr(traffic_kernel, "_run", lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    assert not traffic_kernel.apply_shaping([{"marks": [5], "up_kbit": 8}], interface="eth0")["ok"]  # no kind bits
    assert not traffic_kernel.apply_shaping([{"marks": [0x200001], "up_kbit": -1}], interface="eth0")["ok"]
    assert not traffic_kernel.apply_shaping([], interface="eth0; reboot")["ok"]
    assert not traffic_kernel.hysteria2_port_hop("20000-8443", 8443)["ok"]
    assert not traffic_kernel.hysteria2_port_hop("20000-30000", 25000)["ok"]  # target inside the range
    assert not _dispatch("hysteria2.port_hop", {"ports": "20000-30000", "target": "8443"})["ok"]


def test_tc_batch_puts_every_mark_of_a_user_in_their_class():
    cmds = traffic_kernel._htb("eth0", [{"marks": [0x100001, 0x200001], "up_kbit": 400, "down_kbit": 800}], "up_kbit")
    assert "class add dev eth0 parent 1: classid 1:2 htb rate 400kbit ceil 400kbit" in cmds
    assert sum("fw flowid 1:2" in c for c in cmds) == 2


# ── One-time repairs at startup ─────────────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


def test_bad_ss2022_key_is_replaced(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            await _save_legacy_settings(db, {"ss2022_server_key": "8265fb1426e49196524de51b4a175b29"})
            assert await ensure_ss2022_key(db)
            key = (await _load_legacy_settings(db))["ss2022_server_key"]
            assert len(base64.b64decode(key)) == 16
            assert not await ensure_ss2022_key(db)  # a valid key is left alone
    _run(go())


def test_old_unenforced_default_speed_becomes_unlimited_once(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            await _save_legacy_settings(db, {"speed_limits_enforced": False})
            a = VpnUser(name=f"d-{uuid.uuid4().hex[:6]}", uuid=str(uuid.uuid4()), speed_limit_up=200, speed_limit_down=200)
            b = VpnUser(name=f"c-{uuid.uuid4().hex[:6]}", uuid=str(uuid.uuid4()), speed_limit_up=200, speed_limit_down=500)
            db.add_all([a, b])
            await db.commit()
            await traffic_control.retire_unenforced_default_limits(db)
            await db.refresh(a)
            await db.refresh(b)
            assert (a.speed_limit_up, a.speed_limit_down) == (0, 0)  # the untouched old default
            assert (b.speed_limit_up, b.speed_limit_down) == (200, 500)  # chosen on purpose
            a.speed_limit_up = a.speed_limit_down = 200
            await db.commit()
            await traffic_control.retire_unenforced_default_limits(db)  # runs once only
            await db.refresh(a)
            assert a.speed_limit_up == 200
    _run(go())


def test_profile_endpoints_serve_active_users_only(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(standalone_engines, "engine_installed", lambda name: True)

    async def users():
        await init_db()
        async with AsyncSessionLocal() as db:
            await _save_legacy_settings(db, {"hysteria2_enabled": False, "mieru_enabled": True})
            on = VpnUser(name=f"p-{uuid.uuid4().hex[:6]}", uuid=str(uuid.uuid4()), active=1)
            off = VpnUser(name=f"o-{uuid.uuid4().hex[:6]}", uuid=str(uuid.uuid4()), active=0)
            db.add_all([on, off])
            await db.commit()
            return on.uuid, off.uuid

    on, off = _run(users())
    with TestClient(app) as client:
        sb = client.get(f"/sub-singbox/{on}")
        assert sb.status_code == 200 and "Subscription-Userinfo" in sb.headers
        assert {o["tag"] for o in sb.json()["outbounds"]} >= {"proxy", "auto", "direct"}
        clash = client.get(f"/sub-clash/{on}")
        assert clash.status_code == 200 and clash.headers["content-type"].startswith("text/yaml")
        assert any(p["type"] == "mieru" for p in json.loads(clash.text)["proxies"])
        assert client.get(f"/sub-singbox/{off}").status_code == 404
        assert client.get(f"/sub-clash/{off}").status_code == 404


def test_tls_inbounds_serve_the_domain_certificate_when_one_is_set(cert, monkeypatch, tmp_path):
    from app import tls_trust

    monkeypatch.setattr(_core, "_settings_state", {"tls_cert_file": cert[0], "tls_key_file": cert[1]})
    assert tls_trust.tls_files() == cert
    # A recorded certificate that is gone falls back to TLS_CERT_FILE.
    monkeypatch.setattr(_core, "_settings_state", {"tls_cert_file": str(tmp_path / "gone.pem"), "tls_key_file": cert[1]})
    assert tls_trust.tls_files() == (_core.settings.tls_cert_file, _core.settings.tls_key_file)


def test_marks_are_left_out_when_the_engine_cannot_set_them(tmp_path, cert):
    """Without CAP_NET_ADMIN every marked dial fails with EPERM (seen with an
    unprivileged sing-box): the panel must then not mark at all."""
    def proc(pid, comm, cap_eff):
        d = tmp_path / "proc" / str(pid)
        d.mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
        (d / "status").write_text(f"Name:\t{comm}\nCapEff:\t{cap_eff}\n")

    proc(10, "sing-box", "0000000000000000")
    proc(11, "xray", "0000000000003000")  # CAP_NET_ADMIN | CAP_NET_BIND_SERVICE
    root = str(tmp_path / "proc")
    assert traffic_control.engine_can_mark("sing-box", proc=root) is False
    assert traffic_control.engine_can_mark("xray", proc=root) is True
    assert traffic_control.engine_can_mark("mita", proc=root) is True  # not running yet
    cfg = standalone_engines.singbox_server_config(STATE, _users(), *cert, mark_users=False)
    assert not any("routing_mark" in o for o in cfg["outbounds"]) and not cfg["route"]["rules"]
