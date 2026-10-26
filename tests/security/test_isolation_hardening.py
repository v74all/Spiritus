"""Isolation between VPN users, agents, the panel user and root.

Each test pins a hole closed in the 2026-10 audit: VPN users reaching
loopback services through the engines, the domain proxy hiding client IPs,
root writing panel-chosen paths into nginx.conf or panel-chosen emails into
acme.sh, agent tokens accepted as admin-account tokens, and 2FA being
replaceable with a session token alone.
"""

import asyncio
import ipaddress
import logging
import pathlib
import shutil
import socket
import subprocess
import threading
import time
import uuid

import fakeredis
import pyotp
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.redis_client as redis_client
from app import domain_manager, panel_edge
from app.api.compat import _core, panel_settings
from app.api.compat.legacy_users import MAX_DAYS, BulkCreateRequest, LegacyUserCreate
from app.api.compat.panel_settings import PRIVATE_DESTINATIONS_RULE, _generate_xray_server_config
from app.auth import create_access_token, get_password_hash
from app.database import AsyncSessionLocal, init_db
from app.egress_policy import PRIVATE_DESTINATIONS
from app.main import _OneLineMessages, app
from app.models import Admin, UserRole
from app.privileged_helper_daemon import _dispatch
from app.standalone_engines import clash_api_secret, mieru_server_config, singbox_server_config

PASSWORD = "Sup3rStrong!Pass-1"


# ── Engines: no user reaches loopback or private networks ─────────────────

def _in_private(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return any(ip in ipaddress.ip_network(n) for n in PRIVATE_DESTINATIONS)


def test_private_destination_list_covers_local_services_only():
    for addr in ("127.0.0.1", "127.1.2.3", "10.0.0.1", "100.64.0.1", "169.254.169.254",
                 "172.16.5.5", "192.168.1.1", "0.0.0.0", "::1", "fd00::1", "fe80::1"):
        assert _in_private(addr), addr
    for addr in ("1.1.1.1", "8.8.8.8", "203.0.113.7", "2606:4700:4700::1111"):
        assert not _in_private(addr), addr


@pytest.fixture
def empty_state(monkeypatch):
    s: dict = {}
    monkeypatch.setattr(_core, "_settings_state", s)
    monkeypatch.setattr(panel_settings, "_settings_state", s)
    monkeypatch.setattr(panel_settings.settings, "tls_cert_file", "/nonexistent.crt")
    monkeypatch.setattr(panel_settings.settings, "tls_key_file", "/nonexistent.key")
    return s


def test_xray_blocks_private_destinations_before_any_user_rule(empty_state):
    limit = ([{"tag": "limit-1", "protocol": "freedom"}],
             [{"type": "field", "user": ["ali"], "outboundTag": "limit-1"}])
    routing = _generate_xray_server_config([], [], [], limit)["routing"]
    # IPOnDemand resolves names for the IP rule, so "localhost" is caught too.
    assert routing["domainStrategy"] == "IPOnDemand"
    assert routing["rules"][0] == PRIVATE_DESTINATIONS_RULE
    assert routing["rules"][0]["outboundTag"] == "block"
    assert routing["rules"][1]["outboundTag"] == "limit-1"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _socks_connect(proxy_port: int, host: str, port: int) -> bytes:
    """Ask a SOCKS5 proxy for host:port, send b"hi", return what came back."""
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=4) as s:
        s.sendall(b"\x05\x01\x00")
        s.recv(2)
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + port.to_bytes(2, "big"))
        try:
            reply = s.recv(10)
            if not reply or reply[1] != 0:
                return b""
            s.sendall(b"hi")
            return s.recv(64)
        except OSError:
            return b""


@pytest.mark.skipif(not shutil.which("xray"), reason="xray binary not installed")
def test_xray_really_refuses_loopback(tmp_path, empty_state):
    echo_port, socks_port = _free_port(), _free_port()
    server = socket.socket()
    server.bind(("127.0.0.1", echo_port))
    server.listen(4)

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                conn.sendall(b"ECHO" + conn.recv(16))

    threading.Thread(target=serve, daemon=True).start()
    cfg = _generate_xray_server_config([], [], [])
    config = {
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"auth": "noauth"}}],
        "outbounds": cfg["outbounds"],
        "routing": cfg["routing"],
    }
    path = tmp_path / "xray.json"
    path.write_text(__import__("json").dumps(config))
    proc = subprocess.Popen(["xray", "run", "-c", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        assert _socks_connect(socks_port, "127.0.0.1", echo_port) == b""
        assert _socks_connect(socks_port, "localhost", echo_port) == b""
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        server.close()


class _User:
    id = 7
    name = "ali"
    uuid = "11111111-2222-3333-4444-555555555555"


def test_singbox_refuses_private_destinations_and_locks_its_api():
    cfg = singbox_server_config({"shadowtls_enabled": True}, [_User()], "", "")
    rules = cfg["route"]["rules"]
    assert rules[0] == {"action": "resolve"}
    assert rules[1]["action"] == "reject" and rules[1]["ip_is_private"] is True
    assert rules[1]["ip_cidr"] == PRIVATE_DESTINATIONS
    assert cfg["experimental"]["clash_api"]["secret"] == clash_api_secret()
    assert len(clash_api_secret()) == 64


def test_mieru_refuses_private_destinations():
    cfg = mieru_server_config({"mieru_enabled": True}, [_User()])
    assert cfg["egress"]["rules"] == [{"ipRanges": PRIVATE_DESTINATIONS, "action": "REJECT"}]


# ── The domain proxy keeps client IPs and only serves real certificates ───

@pytest.fixture
def nginx_root(tmp_path, monkeypatch):
    real_path = pathlib.Path

    def redirected(p, *rest):
        p = str(p)
        return real_path(str(tmp_path) + p if p.startswith("/etc/nginx") else p, *rest)

    monkeypatch.setattr(panel_edge, "Path", redirected)
    (tmp_path / "etc/nginx").mkdir(parents=True)
    (tmp_path / "etc/nginx/nginx.conf").write_text("")
    return tmp_path


def test_edge_passes_the_real_client_ip(nginx_root):
    panel_edge._write_configs("panel.example.com", pathlib.Path("/c.pem"), pathlib.Path("/k.pem"))
    stream = (nginx_root / "etc/nginx/spiritus-stream.conf").read_text()
    site = (nginx_root / "etc/nginx/sites-available/spiritus-panel.conf").read_text()
    assert "proxy_protocol on;" in stream
    assert "ssl proxy_protocol;" in site
    # $remote_addr is nginx's own stream proxy (127.0.0.1): the IP allowlist
    # let every visitor in, and every visitor shared one rate-limit bucket.
    assert "X-Forwarded-For $proxy_protocol_addr" in site and "$remote_addr" not in site


def test_xray_behind_the_edge_accepts_the_proxy_header():
    domain_manager.remember_active_domain("panel.example.com")
    try:
        inbounds = panel_edge.retarget_shared_443([
            {"port": 443, "listen": "0.0.0.0", "streamSettings": {"network": "ws"}},
            {"port": 2053, "listen": "0.0.0.0"},
        ])
    finally:
        domain_manager.remember_active_domain("")
    assert inbounds[0]["listen"] == "127.0.0.1"
    assert inbounds[0]["streamSettings"]["sockopt"]["acceptProxyProtocol"] is True
    assert "streamSettings" not in inbounds[1]


def test_edge_certificate_paths_cannot_inject_nginx_directives(tmp_path, monkeypatch):
    root = tmp_path / "tls"
    root.mkdir()
    monkeypatch.setattr(panel_edge, "_CERT_ROOTS", (root,))
    good = root / "fullchain.pem"
    good.write_text("x")
    assert panel_edge._allowed_cert(str(good)) == good.resolve()
    for name in ("a;b.pem", "a\n include x;.pem", "a{b}.pem", "a b.pem"):
        bad = root / name
        bad.write_text("x")
        assert panel_edge._allowed_cert(str(bad)) is None, name
    outside = tmp_path / "secret.env"
    outside.write_text("x")
    assert panel_edge._allowed_cert(str(outside)) is None
    (root / "link.pem").symlink_to(outside)
    assert panel_edge._allowed_cert(str(root / "link.pem")) is None
    assert panel_edge._allowed_cert(str(root / "missing.pem")) is None


def test_helper_refuses_edge_paths_outside_the_tls_directories():
    out = _dispatch("panel.edge", {"action": "apply", "domain": "panel.example.com",
                                   "cert": "/opt/v7lthronyx/.env", "key": "/opt/v7lthronyx/.env"})
    assert out == {"ok": False, "message": "certificate path is not allowed"}


# ── acme.sh never sees a shell-active email ───────────────────────────────

@pytest.mark.parametrize("email", ["a'$(id)'@example.com", "a@b", "--pre-hook=x@example.com", "a b@example.com"])
def test_helper_refuses_unsafe_contact_emails(email, monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("acme.sh must not run")

    monkeypatch.setattr(domain_manager, "_issue_letsencrypt_cert", boom)
    out = _dispatch("certificate.issue", {"domain": "panel.example.com", "contact_email": email, "mode": "acme"})
    assert out == {"ok": False, "message": "invalid certificate request"}


def test_helper_accepts_a_plain_contact_email(monkeypatch):
    seen = {}

    def issue(domain, contact):
        seen.update(domain=domain, contact=contact)
        return domain_manager.DomainSetResult(success=True, domain=domain)

    monkeypatch.setattr(domain_manager, "_issue_letsencrypt_cert", issue)
    out = _dispatch("certificate.issue", {"domain": "panel.example.com",
                                          "contact_email": "ops+tls@example.co.uk", "mode": "acme"})
    assert out["ok"] is True and seen == {"domain": "panel.example.com", "contact": "ops+tls@example.co.uk"}


def test_set_domain_rejects_unsafe_email_before_anything_runs():
    result = asyncio.run(domain_manager.set_domain(None, "panel.example.com", "x'@example.com"))
    assert result.success is False and result.error == "invalid contact email"


# ── Tokens and 2FA ────────────────────────────────────────────────────────

@pytest.fixture
def fake_redis(monkeypatch):
    server = fakeredis.FakeServer()

    async def _get():
        return fakeredis.FakeAsyncRedis(server=server, decode_responses=True)

    monkeypatch.setattr(redis_client, "get_redis", _get)
    return server


@pytest.fixture
def admin_name():
    async def _setup():
        await init_db()
        async with AsyncSessionLocal() as db:
            name = f"iso-{uuid.uuid4().hex[:8]}"
            db.add(Admin(username=name, password_hash=get_password_hash(PASSWORD), role=UserRole.admin))
            await db.commit()
            return name

    return asyncio.run(_setup())


def _bearer(claims: dict) -> dict:
    return {"Authorization": f"Bearer {create_access_token(claims)}"}


def test_agent_and_reseller_tokens_are_not_admin_account_tokens(fake_redis, admin_name):
    with TestClient(app) as client:
        assert client.get("/api/auth/me", headers=_bearer({"sub": admin_name, "is_admin": True})).status_code == 200
        # An agent (or mobile agent session) named like an admin account.
        for claims in (
            {"sub": admin_name, "role": "agent", "agent_id": 1, "is_admin": False},
            {"sub": admin_name, "agent_id": 1},
            {"sub": admin_name, "reseller_id": 1, "is_admin": False},
        ):
            assert client.get("/api/auth/me", headers=_bearer(claims)).status_code == 401, claims
            r = client.post("/api/auth/setup-2fa", json={"password": PASSWORD}, headers=_bearer(claims))
            assert r.status_code == 401, claims


def test_setup_2fa_needs_the_password_and_the_current_code(fake_redis, admin_name):
    headers = _bearer({"sub": admin_name, "is_admin": True})
    with TestClient(app) as client:
        assert client.post("/api/auth/setup-2fa", headers=headers).status_code == 422
        assert client.post("/api/auth/setup-2fa", json={"password": "wrong"}, headers=headers).status_code == 401
        first = client.post("/api/auth/setup-2fa", json={"password": PASSWORD}, headers=headers)
        assert first.status_code == 200
        secret = first.json()["secret"]
        # 2FA is on now: the password alone may not replace it.
        assert client.post("/api/auth/setup-2fa", json={"password": PASSWORD}, headers=headers).status_code == 401
        again = client.post("/api/auth/setup-2fa", json={"password": PASSWORD, "totp_code": pyotp.TOTP(secret).now()},
                            headers=headers)
        assert again.status_code == 200 and again.json()["secret"] != secret


# ── Logs and request bounds ───────────────────────────────────────────────

def test_log_lines_cannot_be_forged():
    record = logging.LogRecord("t", logging.WARNING, __file__, 1, "login.failure user=%s",
                               ("x\nFailed login attempt from 198.51.100.4",), None)
    assert _OneLineMessages().filter(record) is True
    assert "\n" not in record.getMessage() and "\\n" in record.getMessage()


def test_bulk_and_user_requests_are_bounded():
    with pytest.raises(ValidationError):
        BulkCreateRequest(pad=10**9)
    with pytest.raises(ValidationError):
        BulkCreateRequest(traffic=-5)
    with pytest.raises(ValidationError):
        LegacyUserCreate(name="a", days=MAX_DAYS + 1)
    assert BulkCreateRequest(pad=3, days=30).pad == 3
