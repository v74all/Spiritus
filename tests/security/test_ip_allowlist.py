import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.middleware.ip_allowlist import AdminIPAllowlistMiddleware, is_allowed, parse_networks


def _client(allowlist, client_host):
    api = FastAPI()

    @api.get("/api/users")
    def users():
        return {"ok": True}

    @api.get("/api/health")
    def health():
        return {"ok": True}

    @api.get("/sub/abc")
    def sub():
        return {"ok": True}

    api.add_middleware(AdminIPAllowlistMiddleware, allowlist=allowlist, public_prefixes="")
    return TestClient(api, client=(client_host, 50000))


def test_allowed_ip_passes():
    assert _client("203.0.113.0/24", "203.0.113.9").get("/api/users").status_code == 200


def test_other_ip_blocked_on_admin_api():
    assert _client("203.0.113.0/24", "198.51.100.7").get("/api/users").status_code == 403


def test_public_endpoints_stay_open():
    c = _client("203.0.113.0/24", "198.51.100.7")
    assert c.get("/api/health").status_code == 200
    assert c.get("/sub/abc").status_code == 200


def test_loopback_always_allowed():
    assert _client("203.0.113.0/24", "127.0.0.1").get("/api/users").status_code == 200


def test_ipv4_mapped_ipv6_and_garbage():
    nets = parse_networks("203.0.113.0/24")
    assert is_allowed("::ffff:203.0.113.5", nets)
    assert not is_allowed("not-an-ip", nets)
    assert not is_allowed("", nets)


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        Settings(admin_ip_allowlist="999.1.1.1/8", secret_key="x" * 48)
