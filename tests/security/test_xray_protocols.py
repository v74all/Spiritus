"""The server config, the share links and the JSON subscription must agree.

Each of these broke a protocol outright on a real Xray (checked end to end
with xray 26.3, server and client): Xray refuses a VLESS flow the account
was not given, SS-2022 keys must be base64 of the method's key size, the
panel reads traffic through the stats API, and Xray silently ignores
settings in places it does not read them (sockopt.fragment).
"""

import base64
import json
import shutil
import subprocess
import urllib.parse

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.api.compat import _core, panel_settings
from app.api.compat._core import _build_share_links
from app.api.compat.panel_settings import _generate_xray_server_config
from app.main import _subscription_json_config
from app.models import VpnUser
from app.orchestrator import XrayBackend
from app.protocol_engine import ss2022_user_key

SERVER_IP = "203.0.113.7"
SS_KEY = base64.b64encode(bytes(range(16))).decode()


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


_PRIV = X25519PrivateKey.generate()
REALITY_PRIVATE = _b64url(_PRIV.private_bytes(
    serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
REALITY_PUBLIC = _b64url(_PRIV.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _user():
    return VpnUser(id=1, name="ali", uuid="11111111-2222-3333-4444-555555555555", active=1)


STATE = {
    "reality_public_key": REALITY_PUBLIC, "reality_private_key": REALITY_PRIVATE, "reality_short_id": "ab12",
    "trojan_enabled": True, "grpc_enabled": True, "httpupgrade_enabled": True,
    "vless_ws_enabled": True, "vless_xhttp_enabled": True, "vless_vision_enabled": True,
    "vless_reverse_enabled": True, "ss2022_enabled": True, "ss2022_server_key": SS_KEY,
}


@pytest.fixture
def state(monkeypatch, tmp_path):
    s = dict(STATE)
    monkeypatch.setattr(_core, "_settings_state", s)
    monkeypatch.setattr(panel_settings, "_settings_state", s)
    cert, key = tmp_path / "c.crt", tmp_path / "c.key"
    cert.write_text("x"), key.write_text("x")
    monkeypatch.setattr(panel_settings.settings, "tls_cert_file", str(cert))
    monkeypatch.setattr(panel_settings.settings, "tls_key_file", str(key))
    return s


def _server():
    u = _user()
    return _generate_xray_server_config(
        [{"id": u.uuid, "alterId": 0, "email": u.name}],
        [{"id": u.uuid, "email": u.name}],
        [{"password": u.uuid, "email": u.name}],
    )


def _inbound(config, tag):
    return next(ib for ib in config["inbounds"] if ib["tag"] == tag)


def test_vision_flow_only_where_the_link_asks_for_it(state):
    config = _server()
    links = _build_share_links(_user(), server_ip=SERVER_IP)
    by_port = {ib["port"]: ib for ib in config["inbounds"] if ib["protocol"] == "vless"}
    for key in ("vless", "vless_vision", "vless_xhttp", "vless_reverse", "vless_ws"):
        u = urllib.parse.urlsplit(links[key])
        link_flow = urllib.parse.parse_qs(u.query).get("flow", [""])[0]
        server_flow = by_port[u.port]["settings"]["clients"][0].get("flow", "")
        assert link_flow == server_flow, key


def test_ss2022_is_multi_user_with_valid_keys(state):
    ib = _inbound(_server(), "in-ss2022")
    assert "streamSettings" not in ib  # plain SS-2022, as an ss:// link describes
    client = ib["settings"]["clients"][0]
    assert len(base64.b64decode(client["password"])) == 16
    link = _build_share_links(_user(), server_ip=SERVER_IP)["ss2022"]
    userinfo = urllib.parse.urlsplit(link).username
    method, password = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode().split(":", 1)
    assert password == f"{SS_KEY}:{client['password']}"
    sub = _subscription_json_config(_user(), SERVER_IP, state)
    ss = next(o for o in sub["outbounds"] if o["protocol"] == "shadowsocks")
    assert ss["settings"]["servers"][0]["password"] == password


def test_ss2022_key_size_follows_the_method():
    uid = _user().uuid
    assert len(base64.b64decode(ss2022_user_key(uid, "2022-blake3-aes-128-gcm"))) == 16
    assert len(base64.b64decode(ss2022_user_key(uid, "2022-blake3-aes-256-gcm"))) == 32


def test_stats_api_is_on_loopback_and_relay_is_not_public(state):
    config = _server()
    assert config["api"]["listen"].startswith("127.0.0.1:")
    assert "StatsService" in config["api"]["services"]
    assert config["policy"]["levels"]["0"]["statsUserUplink"] is True
    assert _inbound(config, "in-http-relay")["listen"] == "127.0.0.1"


def test_live_user_add_matches_the_inbound(state):
    config = _server()
    user = VpnUser(id=2, name="sara", uuid="22222222-3333-4444-5555-666666666666", active=1)
    assert XrayBackend._client_entry(_inbound(config, "in-vless-vision"), user)["flow"] == "xtls-rprx-vision"
    assert "flow" not in XrayBackend._client_entry(_inbound(config, "in-vless-xhttp"), user)
    empty_vision = {"tag": "in-vless-reality", "protocol": "vless", "settings": {"clients": []}}
    assert XrayBackend._client_entry(empty_vision, user)["flow"] == "xtls-rprx-vision"
    ss = XrayBackend._client_entry(_inbound(config, "in-ss2022"), user)
    assert ss["password"] == ss2022_user_key(user.uuid, "2022-blake3-aes-128-gcm")


def test_json_subscription_uses_fields_xray_reads(state):
    sub = _subscription_json_config(_user(), SERVER_IP, {
        **state, "mux_enabled": True, "fragment_enabled": True,
        "noise_enabled": True, "noise_packet": "rand:50-100", "dpi_tcp_keepalive": True,
    })
    proxies = [o for o in sub["outbounds"] if o["protocol"] not in ("freedom", "blackhole")]
    for o in proxies:
        ss = o["streamSettings"]
        assert "serverNames" not in ss.get("realitySettings", {}), o["tag"]
        assert ss["sockopt"]["dialerProxy"] == "fragment", o["tag"]
        assert not {"fragment", "noisePacket", "noiseDelay", "tcpKeepAlive"} & ss["sockopt"].keys(), o["tag"]
        flow = any(u.get("flow") for v in o["settings"].get("vnext", []) for u in v["users"])
        if ss.get("network") == "xhttp":
            assert not flow, o["tag"]
        if flow or ss.get("network") == "xhttp":
            assert "mux" not in o, o["tag"]
    frag = next(o for o in sub["outbounds"] if o["tag"] == "fragment")
    assert frag["settings"]["fragment"]["packets"] == "tlshello"
    assert frag["settings"]["noises"] == [{"type": "rand", "packet": "50-100", "delay": "10-20"}]


@pytest.mark.skipif(not shutil.which("xray"), reason="xray binary not installed")
def test_xray_accepts_the_generated_configs(state, tmp_path):
    for name, cfg in (("server", _server()), ("client", _subscription_json_config(_user(), SERVER_IP, state))):
        if name == "server":  # placeholder cert files would fail the load, not the schema
            for ib in cfg["inbounds"]:
                ib.get("streamSettings", {}).pop("tlsSettings", None)
                if ib.get("streamSettings", {}).get("security") == "tls":
                    ib["streamSettings"]["security"] = "none"
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(cfg))
        r = subprocess.run(["xray", "run", "-test", "-c", str(path)], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, (name, (r.stdout + r.stderr)[-600:])
