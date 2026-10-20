"""The per-user dict the panel's config modal reads must carry every link
_build_share_links produces — a link built but not copied over shows up in
the UI as "Not configured". Links for sing-box / mita protocols exist only
when that engine is installed: a link with no server behind it is a lie."""

import urllib.parse
import uuid

import pytest

from app import standalone_engines, tls_trust
from app.api.compat import _core
from app.client_profiles import clash_profile, singbox_profile
from app.models import VpnUser

SERVER_IP = "203.0.113.7"


@pytest.fixture
def standalone_protocols_on(monkeypatch):
    state = {
        "shadowtls_enabled": True,
        "naiveproxy_enabled": True,
        "mieru_enabled": True,
    }
    monkeypatch.setattr(_core, "_settings_state", state)
    monkeypatch.setattr(standalone_engines, "engine_installed", lambda name: True)
    # A publicly trusted certificate for the server's IP (Naive needs one).
    monkeypatch.setattr(tls_trust, "load_cert_info", lambda path=None: tls_trust.CertInfo(
        sha256="ab" * 32, self_signed=False, dns_names=(), ip_addresses=(SERVER_IP,)))
    return state


def _user():
    return VpnUser(id=1, uuid=str(uuid.uuid4()), name="alice", active=1)


def test_sing_box_and_mieru_links_reach_the_user_dict(standalone_protocols_on):
    user = _user()
    legacy = _core._user_to_legacy(user, server_ip=SERVER_IP)

    assert legacy["naiveproxy"].startswith(f"naive+https://alice:{user.uuid}@{SERVER_IP}:8447")
    mieru = urllib.parse.urlsplit(legacy["mieru"])
    assert mieru.scheme == "mierus" and mieru.username == "alice" and mieru.password == user.uuid
    q = urllib.parse.parse_qs(mieru.query)
    assert q["port"] == ["8446"] and q["protocol"] == ["TCP"] and q["profile"]
    # ShadowTLS has no share link clients agree on; it ships in the profiles.
    assert legacy["shadowtls"] == ""


def test_shadowtls_is_in_the_sing_box_and_clash_profiles(standalone_protocols_on):
    user = _user()
    links = _core._build_share_links(user, server_ip=SERVER_IP)
    sb = singbox_profile(user, SERVER_IP, links, standalone_protocols_on, "pin")
    ss = next(o for o in sb["outbounds"] if o.get("detour", "").endswith("-shadowtls"))
    stls = next(o for o in sb["outbounds"] if o["tag"] == ss["detour"])
    assert stls["type"] == "shadowtls" and stls["version"] == 3 and stls["password"] == user.uuid
    assert ss["password"].count(":") == 1  # server key : user key (SS-2022 multi-user)
    clash = clash_profile(user, SERVER_IP, links, standalone_protocols_on, "pin")
    proxy = next(p for p in clash["proxies"] if p.get("plugin") == "shadow-tls")
    assert proxy["plugin-opts"]["version"] == 3 and proxy["password"] == ss["password"]
    assert any(p["type"] == "mieru" for p in clash["proxies"])


def test_no_links_without_the_engine(standalone_protocols_on, monkeypatch):
    monkeypatch.setattr(standalone_engines, "engine_installed", lambda name: False)
    standalone_protocols_on.update(hysteria2_enabled=True, tuic_enabled=True)
    links = _core._build_share_links(_user(), server_ip=SERVER_IP)
    assert not {"hysteria2", "tuic", "naiveproxy", "mieru"} & {k for k, v in links.items() if v}
