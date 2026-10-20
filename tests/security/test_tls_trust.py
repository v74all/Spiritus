"""Clients must be told how to verify our TLS certificate, never to skip it.

Xray-core removed allowInsecure (v26.2.6): a share link or JSON config
carrying it makes current clients refuse the profile, which is what broke
servers reached by IP without a domain. These tests pin the replacement:
pcs (self-signed pin), vcn / IP SNI (Let's Encrypt IP certificates), and
REALITY keys generated on first start so certificate-free links exist.
"""

import asyncio
import base64
import datetime
import ipaddress
import json
import urllib.parse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import tls_trust
from app.api.compat import _core
from app.api.compat._core import _build_share_links, _load_legacy_settings, _save_legacy_settings
from app.api.compat.panel_settings import ensure_reality_keys
from app.config import settings
from app.database import AsyncSessionLocal, init_db
from app.main import _subscription_json_config
from app.models import VpnUser

SERVER_IP = "203.0.113.7"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, key, signer, sans):
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(subject)).issuer_name(_name(issuer))
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=6))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(signer, hashes.SHA256())
    )


def _write(tmp_path, cert, name):
    path = tmp_path / name
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(path)


@pytest.fixture
def self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _cert("spiritus", "spiritus", key, key, [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    return _write(tmp_path, cert, "self.crt"), cert.fingerprint(hashes.SHA256()).hex()


@pytest.fixture
def ip_cert(tmp_path):
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    cert = _cert(SERVER_IP, "Test CA E7", key, ca_key, [x509.IPAddress(ipaddress.ip_address(SERVER_IP))])
    return _write(tmp_path, cert, "ip.crt")


@pytest.fixture
def domain_cert(tmp_path):
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    cert = _cert("vpn.example.com", "Test CA R12", key, ca_key, [x509.DNSName("vpn.example.com"), x509.DNSName("*.cdn.example.com")])
    return _write(tmp_path, cert, "domain.crt")


# ── Classification ──────────────────────────────────────────────

def test_self_signed_is_pinned(self_signed):
    path, fp = self_signed
    t = tls_trust.trust_for("www.aparat.com", SERVER_IP, tls_trust.load_cert_info(path))
    assert (t.pcs, t.vcn, t.needs_insecure) == (fp, "", True)
    assert t.pin_colon.replace(":", "").lower() == fp


def test_ip_certificate_behind_camouflage_sni_verifies_by_ip(ip_cert):
    info = tls_trust.load_cert_info(ip_cert)
    t = tls_trust.trust_for("www.aparat.com", SERVER_IP, info)
    assert (t.pcs, t.vcn, t.needs_insecure) == ("", SERVER_IP, False)
    assert tls_trust.ip_certificate_for(SERVER_IP, info)
    assert not tls_trust.ip_certificate_for("198.51.100.1", info)


def test_domain_certificate_matching_sni_needs_nothing(domain_cert):
    info = tls_trust.load_cert_info(domain_cert)
    assert tls_trust.trust_for("vpn.example.com", SERVER_IP, info) == tls_trust.TlsTrust()
    assert tls_trust.trust_for("a.cdn.example.com", SERVER_IP, info) == tls_trust.TlsTrust()
    # A wildcard covers one label only, and a camouflage SNI falls back to the cert's name.
    assert tls_trust.trust_for("a.b.cdn.example.com", SERVER_IP, info).vcn == "vpn.example.com"
    assert tls_trust.trust_for("www.aparat.com", SERVER_IP, info).vcn == "vpn.example.com"


def test_missing_certificate_gives_no_hints(tmp_path):
    assert tls_trust.load_cert_info(str(tmp_path / "nope.crt")) is None
    assert tls_trust.trust_for("x", SERVER_IP, None) == tls_trust.TlsTrust()


# ── Links and JSON config ───────────────────────────────────────

def _user():
    return VpnUser(id=1, name="ali", uuid="11111111-2222-3333-4444-555555555555", active=1)


@pytest.fixture
def tls_state(monkeypatch):
    from app import standalone_engines

    monkeypatch.setattr(standalone_engines, "engine_installed", lambda name: True)
    monkeypatch.setattr(_core, "_settings_state", {
        "vmess_sni": "www.aparat.com", "trojan_enabled": True, "grpc_enabled": True,
        "httpupgrade_enabled": True, "vless_ws_enabled": True, "hysteria2_enabled": True,
        "tuic_enabled": True, "reality_public_key": "pubkey", "reality_short_id": "ab12",
    })


def _query(link):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(link).query)


def _vmess(link):
    return json.loads(base64.b64decode(link[len("vmess://"):]))


def test_links_never_carry_allow_insecure(monkeypatch, tls_state, self_signed):
    path, fp = self_signed
    monkeypatch.setattr(settings, "tls_cert_file", path)
    links = _build_share_links(_user(), server_ip=SERVER_IP)
    blob = json.dumps(links) + "".join(json.dumps(_vmess(v)) for k, v in links.items() if v.startswith("vmess://"))
    assert "allowInsecure" not in blob and "insecure=1" not in links["hysteria2"]
    for key in ("vless_ws", "trojan"):
        assert _query(links[key])["pcs"] == [fp], key
    assert _vmess(links["vmess"])["pcs"] == fp
    assert _query(links["hysteria2"])["pinSHA256"][0].replace(":", "").lower() == fp
    # sing-box has no pinning: only TUIC on a self-signed cert keeps allow_insecure.
    assert _query(links["tuic"])["allow_insecure"] == ["1"]
    # REALITY links need no certificate at all.
    assert "pcs" not in _query(links["vless"])


def test_ip_certificate_links_verify_normally(monkeypatch, tls_state, ip_cert):
    monkeypatch.setattr(settings, "tls_cert_file", ip_cert)
    links = _build_share_links(_user(), server_ip=SERVER_IP)
    assert _query(links["trojan"])["vcn"] == [SERVER_IP]
    assert "pcs" not in _query(links["trojan"])
    vm = _vmess(links["vmess"])
    assert vm["sni"] == SERVER_IP and vm["host"] == "www.aparat.com"
    for key in ("hysteria2", "tuic"):
        q = _query(links[key])
        assert q["sni"] == [SERVER_IP], key
        assert not ({"insecure", "allow_insecure", "pinSHA256"} & q.keys()), key


def test_sub_json_pins_instead_of_allow_insecure(monkeypatch, self_signed):
    path, fp = self_signed
    monkeypatch.setattr(settings, "tls_cert_file", path)
    config = _subscription_json_config(_user(), SERVER_IP, {
        "trojan_enabled": True, "grpc_enabled": True, "vless_ws_enabled": True,
        "cdn_enabled": True, "cdn_domain": "cdn.example.com",
    })
    assert "allowInsecure" not in json.dumps(config)
    tls = [o["streamSettings"]["tlsSettings"] for o in config["outbounds"]
           if o.get("streamSettings", {}).get("security") == "tls"]
    assert tls
    for ts in tls:
        if ts["serverName"] == "cdn.example.com":
            assert "pinnedPeerCertSha256" not in ts  # the CDN's public certificate
        else:
            assert ts["pinnedPeerCertSha256"] == fp


# ── REALITY keys on first start ─────────────────────────────────

def test_reality_keys_generated_once(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(settings, "reality_private_key", "")

    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            await _save_legacy_settings(db, {"reality_private_key": "", "reality_public_key": "", "reality_short_id": ""})
            assert await ensure_reality_keys(db) is True
            s = await _load_legacy_settings(db)
            first = (s["reality_private_key"], s["reality_public_key"], s["reality_short_id"])
            assert all(first)
            assert await ensure_reality_keys(db) is False
            s = await _load_legacy_settings(db)
            assert (s["reality_private_key"], s["reality_public_key"], s["reality_short_id"]) == first

    asyncio.run(go())
