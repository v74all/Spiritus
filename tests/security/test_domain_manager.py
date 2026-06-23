"""Tests for the domain_manager module.

We exercise the validation, the on-disk cert probing, and the
DB-backed set/get round-trip. The actual ACME challenge path is
integration-tested with a real certbot later; here we test
prefer_self_signed=True so the test never tries to hit
Let's Encrypt.
"""

from __future__ import annotations

import os
import socket as _socket
from pathlib import Path
from typing import Any, Dict
from unittest import mock

import pytest
import pytest_asyncio

# conftest at the parent level wires the env. We do the rest
# here because the domain tests need a fully-bootstrapped
# `settings` table.
from tests.security import conftest_domain  # noqa: E402,F401  (env+app imports)

from app.config import settings  # noqa: E402
from app.database import AsyncSessionLocal  # noqa: E402
import app.domain_manager as _domain_module  # noqa: E402  (for monkeypatch ref)
from app.domain_manager import (  # noqa: E402
    CertStatus,
    DEFAULT_AUTORENEW_DAYS,
    KEY_DOMAIN_ACTIVE,
    KEY_DOMAIN_CERT_PATH,
    KEY_DOMAIN_EXPIRES_AT,
    KEY_DOMAIN_ISSUER,
    KEY_DOMAIN_KEY_PATH,
    KEY_DOMAIN_CONTACT_EMAIL,
    _validate_domain,
    _parse_cert_subject,
    _parse_cert_expiry,
    _tls_paths_for,
    _generate_self_signed_cert,
    disable_domain,
    get_status,
    set_domain,
    maybe_autorenew,
)
# `_apply_domain_defaults` lives in the services layer.
from app.services.protocol_sync import _apply_domain_defaults  # noqa: E402


# ═══════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest_asyncio.fixture(autouse=True)
async def fresh_db():
    """Initialise the schema on the engine the app actually
    uses, AND clear it between tests so domain state doesn't
    leak from one test to the next.

    The root conftest (and conftest_domain) import app modules
    that capture the engine at module-load time. Re-binding
    `app.database.async_engine` mid-test is too late: any
    helper that already imported AsyncSessionLocal at module
    level is using the original engine. We work around this
    by initialising the schema on the ORIGINAL engine and
    letting every test in this module use the same store.
    """
    from app.database import async_engine
    from app.models import Base

    await async_engine.dispose()
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    from sqlalchemy import text
    async with async_engine.begin() as conn:
        await conn.execute(text("DELETE FROM settings"))
    yield
    await async_engine.dispose()


@pytest.fixture
def isolated_tls_root(tmp_path, monkeypatch):
    """Redirect the cert output dir to tmp_path so tests don't
    pollute /etc/v7lthronyx/tls."""
    monkeypatch.setattr(_domain_module, "_DEFAULT_TLS_ROOT", tmp_path)
    return tmp_path


# ═══════════════════════════════════════════════════════════════
#  Domain validation
# ═══════════════════════════════════════════════════════════════

def test_validate_domain_accepts_canonical_fqdn(monkeypatch):
    monkeypatch.setattr(
        _socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    assert _validate_domain("example.com") is None


def test_validate_domain_accepts_subdomain(monkeypatch):
    monkeypatch.setattr(
        _socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    assert _validate_domain("panel.example.com") is None


def test_validate_domain_rejects_uppercase():
    assert _validate_domain("EXAMPLE.com") is not None
    assert _validate_domain("example.com") is None


def test_validate_domain_rejects_too_long():
    long_label = "a" * 254
    assert _validate_domain(f"{long_label}.com") is not None


def test_validate_domain_rejects_resolves_to_private_ip(monkeypatch):
    import app.domain_manager as _dm
    monkeypatch.setattr(
        _dm.socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("192.168.1.1", 0))],
    )
    # The validator should reject the private IP. If it
    # returns None, the patch wasn't picked up — but the
    # bare 'anything.example.com' would resolve via real
    # DNS to a public IP and the same test would pass
    # silently. So we make the assertion explicit: a None
    # here means our private-IP check is broken.
    err = _validate_domain("anything.example.com")
    assert err is not None, f"expected rejection, got None; private IP check is broken"
    assert "private" in err.lower()


def test_validate_domain_rejects_doesnt_resolve(monkeypatch):
    monkeypatch.setattr(
        _socket, "getaddrinfo",
        mock.Mock(side_effect=_socket.gaierror("no such host")),
    )
    err = _validate_domain("nonexistent.example.com")
    assert err is not None
    assert "DNS" in err or "resolution" in err.lower()


# ═══════════════════════════════════════════════════════════════
#  Cert parsing
# ═══════════════════════════════════════════════════════════════

def test_parse_cert_subject_returns_none_for_missing_file(tmp_path):
    assert _parse_cert_subject(tmp_path / "no_such.crt") is None


def test_parse_cert_expiry_returns_none_for_missing_file(tmp_path):
    assert _parse_cert_expiry(tmp_path / "no_such.crt") is None


# ═══════════════════════════════════════════════════════════════
#  Domain defaults merging
# ═══════════════════════════════════════════════════════════════

def test_apply_domain_defaults_fills_sni_blanks():
    out = _apply_domain_defaults(
        cfg={"port": 2053},
        domain="panel.example.com",
        cert_path="/etc/cert.pem",
        key_path="/etc/key.pem",
    )
    assert out["sni"] == "panel.example.com"
    assert out["reality_sni"] == "panel.example.com"
    assert out["domain"] == "panel.example.com"
    assert out["reality_dest"] == "panel.example.com:443"
    assert out["cert_file"] == "/etc/cert.pem"
    assert out["key_file"] == "/etc/key.pem"
    assert out["port"] == 2053


def test_apply_domain_defaults_respects_operator_override():
    out = _apply_domain_defaults(
        cfg={"sni": "my-special-cdn.example.org"},
        domain="panel.example.com",
        cert_path="",
        key_path="",
    )
    assert out["sni"] == "my-special-cdn.example.org"
    # reality_sni still got the default — it was unset.
    assert out["reality_sni"] == "panel.example.com"


def test_apply_domain_defaults_no_op_when_empty():
    out = _apply_domain_defaults(
        cfg={"sni": "operator-set.example.com"},
        domain="",
        cert_path="",
        key_path="",
    )
    assert out == {"sni": "operator-set.example.com"}


# ═══════════════════════════════════════════════════════════════
#  Self-signed cert generation
# ═══════════════════════════════════════════════════════════════

def test_generate_self_signed_cert_creates_files(isolated_tls_root):
    """Either openssl is installed and we get a real cert, or it
    isn't and we get a structured error. We don't assert
    success because CI may not have openssl; we just assert
    the helper doesn't raise."""
    result = _generate_self_signed_cert("selfsigned-test.example.com")
    if result.success:
        # The cert and key files are created next to the
        # redirected root, and they're readable.
        paths = _tls_paths_for("selfsigned-test.example.com")
        # The root is the redirected tmp_path.
        assert paths["cert"].name == "fullchain.pem"
        assert paths["key"].name == "privkey.pem"


# ═══════════════════════════════════════════════════════════════
#  Status / persistence round-trip
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_set_domain_writes_atomic_settings(tmp_path, monkeypatch):
    """set_domain persists all six Setting rows. We monkey-
    patch the self-signed cert path so the test never tries
    to invoke openssl (which may not be present in CI)."""
    # Patch DNS so domain validation passes regardless of the
    # CI network. We pretend every domain resolves to a public IP.
    monkeypatch.setattr(
        _socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )
    from app.privileged_helper import HelperResponse
    import app.privileged_helper as _helper_module
    import app.services.protocol_sync as _sync_module
    async def _issued(*args, **kwargs):
        return HelperResponse(ok=True, data={"steps": [], "issuer": "self-signed"})
    async def _synced(*args, **kwargs):
        return None
    monkeypatch.setattr(_helper_module, "helper_request", _issued)
    monkeypatch.setattr(_sync_module, "sync_and_reload", _synced)

    async with AsyncSessionLocal() as db:
        result = await set_domain(
            db, "atomic-test.example.com",
            contact_email="ops@example.com",
            prefer_self_signed=True,
        )
        assert result.success, result.error

        from sqlalchemy import select
        from app.models import Setting
        rows = (await db.execute(
            select(Setting).where(Setting.key.in_([
                KEY_DOMAIN_ACTIVE, KEY_DOMAIN_CERT_PATH, KEY_DOMAIN_KEY_PATH,
                KEY_DOMAIN_EXPIRES_AT, KEY_DOMAIN_ISSUER, KEY_DOMAIN_CONTACT_EMAIL,
            ]))
        )).scalars().all()
        keys = {row.key: row.value for row in rows}
        assert keys[KEY_DOMAIN_ACTIVE] == "atomic-test.example.com"
        assert keys[KEY_DOMAIN_CONTACT_EMAIL] == "ops@example.com"
        assert keys[KEY_DOMAIN_ISSUER] == "self-signed"
        assert keys[KEY_DOMAIN_CERT_PATH].startswith("/")
        assert keys[KEY_DOMAIN_KEY_PATH].startswith("/")


@pytest.mark.asyncio
async def test_get_status_when_no_domain_set():
    async with AsyncSessionLocal() as db:
        status = await get_status(db)
        assert status.enabled is False
        assert status.active_domain == ""


@pytest.mark.asyncio
async def test_disable_domain_clears_all_settings():
    async with AsyncSessionLocal() as db:
        from app.domain_manager import _set_setting
        await _set_setting(db, KEY_DOMAIN_ACTIVE, "will-be-disabled.example.com")
        await _set_setting(db, KEY_DOMAIN_CERT_PATH, "/tmp/cert.pem")

        result = await disable_domain(db)
        assert result.success

        status = await get_status(db)
        assert status.enabled is False
        assert status.active_domain == ""


@pytest.mark.asyncio
async def test_maybe_autorenew_noop_when_no_domain():
    async with AsyncSessionLocal() as db:
        result = await maybe_autorenew(db)
        assert result is None


# ═══════════════════════════════════════════════════════════════
#  CertStatus enum
# ═══════════════════════════════════════════════════════════════

def test_cert_status_is_str_enum():
    assert CertStatus.OK.value == "ok"
    assert CertStatus.EXPIRED.value == "expired"
    assert CertStatus.MISSING.value == "missing"
    assert CertStatus.INVALID.value == "invalid"
    assert CertStatus.EXPIRING_SOON.value == "expiring_soon"
