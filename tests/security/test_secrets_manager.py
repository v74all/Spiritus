"""Tests for the secrets manager + the no-leaked-keys audit.

These run without a running database or panel, so they're safe in CI
even on a fresh checkout. Run with:

    pytest tests/security/test_secrets_manager.py -v
"""

from __future__ import annotations

import json
import stat

import pytest

# ═══════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def temp_secrets_dir(tmp_path, monkeypatch):
    """Point the secrets manager at a fresh tmp dir for the test."""
    from app import secrets as secrets_mod
    monkeypatch.setattr(secrets_mod, "_PROD_SECRETS_DIR", tmp_path)
    monkeypatch.setattr(secrets_mod, "_PROD_SECRETS_FILE", tmp_path / "secrets.json")
    # Force the cache to reload.
    monkeypatch.setattr(secrets_mod, "_cache", None)
    monkeypatch.setattr(secrets_mod, "_cache_loaded_from", None)
    return tmp_path


# ═══════════════════════════════════════════════════════════════
#  Basic get/set
# ═══════════════════════════════════════════════════════════════

def test_get_missing_returns_default(temp_secrets_dir):
    from app import secrets as secrets_mod
    assert secrets_mod.get("does_not_exist") is None
    assert secrets_mod.get("does_not_exist", "fallback") == "fallback"


def test_set_then_get_roundtrip(temp_secrets_dir):
    from app import secrets as secrets_mod
    secrets_mod.set_secret("api_key", "abc123")
    # Bust the in-memory cache so we re-read the file.
    secrets_mod._cache = None
    assert secrets_mod.get("api_key") == "abc123"


def test_set_creates_file_with_mode_600(temp_secrets_dir):
    from app import secrets as secrets_mod
    secrets_mod.set_secret("k", "v")
    target = temp_secrets_dir / "secrets.json"
    assert target.exists()
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_env_var_takes_precedence(temp_secrets_dir, monkeypatch):
    from app import secrets as secrets_mod
    secrets_mod.set_secret("dual_source", "from_file")
    monkeypatch.setenv("DUAL_SOURCE", "from_env")
    assert secrets_mod.get("dual_source") == "from_env"


def test_require_raises_on_missing(temp_secrets_dir):
    from app import secrets as secrets_mod
    with pytest.raises(RuntimeError) as excinfo:
        secrets_mod.require("never_set")
    assert "never_set" in str(excinfo.value)


# ═══════════════════════════════════════════════════════════════
#  get_or_generate
# ═══════════════════════════════════════════════════════════════

def test_get_or_generate_calls_generator_on_first_read(temp_secrets_dir):
    from app import secrets as secrets_mod
    counter = {"n": 0}

    def gen() -> str:
        counter["n"] += 1
        return "first"

    v1 = secrets_mod.get_or_generate("g", gen)
    v2 = secrets_mod.get_or_generate("g", gen)
    assert v1 == "first"
    assert v2 == "first"
    assert counter["n"] == 1, "generator must run exactly once"


def test_get_or_generate_rejects_non_string(temp_secrets_dir):
    from app import secrets as secrets_mod
    with pytest.raises(RuntimeError):
        secrets_mod.get_or_generate("bad", lambda: 12345)  # type: ignore[arg-type, return-value]


# ═══════════════════════════════════════════════════════════════
#  No-leaked-keys audit
# ═══════════════════════════════════════════════════════════════

def test_audit_flags_known_leaked_key(tmp_path):
    """If a developer accidentally re-introduces a sample key, the
    audit helper must surface it."""
    from app import secrets as secrets_mod
    bad_file = tmp_path / "config.py"
    bad_file.write_text(
        'public_key = "oZVaAa694VcKxWb-gH31sPpMIQ9XAozoJ6BOAA1DkC0"\n',
        encoding="utf-8",
    )
    findings = secrets_mod.audit_no_leaked_keys(extra_paths=[tmp_path])
    assert any(str(bad_file) in f[0] for f in findings), findings


def test_audit_clean_for_safe_file(tmp_path):
    from app import secrets as secrets_mod
    safe_file = tmp_path / "config.py"
    safe_file.write_text("public_key = ''  # empty by default\n", encoding="utf-8")
    findings = secrets_mod.audit_no_leaked_keys(extra_paths=[tmp_path])
    assert findings == [], f"expected no findings, got: {findings}"


# ═══════════════════════════════════════════════════════════════
#  Migration script
# ═══════════════════════════════════════════════════════════════

def test_migration_picks_up_legacy_files(tmp_path, monkeypatch, capsys):
    from app import secrets as secrets_mod
    from app import secrets_migrate

    # Lay down legacy artifacts in a temp project root.
    project = tmp_path / "proj"
    project.mkdir()
    (project / "reality_private_key").write_text("legacyPK\n", encoding="utf-8")
    settings = {
        "reality_public_key": "legacyPubK",
        "zarinpal_merchant_id": "merchant123",
        "kill_switch_enabled": True,  # not a secret; must NOT be migrated
    }
    (project / "vpn-settings.json").write_text(json.dumps(settings), encoding="utf-8")

    # Redirect the secrets file to the temp dir. The migrate script
    # imports from app.secrets, which owns the path constants.
    secrets_file = project / "secrets.json"
    monkeypatch.setattr(secrets_mod, "_PROD_SECRETS_FILE", secrets_file)
    monkeypatch.setattr(secrets_mod, "_PROD_SECRETS_DIR", project)
    monkeypatch.setattr(secrets_mod, "_cache", None)
    monkeypatch.setattr(secrets_mod, "_cache_loaded_from", None)

    rc = secrets_migrate.main([
        "--project-root", str(project),
        "--wipe-legacy",
    ])
    assert rc == 0

    payload = json.loads(secrets_file.read_text(encoding="utf-8"))
    assert payload["reality_private_key"] == "legacyPK"
    assert payload["reality_public_key"] == "legacyPubK"
    assert payload["zarinpal_merchant_id"] == "merchant123"
    assert "kill_switch_enabled" not in payload

    # Source files must be gone.
    assert not (project / "reality_private_key").exists()
    assert not (project / "vpn-settings.json").exists()


def test_migration_dry_run_does_not_write(tmp_path, monkeypatch):
    from app import secrets as secrets_mod
    from app import secrets_migrate

    project = tmp_path / "proj"
    project.mkdir()
    (project / "reality_private_key").write_text("k\n", encoding="utf-8")
    secrets_file = project / "secrets.json"
    monkeypatch.setattr(secrets_mod, "_PROD_SECRETS_FILE", secrets_file)
    monkeypatch.setattr(secrets_mod, "_PROD_SECRETS_DIR", project)
    monkeypatch.setattr(secrets_mod, "_cache", None)
    monkeypatch.setattr(secrets_mod, "_cache_loaded_from", None)

    rc = secrets_migrate.main([
        "--project-root", str(project),
        "--dry-run",
    ])
    assert rc == 0
    assert not secrets_file.exists(), "dry-run must not create the secrets file"
    # And the legacy file is left alone.
    assert (project / "reality_private_key").exists()
