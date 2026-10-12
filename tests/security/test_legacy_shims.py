"""Tests for the legacy deprecation shims.

The shims let old import paths (`from protocols import ...`,
`from app_config import settings`, etc.) keep working while emitting
a DeprecationWarning. They will be removed in the next major release;
these tests pin the behaviour so the removal is intentional.
"""

from __future__ import annotations

import warnings

# ═══════════════════════════════════════════════════════════════
#  protocols.py shim
# ═══════════════════════════════════════════════════════════════

def test_protocols_shim_emits_deprecation():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        import protocols  # noqa: F401
    assert any(issubclass(w.category, DeprecationWarning) for w in caught), caught
    assert any("protocols" in str(w.message) for w in caught), caught


def test_protocols_shim_re_exports_protocols_dict():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from protocols import PROTOCOLS
    # Must be the SAME object as the canonical registry.
    from app.protocol_engine import PROTOCOLS as canonical
    assert PROTOCOLS is canonical
    assert len(PROTOCOLS) > 0


def test_protocols_shim_re_exports_get_protocol_engine():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from protocols import get_protocol_engine
    out = get_protocol_engine()
    assert "protocols" in out
    assert "config_generator" in out


# ═══════════════════════════════════════════════════════════════
#  models.py shim
# ═══════════════════════════════════════════════════════════════

def test_models_shim_emits_deprecation():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        import models  # noqa: F401
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_models_shim_re_exports_base():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from models import Base
    from app.models import Base as canonical
    assert Base is canonical


def test_models_shim_re_exports_init_db():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from models import init_db
    # v1 module exposed `init_db`; in v2 it lives in app.database.
    from app.database import init_db as canonical
    assert init_db is canonical


def test_models_shim_re_exports_vpn_user():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from models import VpnUser
    from app.models import VpnUser as canonical
    assert VpnUser is canonical


# ═══════════════════════════════════════════════════════════════
#  app_config.py shim
# ═══════════════════════════════════════════════════════════════

def test_app_config_shim_emits_deprecation():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        import app_config  # noqa: F401
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_app_config_shim_reexports_settings():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from app_config import settings
    from app.config import settings as canonical
    assert settings is canonical


# ═══════════════════════════════════════════════════════════════
#  security.py shim
# ═══════════════════════════════════════════════════════════════

def test_security_shim_emits_deprecation():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        import security  # noqa: F401
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_security_shim_reexports_password_helpers():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from security import get_password_hash, verify_password
    h = get_password_hash("test-password-123")
    assert verify_password("test-password-123", h)
    assert not verify_password("wrong", h)


# ═══════════════════════════════════════════════════════════════
#  main.py shim
# ═══════════════════════════════════════════════════════════════

def test_main_shim_emits_deprecation():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        import main  # noqa: F401
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)


def test_main_shim_reexports_app():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from main import app
    from app.main import app as canonical
    assert app is canonical
