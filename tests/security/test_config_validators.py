"""
Config-time validator tests.

Ensures the panel refuses to load if:
- SECRET_KEY is missing or below the minimum length.
- SECRET_KEY matches one of the known weak/default tokens.
- CORS_ORIGINS contains a wildcard.
"""

import importlib
import os
import pytest


def _reload_config(env: dict):
    # Wipe the module cache so reload uses fresh env.
    import sys
    sys.modules.pop("app.config", None)
    sys.modules.pop("app", None)
    old = os.environ.copy()
    try:
        os.environ.update(env)
        return importlib.import_module("app.config")
    finally:
        os.environ.clear()
        os.environ.update(old)
        sys.modules.pop("app.config", None)


def test_weak_secret_is_rejected():
    with pytest.raises(Exception):
        _reload_config({
            "SECRET_KEY": "change-me",
            "JWT_SECRET_KEY": "",
            "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
            "CORS_ORIGINS": "",
        })


def test_short_secret_is_rejected():
    with pytest.raises(Exception):
        _reload_config({
            "SECRET_KEY": "short",
            "JWT_SECRET_KEY": "",
            "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
            "CORS_ORIGINS": "",
        })


def test_wildcard_cors_is_rejected():
    with pytest.raises(Exception):
        _reload_config({
            "SECRET_KEY": "x" * 48,
            "JWT_SECRET_KEY": "y" * 48,
            "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
            "CORS_ORIGINS": "*",
        })


def test_explicit_origins_are_accepted():
    cfg = _reload_config({
        "SECRET_KEY": "x" * 48,
        "JWT_SECRET_KEY": "y" * 48,
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "CORS_ORIGINS": "https://panel.example.com,https://admin.example.com",
    })
    parts = [o.strip() for o in cfg.settings.cors_origins.split(",") if o.strip()]
    assert parts == ["https://panel.example.com", "https://admin.example.com"]
