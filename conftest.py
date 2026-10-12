"""
Root conftest — runs before any test file or subdirectory conftest.

We import the app's modules and bind the package attribute so that
`monkeypatch.setattr("app.api.protocols.sync_and_reload", stub)`
in test files can find the live function. The package's `__init__.py`
is empty in this repo, so without the import here `app.api` is not
yet resolved as a submodule by the time test modules evaluate
their setattr string.
"""

import os
import secrets

# Set deterministic, strong secrets BEFORE any app module is imported.
# The app's strict validators refuse weak/default secrets, so we
# override the env here rather than in the conftest under each
# subdirectory.
os.environ["SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["JWT_SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["CSRF_SECRET"] = secrets.token_urlsafe(32)
os.environ["ARGON2_SALT"] = secrets.token_hex(16)
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["CORS_ORIGINS"] = ""
os.environ["DEBUG"] = "false"
os.environ["HOST"] = "127.0.0.1"
os.environ["ADMIN_BOOTSTRAP_PASSWORD"] = ""
os.environ["METRICS_BEARER_TOKEN"] = "m" * 48

# Force the package's submodules to be imported once so that
# `monkeypatch.setattr("app.api.protocols.X", ...)` can find them
# via the package's attribute namespace.
import app  # noqa: F401
import app.api  # noqa: F401
import app.api.protocols  # noqa: F401
import app.domain_manager  # noqa: F401
import app.services  # noqa: F401
import app.services.protocol_sync  # noqa: F401
