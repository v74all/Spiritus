"""
Local conftest for the domain manager tests.

Runs the same fixture the root conftest sets up (env vars,
strong secrets), AND initialises the DB schema once per test
session. Without this the test's `from app.database import
AsyncSessionLocal` would point at an engine whose metadata
hasn't been loaded — `setting` table doesn't exist yet and
the first SELECT fails with `no such table: settings`.
"""

import os
import secrets

# Same env wiring as the root conftest, but we ALSO have to
# be careful with SECRET_KEY: pydantic-settings raises on a
# short key, so we MUST inject one before any app import.
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

# Schema lifecycle is owned by the async fixture in test_domain_manager.py.
# Keeping one engine/session factory avoids rebinding imports to different
# event loops, which previously left aiosqlite worker threads hanging.
