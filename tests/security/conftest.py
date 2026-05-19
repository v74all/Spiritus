"""
Shared fixtures for security tests.

Ensures every test runs with strong, deterministic secrets so that
app/config.py's strict validators don't refuse to load.
"""

import os
import secrets

# Inject strong secrets BEFORE the app modules are imported. Pytest runs this
# conftest before test collection, which is the correct ordering.
os.environ.setdefault("SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("JWT_SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("CSRF_SECRET", secrets.token_urlsafe(32))
os.environ.setdefault("ARGON2_SALT", secrets.token_hex(16))
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("CORS_ORIGINS", "")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("HOST", "127.0.0.1")
os.environ.setdefault("ADMIN_BOOTSTRAP_PASSWORD", "")  # disable bootstrap in tests
