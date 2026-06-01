"""
Local conftest for the domain manager tests.

Runs the same fixture the root conftest sets up (env vars,
strong secrets), AND initialises the DB schema once per test
session. Without this the test's `from app.database import
AsyncSessionLocal` would point at an engine whose metadata
hasn't been loaded — `setting` table doesn't exist yet and
the first SELECT fails with `no such table: settings`.
"""

import asyncio
import os
import secrets

# Same env wiring as the root conftest, but we ALSO have to
# be careful with SECRET_KEY: pydantic-settings raises on a
# short key, so we MUST inject one before any app import.
os.environ.setdefault("SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("JWT_SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("CSRF_SECRET", secrets.token_urlsafe(32))
os.environ.setdefault("ARGON2_SALT", secrets.token_hex(16))
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("CORS_ORIGINS", "")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("HOST", "127.0.0.1")
os.environ.setdefault("ADMIN_BOOTSTRAP_PASSWORD", "")

import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _init_schema():
    """Create the schema once for the test session.

    We use SQLite in-memory with a single shared connection so
    every test sees the same store. AsyncSessionLocal binds to
    a connection pool by default; we use StaticPool-style
    behaviour by monkey-patching the engine to share a single
    underlying connection.

    We also pre-import the modules the tests reach for via
    `monkeypatch.setattr("app.X.Y", ...)` — without this
    `monkeypatch` raises `module 'app' has no attribute 'X'`
    because the attribute only resolves on first access.
    """
    # Pre-import the modules tests reach for by string path.
    import app  # noqa: F401
    import app.api  # noqa: F401
    import app.api.protocols  # noqa: F401
    import app.services  # noqa: F401
    import app.services.protocol_sync  # noqa: F401
    import app.domain_manager  # noqa: F401

    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from app.database import Base

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_setup())

    # Re-bind AsyncSessionLocal to this in-process engine so
    # app code that uses `from app.database import AsyncSessionLocal`
    # sees the same store.
    from app import database as _db_mod
    _db_mod.async_engine = engine
    _db_mod.AsyncSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False,
    )

    yield

    asyncio.run(engine.dispose())
