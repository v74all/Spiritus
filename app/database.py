"""
Database module for V7LTHRONYX VPN Panel.

Uses SQLAlchemy 2.0 with async support and PostgreSQL.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from typing import AsyncGenerator
import logging

from .config import settings

# Configure logging
logger = logging.getLogger(__name__)

# SQLAlchemy base class
Base = declarative_base()

# Build engine URL - support both PostgreSQL and SQLite for testing
_db_url = str(settings.database_url)
if not _db_url:
    raise ValueError(
        "DATABASE_URL environment variable is required. "
        "Set it in .env or as an environment variable. "
        "Example: DATABASE_URL=postgresql://user:pass@localhost:5432/vpnpanel"
    )
if _db_url.startswith("postgresql://"):
    _db_url = _db_url.replace("postgresql://", "postgresql+asyncpg://")

# Async engine (SQLite doesn't support pool_size/max_overflow)
_engine_kwargs = {"echo": settings.debug, "future": True}
if not _db_url.startswith("sqlite"):
    _engine_kwargs["pool_size"] = settings.database_pool_size
    _engine_kwargs["max_overflow"] = settings.database_max_overflow

async_engine = create_async_engine(_db_url, **_engine_kwargs)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Database session error: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db():
    """Initialize database and create tables."""
    async with async_engine.begin() as conn:
        logger.info("Creating database tables...")
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")

async def shutdown_db():
    """Close database connections on shutdown."""
    await async_engine.dispose()
    logger.info("Database connections closed")