"""FastAPI Application Setup - Spiritus v2.0"""

from contextlib import asynccontextmanager
from typing import Optional
import logging
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZIPMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, Gauge
import time
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app_config import settings
from models import Base, init_db

# ═══ Logging Setup ═══
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ═══ Global References ═══
redis_client: Optional[redis.Redis] = None
db_engine = None
SessionLocal = None

# ═══ Prometheus Metrics ═══
request_count = Counter(
    "spiritus_requests_total",
    "Total requests",
    ["method", "endpoint", "status"],
)

request_duration = Histogram(
    "spiritus_request_duration_seconds",
    "Request duration in seconds",
    ["method", "endpoint"],
)

active_users = Gauge(
    "spiritus_active_users",
    "Number of active users",
)

total_traffic_bytes = Gauge(
    "spiritus_total_traffic_bytes",
    "Total traffic in bytes",
)


# ═══ Startup/Shutdown ═══
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    
    # Startup
    logger.info("Starting Spiritus v2.0...")
    
    # Redis
    global redis_client
    redis_client = await redis.from_url(
        settings.REDIS_URL,
        decode_responses=True,
        encoding="utf8",
    )
    logger.info("✓ Redis connected")
    
    # Database
    global db_engine, SessionLocal
    db_engine = create_async_engine(
        settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"),
        echo=settings.SQLALCHEMY_ECHO,
        future=True,
        pool_size=20,
        max_overflow=40,
    )
    
    SessionLocal = sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        future=True,
    )
    
    # Create tables
    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✓ Database initialized")
    
    logger.info("✓ Spiritus started successfully")
    
    yield  # Application running
    
    # Shutdown
    logger.info("Shutting down Spiritus...")
    
    if redis_client:
        await redis_client.close()
        logger.info("✓ Redis disconnected")
    
    if db_engine:
        await db_engine.dispose()
        logger.info("✓ Database disconnected")
    
    logger.info("✓ Spiritus stopped")


# ═══ Create FastAPI App ═══
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Modern VPN Management Panel with Security-First Design",
    lifespan=lifespan,
)

# ═══ Middleware ═══
# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_CREDENTIALS,
    allow_methods=settings.CORS_METHODS,
    allow_headers=settings.CORS_HEADERS,
)

# Trusted Host
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", settings.VPN_SERVER_IP],
)

# GZIP Compression
app.add_middleware(GZIPMiddleware, minimum_size=1000)


# ═══ Custom Middleware ═══
@app.middleware("http")
async def security_headers_middleware(request, call_next):
    """Add security headers"""
    start_time = time.time()
    response = await call_next(request)
    
    # Security Headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    
    # Metrics
    duration = time.time() - start_time
    request_duration.labels(
        method=request.method,
        endpoint=request.url.path,
    ).observe(duration)
    
    request_count.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code,
    ).inc()
    
    return response


# ═══ Dependencies ═══
async def get_db():
    """Get database session"""
    async with SessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_redis():
    """Get redis client"""
    return redis_client


# ═══ Health Check ═══
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "timestamp": time.time(),
    }


@app.get("/ready")
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """Readiness check (k8s)"""
    try:
        # Test database
        await db.execute("SELECT 1")
        
        # Test redis
        await redis_client.ping()
        
        return {"ready": True}
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    
    return {
        "content": generate_latest().decode("utf-8"),
        "content_type": CONTENT_TYPE_LATEST,
    }


# ═══ Root Endpoint ═══
@app.get("/")
async def root():
    """API root"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health",
    }


# ═══ Include Routers (will be added) ═══
# from api.admin import router as admin_router
# from api.user import router as user_router
# from api.auth import router as auth_router
# 
# app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
# app.include_router(admin_router, prefix="/api/admin", tags=["Admin"])
# app.include_router(user_router, prefix="/api/user", tags=["User"])


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )
