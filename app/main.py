"""
FastAPI entry point for V7LTHRONYX VPN Panel.

This module initializes the FastAPI application, configures middleware,
and mounts the API routers.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import logging
import os

from .config import settings
from .database import init_db, shutdown_db
from .redis_client import close_redis
from .observability import setup_opentelemetry, prometheus_metrics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vpn-panel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("V7LTHRONYX")

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown events."""
    # Startup
    logger.info("Starting V7LTHRONYX VPN Panel v2.0...")
    await init_db()
    logger.info("Database initialized")

    # Setup OpenTelemetry (optional, won't fail if not installed)
    setup_opentelemetry(app)

    # Initialize Telegram bot
    from .telegram_bot import telegram_bot
    from .config import settings as s
    if s.telegram_bot_token:
        telegram_bot.token = s.telegram_bot_token
        telegram_bot.chat_id = s.telegram_chat_id
        if s.telegram_admin_chat_ids:
            telegram_bot.admin_chat_ids = s.telegram_admin_chat_ids.split(",")
        logger.info("Telegram bot configured")

    # Initialize payment gateways
    from .payments import payment_manager
    if s.zarinpal_merchant_id:
        payment_manager.setup_zarinpal(
            merchant_id=s.zarinpal_merchant_id,
            sandbox=s.zarinpal_sandbox,
            callback_url=s.zarinpal_callback_url,
        )
        logger.info("Zarinpal gateway configured")
    if s.idpay_api_key:
        payment_manager.setup_idpay(
            api_key=s.idpay_api_key,
            sandbox=s.idpay_sandbox,
            callback_url=s.idpay_callback_url,
        )
        logger.info("IDPay gateway configured")
    if s.usdt_wallet_address:
        payment_manager.setup_usdt(
            wallet_address=s.usdt_wallet_address,
            api_key=s.usdt_trongrid_api_key,
        )
        logger.info("USDT TRC-20 gateway configured")
    
    # Generate password if not exists
    pw_file = os.path.join(os.getcwd(), "vpn-panel-password")
    if not os.path.exists(pw_file):
        import secrets
        pw = secrets.token_urlsafe(12)
        with open(pw_file, "w") as f:
            f.write(pw)
        os.chmod(pw_file, 0o600)
        logger.info(f"Panel password generated: {pw_file}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down V7LTHRONYX VPN Panel...")
    await shutdown_db()
    await close_redis()
    logger.info("Shutdown complete")

# Initialize FastAPI app
app = FastAPI(
    title="V7LTHRONYX VPN Panel",
    description="Unified VPN management panel with multi-protocol support",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Will be restricted in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response

# Exception handlers
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"message": "Internal server error", "detail": str(exc)},
    )

# Mount static files
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# ── Mount API Routers ──────────────────────────────────

from .api.auth import router as auth_router
from .api.users import router as users_router
from .api.system import router as system_router
from .api.protocols import router as protocols_router
from .api.abuse import router as abuse_router
from .api.security import router as security_router
from .api.agents import router as agents_router
from .api.payments import router as payments_router
from .api.resellers import router as resellers_router, portal_router

app.include_router(auth_router, prefix="/api")
app.include_router(users_router, prefix="/api")
app.include_router(system_router, prefix="/api")
app.include_router(protocols_router, prefix="/api")
app.include_router(abuse_router, prefix="/api")
app.include_router(security_router, prefix="/api")
app.include_router(agents_router, prefix="/api")
app.include_router(payments_router, prefix="/api")
app.include_router(resellers_router, prefix="/api")
app.include_router(portal_router, prefix="/api")

# ── Health check ────────────────────────────────────────

@app.get("/api/health", tags=["system"])
async def health_check():
    """Health check endpoint for Kubernetes/load balancers."""
    return {"status": "healthy", "service": "v7lthronyx-vpn-panel", "version": "2.0.0"}

@app.get("/api/ready", tags=["system"])
async def readiness_check():
    """Readiness probe for Kubernetes."""
    return {"status": "ready"}

@app.get("/api/live", tags=["system"])
async def liveness_check():
    """Liveness probe for Kubernetes."""
    return {"status": "alive"}

# ── Panel HTML (serves the frontend) ───────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_panel():
    """Serve the main panel HTML."""
    template_path = os.path.join(os.getcwd(), "templates", "panel.html")
    if os.path.exists(template_path):
        with open(template_path, 'r') as f:
            return f.read()
    return HTMLResponse("<h1>V7LTHRONYX VPN Panel v2.0</h1><p>Panel template not found</p>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.web_port,
        reload=settings.debug,
        workers=1
    )