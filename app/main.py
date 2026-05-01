"""
FastAPI entry point for V7LTHRONYX VPN Panel.

This module initializes the FastAPI application, configures middleware,
and mounts the API routers.
"""

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from jinja2 import Environment, FileSystemLoader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import base64
import json
import logging
import os

from .config import settings
from .database import get_async_db, init_db, shutdown_db
from .models import VpnUser
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
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:"
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
from .api.compat import router as compat_router

# Legacy panel routes must be registered first so cookie-auth compatibility
# handlers win over the bearer-token resource routers on shared paths.
app.include_router(compat_router, prefix="/api")
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

_templates_dir = os.path.join(os.getcwd(), "templates")
_jinja_env = Environment(loader=FileSystemLoader(_templates_dir), autoescape=True)

def _url_for_static(filename: str) -> str:
    return f"/static/{filename}"

_jinja_env.globals["url_for"] = lambda endpoint, **kw: _url_for_static(kw.get("filename", ""))

@app.get("/", response_class=HTMLResponse)
async def serve_panel(request: Request):
    """Serve the main panel HTML."""
    template_path = os.path.join(_templates_dir, "panel.html")
    if not os.path.exists(template_path):
        return HTMLResponse("<h1>V7LTHRONYX VPN Panel v2.0</h1><p>Panel template not found</p>")

    template = _jinja_env.get_template("panel.html")
    html = template.render(
        server_ip=settings.host if settings.host != "0.0.0.0" else "",
        server_port=settings.web_port,
        sni_host=settings.vless_ws_host,
        ws_path=settings.vless_ws_path,
    )
    return HTMLResponse(content=html)


@app.get("/agent", response_class=HTMLResponse)
async def serve_agent_panel(request: Request):
    """Serve the reseller/agent panel HTML."""
    template_path = os.path.join(_templates_dir, "agent-panel.html")
    if not os.path.exists(template_path):
        return HTMLResponse("<h1>V7LTHRONYX Agent Panel</h1><p>Agent template not found</p>")

    template = _jinja_env.get_template("agent-panel.html")
    apk_path = os.path.join(os.getcwd(), "static", "downloads", "app-release.apk")
    html = template.render(
        server_ip=settings.host if settings.host != "0.0.0.0" else "",
        server_port=settings.web_port,
        sni_host=settings.vless_ws_host,
        ws_path=settings.vless_ws_path,
        apk_available=os.path.isfile(apk_path),
    )
    return HTMLResponse(content=html)


@app.get("/download/app")
async def download_app():
    apk_path = os.path.join(os.getcwd(), "static", "downloads", "app-release.apk")
    if not os.path.isfile(apk_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(apk_path, filename="vpn-app.apk")


@app.get("/download/app-windows")
async def download_app_windows():
    win_path = os.path.join(os.getcwd(), "static", "downloads", "vpn-windows.zip")
    if not os.path.isfile(win_path):
        raise HTTPException(
            status_code=404,
            detail="Windows build not uploaded on this server yet.",
        )
    return FileResponse(win_path, filename="vpn-windows.zip")


def _public_server_ip(request: Request) -> str:
    if settings.host and settings.host != "0.0.0.0":
        return settings.host
    return request.url.hostname or ""


def _subscription_user_dict(user: VpnUser) -> dict:
    return {
        "id": user.id,
        "name": user.name,
        "uuid": user.uuid,
        "active": bool(user.active),
        "traffic_limit_gb": (user.traffic_limit or 0) / (1024**3),
        "traffic_used_gb": (user.traffic_used or 0) / (1024**3),
        "expire_at": user.expire_at.isoformat() if user.expire_at else "",
        "created_at": user.created_at.isoformat() if user.created_at else "",
    }


async def _subscription_user(user_uuid: str, db: AsyncSession) -> VpnUser:
    result = await db.execute(select(VpnUser).where(VpnUser.uuid == user_uuid))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="Not found")
    return user


async def _subscription_links(user: VpnUser, request: Request, db: AsyncSession) -> dict:
    from .api.compat import _load_legacy_settings, _settings_state, _user_to_legacy

    await _load_legacy_settings(db)
    if not _settings_state.get("server_ip"):
        _settings_state["server_ip"] = _public_server_ip(request)
    return {
        key: value
        for key, value in _user_to_legacy(user).items()
        if key in {
            "vmess",
            "vless",
            "cdn_vmess",
            "trojan",
            "grpc_vmess",
            "httpupgrade_vmess",
            "ss2022",
            "vless_ws",
        } and value
    }


@app.get("/sub/{user_uuid}", response_class=HTMLResponse)
async def subscription_page(
    user_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
):
    """Serve the public user subscription page."""
    user = await _subscription_user(user_uuid, db)
    links = await _subscription_links(user, request, db)
    template = _jinja_env.get_template("sub.html")
    html = template.render(
        request={"url_root": str(request.base_url)},
        user=_subscription_user_dict(user),
        links=links,
        live_up=0,
        live_down=0,
        online_ips=[],
        server_ip=_public_server_ip(request),
        server_port=settings.web_port,
        sni_host=settings.vless_ws_host,
        ws_path=settings.vless_ws_path,
        settings=settings,
        apk_available=os.path.isfile(os.path.join(os.getcwd(), "static", "downloads", "app-release.apk")),
    )
    return HTMLResponse(content=html)


@app.get("/sub-api/{user_uuid}")
async def subscription_api(
    user_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
):
    """Return base64-encoded subscription links for client auto-import."""
    user = await _subscription_user(user_uuid, db)
    if not user.active:
        raise HTTPException(status_code=404, detail="Not found")
    links = await _subscription_links(user, request, db)
    encoded = base64.b64encode("\n".join(links.values()).encode()).decode()
    return Response(
        content=encoded,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f"inline; filename={user.name}.txt",
            "Profile-Update-Interval": "6",
            "Subscription-Userinfo": (
                f"upload=0; download={int(user.traffic_used or 0)}; "
                f"total={int(user.traffic_limit or 0)}"
            ),
        },
    )


def _subscription_json_config(
    user: VpnUser,
    links: dict,
    server_ip: str,
) -> dict:
    outbounds = []
    for key, link in links.items():
        outbounds.append(
            {
                "tag": f"{key}-{user.name}",
                "protocol": "freedom",
                "settings": {},
                "metadata": {"share_link": link},
            }
        )
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True},
            },
            {
                "tag": "http-in",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {},
            },
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": []},
        "remarks": f"V7LTHRONYX-{user.name}@{server_ip}",
    }


@app.get("/sub-json/{user_uuid}")
async def subscription_json(
    user_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
):
    """Return a JSON subscription document for clients that support JSON import."""
    user = await _subscription_user(user_uuid, db)
    if not user.active:
        raise HTTPException(status_code=404, detail="Not found")
    links = await _subscription_links(user, request, db)
    return JSONResponse(
        content=_subscription_json_config(user, links, _public_server_ip(request)),
        headers={"Content-Disposition": f"inline; filename={user.name}.json"},
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.web_port,
        reload=settings.debug,
        workers=1
    )
