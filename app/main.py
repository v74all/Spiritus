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
import subprocess

from .auth import User, get_current_admin_cookie
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

    # Initialize DPI Evasion SNI Manager
    from .dpi_evasion import sni_manager
    await sni_manager.initialize()
    logger.info("DPI Evasion SNI Manager initialized")

    # Initialize Telegram bot
    from .telegram_bot import telegram_bot
    from .config import settings as s
    if getattr(s, 'telegram_bot_token', None):
        telegram_bot.token = getattr(s, 'telegram_bot_token', '')
        telegram_bot.chat_id = getattr(s, 'telegram_chat_id', '')
        if getattr(s, 'telegram_admin_chat_ids', None):
            telegram_bot.admin_chat_ids = getattr(s, 'telegram_admin_chat_ids', '').split(",")
        logger.info("Telegram bot configured")

    # Initialize payment gateways
    from .payments import payment_manager
    if getattr(s, 'zarinpal_merchant_id', None):
        payment_manager.setup_zarinpal(
            merchant_id=getattr(s, 'zarinpal_merchant_id', ''),
            sandbox=getattr(s, 'zarinpal_sandbox', True),
            callback_url=getattr(s, 'zarinpal_callback_url', ''),
        )
        logger.info("Zarinpal gateway configured")
    if getattr(s, 'idpay_api_key', None):
        payment_manager.setup_idpay(
            api_key=getattr(s, 'idpay_api_key', ''),
            sandbox=getattr(s, 'idpay_sandbox', True),
            callback_url=getattr(s, 'idpay_callback_url', ''),
        )
        logger.info("IDPay gateway configured")
    if getattr(s, 'usdt_wallet_address', None):
        payment_manager.setup_usdt(
            wallet_address=getattr(s, 'usdt_wallet_address', ''),
            api_key=getattr(s, 'usdt_trongrid_api_key', ''),
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
    allow_credentials=False,
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
        content={"message": "Internal server error"},
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

# DPI Evasion router
from .api.dpi import router as dpi_router
app.include_router(dpi_router, prefix="/api")

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

@app.api_route("/api/google-relay", methods=["GET", "POST"], tags=["system"])
async def google_relay_proxy(request: Request):
    """
    Google Apps Script Relay — HTTP proxy endpoint.
    Accepts JSON payloads forwarded from Google Apps Script and fetches the target URL.
    Used as emergency relay exit node when server IP is blocked in Iran.

    Request body (JSON):
      {"method": "GET", "url": "https://example.com", "headers": {...}, "body": "..."}

    Response:
      {"status": 200, "body": "...response text..."}
    """
    import httpx

    try:
        if request.method == "POST":
            payload = await request.json()
        else:
            payload = {"method": "GET", "url": str(request.query_params.get("url", ""))}
    except Exception:
        return JSONResponse({"error": "Invalid payload"}, status_code=400)

    method = (payload.get("method") or "GET").upper()
    url = payload.get("url") or ""
    headers = payload.get("headers") or {}
    body = payload.get("body")
    if payload.get("body_b64"):
        import base64
        body = base64.b64decode(payload["body_b64"]).decode("utf-8", errors="replace")

    if not url:
        return JSONResponse({"error": "url is required"}, status_code=400)

    # Basic security: only allow HTTP/HTTPS URLs
    if not url.startswith(("http://", "https://")):
        return JSONResponse({"error": "only http/https URLs allowed"}, status_code=400)

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            if method == "POST" and body:
                r = await client.request(method, url, headers=headers, content=body)
            else:
                r = await client.request(method, url, headers=headers)

            return JSONResponse({
                "status": r.status_code,
                "body": r.text,
            })
    except httpx.TimeoutException:
        return JSONResponse({"status": 504, "body": "Gateway Timeout"})
    except Exception as e:
        return JSONResponse({"status": 502, "body": f"Proxy error: {str(e)[:200]}"})

# ── Panel HTML (serves the frontend) ───────────────────

_templates_dir = os.path.join(os.getcwd(), "templates")
_jinja_env = Environment(loader=FileSystemLoader(_templates_dir), autoescape=True)

def _url_for_static(filename: str) -> str:
    return f"/static/{filename}"

_jinja_env.globals["url_for"] = lambda endpoint, **kw: _url_for_static(kw.get("filename", ""))

def _detect_direction(request: Request) -> str:
    """Auto-detect page direction: cookie override > Accept-Language (fa/ar → rtl)."""
    dir_cookie = request.cookies.get("vpn_dir")
    if dir_cookie in ("ltr", "rtl"):
        return dir_cookie
    lang = request.headers.get("Accept-Language", "")
    primary = lang.split(",")[0].split(";")[0].strip().lower() if lang else ""
    if primary.startswith("fa") or primary.startswith("ar"):
        return "rtl"
    return "ltr"

@app.get("/", response_class=HTMLResponse)
async def serve_panel(request: Request):
    """Serve the main panel HTML."""
    template_path = os.path.join(_templates_dir, "panel.html")
    if not os.path.exists(template_path):
        return HTMLResponse("<h1>V7LTHRONYX VPN Panel v2.0</h1><p>Panel template not found</p>")

    template = _jinja_env.get_template("panel.html")
    html = template.render(
        dir=_detect_direction(request),
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
        dir=_detect_direction(request),
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


@app.post("/api/direction")
async def set_direction(request: Request):
    """Persist direction preference to cookie."""
    data = await request.json()
    new_dir = data.get("dir", "ltr")
    if new_dir not in ("ltr", "rtl"):
        new_dir = "ltr"
    resp = JSONResponse({"dir": new_dir})
    resp.set_cookie(
        key="vpn_dir", value=new_dir,
        max_age=365 * 24 * 3600, path="/",
        samesite="lax", secure=False, httponly=False,
    )
    return resp


def _public_server_ip(request: Request) -> str:
    # Use explicit VPN_SERVER_IP env var first (most reliable)
    if settings.vpn_server_ip and settings.vpn_server_ip.strip():
        return settings.vpn_server_ip.strip()
    configured_host = (settings.host or "").strip()
    if configured_host and configured_host not in {"0.0.0.0", "127.0.0.1", "localhost", "::1"}:
        return settings.host
    forwarded_host = (request.headers.get("x-forwarded-host") or "").split(",", 1)[0].strip()
    request_host = forwarded_host or (request.headers.get("host") or "")
    # For non-localhost requests, extract host from Host header
    if request_host and request_host not in ("localhost", "127.0.0.1", "[::1]"):
        if request_host.startswith("[") and "]" in request_host:
            return request_host[1:request_host.index("]")]
        if ":" in request_host:
            host, port = request_host.rsplit(":", 1)
            if port.isdigit():
                return host
        return request_host
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
    server_ip = _public_server_ip(request)
    return {
        key: value
        for key, value in _user_to_legacy(user, server_ip=server_ip).items()
        if key in {
            "vmess",
            "vless",
            "vless_ws",
            "vless_xhttp",
            "vless_vision",
            "vless_reverse",
            "cdn_vmess",
            "trojan",
            "trojan_cdn",
            "grpc_vmess",
            "httpupgrade_vmess",
            "ss2022",
            "hysteria2",
            "tuic",
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
        dir=_detect_direction(request),
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
    server_ip: str,
    panel_settings: dict,
) -> dict:
    outbounds = []
    prefix = panel_settings.get("config_prefix") or "Proxy"
    sni = panel_settings.get("vmess_sni") or settings.vless_ws_host or server_ip
    fp = panel_settings.get("fingerprint") or "chrome"
    uid = user.uuid

    # ── Emergency Relay: override server address for ALL outbounds ──
    _actual_server = server_ip
    if panel_settings.get("emergency_relay_enabled") and panel_settings.get("emergency_relay_address"):
        server_ip = panel_settings.get("emergency_relay_address", "").strip() or server_ip

    outbounds.append({
        "tag": f"{prefix}-VMess-{user.name}",
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": server_ip,
                "port": int(panel_settings.get("vmess_port") or 443),
                "users": [{"id": uid, "alterId": 0, "security": "auto"}],
            }],
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {
                "path": panel_settings.get("vmess_ws_path") or "/api/v1/stream",
                "headers": {"Host": sni},
            },
            "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
        },
    })

    if panel_settings.get("reality_public_key"):
        outbounds.append({
            "tag": f"{prefix}-VLESS-{user.name}",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_ip,
                    "port": int(panel_settings.get("vless_port") or 2053),
                    "users": [{"id": uid, "encryption": "none", "flow": "xtls-rprx-vision"}],
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [panel_settings.get("reality_sni") or "chat.deepseek.com"],
                    "fingerprint": fp,
                    "publicKey": panel_settings.get("reality_public_key"),
                    "shortId": panel_settings.get("reality_short_id") or "",
                },
            },
        })

    if panel_settings.get("cdn_enabled") and panel_settings.get("cdn_domain"):
        cdn_domain = panel_settings.get("cdn_domain")
        outbounds.append({
            "tag": f"{prefix}-CDN-{user.name}",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": cdn_domain,
                    "port": int(panel_settings.get("cdn_port") or 443),
                    "users": [{"id": uid, "alterId": 0, "security": "auto"}],
                }],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "path": panel_settings.get("cdn_ws_path") or "/cdn-ws",
                    "headers": {"Host": cdn_domain},
                },
                "tlsSettings": {"serverName": cdn_domain, "fingerprint": fp, "allowInsecure": True},
            },
        })

    if panel_settings.get("trojan_enabled"):
        outbounds.append({
            "tag": f"{prefix}-Trojan-{user.name}",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": server_ip,
                    "port": int(panel_settings.get("trojan_port") or 2083),
                    "password": uid,
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
            },
        })

    if panel_settings.get("grpc_enabled"):
        outbounds.append({
            "tag": f"{prefix}-gRPC-{user.name}",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": server_ip,
                    "port": int(panel_settings.get("grpc_port") or 2054),
                    "users": [{"id": uid, "alterId": 0, "security": "auto"}],
                }],
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {"serviceName": panel_settings.get("grpc_service_name") or "GunService"},
                "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
            },
        })

    if panel_settings.get("httpupgrade_enabled"):
        outbounds.append({
            "tag": f"{prefix}-HU-{user.name}",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": server_ip,
                    "port": int(panel_settings.get("httpupgrade_port") or 2055),
                    "users": [{"id": uid, "alterId": 0, "security": "auto"}],
                }],
            },
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "httpupgradeSettings": {
                    "path": panel_settings.get("httpupgrade_path") or "/httpupgrade",
                    "host": sni,
                },
                "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
            },
        })

    if panel_settings.get("vless_ws_enabled"):
        outbounds.append({
            "tag": f"{prefix}-VLESS-WS-{user.name}",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_ip,
                    "port": int(panel_settings.get("vless_ws_port") or 2057),
                    "users": [{"id": uid, "encryption": "none"}],
                }],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "path": panel_settings.get("vless_ws_path") or "/vless-ws",
                    "headers": {"Host": sni},
                },
                "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
            },
        })

    # VLESS XHTTP REALITY (relay-fronted)
    if panel_settings.get("vless_xhttp_enabled"):
        xhttp_reality_sni = panel_settings.get("vless_xhttp_reality_sni") or "digikala.com"
        xhttp_reality_pk = panel_settings.get("vless_xhttp_reality_public_key") or panel_settings.get("reality_public_key") or ""
        xhttp_reality_sid = panel_settings.get("vless_xhttp_reality_short_id") or ""
        # Resolve port avoiding collision with standard VLESS Reality
        _rxp = int(panel_settings.get("vless_xhttp_port") or 0)
        _vrp = int(panel_settings.get("vless_port") or 2053)
        _xhttp_port = _rxp if (_rxp and _rxp != _vrp) else 8449
        outbounds.append({
            "tag": f"{prefix}-VLESS-XHTTP-{user.name}",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_ip,
                    "port": _xhttp_port,
                    "users": [{"id": uid, "encryption": "none", "flow": "xtls-rprx-vision"}],
                }],
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "xhttpSettings": {
                    "mode": panel_settings.get("vless_xhttp_mode") or "auto",
                    "path": panel_settings.get("vless_xhttp_path") or "/xhttp",
                    "host": xhttp_reality_sni,
                },
                "realitySettings": {
                    "serverName": xhttp_reality_sni,
                    "fingerprint": fp,
                    "publicKey": xhttp_reality_pk,
                    "shortId": xhttp_reality_sid,
                },
            },
        })

    # VLESS Vision REALITY (direct, fresh IP)
    if panel_settings.get("vless_vision_enabled"):
        vision_reality_sni = panel_settings.get("vless_vision_reality_sni") or "objects.githubusercontent.com"
        vision_reality_pk = panel_settings.get("vless_vision_reality_public_key") or panel_settings.get("reality_public_key") or ""
        vision_reality_sid = panel_settings.get("vless_vision_reality_short_id") or ""
        outbounds.append({
            "tag": f"{prefix}-VLESS-Vision-{user.name}",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_ip,
                    "port": int(panel_settings.get("vless_vision_port") or 2058),
                    "users": [{"id": uid, "encryption": "none", "flow": "xtls-rprx-vision"}],
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": vision_reality_sni,
                    "fingerprint": fp,
                    "publicKey": vision_reality_pk,
                    "shortId": vision_reality_sid,
                },
            },
        })

    # VLESS Reverse REALITY (backhaul-tunneled)
    if panel_settings.get("vless_reverse_enabled"):
        rev_reality_sni = panel_settings.get("vless_reverse_reality_sni") or "digikala.com"
        rev_reality_pk = panel_settings.get("reality_public_key") or ""
        rev_reality_sid = panel_settings.get("vless_reverse_reality_short_id") or ""
        outbounds.append({
            "tag": f"{prefix}-VLESS-Reverse-{user.name}",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_ip,
                    "port": int(panel_settings.get("vless_reverse_port") or 2059),
                    "users": [{"id": uid, "encryption": "none"}],
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [rev_reality_sni],
                    "fingerprint": fp,
                    "publicKey": rev_reality_pk,
                    "shortId": rev_reality_sid,
                },
            },
        })

    # Trojan CDN (WS+TLS over Cloudflare)
    if panel_settings.get("trojan_cdn_enabled") and panel_settings.get("trojan_cdn_domain"):
        trojan_cdn_domain = panel_settings.get("trojan_cdn_domain")
        trojan_cdn_sni = panel_settings.get("trojan_cdn_sni") or trojan_cdn_domain
        outbounds.append({
            "tag": f"{prefix}-Trojan-CDN-{user.name}",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": trojan_cdn_domain,
                    "port": int(panel_settings.get("trojan_cdn_port") or 443),
                    "password": uid,
                }],
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "path": panel_settings.get("trojan_cdn_ws_path") or "/trojan-ws",
                    "headers": {"Host": trojan_cdn_domain},
                },
                "tlsSettings": {"serverName": trojan_cdn_sni, "fingerprint": fp, "allowInsecure": True},
            },
        })

    # Trojan CDN gRPC
    if panel_settings.get("trojan_cdn_grpc_enabled") and panel_settings.get("trojan_cdn_domain"):
        trojan_cdn_domain = panel_settings.get("trojan_cdn_domain")
        trojan_cdn_sni = panel_settings.get("trojan_cdn_sni") or trojan_cdn_domain
        outbounds.append({
            "tag": f"{prefix}-Trojan-CDN-gRPC-{user.name}",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": trojan_cdn_domain,
                    "port": int(panel_settings.get("trojan_cdn_grpc_port") or 2060),
                    "password": uid,
                }],
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {"serviceName": panel_settings.get("trojan_cdn_grpc_service") or "TrojanService"},
                "tlsSettings": {"serverName": trojan_cdn_sni, "fingerprint": fp, "allowInsecure": True},
            },
        })

    # ShadowSocks 2022
    if panel_settings.get("ss2022_enabled") and panel_settings.get("ss2022_server_key"):
        outbounds.append({
            "tag": f"{prefix}-SS2022-{user.name}",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": server_ip,
                    "port": int(panel_settings.get("ss2022_port") or 2056),
                    "method": panel_settings.get("ss2022_method") or "2022-blake3-aes-128-gcm",
                    "password": panel_settings.get("ss2022_server_key") + ":" + uid,
                }],
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
            },
        })

    if panel_settings.get("fragment_enabled") or panel_settings.get("noise_enabled"):
        for outbound in outbounds:
            stream_settings = outbound.setdefault("streamSettings", {})
            sockopt = stream_settings.setdefault("sockopt", {})
            if panel_settings.get("fragment_enabled"):
                sockopt["fragment"] = {
                    "packets": panel_settings.get("fragment_packets") or "tlshello",
                    "length": panel_settings.get("fragment_length") or "100-200",
                    "interval": panel_settings.get("fragment_interval") or "10-20",
                }
            if panel_settings.get("noise_enabled"):
                sockopt["noisePacket"] = panel_settings.get("noise_packet") or "rand:50-100"
                sockopt["noiseDelay"] = panel_settings.get("noise_delay") or "10-20"

    if panel_settings.get("mux_enabled"):
        for outbound in outbounds:
            outbound["mux"] = {
                "enabled": True,
                "concurrency": int(panel_settings.get("mux_concurrency") or 8),
            }

    # ── DPI Evasion: Host Header Spoofing ──
    # Replaces HTTP Host header with a whitelisted domain while keeping real SNI in TLS
    host_spoof_domain = None
    if panel_settings.get("dpi_http_host_spoof_enabled"):
        host_spoof_domain = panel_settings.get("dpi_http_host_spoof_domain") or "chat.deepseek.com"
    ws_front_domain = None
    if panel_settings.get("dpi_ws_host_front_enabled"):
        ws_front_domain = panel_settings.get("dpi_ws_host_front_domain") or "rubika.ir"
    cdn_front_domain = None
    if panel_settings.get("dpi_cdn_host_front_enabled"):
        cdn_front_domain = panel_settings.get("dpi_cdn_host_front_domain") or "web.splus.ir"

    for outbound in outbounds:
        ss = outbound.get("streamSettings", {})
        network = ss.get("network", "tcp")

        # TCP Keepalive
        if panel_settings.get("dpi_tcp_keepalive"):
            sockopt = ss.setdefault("sockopt", {})
            sockopt["tcpKeepAlive"] = True

        # HTTP Host Spoofing: replace Host header on WS/HTTPUpgrade
        if host_spoof_domain:
            if network == "ws" and "wsSettings" in ss:
                ss["wsSettings"]["headers"] = {"Host": host_spoof_domain}
            elif network == "httpupgrade" and "httpupgradeSettings" in ss:
                ss["httpupgradeSettings"]["host"] = host_spoof_domain

        # WS Host Fronting: different Host for WS upgrade than TLS SNI
        elif ws_front_domain:
            if network == "ws" and "wsSettings" in ss:
                ss["wsSettings"]["headers"] = {"Host": ws_front_domain}
            elif network == "httpupgrade" and "httpupgradeSettings" in ss:
                ss["httpupgradeSettings"]["host"] = ws_front_domain

        # CDN Host Fronting: apply to outbounds going through CDN
        if cdn_front_domain and outbound.get("tag", "").startswith(prefix + "-CDN"):
            if network == "ws" and "wsSettings" in ss:
                ss["wsSettings"]["headers"] = {"Host": cdn_front_domain}
            if "tlsSettings" in ss:
                ss["tlsSettings"]["serverName"] = cdn_front_domain

        # Bug Host: inject additional obfuscation headers
        if panel_settings.get("dpi_bug_host_enabled"):
            bug_domain = panel_settings.get("dpi_bug_host_domain") or "chat.deepseek.com"
            if network == "ws" and "wsSettings" in ss:
                # Add X-Forwarded-Host and other misleading headers
                existing_headers = ss["wsSettings"].get("headers", {})
                existing_headers["X-Forwarded-Host"] = bug_domain
                existing_headers["X-Host"] = bug_domain
                ss["wsSettings"]["headers"] = existing_headers
            elif network == "httpupgrade" and "httpupgradeSettings" in ss:
                ss["httpupgradeSettings"]["host"] = bug_domain

        # Domain Fronting: use CDN domain as SNI while connecting to real server
        if panel_settings.get("dpi_domain_front") and panel_settings.get("dpi_cdn_front"):
            front_domain = panel_settings.get("dpi_cdn_front")
            if "tlsSettings" in ss and outbound.get("tag", "").startswith(prefix + "-CDN"):
                ss["tlsSettings"]["serverName"] = front_domain
                ss["tlsSettings"]["allowInsecure"] = True

    # ── DNS / ICMP Tunneling (server-assisted) ──
    # These require agent-side tunnel binaries (dnstt, icmptunnel).
    # When enabled, add a loopback outbound that the local tunnel routes into.
    _tunnel_active = panel_settings.get("dpi_dns_tunnel") or panel_settings.get("dpi_icmp_tunnel")
    if _tunnel_active:
        tunnel_outbounds = []
        _tunnel_types = []
        if panel_settings.get("dpi_dns_tunnel"):
            _tunnel_types.append("dns")
            tunnel_outbounds.append({
                "tag": f"tunnel-dns-{user.name}",
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIP", "redirect": "127.0.0.1:5353"},
            })
        if panel_settings.get("dpi_icmp_tunnel"):
            _tunnel_types.append("icmp")
            tunnel_outbounds.append({
                "tag": f"tunnel-icmp-{user.name}",
                "protocol": "freedom",
                "settings": {"domainStrategy": "UseIP", "redirect": "127.0.0.1:9999"},
            })
        # Insert tunnel outbounds before direct
        direct_idx = next((i for i, o in enumerate(outbounds) if o.get("tag") == "direct"), len(outbounds))
        for t in reversed(tunnel_outbounds):
            outbounds.insert(direct_idx, t)

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
    from .api.compat import _load_legacy_settings

    panel_settings = await _load_legacy_settings(db)
    return JSONResponse(
        content=_subscription_json_config(user, _public_server_ip(request), panel_settings),
        headers={"Content-Disposition": f"inline; filename={user.name}.json"},
    )

def _generate_xray_server_config(panel_settings: dict) -> dict:
    """Generate the server-side Xray config with inbounds for all enabled protocols."""
    inbounds = []
    sni = panel_settings.get("vmess_sni") or "www.aparat.com"
    fp = panel_settings.get("fingerprint") or "chrome"
    reality_pk = panel_settings.get("reality_private_key") or settings.reality_private_key
    reality_pub = panel_settings.get("reality_public_key") or settings.reality_public_key
    reality_sid = panel_settings.get("reality_short_id") or ""

    # VMess WS+TLS (always-on)
    inbounds.append({
        "tag": "in-vmess-ws",
        "port": int(panel_settings.get("vmess_port") or 443),
        "listen": "0.0.0.0",
        "protocol": "vmess",
        "settings": {"clients": []},
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {"path": panel_settings.get("vmess_ws_path") or "/api/v1/stream"},
            "tlsSettings": {
                "serverName": sni,
                "certificates": [{"certificateFile": "/etc/ssl/certs/fullchain.pem",
                                   "keyFile": "/etc/ssl/private/privkey.pem"}],
                "minVersion": "1.2",
            },
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    })

    # VLESS REALITY (Vision)
    if panel_settings.get("reality_public_key"):
        inbounds.append({
            "tag": "in-vless-reality",
            "port": int(panel_settings.get("vless_port") or 2053),
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [panel_settings.get("reality_sni") or "chat.deepseek.com"],
                    "dest": panel_settings.get("reality_dest") or "chat.deepseek.com:443",
                    "privateKey": reality_pk,
                    "shortIds": [reality_sid] if reality_sid else [""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS XHTTP REALITY (use distinct port to avoid collision)
    if panel_settings.get("vless_xhttp_enabled"):
        xhttp_sni = panel_settings.get("vless_xhttp_reality_sni") or "digikala.com"
        xhttp_dest = panel_settings.get("vless_xhttp_reality_dest") or "digikala.com:443"
        xhttp_pk = panel_settings.get("vless_xhttp_reality_private_key") or reality_pk
        xhttp_sid = panel_settings.get("vless_xhttp_reality_short_id") or ""
        raw_xhttp_port = int(panel_settings.get("vless_xhttp_port") or 0)
        vless_port_val = int(panel_settings.get("vless_port") or 2053)
        if raw_xhttp_port and raw_xhttp_port != vless_port_val:
            xhttp_port = raw_xhttp_port
        else:
            xhttp_port = 8449
        inbounds.append({
            "tag": "in-vless-xhttp",
            "port": xhttp_port,
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "xhttpSettings": {
                    "mode": panel_settings.get("vless_xhttp_mode") or "auto",
                    "path": panel_settings.get("vless_xhttp_path") or "/xhttp",
                    "host": xhttp_sni,
                },
                "realitySettings": {
                    "serverNames": [xhttp_sni],
                    "dest": xhttp_dest,
                    "privateKey": xhttp_pk,
                    "shortIds": [xhttp_sid] if xhttp_sid else [""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS Vision REALITY (fresh IP)
    if panel_settings.get("vless_vision_enabled"):
        vision_sni = panel_settings.get("vless_vision_reality_sni") or "objects.githubusercontent.com"
        vision_dest = panel_settings.get("vless_vision_reality_dest") or "objects.githubusercontent.com:443"
        vision_pk = panel_settings.get("vless_vision_reality_private_key") or reality_pk
        vision_sid = panel_settings.get("vless_vision_reality_short_id") or ""
        inbounds.append({
            "tag": "in-vless-vision",
            "port": int(panel_settings.get("vless_vision_port") or 2058),
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverNames": [vision_sni],
                    "dest": vision_dest,
                    "privateKey": vision_pk,
                    "shortIds": [vision_sid] if vision_sid else [""],
                    "fingerprint": fp,
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # Trojan
    if panel_settings.get("trojan_enabled"):
        inbounds.append({
            "tag": "in-trojan",
            "port": int(panel_settings.get("trojan_port") or 2083),
            "listen": "0.0.0.0",
            "protocol": "trojan",
            "settings": {"clients": []},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": "/etc/ssl/certs/fullchain.pem",
                                       "keyFile": "/etc/ssl/private/privkey.pem"}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # gRPC
    if panel_settings.get("grpc_enabled"):
        inbounds.append({
            "tag": "in-grpc",
            "port": int(panel_settings.get("grpc_port") or 2054),
            "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {"clients": []},
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {"serviceName": panel_settings.get("grpc_service_name") or "GunService"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": "/etc/ssl/certs/fullchain.pem",
                                       "keyFile": "/etc/ssl/private/privkey.pem"}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # HTTPUpgrade
    if panel_settings.get("httpupgrade_enabled"):
        inbounds.append({
            "tag": "in-httpupgrade",
            "port": int(panel_settings.get("httpupgrade_port") or 2055),
            "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {"clients": []},
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "httpupgradeSettings": {"path": panel_settings.get("httpupgrade_path") or "/httpupgrade"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": "/etc/ssl/certs/fullchain.pem",
                                       "keyFile": "/etc/ssl/private/privkey.pem"}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS WS+TLS
    if panel_settings.get("vless_ws_enabled"):
        inbounds.append({
            "tag": "in-vless-ws",
            "port": int(panel_settings.get("vless_ws_port") or 2057),
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": panel_settings.get("vless_ws_path") or "/vless-ws"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": "/etc/ssl/certs/fullchain.pem",
                                       "keyFile": "/etc/ssl/private/privkey.pem"}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # ShadowSocks 2022
    if panel_settings.get("ss2022_enabled") and panel_settings.get("ss2022_server_key"):
        inbounds.append({
            "tag": "in-ss2022",
            "port": int(panel_settings.get("ss2022_port") or 2056),
            "listen": "0.0.0.0",
            "protocol": "shadowsocks",
            "settings": {
                "method": panel_settings.get("ss2022_method") or "2022-blake3-aes-128-gcm",
                "password": panel_settings.get("ss2022_server_key"),
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": "/etc/ssl/certs/fullchain.pem",
                                       "keyFile": "/etc/ssl/private/privkey.pem"}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # CDN WS+TLS
    if panel_settings.get("cdn_enabled") and panel_settings.get("cdn_domain"):
        cdn_domain = panel_settings.get("cdn_domain")
        inbounds.append({
            "tag": "in-cdn-ws",
            "port": int(panel_settings.get("cdn_port") or 2082),
            "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {"clients": []},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": panel_settings.get("cdn_ws_path") or "/cdn-ws"},
                "tlsSettings": {
                    "serverName": cdn_domain,
                    "certificates": [{"certificateFile": "/etc/ssl/certs/fullchain.pem",
                                       "keyFile": "/etc/ssl/private/privkey.pem"}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


@app.post("/api/xray/sync")
async def sync_xray_config(
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
    db: AsyncSession = Depends(get_async_db),
):
    """Generate and apply the Xray server config from current settings."""
    from .api.compat import _load_legacy_settings

    panel_settings = await _load_legacy_settings(db)

    # Fetch active users for client authentication (in async context)
    result = await db.execute(
        select(VpnUser).where(VpnUser.active == 1)
    )
    users = result.scalars().all()
    vmess_clients = [{"id": u.uuid, "alterId": 0, "email": u.name} for u in users]
    vless_clients = [{"id": u.uuid, "email": u.name} for u in users]
    trojan_clients = [{"password": u.uuid, "email": u.name} for u in users]

    # Generate server config (uses settings from compat _settings_state)
    from .api.compat import _generate_xray_server_config as _gen
    config = _gen()

    # Override client lists with actually fetched users
    for inbound in config.get("inbounds", []):
        proto = inbound.get("protocol", "")
        if proto == "vmess":
            inbound.setdefault("settings", {})["clients"] = vmess_clients
        elif proto == "vless":
            inbound.setdefault("settings", {})["clients"] = vless_clients
        elif proto == "trojan":
            inbound.setdefault("settings", {})["clients"] = trojan_clients

    # Write config to disk
    config_path = settings.xray_config_path
    try:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        # Restart Xray to apply
        subprocess.run(["systemctl", "restart", "xray"], capture_output=True, timeout=10)
        n_clients = len(vmess_clients)
        n_inbounds = len(config.get("inbounds", []))
        logger.info(f"Xray config synced: {n_inbounds} inbounds, {n_clients} clients")
        return {"ok": True, "message": f"Xray config applied: {n_inbounds} inbounds, {n_clients} clients"}
    except Exception as e:
        logger.error(f"Failed to sync Xray config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to sync Xray config: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.web_port,
        reload=settings.debug,
        workers=1
    )
