"""
FastAPI entry point for V7LTHRONYX VPN Panel.

This module initializes the FastAPI application, configures middleware,
and mounts the API routers.
"""

import asyncio
import base64
import json
import logging
import math
import os
import re
import subprocess
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import User, get_current_admin_cookie
from .config import settings
from .database import get_async_db, init_db, shutdown_db
from .models import VpnUser
from .observability import setup_opentelemetry
from .privileged_helper import PrivilegedHelperError, helper_request
from .redis_client import close_redis
from .timeutil import utcnow as _utcnow

# Configure logging — stderr is always wired; the file handler is best-effort
# so the panel can still start under tightened systemd profiles where the
# working directory may not be writable by the unprivileged service user.
# systemd captures stderr to journald, so nothing is lost when the file
# handler is skipped.
_log_handlers = [logging.StreamHandler()]
_log_path = os.environ.get("LOG_FILE", "vpn-panel.log")
if _log_path:
    try:
        _fh = logging.FileHandler(_log_path)
        try:
            os.chmod(_log_path, 0o640)
        except OSError:
            pass
        _log_handlers.insert(0, _fh)
    except (OSError, PermissionError) as _e:
        # Surface the reason via stderr so journald shows it, then continue.
        import sys as _sys
        print(
            f"WARN: file log disabled ({type(_e).__name__}: {_e}); "
            "falling back to stderr only.",
            file=_sys.stderr,
        )

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=_log_handlers,
    force=True,
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
    from .config import settings as s
    from .telegram_bot import telegram_bot
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

    # First-run admin bootstrap (replaces the legacy plaintext password file).
    # Creates an Admin row from ADMIN_BOOTSTRAP_PASSWORD env if and only if
    # no admin exists yet. Bootstrap secret is consumed once — operators must
    # remove it from .env after first boot.
    try:
        from .api.auth import bootstrap_initial_admin
        from .database import AsyncSessionLocal
        async with AsyncSessionLocal() as _db:
            await bootstrap_initial_admin(_db)
    except Exception as e:
        # Don't swallow this — without an admin row no one can log in, which
        # is the single most operator-confusing failure mode this codebase
        # has. Surface it loudly and drop a Redis breadcrumb so ops dashboards
        # can detect "panel up but locked" without grepping the journal.
        logger.critical("admin bootstrap failed: %s: %s", type(e).__name__, e)
        try:
            from .redis_client import get_redis
            r = await get_redis()
            await r.setex("bootstrap_status", 3600, f"failed:{type(e).__name__}")
        except Exception:
            pass

    # TLS cert precondition: any TLS-bearing inbound will fail to start in Xray
    # if these files don't exist. Surface a clear log line at boot rather than
    # a cryptic Xray crash later. Defaults are /etc/ssl/certs/fullchain.pem and
    # /etc/ssl/private/privkey.pem; override via TLS_CERT_FILE / TLS_KEY_FILE.
    for _label, _p in (("tls_cert_file", settings.tls_cert_file),
                       ("tls_key_file", settings.tls_key_file)):
        if not os.path.exists(_p):
            logger.error(
                "TLS path missing: %s=%s. TLS-bearing inbounds (VLESS-WS, "
                "Trojan, Hysteria2, WS+TLS Domain Fronting, ...) will fail to "
                "start in Xray. Set %s in your env to point at a valid file.",
                _label, _p, _label.upper(),
            )

    # Xray config bootstrap: load settings from DB (or defaults) and write a
    # fresh xray config on every startup. Without this, a freshly-installed
    # panel leaves xray with an empty {} config until the operator opens the
    # Settings modal and clicks Save — meaning all user configs are broken out
    # of the box. This runs after DB init so the settings row is available.
    try:
        from .api.compat import _load_legacy_settings, _schedule_xray_sync
        from .api.compat.panel_settings import ensure_reality_keys, ensure_ss2022_key
        from .database import AsyncSessionLocal
        async with AsyncSessionLocal() as _db:
            await _load_legacy_settings(_db)
            await ensure_reality_keys(_db)
            await ensure_ss2022_key(_db)
            from .traffic_control import retire_unenforced_default_limits

            await retire_unenforced_default_limits(_db)
        _schedule_xray_sync()
        logger.info("Xray config bootstrap: settings loaded, sync scheduled")
    except Exception as _xray_exc:
        logger.warning("Xray config bootstrap failed (non-fatal): %s", _xray_exc)

    # Users reach the engines live, traffic is counted and quotas / expiry
    # enforced (app/user_runtime.py; importing it installs the DB hook).
    from . import user_runtime

    _runtime_task = None
    if settings.user_runtime_sync:
        _runtime_task = asyncio.create_task(user_runtime.run_forever())

    yield

    # Shutdown
    logger.info("Shutting down V7LTHRONYX VPN Panel...")
    if _runtime_task:
        _runtime_task.cancel()
    await shutdown_db()
    await close_redis()
    logger.info("Shutdown complete")

# Initialize FastAPI app. API docs are gated behind DEBUG to prevent schema
# leakage in production deployments.
app = FastAPI(
    title="V7LTHRONYX VPN Panel",
    description="Unified VPN management panel with multi-protocol support",
    version="2.1.0",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.debug else None,
    redoc_url="/api/redoc" if settings.debug else None,
    openapi_url="/api/openapi.json" if settings.debug else None,
)

# ── CORS ─────────────────────────────────────────────────────────────────────
# Default policy: NO CORS middleware. Add only when an explicit allowlist is
# configured. Wildcard "*" was already rejected at config-load time.
_allowed_origins = [o.strip() for o in (settings.cors_origins or "").split(",") if o.strip()]
if _allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
        expose_headers=["Retry-After"],
        max_age=600,
    )

# ── Request body size limit (anti-DoS) ───────────────────────────────────────
# Reject oversized bodies early, before they are buffered into memory. The JSON
# admin API only ever needs a few KB; bulk-import endpoints stay well under the
# 2 MiB default. Streams without Content-Length are capped while reading.
_MAX_BODY = int(getattr(settings, "max_request_body_bytes", 0) or 0)
if _MAX_BODY > 0:
    @app.middleware("http")
    async def _limit_body_size(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > _MAX_BODY:
                    return JSONResponse({"detail": "Request entity too large"}, status_code=413)
            except ValueError:
                return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
        return await call_next(request)

# ── Rate limit (global) ──────────────────────────────────────────────────────
from .middleware.rate_limit import RateLimitMiddleware

app.add_middleware(RateLimitMiddleware)

# ── Admin IP allowlist (opt-in via ADMIN_IP_ALLOWLIST) ───────────────────────
if settings.admin_ip_allowlist.strip():
    from .middleware.ip_allowlist import AdminIPAllowlistMiddleware

    app.add_middleware(AdminIPAllowlistMiddleware)

# ── CSRF (double-submit cookie) ──────────────────────────────────────────────
from .middleware.csrf import CSRFMiddleware

app.add_middleware(CSRFMiddleware)

# ── Trusted Host allowlist (defence-in-depth vs Host-header poisoning) ────────
# Enforced only when ALLOWED_HOSTS is configured, so existing deployments keep
# working. Starlette validates the Host header against this list and returns a
# 400 for anything else — neutralising Host/BadHost-style spoofing regardless
# of how downstream code reads the host.
_allowed_hosts = [h.strip() for h in (settings.allowed_hosts or "").split(",") if h.strip()]
if _allowed_hosts:
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    # Always permit localhost so health checks / the privileged helper still work.
    for _lh in ("127.0.0.1", "localhost", "[::1]"):
        if _lh not in _allowed_hosts:
            _allowed_hosts.append(_lh)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts)


# ── Security headers ─────────────────────────────────────────────────────────
import secrets as _secrets_mod


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    # Per-request nonce for inline scripts. Templates that need to embed an
    # inline <script> should render it as `<script nonce="{{ csp_nonce }}">`.
    nonce = _secrets_mod.token_urlsafe(16)
    request.state.csp_nonce = nonce

    response = await call_next(request)

    # HSTS: only emit over HTTPS, but headers are still safe to send over HTTP
    # because browsers ignore HSTS from plain HTTP responses. Keep the long
    # max-age + preload eligibility.
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

    # CSP: inline script execution is nonce-only. Legacy event attributes are
    # rebound by static/js/csp-events.js and removed before interaction, so the
    # browser does not need to execute onclick/onchange attribute JavaScript.
    # CSP layout:
    # - script-src: same-origin scripts + nonce'd template scripts.
    # - script-src-attr 'none': inline event attributes are not executable.
    # - style-src/style-src-attr: inline CSS blocks are nonce'd; legacy style
    #   attributes are migrated to CSSOM by csp-events.js and then removed.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "script-src-attr 'none'; "
        f"style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com; "
        "style-src-attr 'none'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "object-src 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"  # modern guidance: disable
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        "accelerometer=(), gyroscope=(), magnetometer=()"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    # Leak-prevention: strip the Server header (FastAPI sets it to "uvicorn").
    if "server" in response.headers:
        del response.headers["server"]
    return response


# ── Exception handler ────────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Avoid leaking stack traces. Always log server-side; only return the
    # exception class name (never the message) to the client in non-debug.
    logger.error(
        "unhandled exception type=%s path=%s",
        type(exc).__name__,
        request.url.path,
        exc_info=settings.debug,
    )
    payload = {"message": "Internal server error"}
    if settings.debug:
        payload["type"] = type(exc).__name__
        payload["detail"] = str(exc)[:500]
    return JSONResponse(status_code=500, content=payload)

# Mount static files. Wrap StaticFiles to disable caching for JS/CSS so
# users always get the latest panel.js after a deploy (combined with
# the ?v=mtime cache-bust on /).
class _NoCacheStatic(StaticFiles):
    async def get_response(self, path, scope):
        resp = await super().get_response(path, scope)
        if path.endswith((".js", ".css", ".html")):
            resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            resp.headers["Pragma"] = "no-cache"
            resp.headers["Expires"] = "0"
        return resp

if os.path.exists("static"):
    app.mount("/static", _NoCacheStatic(directory="static"), name="static")

# ── Mount API Routers ──────────────────────────────────

from .api.abuse import router as abuse_router
from .api.agents import router as agents_router
from .api.auth import router as auth_router
from .api.compat import router as compat_router
from .api.mobile_auth import router as mobile_auth_router
from .api.mobile_auth import session_router as mobile_session_router
from .api.payments import router as payments_router
from .api.protocols import router as protocols_router
from .api.resellers import portal_router
from .api.resellers import router as resellers_router
from .api.security import router as security_router
from .api.system import router as system_router
from .api.users import router as users_router

# Legacy panel routes must be registered first so cookie-auth compatibility
# handlers win over the bearer-token resource routers on shared paths.
app.include_router(compat_router, prefix="/api")
from .api.honeypot import router as honeypot_router
from .api.ops import probe_router as ops_probe_router
from .api.ops import router as ops_router
from .api.telegram import router as telegram_router

app.include_router(honeypot_router)
app.include_router(telegram_router, prefix="/api")
app.include_router(ops_router, prefix="/api")
app.include_router(ops_probe_router, prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(mobile_auth_router, prefix="/api")
app.include_router(mobile_session_router, prefix="/api")
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

# Domain & certificate manager
from .api.domain import router as domain_router

app.include_router(domain_router, prefix="/api")

# ── Health check ────────────────────────────────────────

@app.get("/api/health", tags=["system"])
async def health_check():
    """Health check endpoint for Kubernetes/load balancers."""
    return {"status": "healthy", "service": "v7lthronyx-vpn-panel", "version": "2.1.0"}

@app.get("/api/ready", tags=["system"])
async def readiness_check(db: AsyncSession = Depends(get_async_db)):
    """Check mandatory production dependencies without leaking internals."""
    from sqlalchemy import text

    from .redis_client import get_redis

    unavailable = []
    if not settings.debug and not str(settings.database_url).startswith("postgresql+"):
        unavailable.append("database_backend")
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        unavailable.append("database")
    try:
        redis = await get_redis()
        await redis.ping()
    except Exception:
        unavailable.append("redis")
    if not os.path.isfile(settings.xray_config_path):
        unavailable.append("xray_config")
    else:
        try:
            validated = await asyncio.to_thread(
                subprocess.run,
                [settings.xray_bin_path, "-test", "-config", settings.xray_config_path],
                capture_output=True,
                timeout=10,
                check=False,
            )
            if validated.returncode != 0:
                unavailable.append("xray_config")
        except (OSError, subprocess.SubprocessError):
            unavailable.append("xray_core")
    if unavailable:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "unavailable": unavailable},
        )
    return {"status": "ready"}

@app.get("/api/live", tags=["system"])
async def liveness_check():
    """Liveness probe for Kubernetes."""
    return {"status": "alive"}

@app.api_route("/api/google-relay", methods=["GET", "POST"], tags=["system"])
async def google_relay_proxy(
    request: Request,
    admin: User = Depends(get_current_admin_cookie),
):
    """
    Google Apps Script Relay — HTTP proxy endpoint (admin-only).
    Accepts JSON payloads forwarded from Google Apps Script and fetches the target URL.
    Used as emergency relay exit node when server IP is blocked in Iran.

    Request body (JSON):
      {"method": "GET", "url": "https://example.com", "headers": {...}, "body": "..."}

    Response:
      {"status": 200, "body": "...response text..."}
    """
    import ipaddress

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

    # Method allowlist (block weird verbs that DPI/EDR may misinterpret).
    if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"):
        return JSONResponse({"error": "method not allowed"}, status_code=405)

    # Only http/https URLs.
    if not url.startswith(("http://", "https://")):
        return JSONResponse({"error": "only http/https URLs allowed"}, status_code=400)

    # ─── SSRF protection ────────────────────────────────────────────────
    import socket
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not hostname or len(hostname) > 253:
        return JSONResponse({"error": "invalid hostname"}, status_code=400)
    # Reject literal "localhost" early — getaddrinfo would resolve it to
    # loopback, but operators sometimes alias it to public IPs in /etc/hosts.
    if hostname.lower() in ("localhost", "localhost.localdomain", "ip6-localhost"):
        return JSONResponse({"error": "internal hostname not allowed"}, status_code=400)
    # Resolve ALL A and AAAA records; reject if any one is unsafe.
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return JSONResponse({"error": "hostname did not resolve"}, status_code=400)
    if not infos:
        return JSONResponse({"error": "hostname did not resolve"}, status_code=400)

    _METADATA_HOSTS = {
        "169.254.169.254",                            # AWS / GCP / Azure / OCI
        "fd00:ec2::254",                              # AWS IMDS v6
        "100.100.100.200",                            # Alibaba ECS
    }
    for info in infos:
        try:
            ip_str = info[4][0]
            ip = ipaddress.ip_address(ip_str)
        except (ValueError, IndexError):
            return JSONResponse({"error": "invalid resolved address"}, status_code=400)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
            or str(ip) in _METADATA_HOSTS
        ):
            return JSONResponse(
                {"error": "internal/metadata address blocked"}, status_code=400
            )

    # Disable redirects so a 30x → internal host can't bypass the resolver.
    # Cap body size and total timeout.
    try:
        limits = httpx.Limits(max_keepalive_connections=2, max_connections=4)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=20.0, write=20.0, pool=5.0),
            follow_redirects=False,
            limits=limits,
        ) as client:
            r = await client.request(
                method, url, headers=headers,
                content=body if (method in ("POST", "PUT", "PATCH") and body) else None,
            )
            # Truncate response to prevent abuse as a generic proxy.
            text = r.text[:1_000_000]
            return JSONResponse({"status": r.status_code, "body": text})
    except httpx.TimeoutException:
        return JSONResponse({"status": 504, "body": "Gateway Timeout"})
    except Exception as e:
        return JSONResponse({"status": 502, "body": f"Proxy error: {type(e).__name__}"})

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
    # Cache-bust JS/CSS via mtime so browsers always pick up post-deploy changes
    try:
        _js_path = os.path.join(os.path.dirname(_templates_dir), "static", "js", "panel.js")
        asset_v = str(int(os.path.getmtime(_js_path)))
    except Exception:
        asset_v = "0"
    html = template.render(
        dir=_detect_direction(request),
        server_ip=settings.host if settings.host != "0.0.0.0" else "",
        server_port=settings.web_port,
        sni_host=settings.vless_ws_host,
        ws_path=settings.vless_ws_path,
        asset_v=asset_v,
        csp_nonce=getattr(request.state, "csp_nonce", ""),
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
    try:
        _css_path = os.path.join(os.path.dirname(_templates_dir), "static", "css", "ui.css")
        asset_v = str(int(os.path.getmtime(_css_path)))
    except Exception:
        asset_v = "0"
    html = template.render(
        dir=_detect_direction(request),
        asset_v=asset_v,
        server_ip=settings.host if settings.host != "0.0.0.0" else "",
        server_port=settings.web_port,
        sni_host=settings.vless_ws_host,
        ws_path=settings.vless_ws_path,
        apk_available=os.path.isfile(apk_path),
        csp_nonce=getattr(request.state, "csp_nonce", ""),
    )
    return HTMLResponse(content=html)


@app.get("/landing", response_class=HTMLResponse)
@app.get("/intro", response_class=HTMLResponse)
@app.get("/about", response_class=HTMLResponse)
async def serve_landing(request: Request):
    template = _jinja_env.get_template("landing.html")
    try:
        _js_path = os.path.join(os.path.dirname(_templates_dir), "static", "js", "tailwind.min.js")
        asset_v = str(int(os.path.getmtime(_js_path)))
    except Exception:
        asset_v = "0"
    html = template.render(
        dir=_detect_direction(request),
        server_ip=settings.host if settings.host != "0.0.0.0" else "",
        server_port=settings.web_port,
        asset_v=asset_v,
        csp_nonce=getattr(request.state, "csp_nonce", ""),
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
    from .middleware.csrf import is_secure_request
    resp = JSONResponse({"dir": new_dir})
    resp.set_cookie(
        key="vpn_dir", value=new_dir,
        max_age=365 * 24 * 3600, path="/",
        samesite="lax", secure=is_secure_request(request), httponly=True,
    )
    return resp


def _public_server_ip(request: Request) -> str:
    # One policy for every share link: configured address, then a safe Host.
    # X-Forwarded-Host is not trusted unless it is on ALLOWED_HOSTS, and the
    # value is never cached on the process — see resolve_public_host.
    from .api.compat import resolve_public_host

    return resolve_public_host(request)


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


def _subscription_state(user: VpnUser) -> dict:
    """Plain-language account state for the subscription page.

    ``state``: expired | limit | expiring (<=3 days) | low_traffic (>=90% used) | ok.
    ``days_left`` is None for accounts without an expiry date.
    """
    now = _utcnow()
    days_left = None
    if user.expire_at:
        days_left = max(0, math.ceil((user.expire_at - now).total_seconds() / 86400))
    limit = int(user.traffic_limit or 0)
    used = int(user.traffic_used or 0)
    if user.expire_at and user.expire_at <= now:
        state = "expired"
    elif limit > 0 and used >= limit:
        state = "limit"
    elif days_left is not None and days_left <= 3:
        state = "expiring"
    elif limit > 0 and used >= limit * 0.9:
        state = "low_traffic"
    else:
        state = "ok"
    return {"state": state, "days_left": days_left}


async def _subscription_user(user_uuid: str, db: AsyncSession) -> VpnUser:
    result = await db.execute(select(VpnUser).where(VpnUser.uuid == user_uuid))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="Not found")
    return user


# Share-link key -> protocol key used by the probes (app.api.ops). Links with
# no probe equivalent (CDN-fronted) keep their default place.
_SUB_LINK_ORDER = (
    "vmess", "vless", "vless_ws", "vless_ws_plain_front",
    "vless_xhttp", "vless_vision", "vless_reverse",
    "cdn_vmess", "trojan", "trojan_cdn",
    "grpc_vmess", "httpupgrade_vmess", "ss2022",
    "hysteria2", "tuic", "naiveproxy", "mieru",
)
_SUB_LINK_PROTOCOLS = {
    "vmess": "vmess", "vless": "vless_reality", "vless_ws": "vless_ws",
    "vless_ws_plain_front": "vless_ws_plain_front", "vless_xhttp": "vless_xhttp_reality",
    "vless_vision": "vless_vision_reality", "vless_reverse": "vless_reverse_reality",
    "trojan": "trojan", "trojan_cdn": "trojan_cdn", "grpc_vmess": "grpc",
    "httpupgrade_vmess": "httpupgrade", "ss2022": "ss2022",
    "hysteria2": "hysteria2", "tuic": "tuic", "naiveproxy": "naiveproxy", "mieru": "mieru",
}
# /sub-json outbound tag label ("{prefix}-<label>-{user}") -> probe protocol key.
_SUB_OUTBOUND_PROTOCOLS = {
    "VMess": "vmess", "VLESS": "vless_reality", "Trojan": "trojan", "gRPC": "grpc",
    "HU": "httpupgrade", "VLESS-WS": "vless_ws", "VLESS-XHTTP": "vless_xhttp_reality",
    "VLESS-Vision": "vless_vision_reality", "VLESS-Reverse": "vless_reverse_reality",
    "Trojan-CDN": "trojan_cdn", "SS2022": "ss2022",
}


async def _subscription_links(user: VpnUser, request: Request, db: AsyncSession,
                              with_wireguard: bool = False) -> dict:
    from .api.compat import _load_legacy_settings, _settings_state, _user_to_legacy

    await _load_legacy_settings(db)
    server_ip = _public_server_ip(request)
    # Return ALL non-empty links including IPv6 variants and VLESS Plain
    legacy = _user_to_legacy(user, server_ip=server_ip)
    # Default order (a tuple: this used to be a set, so the order changed
    # with every process restart). Each IPv6 twin follows its IPv4 link.
    ordered = []
    for k in _SUB_LINK_ORDER:
        ordered.append(k)
        ordered.append(k + "_ipv6")
    ordered += sorted(k for k in legacy if k.endswith("_ipv6") and k not in ordered)
    keys = [k for k in ordered if legacy.get(k)]
    if _settings_state.get("auto_protocol_order_enabled", True):
        from .api.ops import protocol_rank, rank_sort_key

        rank = await protocol_rank(db)
        keys.sort(key=lambda k: rank_sort_key(
            _SUB_LINK_PROTOCOLS.get(k.removesuffix("_ipv6")), rank, ordered.index(k)
        ))
    links = {k: legacy[k] for k in keys}
    # The WireGuard .conf is a file, not a one-line URI: it never goes into
    # the base64 list, only onto the page (QR / copy).
    if with_wireguard and legacy.get("wireguard"):
        links["wireguard"] = legacy["wireguard"]
    return links


@app.get("/sub/{user_uuid}", response_class=HTMLResponse)
async def subscription_page(
    user_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
):
    """Serve the public user subscription page.

    Inactive / disabled users get a 404 — same gate as /sub-api and
    /sub-json. Without this an attacker with a leaked UUID could
    still read the configs of a disabled account from the HTML page.
    """
    try:
        user = await _subscription_user(user_uuid, db)
        if not user.active:
            raise HTTPException(status_code=404, detail="Not found")
    except HTTPException:
        # Same page for "unknown link" and "disabled account": a human-readable
        # message without revealing which of the two it is.
        html = _jinja_env.get_template("sub_unavailable.html").render(
            dir=_detect_direction(request),
            csp_nonce=getattr(request.state, "csp_nonce", ""),
        )
        return HTMLResponse(content=html, status_code=404)
    links = await _subscription_links(user, request, db, with_wireguard=True)
    from .api.compat import _settings_state as _vmess_state
    from .api.users import build_import_uri

    mobile_profile = await build_import_uri(request, db, role="subscriber", uuid=user.uuid)
    template = _jinja_env.get_template("sub.html")
    html = template.render(
        mobile_profile=mobile_profile,
        dir=_detect_direction(request),
        request={"url_root": str(request.base_url)},
        user=_subscription_user_dict(user),
        **_subscription_state(user),
        links=links,
        live_up=0,
        live_down=0,
        online_ips=[],
        server_ip=_public_server_ip(request),
        # The VMess connection the details card describes (not the panel's port).
        server_port=_vmess_state.get("vmess_port") or 443,
        sni_host=_vmess_state.get("vmess_sni") or "",
        ws_path=_vmess_state.get("vmess_ws_path") or "/api/v1/stream",
        settings=settings,
        apk_available=os.path.isfile(os.path.join(os.getcwd(), "static", "downloads", "app-release.apk")),
        csp_nonce=getattr(request.state, "csp_nonce", ""),
    )
    return HTMLResponse(content=html)


def _subscription_userinfo_header(user: VpnUser) -> str:
    """Build the standard Subscription-Userinfo header value.

    Clients (v2rayN/NekoBox/V7L app) read this to render traffic and expiry.
    `expire` is a Unix timestamp in seconds; omitted (0) when the user never
    expires.
    """
    expire_ts = 0
    if user.expire_at is not None:
        try:
            expire_ts = int(user.expire_at.timestamp())
        except (OSError, OverflowError, ValueError):
            expire_ts = 0
    return (
        f"upload=0; download={int(user.traffic_used or 0)}; "
        f"total={int(user.traffic_limit or 0)}; expire={expire_ts}"
    )


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
    # dict.fromkeys: protocol variants (e.g. an _ipv6 twin) can resolve to the
    # same URI — clients key their server list on it, duplicates break import.
    encoded = base64.b64encode("\n".join(dict.fromkeys(links.values())).encode()).decode()
    return Response(
        content=encoded,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": "inline; filename={}.txt".format(
                re.sub(r"[^\w\-.]", "_", user.name)
            ),
            "Profile-Update-Interval": "6",
            "Subscription-Userinfo": _subscription_userinfo_header(user),
        },
    )


@app.get("/sub-info/{user_uuid}")
async def subscription_info(
    user_uuid: str,
    request: Request,
    db: AsyncSession = Depends(get_async_db),
):
    """Return public JSON user metadata (name, traffic, expiry, links).

    The V7L mobile client queries this first to render the traffic gauge and
    expiry. It reuses the same shape as /api/users so the client's UserDto
    deserializes it unchanged.
    """
    from .api.compat import _user_to_legacy

    user = await _subscription_user(user_uuid, db)
    if not user.active:
        raise HTTPException(status_code=404, detail="Not found")
    server_ip = _public_server_ip(request)
    data = _user_to_legacy(user, server_ip=server_ip)
    # The mobile client's UserDto types `online_ips` as an integer count,
    # whereas the legacy panel shape returns a list. Normalise to the count
    # so strict client-side deserialization succeeds.
    data["online_ips"] = int(data.get("online_ip_count") or 0)
    return JSONResponse(content=data)


def _subscription_json_config(
    user: VpnUser,
    server_ip: str,
    panel_settings: dict,
    protocol_rank: dict | None = None,
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

    # Xray removed allowInsecure: say how to verify our certificate instead
    # (pin a self-signed one, or check a public one against the name it was
    # issued for). CDN outbounds see the CDN's public certificate: nothing to add.
    from .tls_trust import load_cert_info, trust_for

    _cert = load_cert_info()

    def _tls(server_name: str, ours: bool = True) -> dict:
        ts = {"serverName": server_name, "fingerprint": fp}
        if ours:
            t = trust_for(server_name, _actual_server, _cert)
            if t.pcs:
                ts["pinnedPeerCertSha256"] = t.pcs
            if t.vcn:
                ts["verifyPeerCertByName"] = t.vcn
        return ts

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
            "tlsSettings": _tls(sni),
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
                    "serverName": panel_settings.get("reality_sni") or "chat.deepseek.com",
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
                "tlsSettings": _tls(cdn_domain, ours=False),
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
                "tlsSettings": _tls(sni),
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
                "tlsSettings": _tls(sni),
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
                "tlsSettings": _tls(sni),
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
                "tlsSettings": _tls(sni),
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
                    # No Vision flow: it only runs over raw TCP, not XHTTP.
                    "users": [{"id": uid, "encryption": "none"}],
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
                    "serverName": rev_reality_sni,
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
                "tlsSettings": _tls(trojan_cdn_sni, ours=False),
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
                "tlsSettings": _tls(trojan_cdn_sni, ours=False),
            },
        })

    # ShadowSocks 2022
    if panel_settings.get("ss2022_enabled") and panel_settings.get("ss2022_server_key"):
        from .protocol_engine import ss2022_user_key

        ss_method = panel_settings.get("ss2022_method") or "2022-blake3-aes-128-gcm"
        outbounds.append({
            "tag": f"{prefix}-SS2022-{user.name}",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": server_ip,
                    "port": int(panel_settings.get("ss2022_port") or 2056),
                    "method": ss_method,
                    "password": panel_settings.get("ss2022_server_key") + ":" + ss2022_user_key(uid, ss_method),
                }],
            },
        })

    if protocol_rank:
        # The first outbound is the client's default route: put the protocol
        # that probes in Iran show working best there.
        from .api.ops import rank_sort_key

        head, tail = f"{prefix}-", f"-{user.name}"

        def _proto(tag: str) -> str | None:
            if tag.startswith(head) and tag.endswith(tail):
                return _SUB_OUTBOUND_PROTOCOLS.get(tag[len(head):len(tag) - len(tail)])
            return None

        outbounds = [o for _, o in sorted(
            enumerate(outbounds), key=lambda io: rank_sort_key(_proto(io[1].get("tag", "")), protocol_rank, io[0])
        )]

    # Fragment and noise live on a freedom outbound that every proxy dials
    # through (sockopt.dialerProxy). Xray has no sockopt.fragment: settings
    # written there are ignored and the ClientHello goes out whole.
    fragment_outbound = None
    if panel_settings.get("fragment_enabled") or panel_settings.get("noise_enabled"):
        frag_settings: dict = {}
        if panel_settings.get("fragment_enabled"):
            frag_settings["fragment"] = {
                "packets": panel_settings.get("fragment_packets") or "tlshello",
                "length": panel_settings.get("fragment_length") or "100-200",
                "interval": panel_settings.get("fragment_interval") or "10-20",
            }
        if panel_settings.get("noise_enabled"):
            # "rand:50-100" is type:packet. Xray sends noise ahead of UDP only.
            ntype, sep, npacket = (panel_settings.get("noise_packet") or "rand:50-100").partition(":")
            if not sep:
                ntype, npacket = "rand", ntype
            frag_settings["noises"] = [{
                "type": ntype,
                "packet": npacket,
                "delay": panel_settings.get("noise_delay") or "10-20",
            }]
        fragment_outbound = {"tag": "fragment", "protocol": "freedom", "settings": frag_settings}
        for outbound in outbounds:
            outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = "fragment"

    if panel_settings.get("mux_enabled"):
        for outbound in outbounds:
            # Xray cannot mux a Vision-flow connection, and Mux.Cool over
            # XHTTP (which multiplexes itself) fails outright.
            if any(u.get("flow") for v in outbound.get("settings", {}).get("vnext", []) for u in v.get("users", [])):
                continue
            if outbound.get("streamSettings", {}).get("network") == "xhttp":
                continue
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

        # TCP Keepalive (Xray takes idle/interval seconds; it has no
        # boolean tcpKeepAlive field and would silently ignore one)
        if panel_settings.get("dpi_tcp_keepalive"):
            sockopt = ss.setdefault("sockopt", {})
            sockopt["tcpKeepAliveIdle"] = 30
            sockopt["tcpKeepAliveInterval"] = 15

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

    if fragment_outbound:
        # With dialerProxy this outbound opens the real socket, so the
        # keepalive has to be set here too.
        if panel_settings.get("dpi_tcp_keepalive"):
            fragment_outbound["streamSettings"] = {"sockopt": {"tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15}}
        outbounds.append(fragment_outbound)
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
    rank = None
    if panel_settings.get("auto_protocol_order_enabled", True):
        from .api.ops import protocol_rank

        rank = await protocol_rank(db)
    return JSONResponse(
        content=_subscription_json_config(user, _public_server_ip(request), panel_settings, rank),
        headers={"Content-Disposition": "inline; filename={}.json".format(
            re.sub(r"[^\w\-.]", "_", user.name)
        )},
    )


async def _profile_inputs(user_uuid: str, request: Request, db: AsyncSession):
    from .api.compat import _settings_state
    from .tls_trust import load_cert_info

    user = await _subscription_user(user_uuid, db)
    if not user.active:
        raise HTTPException(status_code=404, detail="Not found")
    links = await _subscription_links(user, request, db)
    cert = load_cert_info()
    return user, links, dict(_settings_state), cert


def _profile_headers(user: VpnUser, ext: str) -> dict:
    return {
        "Content-Disposition": "inline; filename={}.{}".format(re.sub(r"[^\w\-.]", "_", user.name), ext),
        "Profile-Update-Interval": "6",
        "Subscription-Userinfo": _subscription_userinfo_header(user),
    }


@app.get("/sub-singbox/{user_uuid}")
async def subscription_singbox(user_uuid: str, request: Request, db: AsyncSession = Depends(get_async_db)):
    """sing-box profile (Hiddify, NekoBox, sing-box apps), incl. ShadowTLS."""
    from .client_profiles import singbox_profile

    user, links, state, cert = await _profile_inputs(user_uuid, request, db)
    # Without a publicly trusted certificate Naive runs on its own short-lived
    # one (standalone_engines.naive_certificate); the profile trusts exactly it.
    cert_pem = state.get("naive_cert_pem", "") if (cert is None or cert.self_signed) else ""
    profile = singbox_profile(user, _public_server_ip(request), links, state,
                              cert.spki_sha256 if cert else "", cert_pem)
    return JSONResponse(content=profile, headers=_profile_headers(user, "json"))


@app.get("/sub-clash/{user_uuid}")
async def subscription_clash(user_uuid: str, request: Request, db: AsyncSession = Depends(get_async_db)):
    """Clash Meta / mihomo profile, incl. ShadowTLS and Mieru. JSON is valid YAML."""
    from .client_profiles import clash_profile

    user, links, state, cert = await _profile_inputs(user_uuid, request, db)
    profile = clash_profile(user, _public_server_ip(request), links, state, cert.sha256 if cert else "")
    return Response(content=json.dumps(profile, indent=2, ensure_ascii=False),
                    media_type="text/yaml; charset=utf-8", headers=_profile_headers(user, "yaml"))


def _generate_xray_server_config(panel_settings: dict) -> dict:
    """Generate the server-side Xray config with inbounds for all enabled protocols.

    NOTE: Currently unused. The canonical implementation lives in
    app/api/compat.py — the runtime path at line ~1247 explicitly imports it
    via `from .api.compat import _generate_xray_server_config as _gen`. This
    copy is kept temporarily so the in-progress WS+TLS migration retains a
    second reference for diffing; it can be deleted once the migration ships.
    """
    inbounds = []
    sni = panel_settings.get("vmess_sni") or "www.aparat.com"
    fp = panel_settings.get("fingerprint") or "chrome"
    reality_pk = panel_settings.get("reality_private_key") or settings.reality_private_key
    panel_settings.get("reality_public_key") or settings.reality_public_key
    reality_sid = panel_settings.get("reality_short_id") or ""
    # IPv6 dual-stack: "::" accepts both v4+v6 on Linux (IPV6_V6ONLY=false)
    listen_addr = "::" if panel_settings.get("ipv6_enabled") else "0.0.0.0"

    # VMess WS+TLS (always-on)
    inbounds.append({
        "tag": "in-vmess-ws",
        "port": int(panel_settings.get("vmess_port") or 443),
        "listen": listen_addr,
        "protocol": "vmess",
        "settings": {"clients": []},
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "wsSettings": {"path": panel_settings.get("vmess_ws_path") or "/api/v1/stream"},
            "tlsSettings": {
                "serverName": sni,
                "certificates": [{"certificateFile": settings.tls_cert_file,
                                   "keyFile": settings.tls_key_file}],
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
            "listen": listen_addr,
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
        xhttp_port = raw_xhttp_port if raw_xhttp_port and raw_xhttp_port != vless_port_val else 8449
        inbounds.append({
            "tag": "in-vless-xhttp",
            "port": xhttp_port,
            "listen": listen_addr,
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
            "listen": listen_addr,
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
            "listen": listen_addr,
            "protocol": "trojan",
            "settings": {"clients": []},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": settings.tls_cert_file,
                                       "keyFile": settings.tls_key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # gRPC
    if panel_settings.get("grpc_enabled"):
        inbounds.append({
            "tag": "in-grpc",
            "port": int(panel_settings.get("grpc_port") or 2054),
            "listen": listen_addr,
            "protocol": "vmess",
            "settings": {"clients": []},
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "grpcSettings": {"serviceName": panel_settings.get("grpc_service_name") or "GunService"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": settings.tls_cert_file,
                                       "keyFile": settings.tls_key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # HTTPUpgrade
    if panel_settings.get("httpupgrade_enabled"):
        inbounds.append({
            "tag": "in-httpupgrade",
            "port": int(panel_settings.get("httpupgrade_port") or 2055),
            "listen": listen_addr,
            "protocol": "vmess",
            "settings": {"clients": []},
            "streamSettings": {
                "network": "httpupgrade",
                "security": "tls",
                "httpupgradeSettings": {"path": panel_settings.get("httpupgrade_path") or "/httpupgrade"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": settings.tls_cert_file,
                                       "keyFile": settings.tls_key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS WS+TLS
    if panel_settings.get("vless_ws_enabled"):
        inbounds.append({
            "tag": "in-vless-ws",
            "port": int(panel_settings.get("vless_ws_port") or 2057),
            "listen": listen_addr,
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": panel_settings.get("vless_ws_path") or "/vless-ws"},
                "tlsSettings": {
                    "serverName": sni,
                    "certificates": [{"certificateFile": settings.tls_cert_file,
                                       "keyFile": settings.tls_key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # VLESS WS+TLS Domain Fronting — TLS with spoofed SNI
    # Client connects directly to our server with TLS, SNI shows a trusted domain
    # (e.g. chat.deepseek.com) to bypass DPI. Server terminates TLS with its own cert.
    if panel_settings.get("vless_ws_plain_front_enabled"):
        _front_host = panel_settings.get("vless_ws_plain_front_domain") or "chat.deepseek.com"
        _front_port = int(panel_settings.get("vless_ws_plain_front_port") or 2052)
        inbounds.append({
            "tag": "in-vless-ws-plain",
            "port": _front_port,
            "listen": listen_addr,
            "protocol": "vless",
            "settings": {"clients": [], "decryption": "none"},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "path": panel_settings.get("vless_ws_plain_front_path") or "/",
                },
                "tlsSettings": {
                    "serverName": _front_host,
                    "certificates": [{"certificateFile": settings.tls_cert_file,
                                       "keyFile": settings.tls_key_file}],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        })

    # ShadowSocks 2022
    if panel_settings.get("ss2022_enabled") and panel_settings.get("ss2022_server_key"):
        inbounds.append({
            "tag": "in-ss2022",
            "port": int(panel_settings.get("ss2022_port") or 2056),
            "listen": listen_addr,
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
                    "certificates": [{"certificateFile": settings.tls_cert_file,
                                       "keyFile": settings.tls_key_file}],
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
            "listen": listen_addr,
            "protocol": "vmess",
            "settings": {"clients": []},
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {"path": panel_settings.get("cdn_ws_path") or "/cdn-ws"},
                "tlsSettings": {
                    "serverName": cdn_domain,
                    "certificates": [{"certificateFile": settings.tls_cert_file,
                                       "keyFile": settings.tls_key_file}],
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

    await _load_legacy_settings(db)

    # Fetch active users for client authentication (in async context)
    # Same config the live user sync works from (Vision flow, SS-2022 keys,
    # speed-limit outbounds): app/user_runtime.py.
    from .user_runtime import _desired_xray_config

    config, n_users = await _desired_xray_config(db)
    vmess_clients = [None] * n_users

    try:
        installed = await helper_request(
            "config.install",
            {"target": "xray", "content": json.dumps(config, indent=2)},
        )
        if not installed.ok:
            raise RuntimeError(installed.message or "config install failed")
        restarted = await helper_request("service.restart", {"service": "xray"}, timeout=35)
        if not restarted.ok:
            raise RuntimeError(restarted.message or "Xray restart failed")
        n_clients = len(vmess_clients)
        n_inbounds = len(config.get("inbounds", []))
        logger.info(f"Xray config synced: {n_inbounds} inbounds, {n_clients} clients")
        return {"ok": True, "message": f"Xray config applied: {n_inbounds} inbounds, {n_clients} clients"}
    except (PrivilegedHelperError, RuntimeError) as e:
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
