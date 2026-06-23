"""
DEPRECATED: This module is a compatibility shim and will be removed in
the next major release.

The real entrypoint is `app.main:app` (the v2 FastAPI application,
which has CSRF middleware, the auth router, the DPI router, the
orchestrator, OpenTelemetry, Redis-backed rate limiting, etc.).

The file that used to live at this path was a stripped-down v1 of the
panel (no auth, no rate limiting, no DPI). It is preserved as
`main_legacy.py.bak` for reference but should NOT be the entrypoint
for any deployment.

What changed:
- Old:    `uvicorn main:app`            (root module)
- New:    `uvicorn app.main:app`        (package module)

Migration:
    # systemd unit ExecStart
    ExecStart=/opt/v7lthronyx/venv/bin/uvicorn app.main:app \\
        --host 127.0.0.1 --port 38471
"""

from __future__ import annotations

import warnings

warnings.warn(
    "the root-level `main` module is deprecated; use `app.main:app` instead. "
    "The legacy module is preserved as `main_legacy.py.bak`.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export the live v2 application so any tooling that did
# `uvicorn main:app` keeps working — but with all of v2's behaviour.
try:
    from app.main import app  # noqa: E402,F401
except Exception:  # noqa: BLE001
    # If app.main fails to import (e.g. SECRET_KEY missing on a
    # first-boot box), the operator gets the real traceback from the
    # subprocess that runs uvicorn — which is more useful than a
    # deprecation warning hiding it.
    raise
