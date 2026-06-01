"""
DEPRECATED: This module is a compatibility shim and will be removed in
the next major release.

The real SQLAlchemy models live in `app/models.py`. This shim re-exports
them so legacy scripts that did `from models import Base, VpnUser, ...`
keep working until the operator migrates.

Migration:
    sed -i 's/^from models /from app.models /' your_script.py
"""

from __future__ import annotations

import warnings as _warnings

_warnings.warn(
    "importing from the root-level `models` is deprecated and will be removed "
    "in a future release. Use `from app.models import ...` instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export every public name from app.models so legacy code that did
# `from models import Base, VpnUser, ...` still works. The v1 module
# also exposed `init_db` — that helper now lives in `app.database`,
# which is where the v2 entrypoint calls it. We re-export it here so
# legacy scripts that ran `init_db()` keep working.
from app.models import *  # noqa: E402,F401,F403
from app.models import Base  # noqa: E402,F401
from app.database import init_db  # noqa: E402,F401
