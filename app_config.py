"""
DEPRECATED: This module is a compatibility shim and will be removed in
the next major release.

The real implementation lives in `app/config.py` (FastAPI v2). This
file exists only so that operators with custom tooling importing
`app_config` at the repo root still get a working settings object
until they migrate.

What changed:
- Old:    `from app_config import settings`     (root module)
- New:    `from app.config import settings`     (package module)

Migration:
    sed -i 's/from app_config import settings/from app.config import settings/' \\
        your_script.py

Do NOT add new code that imports from this module.
"""

from __future__ import annotations

import logging
import sys
import warnings
from pathlib import Path

warnings.warn(
    "importing from the root-level `app_config` is deprecated and will be "
    "removed in a future release. Use `from app.config import settings` "
    "instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export the live `Settings` object so any code that did
# `from app_config import settings` keeps working — but operators who
# have rotated SECRET_KEY in their environment will see those values,
# not whatever used to live in this file.
try:
    _project_root = str(Path(__file__).resolve().parent)
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)
    from app.config import settings  # noqa: E402,F401
except Exception as _exc:  # noqa: BLE001
    # A deprecated import that breaks production is worse than a
    # deprecated import that fails. Log and synthesize a minimal
    # stand-in so legacy code at least parses.
    logging.getLogger(__name__).error(
        "could not import app.config (%s); legacy app_config will be empty", _exc
    )

    class _Empty:
        def __getattr__(self, _name):
            return None

    settings = _Empty()  # type: ignore[assignment]
