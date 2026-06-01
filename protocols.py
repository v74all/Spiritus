"""
DEPRECATED: This module is a compatibility shim and will be removed in
the next major release.

The real protocol engine lives in `app/protocol_engine.py`. This shim
re-exports the canonical protocol registry so legacy code that did
`from protocols import ...` keeps working.

Migration:
    sed -i 's/^from protocols /from app.protocol_engine /' your_script.py
"""

from __future__ import annotations

import warnings as _warnings

_warnings.warn(
    "importing from the root-level `protocols` is deprecated and will be "
    "removed in a future release. Use `from app.protocol_engine import ...` "
    "instead.",
    DeprecationWarning,
    stacklevel=2,
)

from app.protocol_engine import *  # noqa: E402,F401,F403
from app.protocol_engine import PROTOCOLS, ProtocolSpec, XrayConfigGenerator  # noqa: E402,F401


# Legacy name alias — `protocols.py` exposed `get_protocol_engine()`.
# Provide a minimal stub so old call sites that import it don't break.
def get_protocol_engine(*_args, **_kwargs):
    """Stub. The new entrypoint is `app.protocol_engine.PROTOCOLS`."""
    return {"protocols": PROTOCOLS, "config_generator": XrayConfigGenerator}
