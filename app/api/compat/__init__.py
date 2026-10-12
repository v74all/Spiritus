"""Legacy panel API (cookie-auth shape), split by area.

Route registration order matches the original single-module layout, which
matters for overlapping paths. Helpers live in ``_core`` and are re-exported
so ``from app.api.compat import _load_legacy_settings`` keeps working.
"""

from __future__ import annotations

from fastapi import APIRouter

from . import _core, agents, legacy_auth, legacy_users, monitor, panel_settings, tools
from ._core import *  # noqa: F403
from .agents import *  # noqa: F403
from .legacy_auth import *  # noqa: F403
from .legacy_users import *  # noqa: F403
from .monitor import *  # noqa: F403
from .panel_settings import *  # noqa: F403
from .tools import *  # noqa: F403

router = APIRouter(tags=["compat"])  # defined after the star imports, which each export a ``router``
for _module in (legacy_auth, legacy_users, monitor, panel_settings, tools, agents):
    router.include_router(_module.router)

