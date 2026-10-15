"""The per-user dict the panel's config modal reads must carry every link
_build_share_links produces — a link built but not copied over shows up in
the UI as "Not configured"."""

import uuid

import pytest

from app.api.compat import _core
from app.models import VpnUser


@pytest.fixture
def standalone_protocols_on(monkeypatch):
    state = {
        "shadowtls_enabled": True,
        "naiveproxy_enabled": True,
        "mieru_enabled": True,
    }
    monkeypatch.setattr(_core, "_settings_state", state)
    return state


def test_sing_box_and_mieru_links_reach_the_user_dict(standalone_protocols_on):
    user = VpnUser(id=1, uuid=str(uuid.uuid4()), name="alice", active=True)

    legacy = _core._user_to_legacy(user, server_ip="203.0.113.7")

    assert legacy["shadowtls"].startswith("shadowtls://")
    assert legacy["naiveproxy"].startswith("naive+https://")
    assert legacy["mieru"].startswith("mieru://")
