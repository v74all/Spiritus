import asyncio
import re
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.database import AsyncSessionLocal, init_db
from app.main import _subscription_state, app
from app.models import VpnUser
from app.timeutil import utcnow

GB = 1024**3


def _mk(**kw):
    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            u = VpnUser(uuid=str(uuid.uuid4()), name="sara", active=kw.pop("active", 1), **kw)
            db.add(u)
            await db.commit()
            return u.uuid

    return asyncio.run(go())


@pytest.mark.parametrize(
    ("kw", "state"),
    [
        ({"traffic_limit": 10 * GB, "traffic_used": GB}, "ok"),
        ({}, "ok"),  # unlimited traffic, no expiry
        ({"expire_at": utcnow() - timedelta(days=1)}, "expired"),
        ({"traffic_limit": GB, "traffic_used": GB}, "limit"),
        ({"expire_at": utcnow() + timedelta(days=2)}, "expiring"),
        ({"traffic_limit": 10 * GB, "traffic_used": 9 * GB + GB // 2}, "low_traffic"),
    ],
)
def test_state_classification(kw, state):
    assert _subscription_state(VpnUser(**kw))["state"] == state


def test_page_is_plain_language_and_localised():
    uid = _mk(traffic_limit=10 * GB, traffic_used=GB, expire_at=utcnow() + timedelta(days=20))
    with TestClient(app) as client:
        en = client.get(f"/sub/{uid}", headers={"Accept-Language": "en"})
        assert en.status_code == 200
        assert "Connect in 3 steps" in en.text and "Your subscription is active" in en.text
        assert "hiddify://import/" in en.text and "Troubleshooting" in en.text
        fa = client.get(f"/sub/{uid}", headers={"Accept-Language": "fa"})
        assert "اتصال در ۳ قدم" in fa.text and "اشتراک شما فعال است" in fa.text
        assert 'dir="rtl"' in fa.text


def test_unlimited_account_is_not_shown_as_zero_gb():
    uid = _mk()
    with TestClient(app) as client:
        html = client.get(f"/sub/{uid}", headers={"Accept-Language": "en"}).text
        assert "Unlimited" in html and "No traffic limit" in html


def test_expired_account_gets_clear_banner():
    uid = _mk(expire_at=utcnow() - timedelta(days=2))
    with TestClient(app) as client:
        assert "Your subscription has expired" in client.get(f"/sub/{uid}", headers={"Accept-Language": "en"}).text


def test_unknown_and_disabled_links_get_identical_friendly_404():
    disabled = _mk(active=0)
    with TestClient(app) as client:
        a = client.get(f"/sub/{disabled}", headers={"Accept-Language": "en"})
        b = client.get(f"/sub/{uuid.uuid4()}", headers={"Accept-Language": "en"})
        assert a.status_code == b.status_code == 404
        strip = lambda t: re.sub(r'nonce="[^"]+"', '', t)  # noqa: E731 - per-request CSP nonce
        assert strip(a.text) == strip(b.text)  # no oracle for which case it is
        assert "not available" in a.text
