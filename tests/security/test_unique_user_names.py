"""Duplicate VPN user names broke every by-name action (toggle/renew/delete)."""

import asyncio
import uuid

from starlette.requests import Request

from app.api.compat.legacy_users import (
    BulkCreateRequest,
    LegacyUserCreate,
    legacy_bulk_users,
    legacy_create_user,
)
from app.database import AsyncSessionLocal, init_db
from app.models import VpnUser
from app.services.user_names import taken_vpn_user_names


def _request():
    return Request({"type": "http", "method": "POST", "path": "/api/users", "headers": [(b"host", b"panel.test")]})


def _run(coro_fn):
    async def go():
        await init_db()
        async with AsyncSessionLocal() as db:
            return await coro_fn(db)

    return asyncio.run(go())


def test_taken_names_reports_only_existing():
    name = f"dup-{uuid.uuid4().hex[:6]}"

    async def go(db):
        db.add(VpnUser(uuid=str(uuid.uuid4()), name=name, active=1))
        await db.commit()
        return await taken_vpn_user_names(db, [name, name + "-free"])

    assert _run(go) == {name}


def test_second_create_with_same_name_is_refused():
    name = f"dup-{uuid.uuid4().hex[:6]}"
    body = LegacyUserCreate(name=name, traffic=10, days=30)

    async def go(db):
        first = await legacy_create_user(body, _request(), admin=None, db=db)
        second = await legacy_create_user(body, _request(), admin=None, db=db)
        rows = (await db.execute(VpnUser.__table__.select().where(VpnUser.name == name))).all()
        return first, second, len(rows)

    first, second, rows = _run(go)
    assert first["ok"] is True
    assert second["ok"] is False and "already exists" in second["error"]
    assert rows == 1


def test_numbered_bulk_create_refuses_clashing_batch():
    prefix = f"bulk{uuid.uuid4().hex[:4]}"
    body = BulkCreateRequest(prefix=prefix, count=3, traffic=5, days=7, numbered=True, start=1, pad=2)

    async def go(db):
        first = await legacy_bulk_users(body, _request(), admin=None, db=db)
        second = await legacy_bulk_users(body, _request(), admin=None, db=db)
        rows = (await db.execute(VpnUser.__table__.select().where(VpnUser.name.like(prefix + "-%")))).all()
        return first, second, len(rows)

    first, second, rows = _run(go)
    assert first["ok"] is True
    assert second["ok"] is False and f"{prefix}-01" in second["error"]
    assert rows == 3
