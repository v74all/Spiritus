"""`install.sh reset-password` / `python -m app.reset_password`: offline admin recovery."""

import asyncio
import uuid

import fakeredis
import pytest
from sqlalchemy import select

import app.redis_client as redis_client
from app.auth import get_password_hash, validate_password_strength, verify_password
from app.database import AsyncSessionLocal, init_db
from app.models import Admin, AuditLog, UserRole
from app.reset_password import generate_password, reset_admin_password

OLD_PASSWORD = "Sup3rStrong!Pass-1"


@pytest.fixture
def fake_redis(monkeypatch):
    server = fakeredis.FakeServer()

    async def _get():
        return fakeredis.FakeAsyncRedis(server=server, decode_responses=True)

    monkeypatch.setattr(redis_client, "get_redis", _get)
    return server


def _make_admin(totp: bool = False) -> str:
    async def _setup():
        await init_db()
        async with AsyncSessionLocal() as db:
            name = f"reset-{uuid.uuid4().hex[:8]}"
            db.add(Admin(
                username=name,
                password_hash=get_password_hash(OLD_PASSWORD),
                role=UserRole.superadmin,
                totp_enabled=totp,
                totp_secret="JBSWY3DPEHPK3PXP" if totp else None,
            ))
            await db.commit()
            return name

    return asyncio.run(_setup())


async def _load(name: str) -> Admin:
    async with AsyncSessionLocal() as db:
        return (await db.execute(select(Admin).where(Admin.username == name))).scalar_one()


def test_generated_passwords_pass_the_strength_check():
    for _ in range(200):
        assert validate_password_strength(generate_password()) is None


def test_reset_sets_a_working_password_and_logs_out_sessions(fake_redis):
    name = _make_admin()

    code, new_pw = asyncio.run(reset_admin_password(name, disable_2fa=False))

    assert code == 0 and new_pw
    admin = asyncio.run(_load(name))
    assert verify_password(new_pw, admin.password_hash)
    assert not verify_password(OLD_PASSWORD, admin.password_hash)

    async def _epoch():
        redis = await redis_client.get_redis()
        return await redis.get(f"pwd_epoch:{name}")

    assert asyncio.run(_epoch()) is not None

    async def _audited():
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(
                select(AuditLog).where(AuditLog.action == "password_reset_cli",
                                       AuditLog.admin_id == admin.id)
            )).scalars().all()
            return len(rows)

    assert asyncio.run(_audited()) == 1


def test_reset_keeps_2fa_unless_asked_to_disable_it(fake_redis):
    name = _make_admin(totp=True)

    asyncio.run(reset_admin_password(name, disable_2fa=False))
    assert asyncio.run(_load(name)).totp_enabled is True

    asyncio.run(reset_admin_password(name, disable_2fa=True))
    admin = asyncio.run(_load(name))
    assert admin.totp_enabled is False
    assert admin.totp_secret is None


def test_unknown_or_ambiguous_username_changes_nothing(fake_redis):
    name = _make_admin()
    _make_admin()  # at least two admins now exist
    before = asyncio.run(_load(name)).password_hash

    assert asyncio.run(reset_admin_password("no-such-admin", disable_2fa=False)) == (2, None)
    assert asyncio.run(reset_admin_password(None, disable_2fa=False)) == (2, None)
    assert asyncio.run(_load(name)).password_hash == before
