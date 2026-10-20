"""Saving legacy settings must survive concurrent loads.

_load_legacy_settings rebuilds the shared _settings_state from the DB on
every call (the panel polls it). A save that serialised that shared dict
after an await could write back whatever a concurrent load had just put
there, silently dropping the update.
"""

import asyncio

from app.api.compat._core import _load_legacy_settings, _save_legacy_settings
from app.database import AsyncSessionLocal, init_db


async def _load_once():
    async with AsyncSessionLocal() as db:
        await _load_legacy_settings(db)


async def _save(values):
    async with AsyncSessionLocal() as db:
        await _save_legacy_settings(db, values)


def test_save_is_not_clobbered_by_concurrent_loads(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # keep the settings-file mirror out of the repo

    async def go():
        await init_db()
        await _save({"race_marker": 0})
        for i in range(1, 30):
            await asyncio.gather(_save({"race_marker": i}), *(_load_once() for _ in range(8)))
            async with AsyncSessionLocal() as db:
                assert (await _load_legacy_settings(db))["race_marker"] == i

    asyncio.run(go())


def test_concurrent_saves_of_different_keys_both_persist(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    async def go():
        await init_db()
        for i in range(10):
            await asyncio.gather(_save({"race_a": i}), _save({"race_b": i}))
            async with AsyncSessionLocal() as db:
                s = await _load_legacy_settings(db)
            assert (s["race_a"], s["race_b"]) == (i, i)

    asyncio.run(go())
