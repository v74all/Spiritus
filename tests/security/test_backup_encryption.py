import asyncio
import os
import stat
import uuid

import pytest
from fastapi.testclient import TestClient

import app.api.compat.tools as compat
from app.auth import create_access_token, get_password_hash
from app.backup_crypto import BackupDecryptionError, decrypt_backup, encrypt_backup
from app.database import AsyncSessionLocal, init_db
from app.main import app
from app.models import Admin, UserRole


def test_roundtrip_and_tamper_detection():
    blob = encrypt_backup(b'{"users": []}')
    assert b"users" not in blob
    assert decrypt_backup(blob) == b'{"users": []}'
    with pytest.raises(BackupDecryptionError):
        decrypt_backup(blob[:-4] + b"AAAA")


@pytest.fixture
def admin_headers():
    async def _setup():
        await init_db()
        async with AsyncSessionLocal() as db:
            name = f"bk-{uuid.uuid4().hex[:8]}"
            db.add(Admin(username=name, password_hash=get_password_hash("Sup3rStrong!Pass-1"), role=UserRole.admin))
            await db.commit()
            return name

    name = asyncio.run(_setup())
    return {"Authorization": "Bearer " + create_access_token({"sub": name, "is_admin": True})}


def test_backup_is_encrypted_private_and_restorable(tmp_path, monkeypatch, admin_headers):
    monkeypatch.setattr(compat, "_BACKUP_DIR", str(tmp_path / "backups"))
    with TestClient(app) as client:
        created = client.post("/api/backup/create", headers=admin_headers)
        assert created.status_code == 200, created.text
        name = created.json()["name"]
        assert name.endswith(".json.enc")

        path = tmp_path / "backups" / name
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
        assert b'"users"' not in path.read_bytes()

        restored = client.post("/api/backup/restore", json={"name": name}, headers=admin_headers)
        assert restored.status_code == 200, restored.text

        # A flipped byte must be rejected rather than half-restored.
        data = bytearray(path.read_bytes())
        data[-5] ^= 0xFF
        path.write_bytes(bytes(data))
        bad = client.post("/api/backup/restore", json={"name": name}, headers=admin_headers)
        assert bad.status_code == 400


@pytest.mark.parametrize("name", ["../etc/passwd", "backup-1.json", "x/backup-20260101-000000.json", ""])
def test_restore_rejects_bad_names(name, admin_headers):
    with TestClient(app) as client:
        r = client.post("/api/backup/restore", json={"name": name}, headers=admin_headers)
        assert r.status_code == 400
