"""Authenticated encryption for panel backups (Fernet: AES-128-CBC + HMAC-SHA256).

The key comes from ``BACKUP_ENCRYPTION_KEY`` when set, otherwise it is derived
from ``SECRET_KEY`` with HKDF. Use a dedicated key in production: rotating
``SECRET_KEY`` would otherwise make existing backups undecryptable.
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import settings

ENCRYPTED_SUFFIX = ".enc"


class BackupDecryptionError(ValueError):
    pass


def _fernet() -> Fernet:
    material = (settings.backup_encryption_key or settings.secret_key).encode()
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"spiritus-backup-v1",
        info=b"backup-encryption",
    ).derive(material)
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_backup(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt_backup(token: bytes) -> bytes:
    try:
        return _fernet().decrypt(token)
    except InvalidToken as exc:
        raise BackupDecryptionError("backup is corrupt or the encryption key changed") from exc
