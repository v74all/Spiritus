"""Tamper-evident audit log.

Every entry stores ``entry_hash = HMAC(key, prev_hash || canonical(entry))``.
Editing, deleting or re-ordering rows breaks the chain from that row onward,
and because the HMAC key derives from ``SECRET_KEY`` an attacker with only
database write access cannot recompute valid hashes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

from fastapi import Request
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .models import AuditLog
from .timeutil import utcnow

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64
_MAX_UA = 500


def _key() -> bytes:
    return hashlib.sha256(b"spiritus-audit-chain:" + settings.secret_key.encode()).digest()


def _canonical(
    *,
    action: str,
    admin_id: int | None,
    target_type: str | None,
    target_id: int | None,
    details: dict[str, Any],
    ip_address: str | None,
    user_agent: str | None,
    created_at: Any,
) -> bytes:
    created = created_at.replace(tzinfo=None).isoformat() if created_at else ""
    return json.dumps(
        [action, admin_id, target_type, target_id, details, ip_address, user_agent, created],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def compute_hash(prev_hash: str, canonical: bytes) -> str:
    return hmac.new(_key(), prev_hash.encode() + b"|" + canonical, hashlib.sha256).hexdigest()


def client_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    return request.client.host


async def record_audit(
    db: AsyncSession,
    action: str,
    *,
    admin_id: int | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditLog | None:
    """Append an entry to the chain. Never raises: auditing must not break the caller."""
    try:
        if request is not None:
            ip_address = ip_address or client_ip(request)
            user_agent = user_agent or request.headers.get("user-agent")
        if user_agent:
            user_agent = user_agent[:_MAX_UA]
        # Round-trip so the hashed value equals what the JSON column returns.
        clean_details = json.loads(json.dumps(details or {}, default=str))

        if db.get_bind().dialect.name == "postgresql":
            # Serialise writers so two concurrent inserts cannot fork the chain.
            await db.execute(text("SELECT pg_advisory_xact_lock(7461023)"))

        last = await db.execute(
            select(AuditLog.entry_hash)
            .where(AuditLog.entry_hash.is_not(None))
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
        prev_hash = last.scalar_one_or_none() or GENESIS_HASH
        created_at = utcnow()
        entry = AuditLog(
            admin_id=admin_id,
            action=action[:100],
            target_type=target_type,
            target_id=target_id,
            details=clean_details,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=created_at,
            prev_hash=prev_hash,
        )
        entry.entry_hash = compute_hash(
            prev_hash,
            _canonical(
                action=entry.action,
                admin_id=admin_id,
                target_type=target_type,
                target_id=target_id,
                details=clean_details,
                ip_address=ip_address,
                user_agent=user_agent,
                created_at=created_at,
            ),
        )
        db.add(entry)
        await db.commit()
        return entry
    except Exception:
        logger.exception("audit.record_failed action=%s", action)
        try:
            await db.rollback()
        except Exception:
            pass
        return None


async def verify_chain(db: AsyncSession, batch_size: int = 1000) -> dict[str, Any]:
    """Re-compute the whole chain. Returns ``{"ok": bool, "checked": n, "broken_at": id|None}``."""
    prev_hash = GENESIS_HASH
    checked = 0
    last_id = 0
    while True:
        rows = (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.entry_hash.is_not(None), AuditLog.id > last_id)
                .order_by(AuditLog.id)
                .limit(batch_size)
            )
        ).scalars().all()
        if not rows:
            return {"ok": True, "checked": checked, "broken_at": None}
        for row in rows:
            expected = compute_hash(
                row.prev_hash or "",
                _canonical(
                    action=row.action,
                    admin_id=row.admin_id,
                    target_type=row.target_type,
                    target_id=row.target_id,
                    details=row.details or {},
                    ip_address=row.ip_address,
                    user_agent=row.user_agent,
                    created_at=row.created_at,
                ),
            )
            if row.prev_hash != prev_hash or not hmac.compare_digest(expected, row.entry_hash):
                return {"ok": False, "checked": checked, "broken_at": row.id}
            prev_hash = row.entry_hash
            checked += 1
            last_id = row.id
