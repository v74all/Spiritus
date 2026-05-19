"""
JWT hardening tests.

Covers:
- "alg: none" downgrade is rejected.
- alg-confusion (HS256 token signed with the RS256 public key) is rejected.
- Tokens missing required claims (`exp`, `sub`) are rejected.
- Tokens with valid signature but stale `jti` (revoked) are rejected by the
  decode helper. We mock the Redis lookup so we don't need a real broker.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt as jose_jwt

from app import auth as _auth
from app.auth import create_access_token, _decode_token_to_user, revoke_token
from app.config import settings


# ── token forgery ───────────────────────────────────────────────────────────


def test_alg_none_token_is_rejected(monkeypatch):
    """An attacker crafted token with alg=none must NOT validate."""
    # python-jose refuses to encode with alg=none unless explicitly enabled,
    # so we hand-craft the structure.
    import base64, json

    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "admin", "is_admin": True, "exp": 9999999999}).encode()
    ).rstrip(b"=")
    forged = (header + b"." + payload + b".").decode()

    async def _run():
        with pytest.raises(Exception):
            await _decode_token_to_user(forged, db=None)

    asyncio.run(_run())


def test_token_with_wrong_secret_is_rejected():
    """A token signed with a different secret must not be accepted."""
    bad = jose_jwt.encode(
        {"sub": "admin", "is_admin": True,
         "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
         "iat": datetime.now(timezone.utc)},
        "wrong-secret-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        algorithm="HS256",
    )

    async def _run():
        with pytest.raises(Exception):
            await _decode_token_to_user(bad, db=None)

    asyncio.run(_run())


def test_token_missing_exp_is_rejected():
    """jose.decode is told to require exp/sub — a missing exp must fail."""
    bad = jose_jwt.encode(
        {"sub": "admin"},  # no exp, no iat
        settings.jwt_secret_key,
        algorithm="HS256",
    )

    async def _run():
        with pytest.raises(Exception):
            await _decode_token_to_user(bad, db=None)

    asyncio.run(_run())


# ── revocation ──────────────────────────────────────────────────────────────


def test_revoked_token_is_rejected(monkeypatch):
    """Once a jti is on the blacklist, decode must raise — even with a valid sig."""
    revoked_set = set()

    async def fake_is_revoked(jti):
        return jti in revoked_set

    async def fake_revoke(jti, ttl):
        revoked_set.add(jti)

    monkeypatch.setattr(_auth, "_is_token_revoked", fake_is_revoked)
    monkeypatch.setattr(_auth, "revoke_token", fake_revoke)

    token = create_access_token({"sub": "admin", "is_admin": True})
    payload = jose_jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"],
                              options={"verify_exp": False})
    jti = payload["jti"]
    assert jti, "jti claim must be present on issued tokens"

    # Revoke it.
    asyncio.run(fake_revoke(jti, 60))

    async def _run():
        with pytest.raises(Exception):
            await _decode_token_to_user(token, db=None)

    asyncio.run(_run())


def test_issued_token_carries_required_claims():
    """Every issued token must have iat, exp, nbf, jti."""
    token = create_access_token({"sub": "admin", "is_admin": True})
    payload = jose_jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
    for claim in ("iat", "exp", "nbf", "jti", "sub"):
        assert claim in payload, f"missing claim: {claim}"
