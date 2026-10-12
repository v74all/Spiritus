"""
DEPRECATED: This module is a compatibility shim and will be removed in
the next major release.

The real security primitives (Argon2 password hashing, JWT issuance
and validation, TOTP, password policy) live in `app/auth.py`. The
`app/security.py` module covers the WebAuthn / mTLS / fail2ban side
of things. The file that used to live at this path was a v1 module
that did `from app_config import settings` — it was imported by
zero production modules and zero tests after the v2 refactor.

This shim re-exports the public names so legacy scripts that did
`from security import hash_password, verify_password, ...` keep
working.

Migration:
    sed -i 's/^from security /from app.auth /' your_script.py
"""

from __future__ import annotations

import warnings as _warnings

_warnings.warn(
    "importing from the root-level `security` is deprecated and will be "
    "removed in a future release. Use `from app.auth import ...` for "
    "password/JWT/TOTP helpers, or `from app.security import ...` for "
    "WebAuthn/mTLS/fail2ban.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export the password/JWT/TOTP helpers from app.auth.
from app.auth import (  # noqa: E402,F401
    create_access_token,
    generate_totp_secret,
    get_password_hash,
    get_totp_uri,
    verify_password,
    verify_totp,
)
