"""Centralised UTC time helpers.

The DB schema stores datetimes as tz-naive (Column(DateTime) without
timezone=True), so all writes/reads/comparisons must be naive UTC.
Using datetime.utcnow() works but is deprecated in 3.12+; this helper
returns the same value via the non-deprecated path.

If/when the schema is migrated to TIMESTAMPTZ, switch the body to
`datetime.now(timezone.utc)` and audit all callers.
"""

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return current UTC time as a tz-naive datetime (DB-compatible)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
