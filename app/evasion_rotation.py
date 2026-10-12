"""uTLS fingerprint rotation and automatic protocol failover.

Both classes are in-memory, dependency-free and driven by explicit reports
(``mark_flagged`` / ``report``) so they can be fed from probes, user reports or
the DPI health checks.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable, Sequence

# Fingerprints understood by Xray/sing-box uTLS.
UTLS_FINGERPRINTS: tuple[str, ...] = ("chrome", "firefox", "safari", "edge", "ios", "android")

DEFAULT_PROTOCOL_ORDER: tuple[str, ...] = (
    "vless_vision_reality",
    "vless_xhttp_reality",
    "hysteria2",
    "tuic",
    "trojan_cdn",
    "vless_ws_tls",
)


class FingerprintRotator:
    def __init__(
        self,
        pool: Sequence[str] = UTLS_FINGERPRINTS,
        interval_seconds: int = 3600,
        flag_cooldown_seconds: int = 6 * 3600,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not pool:
            raise ValueError("fingerprint pool must not be empty")
        self._pool = tuple(pool)
        self._interval = interval_seconds
        self._cooldown = flag_cooldown_seconds
        self._clock = clock
        self._current: str | None = None
        self._rotated_at = 0.0
        self._flagged: dict[str, float] = {}

    def _available(self) -> list[str]:
        now = self._clock()
        self._flagged = {fp: t for fp, t in self._flagged.items() if now - t < self._cooldown}
        return [fp for fp in self._pool if fp not in self._flagged]

    def rotate(self) -> str:
        """Pick a new fingerprint (CSPRNG), avoiding the current and flagged ones."""
        candidates = [fp for fp in self._available() if fp != self._current]
        if not candidates:
            candidates = self._available() or list(self._pool)
        self._current = secrets.choice(candidates)
        self._rotated_at = self._clock()
        return self._current

    def current(self) -> str:
        """Current fingerprint, rotating when the interval elapsed or it was flagged."""
        due = self._current is None or self._clock() - self._rotated_at >= self._interval
        if due or self._current in self._flagged:
            return self.rotate()
        return self._current  # type: ignore[return-value]

    def mark_flagged(self, fingerprint: str) -> None:
        """Quarantine a fingerprint that appears to be blocked/fingerprinted."""
        if fingerprint in self._pool:
            self._flagged[fingerprint] = self._clock()

    def status(self) -> dict[str, object]:
        return {
            "current": self._current,
            "flagged": sorted(self._flagged),
            "pool": list(self._pool),
            "interval_seconds": self._interval,
        }


class ProtocolRotator:
    """Fail over to the next protocol after repeated failures; retry after a cooldown."""

    def __init__(
        self,
        order: Sequence[str] = DEFAULT_PROTOCOL_ORDER,
        failure_threshold: int = 3,
        cooldown_seconds: int = 900,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not order:
            raise ValueError("protocol order must not be empty")
        self._order = tuple(order)
        self._threshold = failure_threshold
        self._cooldown = cooldown_seconds
        self._clock = clock
        self._failures: dict[str, int] = {}
        self._blocked_at: dict[str, float] = {}

    def report(self, protocol: str, ok: bool) -> None:
        if protocol not in self._order:
            return
        if ok:
            self._failures[protocol] = 0
            self._blocked_at.pop(protocol, None)
            return
        self._failures[protocol] = self._failures.get(protocol, 0) + 1
        if self._failures[protocol] >= self._threshold:
            self._blocked_at[protocol] = self._clock()

    def is_blocked(self, protocol: str) -> bool:
        blocked_at = self._blocked_at.get(protocol)
        if blocked_at is None:
            return False
        if self._clock() - blocked_at >= self._cooldown:
            # Half-open: allow one more attempt before blocking again.
            self._blocked_at.pop(protocol)
            self._failures[protocol] = self._threshold - 1
            return False
        return True

    def next_protocol(self) -> str | None:
        """Highest-priority protocol that is not currently blocked (None if all are)."""
        for protocol in self._order:
            if not self.is_blocked(protocol):
                return protocol
        return None

    def status(self) -> dict[str, object]:
        return {
            "order": list(self._order),
            "blocked": [p for p in self._order if self.is_blocked(p)],
            "failures": {p: n for p, n in self._failures.items() if n},
            "active": self.next_protocol(),
        }


fingerprint_rotator = FingerprintRotator()
protocol_rotator = ProtocolRotator()
