"""Service layer for the V7LTHRONYX VPN Panel.

The `services` package is the place for code that orchestrates the
panel's external side-effects (Xray config writes, systemd calls,
Celery fan-out, Telegram notifications, payment gateway calls,
...). Endpoints in `app/api/` are thin wrappers that handle HTTP
plumbing; everything that actually *does* something lives here.
"""
