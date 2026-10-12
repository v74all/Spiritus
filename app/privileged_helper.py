"""Narrow client for the root-owned V7L privileged helper.

The web process never invokes sudo or accepts arbitrary commands. Requests are
small JSON messages sent over a root-owned Unix socket and are validated again
by the helper daemon.
"""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .config import settings


class PrivilegedHelperError(RuntimeError):
    pass


@dataclass(frozen=True)
class HelperResponse:
    ok: bool
    message: str = ""
    data: Mapping[str, Any] | None = None


def _decode_response(raw: bytes) -> HelperResponse:
    if not raw or len(raw) > 1_048_576:
        raise PrivilegedHelperError("invalid privileged helper response")
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PrivilegedHelperError("malformed privileged helper response") from exc
    return HelperResponse(
        ok=bool(result.get("ok")),
        message=str(result.get("message", "")),
        data=result.get("data") if isinstance(result.get("data"), dict) else None,
    )


async def helper_request(
    operation: str,
    payload: Mapping[str, Any] | None = None,
    *,
    timeout: float = 30.0,
) -> HelperResponse:
    request = json.dumps(
        {"operation": operation, "payload": dict(payload or {})},
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    if len(request) > 1_048_576:
        raise PrivilegedHelperError("helper request exceeds 1 MiB")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(settings.privileged_helper_socket),
            timeout=3.0,
        )
        writer.write(request)
        await writer.drain()
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        await writer.wait_closed()
    except (TimeoutError, OSError) as exc:
        raise PrivilegedHelperError("privileged helper unavailable") from exc

    return _decode_response(raw)


def helper_request_sync(
    operation: str,
    payload: Mapping[str, Any] | None = None,
    *,
    timeout: float = 30.0,
) -> HelperResponse:
    """Synchronous client for worker threads and Celery tasks."""
    request = json.dumps(
        {"operation": operation, "payload": dict(payload or {})},
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    if len(request) > 1_048_576:
        raise PrivilegedHelperError("helper request exceeds 1 MiB")

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(settings.privileged_helper_socket)
        client.sendall(request)
        chunks = bytearray()
        while not chunks.endswith(b"\n"):
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > 1_048_576:
                raise PrivilegedHelperError("invalid privileged helper response")
    except (OSError, TimeoutError) as exc:
        raise PrivilegedHelperError("privileged helper unavailable") from exc
    finally:
        client.close()
    return _decode_response(bytes(chunks))
