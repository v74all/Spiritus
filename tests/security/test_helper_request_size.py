"""A full Xray config is sent to the helper as one JSON line, ~1.5 KB per
user. The stream's default 64 KiB line limit refused it past ~35 users, so
settings and user changes silently stopped reaching Xray."""

import asyncio
import json

import pytest

import app.privileged_helper_daemon as helper_daemon


@pytest.mark.asyncio
async def test_helper_accepts_a_config_for_thousands_of_users(monkeypatch, tmp_path):
    seen = {}

    def _dispatch(operation, payload):
        seen["size"] = len(payload["content"])
        return {"ok": True, "message": "config installed"}

    monkeypatch.setattr(helper_daemon, "_peer_allowed", lambda writer: True)
    monkeypatch.setattr(helper_daemon, "_dispatch", _dispatch)
    path = tmp_path / "helper.sock"
    server = await helper_daemon.start_server(path)
    content = json.dumps({"inbounds": [{"settings": {"clients": [{"id": "x" * 36, "email": f"u{i}"} for i in range(40_000)]}}]})
    assert len(content) > 2_000_000
    try:
        reader, writer = await asyncio.open_unix_connection(str(path))
        writer.write(json.dumps({"operation": "config.install", "payload": {"target": "xray", "content": content}}).encode() + b"\n")
        await writer.drain()
        reply = json.loads(await asyncio.wait_for(reader.readline(), timeout=10))
        writer.close()
    finally:
        server.close()
        await server.wait_closed()
    assert reply["ok"] is True
    assert seen["size"] == len(content)
