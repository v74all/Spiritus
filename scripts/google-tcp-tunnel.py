#!/usr/bin/env python3
"""
V7LTHRONYX Google TCP Tunnel
=============================
Emergency TCP-over-HTTP tunnel through Google Apps Script.
Encapsulates TCP streams inside HTTP POST requests to bypass IP blocking.

When the VPN server IP is blocked in Iran, this script creates a local
TCP tunnel that forwards all traffic through Google's infrastructure.

Flow:
  Xray client → 127.0.0.1:LOCAL_PORT → Google GAS → VPN server → Xray inbound

Usage:
  python3 google-tcp-tunnel.py
  python3 google-tcp-tunnel.py --port 5555 --target 91.107.131.44
  python3 google-tcp-tunnel.py --map "443>1443,2053>12053" --target 91.107.131.44

Author : v7lthronyx (Aiden Azad)
License: MIT
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import signal
import sys
from typing import Dict, Optional, Tuple

logger = logging.getLogger("google-tunnel")

# Google Apps Script relay URL (your deployed script)
GAS_URL = os.environ.get(
    "GAS_RELAY_URL",
    "https://script.google.com/macros/s/AKfycbxnsc272M4hguTU3KJaglU1-zsPjRFPVtuIQIS_VX0hAr1pP-B_A0xX9wQK_kYOeLs/exec",
)

# VPN server HTTP relay endpoint
VPN_RELAY_ENDPOINT = os.environ.get("VPN_RELAY_ENDPOINT", "http://91.107.131.44:38471/api/google-relay")

# Default ports to tunnel (VPN inbounds on server)
DEFAULT_TUNNEL_PORTS = {
    443: 1443,     # VMess WS TLS → local 1443
    2053: 12053,   # VLESS Reality TCP → local 12053
    8449: 18449,   # VLESS XHTTP Reality → local 18449
    2058: 12058,   # VLESS Vision Reality → local 12058
    2059: 12059,   # VLESS Reverse Reality → local 12059
    2083: 12083,   # Trojan TCP TLS → local 12083
    2054: 12054,   # gRPC → local 12054
    2055: 12055,   # HTTPUpgrade → local 12055
    2057: 12057,   # VLESS WS TLS → local 12057
    2056: 12056,   # SS2022 → local 12056
}

BUFFER_SIZE = 65536
HTTP_TIMEOUT = 30
POLL_INTERVAL = 0.5  # seconds between long-polls


async def http_relay(
    session: "aiohttp.ClientSession",
    target_host: str,
    target_port: int,
    data: bytes,
) -> Optional[bytes]:
    """Send data through Google GAS → VPN relay and return response."""
    import aiohttp

    payload = {
        "method": "POST",
        "url": VPN_RELAY_ENDPOINT,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "host": target_host,
            "port": target_port,
            "data_b64": base64.b64encode(data).decode("ascii"),
        }),
    }

    try:
        async with session.post(GAS_URL, json=payload, timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT)) as resp:
            if resp.status != 200:
                logger.debug(f"[{target_port}] HTTP {resp.status} from GAS relay")
                return None
            result = await resp.json()
            if result.get("error"):
                logger.debug(f"[{target_port}] Relay error: {result['error']}")
                return None
            body = result.get("body", "")
            if isinstance(body, dict):
                # VPN relay returned structured response
                resp_b64 = body.get("data_b64", "")
            elif isinstance(body, str):
                try:
                    inner = json.loads(body)
                    resp_b64 = inner.get("data_b64", "")
                except json.JSONDecodeError:
                    resp_b64 = body
            else:
                resp_b64 = ""
            if resp_b64:
                return base64.b64decode(resp_b64)
            return b""
    except Exception as e:
        logger.debug(f"[{target_port}] Relay request failed: {e}")
        return None


async def handle_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    session: "aiohttp.ClientSession",
) -> None:
    """Handle a single TCP connection by tunneling through Google."""
    client_addr = client_writer.get_extra_info("peername", ("?", 0))
    logger.info(f"[{target_port}] Connection from {client_addr[0]}:{client_addr[1]}")

    # Track pending data from server (for full-duplex emulation)
    pending_response: Optional[bytes] = None
    client_closed = False

    async def send_to_server(data: bytes) -> Optional[bytes]:
        """Send data to VPN server via Google relay, return response."""
        return await http_relay(session, target_host, target_port, data)

    try:
        while True:
            # Try to read from client (with timeout for polling)
            try:
                client_data = await asyncio.wait_for(
                    client_reader.read(BUFFER_SIZE), timeout=0.1
                )
            except asyncio.TimeoutError:
                client_data = None

            if client_data:
                # We got data from client, send to server
                if pending_response is not None:
                    # Server sent us data we haven't delivered yet
                    # Send it to client first, then process new client data
                    client_writer.write(pending_response)
                    await client_writer.drain()
                    pending_response = None

                response = await send_to_server(client_data)
                if response:
                    client_writer.write(response)
                    await client_writer.drain()
            elif pending_response is not None:
                # No new client data, deliver pending server data
                client_writer.write(pending_response)
                await client_writer.drain()
                pending_response = None
            else:
                # Check if client is still connected
                if client_reader.at_eof():
                    break

    except (ConnectionError, OSError, asyncio.TimeoutError) as e:
        logger.debug(f"[{target_port}] Connection error: {e}")
    finally:
        try:
            client_writer.close()
        except Exception:
            pass
        logger.debug(f"[{target_port}] Connection closed: {client_addr[0]}:{client_addr[1]}")


async def run_tunnel(
    target_host: str,
    port_map: Dict[int, int],
    bind_host: str = "127.0.0.1",
) -> None:
    """Start TCP tunnel listeners for all mapped ports."""
    import aiohttp

    servers = []
    connector = aiohttp.TCPConnector(force_close=True, limit=20, limit_per_host=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        for remote_port, local_port in port_map.items():
            try:
                server = await asyncio.start_server(
                    lambda r, w, rp=remote_port: handle_connection(
                        r, w, target_host, rp, session
                    ),
                    host=bind_host,
                    port=local_port,
                )
                servers.append((server, remote_port, local_port))
                logger.info(
                    f"Tunnel: 127.0.0.1:{local_port} -> {target_host}:{remote_port}"
                )
            except OSError as e:
                logger.error(f"Failed to bind port {local_port}: {e}")

        if not servers:
            logger.error("No ports could be bound. Exiting.")
            return

        logger.info(
            f"Google TCP Tunnel ACTIVE — {len(servers)} ports tunneling to {target_host}"
        )
        logger.info("Press Ctrl+C to stop.")
        logger.info("")
        logger.info("Configure your Xray client to connect to these addresses:")
        logger.info(f"  Server address: 127.0.0.1")
        for _, remote_port, local_port in servers:
            logger.info(f"  Port {remote_port} -> connect to 127.0.0.1:{local_port}")
        logger.info("")

        stop_event = asyncio.Event()

        def _shutdown():
            logger.info("Shutting down...")
            stop_event.set()

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _shutdown)
            except NotImplementedError:
                signal.signal(sig, lambda *_: _shutdown())

        try:
            await stop_event.wait()
        except KeyboardInterrupt:
            pass

        for server, _, _ in servers:
            server.close()
        for server, _, _ in servers:
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=5)
            except asyncio.TimeoutError:
                pass

    logger.info("Tunnel stopped.")


def parse_port_map(raw: Optional[str], default: Dict[int, int]) -> Dict[int, int]:
    """Parse port mapping string: '443>1443,2053>12053' or '443,2053' (auto-local)."""
    if not raw:
        return default

    port_map = {}
    offset = 10000  # Auto-assign local ports starting at 10000 + remote
    for part in raw.split(","):
        part = part.strip()
        if ">" in part:
            remote, local = part.split(">", 1)
            port_map[int(remote.strip())] = int(local.strip())
        else:
            remote = int(part)
            port_map[remote] = offset + remote
    return port_map


def main():
    parser = argparse.ArgumentParser(
        description="V7LTHRONYX Google TCP Tunnel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "  python3 google-tcp-tunnel.py --target 91.107.131.44\n"
               "  python3 google-tcp-tunnel.py -t 91.107.131.44 -p 443,2053,2057\n"
               "  python3 google-tcp-tunnel.py -t 91.107.131.44 -p 443>1443,2053>12053",
    )
    parser.add_argument(
        "--target", "-t",
        default=os.environ.get("TARGET", "91.107.131.44"),
        help="Target VPN server IP/hostname",
    )
    parser.add_argument(
        "--ports", "-p",
        default=os.environ.get("PORTS", ""),
        help="Ports to tunnel (e.g., 443,2053 or 443>1443,2053>12053)",
    )
    parser.add_argument(
        "--bind", "-b",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    port_map = parse_port_map(args.ports or None, DEFAULT_TUNNEL_PORTS)

    print(f"""
    ██████╗  ██████╗  ██████╗  ██████╗ ██╗     ███████╗
   ██╔════╝ ██╔═══██╗██╔═══██╗██╔════╝ ██║     ██╔════╝
   ██║  ███╗██║   ██║██║   ██║██║  ███╗██║     █████╗
   ██║   ██║██║   ██║██║   ██║██║   ██║██║     ██╔══╝
   ╚██████╔╝╚██████╔╝╚██████╔╝╚██████╔╝███████╗███████╗
    ╚═════╝  ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
       GOOGLE TCP TUNNEL v1.0 — Emergency Mode
    Target: {args.target}
    Ports:  {len(port_map)} tunnels
    """)

    for remote, local in sorted(port_map.items()):
        print(f"  127.0.0.1:{local} -> {args.target}:{remote}")
    print()

    try:
        asyncio.run(run_tunnel(args.target, port_map, args.bind))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
