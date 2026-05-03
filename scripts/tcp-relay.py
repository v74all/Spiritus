#!/usr/bin/env python3
"""
V7LTHRONYX Emergency TCP Relay
===============================
Blind TCP port forwarder for emergency VPN bypass.
Forwards all TCP connections to the real VPN server.

Deploy this on ANY clean VPS (even $3/month) and point
the panel's Emergency Relay setting to this server's IP.

Usage:
    python3 tcp-relay.py --target 91.107.131.44
    python3 tcp-relay.py --target 91.107.131.44 --ports 443,2053,2057,2058
    TARGET=91.107.131.44 PORTS=443,8449,2053 python3 tcp-relay.py

Author : v7lthronyx (Aiden Azad)
License: MIT
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
from typing import Optional

logger = logging.getLogger("tcp-relay")

# Default ports to relay (mirrors Xray inbounds on the VPN server)
DEFAULT_PORTS = [
    443,    # VMess WS TLS
    2053,   # VLESS Reality TCP
    8449,   # VLESS XHTTP Reality
    2058,   # VLESS Vision Reality
    2059,   # VLESS Reverse Reality
    2083,   # Trojan TCP TLS
    2054,   # gRPC
    2055,   # HTTPUpgrade
    2057,   # VLESS WS TLS
    2056,   # SS2022
]

BUFFER_SIZE = 65536  # 64KB
CONNECTION_TIMEOUT = 30  # seconds


async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, direction: str) -> None:
    """Bidirectional pipe between two connections."""
    try:
        while True:
            data = await asyncio.wait_for(src.read(BUFFER_SIZE), timeout=CONNECTION_TIMEOUT)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def handle_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
) -> None:
    """Handle a single client connection by forwarding to the target."""
    client_addr = client_writer.get_extra_info("peername", ("?", 0))
    logger.debug(f"[{target_port}] New connection from {client_addr[0]}:{client_addr[1]}")

    try:
        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port),
            timeout=10,
        )
    except (asyncio.TimeoutError, ConnectionError, OSError) as e:
        logger.warning(f"[{target_port}] Failed to connect to target {target_host}:{target_port}: {e}")
        client_writer.close()
        return

    # Bidirectional forward
    task1 = asyncio.ensure_future(pipe(client_reader, target_writer, "C->T"))
    task2 = asyncio.ensure_future(pipe(target_reader, client_writer, "T->C"))

    try:
        await asyncio.wait_for(
            asyncio.gather(task1, task2, return_exceptions=True),
            timeout=CONNECTION_TIMEOUT * 2,
        )
    except asyncio.TimeoutError:
        pass

    # Cleanup
    for w in (client_writer, target_writer):
        try:
            w.close()
        except Exception:
            pass

    logger.debug(f"[{target_port}] Connection closed: {client_addr[0]}:{client_addr[1]}")


async def run_relay(
    target_host: str,
    ports: list[int],
    bind_host: str = "0.0.0.0",
) -> None:
    """Start TCP relay servers on all specified ports."""
    servers = []
    for port in ports:
        try:
            server = await asyncio.start_server(
                lambda r, w, p=port: handle_connection(r, w, target_host, p),
                host=bind_host,
                port=port,
            )
            servers.append(server)
            logger.info(f"Relay listening: 0.0.0.0:{port} -> {target_host}:{port}")
        except OSError as e:
            logger.error(f"Failed to bind port {port}: {e}")
            # Continue with other ports even if one fails

    if not servers:
        logger.error("No ports could be bound. Exiting.")
        return

    logger.info(f"Emergency TCP Relay ACTIVE — {len(servers)} ports forwarding to {target_host}")
    logger.info("Press Ctrl+C to stop.")

    # Wait forever (or until signal)
    stop_event = asyncio.Event()

    def _shutdown():
        logger.info("Shutting down...")
        stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            signal.signal(sig, lambda *_: _shutdown())

    try:
        await stop_event.wait()
    except KeyboardInterrupt:
        pass

    # Graceful shutdown
    for server in servers:
        server.close()
    for server in servers:
        try:
            await asyncio.wait_for(server.wait_closed(), timeout=5)
        except asyncio.TimeoutError:
            pass

    logger.info("Relay stopped.")


def parse_ports(raw: Optional[str]) -> list[int]:
    """Parse comma-separated port string into sorted int list."""
    if not raw:
        return DEFAULT_PORTS
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser(
        description="V7LTHRONYX Emergency TCP Relay",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python3 tcp-relay.py --target 91.107.131.44\n"
               "  TARGET=91.107.131.44 PORTS=443,2053,2057 python3 tcp-relay.py",
    )
    parser.add_argument("--target", "-t", default=os.environ.get("TARGET", ""),
                        help="Target VPN server IP/hostname")
    parser.add_argument("--ports", "-p", default=os.environ.get("PORTS", ""),
                        help="Comma-separated list of ports to relay")
    parser.add_argument("--bind", "-b", default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if not args.target:
        print("ERROR: --target is required (IP or hostname of your VPN server)")
        print("Example: python3 tcp-relay.py --target 91.107.131.44")
        sys.exit(1)

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ports = parse_ports(args.ports or None)
    print(f"""
    ███████╗███╗   ███╗███████╗██████╗  ██████╗
    ██╔════╝████╗ ████║██╔════╝██╔══██╗██╔════╝
    █████╗  ██╔████╔██║█████╗  ██████╔╝██║  ███╗
    ██╔══╝  ██║╚██╔╝██║██╔══╝  ██╔══██╗██║   ██║
    ███████╗██║ ╚═╝ ██║███████╗██║  ██║╚██████╔╝
    ╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝
         EMERGENCY TCP RELAY v1.0
    Target: {args.target}
    Ports:  {len(ports)} ports — {",".join(str(p) for p in ports[:10])}{"..." if len(ports) > 10 else ""}
    """)

    try:
        asyncio.run(run_relay(args.target, ports, args.bind))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
