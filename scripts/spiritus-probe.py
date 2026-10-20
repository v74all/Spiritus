#!/usr/bin/env python3
"""Spiritus in-country probe.

Run this on a phone (Termux) or computer *inside* an Iranian network, with no
VPN active, to measure which of the panel's protocols get through that
carrier. It asks the panel what to test, tests each port from here, and
reports the results back. The panel works out the carrier from the address
the report arrives from (or use --carrier to set it by hand); it does not
store the probe's IP.

What is tested:
  * REALITY / ShadowTLS ports: a full TLS handshake using the configured
    camouflage SNI (verified certificate). A completed handshake means the
    port and SNI passed DPI.
  * Other TCP ports: a TCP connect.
  UDP protocols (Hysteria2, TUIC, WireGuard, ...) are not tested.

Usage:
  export SPIRITUS_PROBE_TOKEN=spr_...        # keeps the token out of shell history
  python3 spiritus-probe.py --panel https://panel.example.com:38471
  python3 spiritus-probe.py --panel http://1.2.3.4:38471 --interval 900

Standard library only (Python 3.8+).
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

ATTEMPTS = 2


def _request(url, token, *, data=None, insecure=False, timeout=30):
    req = urllib.request.Request(url, method="POST" if data is not None else "GET")
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("User-Agent", "spiritus-probe/1")
    body = None
    if data is not None:
        req.add_header("Content-Type", "application/json")
        body = json.dumps(data).encode()
    ctx = None
    if url.startswith("https://"):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, body, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode())


def _test_once(host, port, method, sni, timeout):
    addr = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4]
    start = time.perf_counter()
    sock = socket.create_connection(addr[:2], timeout=timeout)
    try:
        if method == "tls":
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                tls.do_handshake()
                return (time.perf_counter() - start) * 1000
        return (time.perf_counter() - start) * 1000
    finally:
        sock.close()


def _short_error(exc):
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "certificate verification failed"
    if isinstance(exc, ConnectionResetError):
        return "connection reset"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    return (getattr(exc, "strerror", None) or str(exc) or type(exc).__name__)[:120]


def test_target(host, target, timeout):
    best, error = None, None
    for _ in range(ATTEMPTS):
        try:
            ms = _test_once(host, target["port"], target["method"], target.get("sni") or host, timeout)
            best = ms if best is None else min(best, ms)
        except Exception as exc:  # noqa: BLE001 - every failure is a result
            error = _short_error(exc)
    return {
        "protocol": target["protocol"],
        "method": target["method"],
        "ok": best is not None,
        "latency_ms": round(best, 1) if best is not None else None,
        "error": None if best is not None else error,
    }


def run_once(args, token):
    panel = args.panel.rstrip("/")
    plan = _request(panel + "/api/probe/targets", token, insecure=args.insecure)
    host = plan.get("server") or ""
    targets = plan.get("targets") or []
    if not host or not targets:
        print("Panel returned no server address or no testable protocols.")
        return plan.get("min_interval_seconds", 60)

    print("Testing %d protocol(s) on %s" % (len(targets), host))
    results = []
    for t in targets:
        r = test_target(host, t, args.timeout)
        results.append(r)
        status = "OK   %7.1f ms" % r["latency_ms"] if r["ok"] else "FAIL %s" % r["error"]
        print("  %-24s %5s/%-4s %s" % (t["name"], t["port"], t["method"], status))

    payload = {"results": results}
    if args.carrier:
        payload["carrier"] = args.carrier
    for attempt in (1, 2):  # one retry: links from inside Iran drop requests often
        try:
            ack = _request(panel + "/api/probe/report", token, data=payload, insecure=args.insecure)
            print("Reported %s result(s) as carrier: %s" % (ack.get("stored"), ack.get("carrier")))
            break
        except urllib.error.HTTPError as exc:
            print("Report rejected: HTTP %s %s" % (exc.code, exc.read().decode(errors="replace")[:200]))
            break
        except (urllib.error.URLError, OSError) as exc:
            if attempt == 2:
                raise
            print("Report failed (%s), retrying in 5 s" % _short_error(getattr(exc, "reason", exc)))
            time.sleep(5)
    return plan.get("min_interval_seconds", 60)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--panel", required=True, help="Panel URL, e.g. https://panel.example.com:38471")
    ap.add_argument("--token", default=os.environ.get("SPIRITUS_PROBE_TOKEN", ""),
                    help="Probe token (default: $SPIRITUS_PROBE_TOKEN)")
    ap.add_argument("--interval", type=int, default=0,
                    help="Repeat every N seconds (0 = run once). Minimum 60.")
    ap.add_argument("--carrier", default="", help="Override the detected carrier name, e.g. 'MTN Irancell'")
    ap.add_argument("--timeout", type=float, default=5.0, help="Per-attempt timeout in seconds")
    ap.add_argument("--insecure", action="store_true",
                    help="Do not verify the panel's HTTPS certificate (self-signed panels)")
    args = ap.parse_args()

    token = args.token.strip()
    if not token.startswith("spr_"):
        ap.error("a probe token (spr_...) is required: --token or SPIRITUS_PROBE_TOKEN")

    while True:
        try:
            min_interval = run_once(args, token)
        except urllib.error.HTTPError as exc:
            print("Panel error: HTTP %s %s" % (exc.code, exc.read().decode(errors="replace")[:200]))
            if exc.code == 401:
                return 1
            min_interval = 60
        except (urllib.error.URLError, OSError) as exc:
            print("Cannot reach panel: %s" % _short_error(getattr(exc, "reason", exc)))
            min_interval = 60
        if args.interval <= 0:
            return 0
        time.sleep(max(args.interval, 60, int(min_interval or 0)))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
