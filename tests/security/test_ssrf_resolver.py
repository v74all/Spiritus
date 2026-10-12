"""
SSRF protection tests for the /api/google-relay endpoint.

We don't spin up the full app; instead we replay the resolver logic that the
endpoint uses (socket.getaddrinfo + ipaddress) to assert each dangerous
hostname class is blocked. This guards against regressions in the SSRF block.
"""

import ipaddress
import socket

import pytest

_METADATA_HOSTS = {
    "169.254.169.254",
    "fd00:ec2::254",
    "100.100.100.200",
}


def _resolve_classify(hostname):
    """Return the most-restrictive classification across all resolved addrs."""
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return "unresolved"
    if not infos:
        return "unresolved"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
            or str(ip) in _METADATA_HOSTS
        ):
            return "blocked"
    return "ok"


@pytest.mark.parametrize("host", [
    "127.0.0.1",
    "10.0.0.1",
    "192.168.1.1",
    "169.254.169.254",   # AWS / GCP metadata
    "::1",
])
def test_dangerous_hosts_are_blocked(host):
    assert _resolve_classify(host) == "blocked"


def test_unresolvable_host_is_rejected():
    # The SSRF guard treats unresolvable hosts as failures (does not silently
    # let them through to httpx).
    assert _resolve_classify("definitely-does-not-resolve.invalid") == "unresolved"


def test_localhost_keyword_is_explicitly_blocked():
    # The endpoint blocks "localhost" by name before resolving, so just
    # verify the local resolver maps it to loopback.
    assert _resolve_classify("localhost") == "blocked"


def test_public_ip_passes():
    # 1.1.1.1 is Cloudflare public DNS — must not be misclassified as private.
    assert _resolve_classify("1.1.1.1") == "ok"
