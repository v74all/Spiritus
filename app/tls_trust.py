"""How a client should verify this server's TLS certificate.

Xray-core removed ``allowInsecure`` (v26.2.6; fully off since 2026-08-01):
a link or config that relies on it now fails to start on current clients.
Each TLS link therefore says how to verify the certificate instead:

- publicly trusted and valid for the SNI the link sends: nothing extra;
- publicly trusted but issued for another name, e.g. a Let's Encrypt IP
  certificate behind a camouflage SNI: verify against that name
  (``vcn`` / ``verifyPeerCertByName``);
- self-signed: pin this exact certificate by its SHA-256
  (``pcs`` / ``pinnedPeerCertSha256``; Hysteria2 calls it ``pinSHA256``).

The certificate is the one Xray serves (``settings.tls_cert_file``); it is
re-read whenever the file changes, so a renewal is picked up on its own.
"""

from __future__ import annotations

import base64
import fnmatch
import ipaddress
import logging
import os
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .config import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CertInfo:
    sha256: str  # leaf fingerprint, 64 lowercase hex chars
    self_signed: bool
    dns_names: tuple[str, ...]
    ip_addresses: tuple[str, ...]
    # base64 SHA-256 of the public key (SPKI DER): sing-box's
    # certificate_public_key_sha256. Mihomo pins the leaf (sha256 above).
    spki_sha256: str = ""


@dataclass(frozen=True)
class TlsTrust:
    """What a link must carry so a strict client accepts the certificate."""

    pcs: str = ""  # pin (self-signed)
    vcn: str = ""  # verify against this name instead of the SNI
    # True when the certificate cannot be verified any other way
    # (self-signed) and the protocol has no pinning: only then may a
    # sing-box-only link (TUIC) still ask to skip verification.
    needs_insecure: bool = False

    @property
    def pin_colon(self) -> str:
        """The pin as AA:BB:..., the form Hysteria2's pinSHA256 documents."""
        return ":".join(self.pcs[i:i + 2] for i in range(0, len(self.pcs), 2)).upper()


_CACHE: dict[str, tuple[float, CertInfo | None]] = {}
# "Not passed": load the served certificate. None means "there is none".
_UNSET = object()


def tls_files() -> tuple[str, str]:
    """(cert, key) every TLS inbound serves: the active domain's certificate
    when one is set up in the panel (domain_manager records it in the
    settings), else TLS_CERT_FILE / TLS_KEY_FILE."""
    from .api.compat._core import _settings_state

    cert, key = _settings_state.get("tls_cert_file") or "", _settings_state.get("tls_key_file") or ""
    if cert and key and os.path.exists(cert) and os.path.exists(key):
        return cert, key
    return settings.tls_cert_file, settings.tls_key_file


def load_cert_info(path: str | None = None) -> CertInfo | None:
    """Leaf certificate facts for ``path`` (default: the cert Xray serves)."""
    path = path or tls_files()[0]
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    cached = _CACHE.get(path)
    if cached and cached[0] == mtime:
        return cached[1]
    info = None
    try:
        with open(path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns = tuple(n.lower() for n in san.get_values_for_type(x509.DNSName))
            ips = tuple(str(a) for a in san.get_values_for_type(x509.IPAddress))
        except x509.ExtensionNotFound:
            dns, ips = (), ()
        spki = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(spki)
        info = CertInfo(
            sha256=cert.fingerprint(hashes.SHA256()).hex(),
            self_signed=cert.issuer == cert.subject,
            dns_names=dns,
            ip_addresses=ips,
            spki_sha256=base64.b64encode(digest.finalize()).decode(),
        )
    except Exception as exc:  # noqa: BLE001 - an unreadable cert just means "no hints"
        logger.warning("tls_trust: cannot read %s: %s", path, exc)
    _CACHE[path] = (mtime, info)
    return info


def _covers(info: CertInfo, name: str) -> bool:
    name = (name or "").strip().strip("[]").lower()
    if not name:
        return False
    try:
        ip = ipaddress.ip_address(name)
        return any(ipaddress.ip_address(a) == ip for a in info.ip_addresses)
    except ValueError:
        pass
    # A wildcard covers exactly one label: *.example.com matches a.example.com only.
    return any(
        d == name or (d.startswith("*.") and fnmatch.fnmatch(name, d) and name.count(".") == d.count("."))
        for d in info.dns_names
    )


def trust_for(sni: str, server: str, info=_UNSET) -> TlsTrust:
    """How to verify the server's certificate on a link that sends ``sni``
    to ``server`` (the address in the link). ``info`` defaults to the
    certificate Xray serves; pass None for "no certificate"."""
    if info is _UNSET:
        info = load_cert_info()
    if info is None:
        return TlsTrust()
    if info.self_signed:
        return TlsTrust(pcs=info.sha256, needs_insecure=True)
    if _covers(info, sni):
        return TlsTrust()
    for name in (server, *info.ip_addresses, *info.dns_names):
        if name and not name.startswith("*.") and _covers(info, name):
            return TlsTrust(vcn=name.strip("[]"))
    return TlsTrust(pcs=info.sha256, needs_insecure=True)


def ip_certificate_for(server: str, info=_UNSET) -> bool:
    """True when the served certificate is publicly issued for ``server``'s
    IP. Then protocols that cannot carry ``vcn`` (VMess JSON links,
    Hysteria2, TUIC) can send the IP itself as SNI and verify normally."""
    if info is _UNSET:
        info = load_cert_info()
    if info is None or info.self_signed:
        return False
    try:
        ipaddress.ip_address((server or "").strip("[]"))
    except ValueError:
        return False
    return _covers(info, server)
