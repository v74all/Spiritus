"""
WebAuthn (Passkey) + mTLS + Fail2ban for V7LTHRONYX VPN Panel.

WebAuthn:
- Register passkeys (FIDO2) for passwordless login
- Challenge-response authentication
- Supports YubiKey, Touch ID, Windows Hello

mTLS:
- Client certificate authentication for admin panel
- Certificate generation and management
- CN-based identity mapping to admin accounts

Fail2ban:
- Monitor login failures and ban IPs
- Integration with system fail2ban
- Custom filter and action configurations
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import time
import logging
import re
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta, timezone
from .timeutil import utcnow as _utcnow

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Admin, Fail2banBan
from .config import settings
from .redis_client import get_redis

try:
    from webauthn import (
        generate_authentication_options as _wa_generate_authentication_options,
        generate_registration_options as _wa_generate_registration_options,
        options_to_json as _wa_options_to_json,
        verify_authentication_response as _wa_verify_authentication_response,
        verify_registration_response as _wa_verify_registration_response,
    )
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor
except ImportError:  # pragma: no cover - surfaced as a controlled 503 at runtime
    _wa_generate_authentication_options = None

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  WebAuthn (Passkey) Manager
# ═══════════════════════════════════════════════════════════════

class WebAuthnManager:
    """Standards-based WebAuthn ceremonies with Redis one-time challenges."""

    def _configured(self) -> None:
        if _wa_generate_authentication_options is None:
            raise RuntimeError("webauthn package is not installed")
        if not settings.webauthn_rp_id or not settings.webauthn_origins:
            raise RuntimeError("WEBAUTHN_RP_ID and WEBAUTHN_ORIGINS must be configured")

    @staticmethod
    async def _store_challenge(kind: str, username: str, challenge: bytes) -> None:
        redis = await get_redis()
        await redis.setex(f"webauthn:{kind}:{username}", 300, bytes_to_base64url(challenge))

    @staticmethod
    async def _take_challenge(kind: str, username: str) -> bytes:
        redis = await get_redis()
        key = f"webauthn:{kind}:{username}"
        raw = await redis.eval(
            "local v=redis.call('get',KEYS[1]); if v then redis.call('del',KEYS[1]); end; return v",
            1,
            key,
        )
        if not raw:
            raise ValueError("challenge expired, missing, or already used")
        return base64url_to_bytes(raw)

    @staticmethod
    def _valid_credentials(credentials: List[Dict] | None) -> List[Dict]:
        return [c for c in (credentials or []) if c.get("version") == 1 and c.get("public_key")]

    async def generate_registration_options(self, username: str, existing_credentials=None) -> Dict[str, Any]:
        self._configured()
        exclude = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"]))
            for c in self._valid_credentials(existing_credentials)
        ]
        options = _wa_generate_registration_options(
            rp_id=settings.webauthn_rp_id,
            rp_name=settings.webauthn_rp_name,
            user_id=hashlib.sha256(username.encode("utf-8")).digest(),
            user_name=username,
            user_display_name=username,
            exclude_credentials=exclude,
        )
        await self._store_challenge("register", username, options.challenge)
        return {"publicKey": json.loads(_wa_options_to_json(options))}

    async def verify_registration(
        self, username: str, client_data_json: str, attestation_object: str,
        credential_id: str, transports: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        self._configured()
        challenge = await self._take_challenge("register", username)
        credential = {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_json,
                "attestationObject": attestation_object,
                "transports": transports or [],
            },
        }
        last_error = None
        verification = None
        for origin in [o.strip() for o in settings.webauthn_origins.split(",") if o.strip()]:
            try:
                verification = _wa_verify_registration_response(
                    credential=credential,
                    expected_challenge=challenge,
                    expected_rp_id=settings.webauthn_rp_id,
                    expected_origin=origin,
                    require_user_verification=True,
                )
                break
            except Exception as exc:  # library raises typed verification errors
                last_error = exc
        if verification is None:
            raise ValueError(f"registration verification failed: {type(last_error).__name__}")
        return {
            "id": bytes_to_base64url(verification.credential_id),
            "public_key": bytes_to_base64url(verification.credential_public_key),
            "sign_count": int(verification.sign_count),
            "transports": transports or [],
            "device_type": str(verification.credential_device_type),
            "backed_up": bool(verification.credential_backed_up),
            "registered_at": _utcnow().isoformat(),
            "version": 1,
        }

    async def generate_authentication_options(self, username: str, credentials: List[Dict]) -> Dict[str, Any]:
        self._configured()
        valid = self._valid_credentials(credentials)
        if not valid:
            raise ValueError("no valid passkeys are registered")
        options = _wa_generate_authentication_options(
            rp_id=settings.webauthn_rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["id"])) for c in valid
            ],
        )
        await self._store_challenge("authenticate", username, options.challenge)
        return {"publicKey": json.loads(_wa_options_to_json(options))}

    async def verify_authentication(
        self, username: str, credential_id: str, client_data_json: str,
        authenticator_data: str, signature: str, stored_credentials: List[Dict],
        user_handle: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._configured()
        challenge = await self._take_challenge("authenticate", username)
        matched = next(
            (c for c in self._valid_credentials(stored_credentials) if c["id"] == credential_id),
            None,
        )
        if matched is None:
            raise ValueError("unknown credential")
        credential = {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_json,
                "authenticatorData": authenticator_data,
                "signature": signature,
                "userHandle": user_handle,
            },
        }
        verification = None
        last_error = None
        for origin in [o.strip() for o in settings.webauthn_origins.split(",") if o.strip()]:
            try:
                verification = _wa_verify_authentication_response(
                    credential=credential,
                    expected_challenge=challenge,
                    expected_rp_id=settings.webauthn_rp_id,
                    expected_origin=origin,
                    credential_public_key=base64url_to_bytes(matched["public_key"]),
                    credential_current_sign_count=int(matched.get("sign_count", 0)),
                    require_user_verification=True,
                )
                break
            except Exception as exc:
                last_error = exc
        if verification is None:
            raise ValueError(f"authentication verification failed: {type(last_error).__name__}")
        return {"credential_id": credential_id, "sign_count": int(verification.new_sign_count)}


# ═══════════════════════════════════════════════════════════════
#  mTLS (Mutual TLS) Manager
# ═══════════════════════════════════════════════════════════════

class MTLSManager:
    """mTLS client certificate authentication for admin panel.

    Generates and manages client certificates for admin authentication.
    Requires nginx/Apaxhe to verify client certs and pass CN header.
    """

    def __init__(
        self,
        ca_cert_path: str = "/opt/v7lthronyx/mtls/ca.crt",
        ca_key_path: str = "/opt/v7lthronyx/mtls/ca.key",
        certs_dir: str = "/opt/v7lthronyx/mtls/clients",
    ):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.certs_dir = certs_dir

    def init_ca(self) -> Dict[str, str]:
        """Initialize the Certificate Authority."""
        os.makedirs(os.path.dirname(self.ca_cert_path), exist_ok=True)
        os.makedirs(self.certs_dir, exist_ok=True)

        if os.path.exists(self.ca_cert_path):
            return {"status": "exists", "ca_cert": self.ca_cert_path}

        # Generate CA key and cert
        result = subprocess.run(
            [
                "openssl", "req", "-x509", "-new", "-nodes",
                "-newkey", "rsa:4096",
                "-keyout", self.ca_key_path,
                "-out", self.ca_cert_path,
                "-days", "3650",
                "-subj", "/C=US/O=V7LTHRONYX/CN=V7LTHRONYX-CA",
            ],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            logger.error(f"Failed to create CA: {result.stderr}")
            return {"status": "error", "error": result.stderr}

        os.chmod(self.ca_key_path, 0o600)
        return {"status": "created", "ca_cert": self.ca_cert_path}

    def generate_client_cert(
        self,
        username: str,
        days: int = 365,
    ) -> Dict[str, str]:
        """Generate a client certificate for an admin user."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", username):
            raise ValueError("username contains unsafe certificate filename characters")
        os.makedirs(self.certs_dir, exist_ok=True)

        cn = f"v7lthronyx-admin-{username}"
        key_path = os.path.join(self.certs_dir, f"{username}.key")
        csr_path = os.path.join(self.certs_dir, f"{username}.csr")
        cert_path = os.path.join(self.certs_dir, f"{username}.crt")
        p12_path = os.path.join(self.certs_dir, f"{username}.p12")

        # Generate client key
        result = subprocess.run(
            ["openssl", "genrsa", "-out", key_path, "2048"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            raise RuntimeError("failed to generate client private key")

        # Generate CSR
        result = subprocess.run(
            [
                "openssl", "req", "-new",
                "-key", key_path,
                "-out", csr_path,
                "-subj", f"/C=US/O=V7LTHRONYX/CN={cn}",
            ],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            raise RuntimeError("failed to generate client certificate request")

        # Sign with CA
        result = subprocess.run(
            [
                "openssl", "x509", "-req",
                "-in", csr_path,
                "-CA", self.ca_cert_path,
                "-CAkey", self.ca_key_path,
                "-CAcreateserial",
                "-out", cert_path,
                "-days", str(days),
            ],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            raise RuntimeError("failed to sign client certificate")

        # Create PKCS#12 bundle (for browser import)
        p12_password = secrets.token_urlsafe(16)
        result = subprocess.run(
            [
                "openssl", "pkcs12", "-export",
                "-out", p12_path,
                "-inkey", key_path,
                "-in", cert_path,
                "-certfile", self.ca_cert_path,
                "-passout", f"pass:{p12_password}",
            ],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            raise RuntimeError("failed to generate PKCS#12 bundle")

        # Clean up CSR
        os.remove(csr_path)

        os.chmod(key_path, 0o600)

        return {
            "cn": cn,
            "key_path": key_path,
            "cert_path": cert_path,
            "p12_path": p12_path,
            "p12_password": p12_password,
        }

    def revoke_client_cert(self, username: str) -> bool:
        """Revoke a client certificate."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", username):
            return False
        cert_path = os.path.join(self.certs_dir, f"{username}.crt")
        if not os.path.exists(cert_path):
            return False

        # In production, maintain a CRL (Certificate Revocation List)
        # For now, just remove the cert files
        for ext in [".key", ".crt", ".p12"]:
            path = os.path.join(self.certs_dir, f"{username}{ext}")
            if os.path.exists(path):
                os.remove(path)

        return True

    def generate_nginx_config(self, port: int = 38471) -> str:
        """Generate nginx mTLS configuration snippet."""
        return f"""
# V7LTHRONYX mTLS Configuration
# Add this to your nginx server block

server {{
    listen {port} ssl;
    server_name _;

    # Server TLS
    ssl_certificate     /opt/v7lthronyx/mtls/server.crt;
    ssl_certificate_key /opt/v7lthronyx/mtls/server.key;

    # Client certificate verification
    ssl_client_certificate /opt/v7lthronyx/mtls/ca.crt;
    ssl_verify_client optional;
    ssl_verify_depth 2;

    # Pass CN to backend
    location / {{
        proxy_pass http://127.0.0.1:38472;
        proxy_set_header X-Client-Cert-CN $ssl_client_s_dn_cn;
        proxy_set_header X-Client-Cert-Verified $ssl_client_verify;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
}}
"""

    async def verify_client_cert_cn(self, cn: str, db: AsyncSession) -> Optional[Admin]:
        """Look up an admin by their mTLS certificate CN."""
        result = await db.execute(
            select(Admin).where(Admin.mtls_cn == cn)
        )
        return result.scalar_one_or_none()


# ═══════════════════════════════════════════════════════════════
#  Fail2ban Integration
# ═══════════════════════════════════════════════════════════════

class Fail2banManager:
    """Fail2ban integration for brute-force protection.

    Monitors login failures and bans IPs via iptables/systemd.
    Also integrates with the database for persistent ban tracking.
    """

    PANEL_FILTER_NAME = "v7lthronyx-panel"
    SSH_FILTER_NAME = "v7lthronyx-ssh"
    XRAY_FILTER_NAME = "v7lthronyx-xray"

    def __init__(
        self,
        max_retries: int = 3,
        ban_time: int = 3600,
        find_time: int = 600,
    ):
        self.max_retries = max_retries
        self.ban_time = ban_time
        self.find_time = find_time

    def install_filter(self, service: str = "panel") -> bool:
        """Install fail2ban filter configuration."""
        filter_dir = "/etc/fail2ban/filter.d"
        if not os.path.exists(filter_dir):
            logger.warning("fail2ban not installed, skipping filter setup")
            return False

        os.makedirs(filter_dir, exist_ok=True)

        filters = {
            "panel": {
                "name": self.PANEL_FILTER_NAME,
                "pattern": r'^.*Failed login attempt.*from <HOST>.*$',
            },
            "ssh": {
                "name": self.SSH_FILTER_NAME,
                "pattern": r'^.*Failed password.*from <HOST>.*$',
            },
            "xray": {
                "name": self.XRAY_FILTER_NAME,
                "pattern": r'^.*rejected.*from <HOST>.*$',
            },
        }

        if service not in filters:
            return False

        filt = filters[service]
        filter_path = os.path.join(filter_dir, f"{filt['name']}.conf")

        filter_content = f"""# V7LTHRONYX {service} fail2ban filter
[Definition]
failregex = {filt['pattern']}
ignoreregex =
"""

        with open(filter_path, 'w') as f:
            f.write(filter_content)

        return True

    def install_jail(self, service: str = "panel", port: int = 38471) -> bool:
        """Install fail2ban jail configuration."""
        jail_dir = "/etc/fail2ban/jail.d"
        if not os.path.exists(jail_dir):
            logger.warning("fail2ban not installed, skipping jail setup")
            return False

        os.makedirs(jail_dir, exist_ok=True)

        jails = {
            "panel": {
                "filter": self.PANEL_FILTER_NAME,
                "port": port,
                "log_path": "/opt/v7lthronyx/vpn-panel.log",
            },
            "ssh": {
                "filter": "sshd",
                "port": 22,
                "log_path": "/var/log/auth.log",
            },
            "xray": {
                "filter": self.XRAY_FILTER_NAME,
                "port": "all",
                "log_path": "/var/log/xray/error.log",
            },
        }

        if service not in jails:
            return False

        jail = jails[service]
        jail_path = os.path.join(jail_dir, f"v7lthronyx-{service}.conf")

        jail_content = f"""[v7lthronyx-{service}]
enabled = true
filter = {jail['filter']}
port = {jail['port']}
logpath = {jail['log_path']}
maxretry = {self.max_retries}
bantime = {self.ban_time}
findtime = {self.find_time}
action = iptables-multiport[name=v7lthronyx-{service}, port="{jail['port']}", protocol=tcp]
"""

        with open(jail_path, 'w') as f:
            f.write(jail_content)

        # Reload fail2ban
        try:
            subprocess.run(
                ["systemctl", "reload", "fail2ban"],
                capture_output=True, text=True, timeout=10
            )
        except Exception:
            pass

        return True

    async def record_failed_attempt(
        self,
        ip_address: str,
        service: str,
        db: AsyncSession,
        reason: str = "Failed login",
    ) -> None:
        """Record a failed login attempt in the database."""
        result = await db.execute(
            select(Fail2banBan).where(
                Fail2banBan.ip_address == ip_address,
                Fail2banBan.service == service,
            )
        )
        ban = result.scalar_one_or_none()

        if ban:
            ban.ban_count += 1
            ban.reason = reason
            if ban.ban_count >= self.max_retries:
                ban.banned_until = _utcnow() + timedelta(seconds=self.ban_time)
        else:
            ban = Fail2banBan(
                ip_address=ip_address,
                service=service,
                reason=reason,
                ban_count=1,
            )
            db.add(ban)

        await db.commit()

    async def is_banned(
        self, ip_address: str, service: str, db: AsyncSession
    ) -> bool:
        """Check if an IP is currently banned."""
        result = await db.execute(
            select(Fail2banBan).where(
                Fail2banBan.ip_address == ip_address,
                Fail2banBan.service == service,
            )
        )
        ban = result.scalar_one_or_none()

        if not ban:
            return False

        if ban.banned_until and ban.banned_until > _utcnow():
            return True

        return False

    async def unban(
        self, ip_address: str, service: str, db: AsyncSession
    ) -> bool:
        """Remove a ban for an IP."""
        result = await db.execute(
            select(Fail2banBan).where(
                Fail2banBan.ip_address == ip_address,
                Fail2banBan.service == service,
            )
        )
        ban = result.scalar_one_or_none()

        if ban:
            await db.delete(ban)
            await db.commit()
            return True
        return False

    async def get_all_bans(self, db: AsyncSession) -> List[Dict[str, Any]]:
        """Get all active bans."""
        result = await db.execute(
            select(Fail2banBan).order_by(Fail2banBan.created_at.desc())
        )
        bans = result.scalars().all()

        return [
            {
                "id": b.id,
                "ip_address": b.ip_address,
                "service": b.service,
                "reason": b.reason,
                "ban_count": b.ban_count,
                "banned_until": b.banned_until.isoformat() if b.banned_until else None,
                "created_at": b.created_at.isoformat() if b.created_at else None,
            }
            for b in bans
        ]

    def install_all(self) -> Dict[str, bool]:
        """Install all fail2ban filters and jails."""
        results = {}
        for service in ["panel", "ssh", "xray"]:
            results[f"{service}_filter"] = self.install_filter(service)
            results[f"{service}_jail"] = self.install_jail(service)
        return results


# ═══════════════════════════════════════════════════════════════
#  Global instances
# ═══════════════════════════════════════════════════════════════

webauthn_manager = WebAuthnManager()
mtls_manager = MTLSManager()
fail2ban_manager = Fail2banManager()
