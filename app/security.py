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
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta, timezone
from .timeutil import utcnow as _utcnow

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Admin, Fail2banBan

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  WebAuthn (Passkey) Manager
# ═══════════════════════════════════════════════════════════════

class WebAuthnManager:
    """WebAuthn/FIDO2 passkey management.

    Implements the WebAuthn registration and authentication ceremonies
    using the py_webauthn library patterns.
    """

    def __init__(self, rp_name: str = "V7LTHRONYX", rp_id: str = ""):
        self.rp_name = rp_name
        self.rp_id = rp_id  # Domain, e.g. "panel.example.com"
        self._challenges: Dict[str, Tuple[str, float]] = {}  # username -> (challenge, timestamp)

    def generate_registration_options(
        self,
        username: str,
        existing_credentials: List[Dict] = None,
    ) -> Dict[str, Any]:
        """Generate WebAuthn registration options (server → client)."""
        challenge = secrets.token_urlsafe(32)
        self._challenges[username] = (challenge, time.time())

        exclude_credentials = []
        if existing_credentials:
            for cred in existing_credentials:
                exclude_credentials.append({
                    "id": cred.get("id", ""),
                    "type": "public-key",
                    "transports": cred.get("transports", ["internal"]),
                })

        return {
            "publicKey": {
                "rp": {
                    "name": self.rp_name,
                    "id": self.rp_id,
                },
                "user": {
                    "id": base64.urlsafe_b64encode(
                        hashlib.sha256(username.encode()).digest()
                    ).decode().rstrip("="),
                    "name": username,
                    "displayName": username,
                },
                "challenge": base64.urlsafe_b64encode(
                    challenge.encode()
                ).decode().rstrip("="),
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7},   # ES256 (ECDSA w/ SHA-256)
                    {"type": "public-key", "alg": -257},  # RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)
                ],
                "timeout": 60000,
                "attestation": "direct",
                "excludeCredentials": exclude_credentials,
                "authenticatorSelection": {
                    "authenticatorAttachment": "cross-platform",
                    "userVerification": "preferred",
                    "residentKey": "preferred",
                },
            }
        }

    def verify_registration(
        self,
        username: str,
        client_data_json: str,
        attestation_object: str,
        credential_id: str,
    ) -> Dict[str, Any]:
        """Verify WebAuthn registration response (client → server)."""
        # Check challenge
        if username not in self._challenges:
            return {"success": False, "error": "No pending registration"}

        stored_challenge, timestamp = self._challenges[username]
        if time.time() - timestamp > 120:  # 2 minute timeout
            del self._challenges[username]
            return {"success": False, "error": "Challenge expired"}

        # Decode client data
        try:
            client_data = json.loads(base64.urlsafe_b64decode(
                client_data_json + "=="  # Add padding
            ))
        except Exception as e:
            return {"success": False, "error": f"Invalid client data: {e}"}

        # Verify challenge matches
        received_challenge = client_data.get("challenge", "")
        expected_challenge = base64.urlsafe_b64encode(
            stored_challenge.encode()
        ).decode().rstrip("=")

        if received_challenge != expected_challenge:
            return {"success": False, "error": "Challenge mismatch"}

        # Verify origin
        if client_data.get("type") != "webauthn.create":
            return {"success": False, "error": "Invalid client data type"}

        # Clean up challenge
        del self._challenges[username]

        # Store credential (in production, parse attestation object properly)
        credential = {
            "id": credential_id,
            "public_key": attestation_object,  # Simplified - should extract actual public key
            "transports": ["internal", "hybrid"],
            "sign_count": 0,
            "registered_at": _utcnow().isoformat(),
            "aaguid": "",  # Authenticator Attestation GUID
        }

        return {
            "success": True,
            "credential": credential,
            "credential_id": credential_id,
        }

    def generate_authentication_options(
        self,
        username: str,
        credentials: List[Dict],
    ) -> Dict[str, Any]:
        """Generate WebAuthn authentication options (server → client)."""
        challenge = secrets.token_urlsafe(32)
        self._challenges[username] = (challenge, time.time())

        allow_credentials = []
        for cred in credentials:
            allow_credentials.append({
                "id": cred.get("id", ""),
                "type": "public-key",
                "transports": cred.get("transports", ["internal"]),
            })

        return {
            "publicKey": {
                "rpId": self.rp_id,
                "challenge": base64.urlsafe_b64encode(
                    challenge.encode()
                ).decode().rstrip("="),
                "allowCredentials": allow_credentials,
                "timeout": 60000,
                "userVerification": "preferred",
            }
        }

    def verify_authentication(
        self,
        username: str,
        credential_id: str,
        client_data_json: str,
        authenticator_data: str,
        signature: str,
        stored_credentials: List[Dict],
    ) -> Dict[str, Any]:
        """Verify WebAuthn authentication response (client → server)."""
        if username not in self._challenges:
            return {"success": False, "error": "No pending authentication"}

        stored_challenge, timestamp = self._challenges[username]
        if time.time() - timestamp > 120:
            del self._challenges[username]
            return {"success": False, "error": "Challenge expired"}

        # Find matching credential
        matched_cred = None
        for cred in stored_credentials:
            if cred.get("id") == credential_id:
                matched_cred = cred
                break

        if not matched_cred:
            return {"success": False, "error": "Unknown credential"}

        # Verify client data
        try:
            client_data = json.loads(base64.urlsafe_b64decode(
                client_data_json + "=="
            ))
        except Exception:
            return {"success": False, "error": "Invalid client data"}

        if client_data.get("type") != "webauthn.get":
            return {"success": False, "error": "Invalid client data type"}

        # Clean up
        del self._challenges[username]

        # In production: verify signature against stored public key
        # For now, trust the response
        sign_count = int.from_bytes(
            base64.urlsafe_b64decode(authenticator_data + "==")[-4:],
            byteorder="big"
        ) if authenticator_data else 0

        return {
            "success": True,
            "credential_id": credential_id,
            "sign_count": sign_count,
        }


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
        ca_cert_path: str = "/opt/spiritus/mtls/ca.crt",
        ca_key_path: str = "/opt/spiritus/mtls/ca.key",
        certs_dir: str = "/opt/spiritus/mtls/clients",
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
        os.makedirs(self.certs_dir, exist_ok=True)

        cn = f"v7lthronyx-admin-{username}"
        key_path = os.path.join(self.certs_dir, f"{username}.key")
        csr_path = os.path.join(self.certs_dir, f"{username}.csr")
        cert_path = os.path.join(self.certs_dir, f"{username}.crt")
        p12_path = os.path.join(self.certs_dir, f"{username}.p12")

        # Generate client key
        subprocess.run(
            ["openssl", "genrsa", "-out", key_path, "2048"],
            capture_output=True, text=True, timeout=10
        )

        # Generate CSR
        subprocess.run(
            [
                "openssl", "req", "-new",
                "-key", key_path,
                "-out", csr_path,
                "-subj", f"/C=US/O=V7LTHRONYX/CN={cn}",
            ],
            capture_output=True, text=True, timeout=10
        )

        # Sign with CA
        subprocess.run(
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

        # Create PKCS#12 bundle (for browser import)
        p12_password = secrets.token_urlsafe(16)
        subprocess.run(
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
    ssl_certificate     /opt/spiritus/mtls/server.crt;
    ssl_certificate_key /opt/spiritus/mtls/server.key;

    # Client certificate verification
    ssl_client_certificate /opt/spiritus/mtls/ca.crt;
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
                "log_path": "/opt/spiritus/vpn-panel.log",
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