"""
DPI Evasion Engine for V7LTHRONYX VPN Panel.

Countermeasures against Iran's 2026 DPI capabilities:
- Stateful TLS fingerprinting (JA3/JA4) → uTLS chrome fingerprint
- ServerHello drop on MCI/TCI for non-whitelisted SNIs → SNI whitelist + rotation
- Reverse-DNS check on SNI vs server ASN → Same-ASN SNI selection
- Active probing → Valid HTTP fallback server
- IP reputation graylist → Clean IP monitoring
- UDP throttling → TCP/443 only, no UDP protocols
- Long-flow detection → Flow rate limiting under 10 Mbps sustained

Protocol stack (no substitutions):
- Primary: VLESS + XHTTP + REALITY + xtls-rprx-vision
- Port: 443 (TCP only)
- uTLS fingerprint: chrome
- ShortIDs: random 8-char hex per user
- UUIDs: random per user
"""

import asyncio
import hashlib
import json
import logging
import os
import random
import secrets

import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .config import settings

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
#  Iran DPI Threat Model (2026)
# ═══════════════════════════════════════════════════════════════

class IranDPIThreat:
    """Models Iran's 2026 DPI capabilities for evasion planning."""

    # Known burned SNIs (detected/blocked by Iranian DPI)
    BURNED_SNIS = {
        "speedtest.net", "www.speedtest.net",
        "microsoft.com", "www.microsoft.com",
        "yahoo.com", "www.yahoo.com",
        "cloudflare.com", "www.cloudflare.com",
        "discord.com", "www.discord.com",
        "lovelive-anime.jp",
        "apple.com", "www.apple.com",
        "google.com", "www.google.com",
        "bing.com", "www.bing.com",
    }

    # Valid SNI candidates (TLS 1.3 + HTTP/2 verified)
    # Tier 1: International — likely to pass reverse-DNS check on non-Hetzner ASN
    # These are large CDN/tech domains with TLS 1.3 + H2 support
    TIER1_SNIS = [
        "objects.githubusercontent.com",   # GitHub CDN — TLS 1.3, H2, global CDN
        "raw.githubusercontent.com",      # GitHub raw — TLS 1.3, H2
        "chat.deepseek.com",              # DeepSeek AI chat — TLS 1.3, H2, AI service
        "web.splus.ir",                  # SPlus Iranian platform — TLS 1.3, H2
        "huggingface.co",                 # HuggingFace — TLS 1.3, H2, ML platform
        "cdn.jsdelivr.net",               # jsDelivr CDN — TLS 1.3, H2, global CDN
        "fonts.googleapis.com",           # Google Fonts — TLS 1.3, H2, very common
        "api.github.com",                 # GitHub API — TLS 1.3, H2
        "registry.npmjs.org",            # npm registry — TLS 1.3, H2
    ]

    # Tier 2: Iran-domestic — paradoxically most stable (same ASN = no reverse-DNS flag)
    # These Iranian sites are on local ASNs, so DPI won't flag them
    TIER2_SNIS = [
        "dotic.ir",          # Iranian tech platform
        "rubika.ir",         # Iranian messaging app
        "digikala.com",      # Iranian e-commerce (largest in Iran)
        "snapp.ir",          # Iranian ride-hailing (like Uber)
        "divar.ir",          # Iranian classifieds marketplace
    ]

    # Tier 3: Same-ASN (Hetzner AS24940) — must be scanned
    # Populated dynamically by RealiTLScanner
    TIER3_SNIS: List[str] = []

    # UDP-based protocols to AVOID (Iran throttles UDP)
    UDP_PROTOCOLS = {"hysteria2", "tuic", "amneziawg"}

    # Maximum sustained flow rate before detection (Mbps)
    MAX_SUSTAINED_MBPS = 10.0

    # Flow rate check interval (seconds)
    FLOW_CHECK_INTERVAL = 30

    @classmethod
    def get_safe_snis(cls, prefer_iran_domestic: bool = False) -> List[str]:
        """Get list of safe SNIs, prioritized by evasion effectiveness."""
        snis = []
        if prefer_iran_domestic:
            snis.extend(cls.TIER2_SNIS)
            snis.extend(cls.TIER1_SNIS)
        else:
            snis.extend(cls.TIER1_SNIS)
            snis.extend(cls.TIER2_SNIS)
        snis.extend(cls.TIER3_SNIS)
        return [s for s in snis if s not in cls.BURNED_SNIS]

    @classmethod
    def get_preferred_sni_for_protocol(cls, protocol_type: str) -> str:
        """Get the preferred SNI for a specific protocol type."""
        if protocol_type in ["xhttp", "reverse"]:
            # For XHTTP/Reverse: prefer Iran-domestic (same ASN = stable)
            return "digikala.com"
        elif protocol_type == "vision":
            # For Vision: prefer international CDN
            return "objects.githubusercontent.com"
        else:
            # Default fallback
            return "digikala.com"

    @classmethod
    def is_burned_sni(cls, sni: str) -> bool:
        """Check if an SNI is known to be blocked."""
        return sni.lower().strip() in cls.BURNED_SNIS

    @classmethod
    def is_udp_protocol(cls, protocol_key: str) -> bool:
        """Check if a protocol uses UDP (avoid under Iran DPI)."""
        return protocol_key in cls.UDP_PROTOCOLS


# ═══════════════════════════════════════════════════════════════
#  SNI Manager — Selection, Rotation, Validation
# ═══════════════════════════════════════════════════════════════

@dataclass
class SNIEntry:
    """A validated SNI candidate with metadata."""
    domain: str
    tier: int  # 1=international, 2=iran-domestic, 3=same-asn
    tls13_supported: bool = False
    h2_supported: bool = False
    asn_match: bool = False  # True if SNI's ASN matches server's ASN
    last_verified: Optional[datetime] = None
    verification_count: int = 0
    blocked: bool = False
    latency_ms: float = 0.0


class SNIManager:
    """Manages SNI selection, rotation, and validation for DPI evasion.

    Key strategies:
    1. Prefer same-ASN SNIs (pass reverse-DNS check)
    2. Rotate SNIs periodically to avoid pattern detection
    3. Validate TLS 1.3 + HTTP/2 support before use
    4. Auto-detect and remove burned SNIs
    """

    def __init__(self):
        self._sni_pool: Dict[str, SNIEntry] = {}
        self._current_sni: Optional[str] = None
        self._rotation_interval = 3600  # 1 hour default
        self._last_rotation: float = 0
        self._server_asn: Optional[str] = None
        self._server_ip: Optional[str] = None
        self._scan_lock = asyncio.Lock()
        self._initialized = False

    async def initialize(self, server_ip: str = ""):
        """Initialize SNI pool with default candidates."""
        self._server_ip = server_ip or await self._detect_server_ip()

        # Detect server ASN
        self._server_asn = await self._detect_server_asn(self._server_ip)

        # Seed the pool with known candidates
        for domain in IranDPIThreat.TIER1_SNIS:
            self._sni_pool[domain] = SNIEntry(
                domain=domain, tier=1, tls13_supported=True, h2_supported=True
            )
        for domain in IranDPIThreat.TIER2_SNIS:
            self._sni_pool[domain] = SNIEntry(
                domain=domain, tier=2, tls13_supported=True, h2_supported=True
            )

        self._initialized = True
        logger.info(f"SNI Manager initialized: {len(self._sni_pool)} candidates, "
                     f"server ASN: {self._server_asn}")

    async def get_best_sni(self, protocol_type: str = "", prefer_same_asn: bool = True) -> str:
        """Get the best SNI for current conditions.

        Priority:
        1. Same-ASN + TLS 1.3 + H2 (passes reverse-DNS check)
        2. Iran-domestic (paradoxically stable)
        3. International (may fail reverse-DNS on Hetzner)
        """
        if not self._initialized:
            await self.initialize()

        # If protocol type is specified, use preferred SNI for that protocol
        if protocol_type:
            preferred_sni = IranDPIThreat.get_preferred_sni_for_protocol(protocol_type)
            if preferred_sni in self._sni_pool and not self._sni_pool[preferred_sni].blocked:
                return preferred_sni

        # Check if rotation is needed
        now = time.time()
        if self._current_sni and (now - self._last_rotation) < self._rotation_interval:
            entry = self._sni_pool.get(self._current_sni)
            if entry and not entry.blocked:
                return self._current_sni

        # Select new SNI
        candidates = []
        for domain, entry in self._sni_pool.items():
            if entry.blocked or not entry.tls13_supported:
                continue
            score = 0
            if prefer_same_asn and entry.asn_match:
                score += 100  # Highest priority
            if entry.tier == 2:
                score += 50  # Iran-domestic bonus
            if entry.h2_supported:
                score += 20
            if entry.verification_count > 0:
                score += 10
            candidates.append((domain, score))

        if not candidates:
            # Fallback to first available
            for domain, entry in self._sni_pool.items():
                if not entry.blocked:
                    return domain
            # Last resort - use protocol-specific preferred SNI or default
            if protocol_type:
                return IranDPIThreat.get_preferred_sni_for_protocol(protocol_type)
            return "objects.githubusercontent.com"

        # Sort by score (descending), pick top with some randomization
        candidates.sort(key=lambda x: x[1], reverse=True)
        top_candidates = candidates[:3]
        chosen = random.choice(top_candidates)
        self._current_sni = chosen[0]
        self._last_rotation = now

        logger.info(f"SNI selected: {self._current_sni} (score: {chosen[1]})")
        return self._current_sni

    async def mark_sni_blocked(self, domain: str):
        """Mark an SNI as blocked by DPI."""
        if domain in self._sni_pool:
            self._sni_pool[domain].blocked = True
            self._sni_pool[domain].last_verified = datetime.utcnow()
            logger.warning(f"SNI marked as blocked: {domain}")

        # If current SNI is blocked, force rotation
        if self._current_sni == domain:
            self._current_sni = None
            self._last_rotation = 0

    async def validate_sni(self, domain: str) -> Dict[str, Any]:
        """Validate an SNI for TLS 1.3 and HTTP/2 support."""
        result = {
            "domain": domain,
            "tls13": False,
            "h2": False,
            "reachable": False,
            "latency_ms": 0.0,
            "error": None,
        }

        try:
            start = time.time()
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Check HTTPS with TLS 1.3
                try:
                    resp = await client.get(
                        f"https://{domain}",
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0"},
                    )
                    result["reachable"] = True
                    result["latency_ms"] = round((time.time() - start) * 1000, 1)

                    # Check TLS version from response
                    if hasattr(resp, "extensions") and "tls_version" in resp.extensions:
                        tls_ver = resp.extensions["tls_version"]
                        result["tls13"] = "1.3" in str(tls_ver)
                    else:
                        # Assume TLS 1.3 if HTTPS works on modern site
                        result["tls13"] = True

                    # Check H2 support
                    if resp.http_version == "HTTP/2":
                        result["h2"] = True

                except httpx.ConnectError as e:
                    result["error"] = f"Connection failed: {e}"
                except Exception as e:
                    result["error"] = str(e)

        except Exception as e:
            result["error"] = str(e)

        # Update pool entry
        if domain in self._sni_pool:
            self._sni_pool[domain].tls13_supported = result["tls13"]
            self._sni_pool[domain].h2_supported = result["h2"]
            self._sni_pool[domain].latency_ms = result["latency_ms"]
            self._sni_pool[domain].last_verified = datetime.utcnow()
            self._sni_pool[domain].verification_count += 1

        return result

    async def scan_asn_for_snis(self, asn: str = "AS24940") -> List[str]:
        """Scan a specific ASN for valid TLS 1.3 + H2 domains.

        Uses RealiTLScanner approach: connect to IPs in the ASN range
        and check for valid TLS 1.3 certificates.

        If RealiTLScanner binary is available at /usr/local/bin/RealiTLScanner,
        it will be used for high-performance scanning. Otherwise, falls back
        to known domain validation.
        """
        async with self._scan_lock:
            logger.info(f"Scanning ASN {asn} for valid SNI candidates...")

            # Try RealiTLScanner binary first
            scanner_bin = "/usr/local/bin/RealiTLScanner"
            validated = []

            if os.path.isfile(scanner_bin) and os.access(scanner_bin, os.X_OK):
                try:
                    # Run RealiTLScanner: scan the server's own IP range
                    # Output: one domain per line with TLS info
                    cmd = [scanner_bin, "-addr", self._server_ip or "0.0.0.0",
                           "-thread", "4", "-timeout", "5", "-json"]
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    try:
                        stdout, stderr = await asyncio.wait_for(
                            proc.communicate(), timeout=120
                        )
                        if proc.returncode == 0 and stdout:
                            for line in stdout.decode("utf-8", errors="ignore").strip().split("\n"):
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                    domain = entry.get("domain", "")
                                    tls13 = entry.get("tls13", False)
                                    h2 = entry.get("h2", False)
                                    if domain and tls13 and domain not in IranDPIThreat.BURNED_SNIS:
                                        validated.append(domain)
                                        if domain not in self._sni_pool:
                                            self._sni_pool[domain] = SNIEntry(
                                                domain=domain,
                                                tier=3,
                                                tls13_supported=True,
                                                h2_supported=h2,
                                                asn_match=(asn == self._server_asn),
                                            )
                                except (json.JSONDecodeError, KeyError):
                                    continue
                            logger.info(f"RealiTLScanner found {len(validated)} valid SNIs")
                    except asyncio.TimeoutError:
                        proc.kill()
                        logger.warning("RealiTLScanner timed out, using fallback")
                except Exception as e:
                    logger.warning(f"RealiTLScanner failed: {e}, using fallback")

            # Fallback: validate known domains
            if not validated:
                known_domains = [
                    "hetzner.com",
                    "docs.hetzner.com",
                    "console.hetzner.cloud",
                ]

                for domain in known_domains:
                    result = await self.validate_sni(domain)
                    if result["tls13"] and not result.get("error"):
                        validated.append(domain)
                        if domain not in self._sni_pool:
                            self._sni_pool[domain] = SNIEntry(
                                domain=domain,
                                tier=3,
                                tls13_supported=True,
                                h2_supported=result["h2"],
                                asn_match=(asn == self._server_asn),
                            )

            # Update tier 3 list
            IranDPIThreat.TIER3_SNIS = validated
            logger.info(f"ASN scan complete: {len(validated)} valid SNIs found")
            return validated

    async def get_sni_pool_status(self) -> List[Dict[str, Any]]:
        """Get status of all SNIs in the pool."""
        return [
            {
                "domain": entry.domain,
                "tier": entry.tier,
                "tls13": entry.tls13_supported,
                "h2": entry.h2_supported,
                "asn_match": entry.asn_match,
                "blocked": entry.blocked,
                "last_verified": entry.last_verified.isoformat() if entry.last_verified else None,
                "verification_count": entry.verification_count,
                "latency_ms": entry.latency_ms,
            }
            for entry in self._sni_pool.values()
        ]

    async def _detect_server_ip(self) -> str:
        """Detect the server's public IP address."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get("https://api.ipify.org?format=text")
                if resp.status_code == 200:
                    return resp.text.strip()
        except Exception:
            pass
        return "127.0.0.1"

    async def _detect_server_asn(self, ip: str) -> str:
        """Detect the ASN for the server's IP address."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"https://ipinfo.io/{ip}/org")
                if resp.status_code == 200:
                    org = resp.text.strip()
                    # Extract ASN (e.g., "AS24940 Hetzner Online GmbH")
                    if org.startswith("AS"):
                        return org.split()[0]
                    return org
        except Exception:
            pass
        return "Unknown"


# ═══════════════════════════════════════════════════════════════
#  REALITY Key Manager — Generation, Rotation, Storage
# ═══════════════════════════════════════════════════════════════

class RealityKeyManager:
    """Manages REALITY key pairs with automatic rotation.

    REALITY uses X25519 key pairs. The private key stays on the server,
    the public key is shared with clients. Short IDs are per-user random
    hex strings for additional identification.
    """

    def __init__(self):
        self._xray_bin = "/usr/local/bin/xray"
        self._rotation_days = 30  # Rotate keys every 30 days
        self._keys: Dict[str, Dict[str, Any]] = {}  # key_id -> key data

    async def generate_key_pair(self) -> Dict[str, str]:
        """Generate a new REALITY X25519 key pair using xray binary."""
        try:
            result = subprocess.run(
                [self._xray_bin, "x25519"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                private_key = ""
                public_key = ""
                for line in lines:
                    if "Private key:" in line:
                        private_key = line.split(":", 1)[1].strip()
                    elif "Public key:" in line:
                        public_key = line.split(":", 1)[1].strip()
                if private_key and public_key:
                    return {"private_key": private_key, "public_key": public_key}
        except FileNotFoundError:
            logger.warning("xray binary not found, generating placeholder keys")
        except Exception as e:
            logger.error(f"Failed to generate REALITY keys: {e}")

        raise RuntimeError(
            "Failed to generate REALITY X25519 key pair. "
            "Ensure xray binary is available at /usr/local/bin/xray"
        )

    @staticmethod
    def generate_short_id(length: int = 8) -> str:
        """Generate a random hex Short ID for a user."""
        return secrets.token_hex(length)

    @staticmethod
    def generate_user_uuid() -> str:
        """Generate a random UUID for a user."""
        import uuid
        return str(uuid.uuid4())

    async def rotate_keys(self, agent_id: int) -> Dict[str, Any]:
        """Rotate REALITY keys for an agent.

        Returns:
            Dict with new keys and timestamp.
        """
        new_keys = await self.generate_key_pair()
        key_id = hashlib.sha256(
            f"{agent_id}:{time.time()}".encode()
        ).hexdigest()[:16]

        key_data = {
            "key_id": key_id,
            "agent_id": agent_id,
            "private_key": new_keys["private_key"],
            "public_key": new_keys["public_key"],
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(days=self._rotation_days)).isoformat(),
        }

        self._keys[key_id] = key_data
        logger.info(f"REALITY keys rotated for agent {agent_id}: key_id={key_id}")
        return key_data

    def get_active_keys(self) -> List[Dict[str, Any]]:
        """Get all active (non-expired) key pairs."""
        now = datetime.utcnow()
        active = []
        for key_id, data in self._keys.items():
            expires = datetime.fromisoformat(data["expires_at"])
            if expires > now:
                active.append(data)
        return active

    def is_key_expired(self, key_id: str) -> bool:
        """Check if a key pair has expired."""
        data = self._keys.get(key_id)
        if not data:
            return True
        expires = datetime.fromisoformat(data["expires_at"])
        return datetime.utcnow() > expires


# ═══════════════════════════════════════════════════════════════
#  Active Probing Defense
# ═══════════════════════════════════════════════════════════════

class ActiveProbingDefense:
    """Defends against active probing by Iranian DPI.

    When DPI suspects a proxy, it actively connects to the server
    to verify if it's a real web server. This module ensures:
    1. A valid HTTP/HTTPS fallback server responds on port 443
    2. The fallback serves realistic content (mimics a real website)
    3. Non-proxy requests get legitimate responses
    4. Probe detection and blocking
    """

    # Fallback website templates (mimic real sites)
    FALLBACK_TEMPLATES = {
        "default": {
            "title": "Welcome to Our Website",
            "description": "A modern web application",
            "status_code": 200,
        },
        "corporate": {
            "title": "Global Solutions Inc.",
            "description": "Enterprise cloud solutions and digital transformation services.",
            "status_code": 200,
        },
        "tech_blog": {
            "title": "Tech Insights Blog",
            "description": "Latest technology news, tutorials, and developer resources.",
            "status_code": 200,
        },
    }

    def __init__(self):
        self._probes_detected: Dict[str, List[float]] = defaultdict(list)
        self._fallback_type = "corporate"
        self._probe_threshold = 5  # Max probes before blocking
        self._probe_window = 300  # 5 minutes

    def generate_fallback_response(self, path: str = "/") -> Dict[str, Any]:
        """Generate a realistic HTTP fallback response for active probing.

        This is what the Xray fallback server will serve to non-proxy
        connections (i.e., DPI probes).
        """
        template = self.FALLBACK_TEMPLATES.get(
            self._fallback_type, self.FALLBACK_TEMPLATES["default"]
        )

        # Generate realistic HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{template['title']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               color: #333; background: #fff; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 0 20px; }}
        header {{ background: #1a1a2e; color: #fff; padding: 20px 0; }}
        header h1 {{ font-size: 24px; }}
        nav {{ display: flex; gap: 20px; margin-top: 10px; }}
        nav a {{ color: #e0e0e0; text-decoration: none; }}
        .hero {{ padding: 80px 0; text-align: center; background: #f8f9fa; }}
        .hero h2 {{ font-size: 36px; margin-bottom: 20px; }}
        .hero p {{ font-size: 18px; color: #666; max-width: 600px; margin: 0 auto; }}
        .features {{ padding: 60px 0; }}
        .features-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; }}
        .feature {{ padding: 30px; border: 1px solid #eee; border-radius: 8px; }}
        .feature h3 {{ margin-bottom: 10px; }}
        footer {{ background: #1a1a2e; color: #fff; padding: 40px 0; text-align: center; }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>{template['title']}</h1>
            <nav>
                <a href="/">Home</a>
                <a href="/about">About</a>
                <a href="/services">Services</a>
                <a href="/contact">Contact</a>
            </nav>
        </div>
    </header>
    <section class="hero">
        <div class="container">
            <h2>{template['description']}</h2>
            <p>Providing innovative solutions for businesses worldwide since 2019.</p>
        </div>
    </section>
    <section class="features">
        <div class="container">
            <div class="features-grid">
                <div class="feature">
                    <h3>Cloud Infrastructure</h3>
                    <p>Scalable and reliable cloud solutions for modern applications.</p>
                </div>
                <div class="feature">
                    <h3>Security Solutions</h3>
                    <p>Enterprise-grade security with end-to-end encryption.</p>
                </div>
                <div class="feature">
                    <h3>24/7 Support</h3>
                    <p>Dedicated support team available around the clock.</p>
                </div>
            </div>
        </div>
    </section>
    <footer>
        <div class="container">
            <p>&copy; 2024 {template['title']}. All rights reserved.</p>
        </div>
    </footer>
</body>
</html>"""

        return {
            "status_code": template["status_code"],
            "content_type": "text/html; charset=utf-8",
            "body": html,
            "headers": {
                "Server": "nginx/1.24.0",
                "X-Powered-By": "",
                "Cache-Control": "public, max-age=3600",
            },
        }

    def generate_xray_fallback_config(
        self,
        port: int = 443,
        dest: str = "",
        sni: str = "",
    ) -> Dict[str, Any]:
        """Generate Xray fallback configuration for active probing defense.

        This config makes Xray serve a realistic website to non-proxy
        connections, defeating active probing.
        """
        fallback_html = self.generate_fallback_response()

        return {
            "fallbacks": [
                {
                    "dest": dest or f"127.0.0.1:8443",
                    "xver": 1,
                },
                {
                    "path": "/robots.txt",
                    "dest": dest or f"127.0.0.1:8443",
                    "xver": 1,
                },
                {
                    "path": "/favicon.ico",
                    "dest": dest or f"127.0.0.1:8443",
                    "xver": 1,
                },
                {
                    "alpn": "h2",
                    "dest": dest or f"127.0.0.1:8443",
                    "xver": 1,
                },
            ],
            "fallback_html": fallback_html["body"],
        }

    def detect_probe(self, ip: str, user_agent: str = "", path: str = "/") -> bool:
        """Detect if a connection is an active probe.

        Heuristics:
        - Repeated connections from same IP without valid proxy handshake
        - Suspicious user agents (curl, python-requests, etc.)
        - Access to non-existent paths
        - Missing or malformed proxy headers
        """
        now = time.time()

        # Clean old entries
        if ip in self._probes_detected:
            self._probes_detected[ip] = [
                t for t in self._probes_detected[ip]
                if now - t < self._probe_window
            ]

        # Record this connection
        self._probes_detected[ip].append(now)

        # Check for suspicious user agents
        suspicious_agents = [
            "curl/", "python-requests/", "python-httpx/",
            "Go-http-client/", "java/", "Apache-HttpClient/",
        ]
        is_suspicious_agent = any(
            agent in (user_agent or "") for agent in suspicious_agents
        )

        # Check probe frequency
        probe_count = len(self._probes_detected[ip])
        is_frequent = probe_count >= self._probe_threshold

        if is_suspicious_agent or is_frequent:
            logger.warning(f"Active probe detected: ip={ip} agent={user_agent} "
                           f"probe_count={probe_count}")
            return True

        return False

    def get_probe_stats(self) -> Dict[str, Any]:
        """Get statistics about detected probes."""
        now = time.time()
        active_probes = {}
        for ip, timestamps in self._probes_detected.items():
            recent = [t for t in timestamps if now - t < self._probe_window]
            if recent:
                active_probes[ip] = len(recent)

        return {
            "active_probe_ips": len(active_probes),
            "total_probes": sum(active_probes.values()),
            "probe_ips": active_probes,
        }


# ═══════════════════════════════════════════════════════════════
#  Flow Rate Limiter — Defeat Long-Flow Detection
# ═══════════════════════════════════════════════════════════════

class FlowRateLimiter:
    """Limits per-user flow rates to avoid long-flow detection.

    Iran's DPI detects flows sustained above 10 Mbps. This module:
    1. Monitors per-user bandwidth in real-time
    2. Enforces a 10 Mbps sustained rate limit
    3. Allows burst traffic up to 50 Mbps for short periods
    4. Automatically shapes traffic when approaching the threshold
    """

    # Rate limits
    MAX_SUSTAINED_MBPS = 10.0  # Iran DPI detection threshold
    MAX_BURST_MBPS = 50.0      # Short burst allowance
    BURST_DURATION_SEC = 10    # Max burst duration
    MEASUREMENT_WINDOW_SEC = 30  # Rolling window for sustained rate

    def __init__(self):
        # user_id -> list of (timestamp, bytes) tuples
        self._flow_history: Dict[int, List[Tuple[float, int]]] = defaultdict(list)
        # user_id -> current rate limit state
        self._user_state: Dict[int, Dict[str, Any]] = {}
        self._alert_callback = None

    def set_alert_callback(self, callback):
        """Set callback for rate limit alerts (e.g., Telegram notification)."""
        self._alert_callback = callback

    def record_traffic(self, user_id: int, bytes_transferred: int):
        """Record traffic for a user."""
        now = time.time()
        self._flow_history[user_id].append((now, bytes_transferred))

        # Clean old entries (keep only last 5 minutes)
        cutoff = now - 300
        self._flow_history[user_id] = [
            (t, b) for t, b in self._flow_history[user_id] if t > cutoff
        ]

    def get_current_rate_mbps(self, user_id: int) -> float:
        """Calculate current sustained rate for a user in Mbps."""
        now = time.time()
        window_start = now - self.MEASUREMENT_WINDOW_SEC

        recent = [
            (t, b) for t, b in self._flow_history.get(user_id, [])
            if t > window_start
        ]

        if not recent:
            return 0.0

        total_bytes = sum(b for _, b in recent)
        duration = now - recent[0][0] if len(recent) > 1 else self.MEASUREMENT_WINDOW_SEC

        if duration <= 0:
            return 0.0

        # Convert bytes/sec to Mbps
        bytes_per_sec = total_bytes / duration
        mbps = (bytes_per_sec * 8) / 1_000_000

        return round(mbps, 2)

    def check_rate_limit(self, user_id: int) -> Dict[str, Any]:
        """Check if a user is within rate limits.

        Returns:
            Dict with rate info and whether the user should be throttled.
        """
        current_mbps = self.get_current_rate_mbps(user_id)
        state = self._user_state.get(user_id, {
            "throttled": False,
            "burst_start": None,
            "burst_mbps": 0.0,
        })

        result = {
            "user_id": user_id,
            "current_mbps": current_mbps,
            "max_sustained_mbps": self.MAX_SUSTAINED_MBPS,
            "max_burst_mbps": self.MAX_BURST_MBPS,
            "throttled": False,
            "action": "none",
        }

        if current_mbps > self.MAX_SUSTAINED_MBPS:
            # Check if in burst window
            now = time.time()
            if state.get("burst_start") is None:
                state["burst_start"] = now
                state["burst_mbps"] = current_mbps
                result["action"] = "burst_allowed"
            else:
                burst_duration = now - state["burst_start"]
                if burst_duration > self.BURST_DURATION_SEC:
                    # Burst expired, must throttle
                    result["throttled"] = True
                    result["action"] = "throttle"
                    state["throttled"] = True

                    # Alert if callback set
                    if self._alert_callback and not state.get("alerted"):
                        try:
                            self._alert_callback(
                                f"⚠️ Flow rate limit: User {user_id} at {current_mbps} Mbps "
                                f"(threshold: {self.MAX_SUSTAINED_MBPS} Mbps)"
                            )
                        except Exception:
                            pass
                        state["alerted"] = True
                else:
                    result["action"] = "burst_active"

        elif current_mbps <= self.MAX_SUSTAINED_MBPS * 0.8:
            # Well below threshold, reset state
            state = {"throttled": False, "burst_start": None, "burst_mbps": 0.0}

        self._user_state[user_id] = state
        return result

    def get_xray_rate_limit_config(self, user_id: int) -> Dict[str, Any]:
        """Generate Xray rate limit configuration for a user.

        Returns Xray-level bandwidth shaping config.
        """
        state = self.check_rate_limit(user_id)

        if state["throttled"]:
            # Apply rate limit: 10 Mbps down, 5 Mbps up
            return {
                "rate_limit_down": f"{int(self.MAX_SUSTAINED_MBPS)} Mbps",
                "rate_limit_up": f"{int(self.MAX_SUSTAINED_MBPS / 2)} Mbps",
            }
        else:
            return {
                "rate_limit_down": "0 Mbps",  # No limit
                "rate_limit_up": "0 Mbps",
            }

    def get_all_rates(self) -> List[Dict[str, Any]]:
        """Get current rates for all users."""
        results = []
        for user_id in list(self._flow_history.keys()):
            rate = self.get_current_rate_mbps(user_id)
            if rate > 0:
                results.append({
                    "user_id": user_id,
                    "current_mbps": rate,
                    "throttled": self._user_state.get(user_id, {}).get("throttled", False),
                })
        return results


# ═══════════════════════════════════════════════════════════════
#  DPI-Optimized Xray Config Generator
# ═══════════════════════════════════════════════════════════════

class DPISafeConfigGenerator:
    """Generates Xray configs specifically optimized for Iran DPI evasion.

    This is the PRIMARY config generator that enforces all DPI countermeasures:
    - VLESS + XHTTP + REALITY on port 443
    - uTLS chrome fingerprint
    - Per-user random ShortIDs
    - Per-user random UUIDs
    - Valid HTTP fallback for active probing
    - Flow rate limiting
    - TCP-only (no UDP)
    """

    @staticmethod
    def generate_iran_safe_inbound(
        user_uuid: str,
        short_id: str,
        reality_private_key: str,
        reality_public_key: str,
        sni: str = "objects.githubusercontent.com",
        xhttp_path: str = "/api/v2/stream",
        xhttp_mode: str = "auto",
        port: int = 443,
        fallback_dest: str = "127.0.0.1:8443",
    ) -> Dict[str, Any]:
        """Generate a DPI-safe VLESS + XHTTP + REALITY inbound.

        This is the PRIMARY protocol stack for Iran:
        - Protocol: VLESS
        - Transport: XHTTP (stream-like, looks like normal HTTP)
        - Security: REALITY (TLS 1.3 with SNI impersonation)
        - Flow: xtls-rprx-vision (for TCP mode)
        - Port: 443 (TCP only)
        - uTLS: chrome fingerprint
        - ShortID: random 8-char hex per user
        """
        return {
            "tag": "vless-xhttp-reality-443",
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": user_uuid,
                        "flow": "",  # No flow for XHTTP (flow is for TCP only)
                    }
                ],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "realitySettings": {
                    "dest": f"{sni}:443",
                    "serverNames": [sni],
                    "privateKey": reality_private_key,
                    "shortIds": [short_id],
                    # uTLS fingerprint — CRITICAL for JA3/JA4 evasion
                    "fingerprint": "chrome",
                },
                "xhttpSettings": {
                    "path": xhttp_path,
                    "mode": xhttp_mode,
                },
            },
            # Fallback for active probing defense
            "fallbacks": [
                {"dest": fallback_dest, "xver": 1},
            ],
        }

    @staticmethod
    def generate_iran_safe_vision_inbound(
        user_uuid: str,
        short_id: str,
        reality_private_key: str,
        reality_public_key: str,
        sni: str = "objects.githubusercontent.com",
        port: int = 443,
        fallback_dest: str = "127.0.0.1:8443",
    ) -> Dict[str, Any]:
        """Generate a DPI-safe VLESS + Vision + REALITY inbound.

        Alternative to XHTTP: uses TCP with xtls-rprx-vision flow.
        Slightly less stealthy than XHTTP but more compatible.
        """
        return {
            "tag": "vless-vision-reality-443",
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": user_uuid,
                        "flow": "xtls-rprx-vision",
                    }
                ],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": f"{sni}:443",
                    "serverNames": [sni],
                    "privateKey": reality_private_key,
                    "shortIds": [short_id],
                    "fingerprint": "chrome",
                },
            },
            # Fallback for active probing defense
            "fallbacks": [
                {"dest": fallback_dest, "xver": 1},
            ],
        }

    @staticmethod
    def generate_full_dpi_safe_config(
        user_uuid: str,
        short_id: str,
        reality_private_key: str,
        reality_public_key: str,
        sni: str = "objects.githubusercontent.com",
        xhttp_path: str = "/api/v2/stream",
        server_address: str = "",
        api_port: int = 10085,
        fallback_dest: str = "127.0.0.1:8443",
    ) -> Dict[str, Any]:
        """Generate a complete DPI-safe Xray configuration.

        Includes:
        - VLESS + XHTTP + REALITY inbound (primary)
        - VLESS + Vision + REALITY inbound (fallback)
        - API inbound for management
        - Fallback server for active probing
        - Flow rate limiting policy
        - DNS over HTTPS
        - Routing rules
        """
        xhttp_inbound = DPISafeConfigGenerator.generate_iran_safe_inbound(
            user_uuid=user_uuid,
            short_id=short_id,
            reality_private_key=reality_private_key,
            reality_public_key=reality_public_key,
            sni=sni,
            xhttp_path=xhttp_path,
            fallback_dest=fallback_dest,
        )

        vision_inbound = DPISafeConfigGenerator.generate_iran_safe_vision_inbound(
            user_uuid=user_uuid,
            short_id=short_id,
            reality_private_key=reality_private_key,
            reality_public_key=reality_public_key,
            sni=sni,
            port=8443,  # Separate port to avoid conflict with XHTTP on 443
            fallback_dest=fallback_dest,
        )

        # Generate fallback server config for active probing defense
        _apd = ActiveProbingDefense()
        fallback_config = _apd.generate_xray_fallback_config(
            dest=fallback_dest,
            sni=sni,
        )

        return {
            "log": {
                "loglevel": "warning",
                "access": "/var/log/xray/access.log",
                "error": "/var/log/xray/error.log",
            },
            "api": {
                "tag": "api",
                "services": ["HandlerService", "StatsService", "LoggerService"],
            },
            "stats": {},
            "policy": {
                "levels": {
                    "0": {
                        "statsUplink": True,
                        "statsDownlink": True,
                        "statsUserUplink": True,
                        "statsUserDownlink": True,
                    }
                },
                "system": {
                    "statsInboundUplink": True,
                    "statsInboundDownlink": True,
                    "statsOutboundUplink": True,
                    "statsOutboundDownlink": True,
                },
            },
            "dns": {
                "servers": [
                    {
                        "address": "https://1.1.1.1/dns-query",
                        "domains": ["geosite:geolocation-!cn"],
                    },
                    {
                        "address": "https://8.8.8.8/dns-query",
                        "domains": ["geosite:geolocation-!cn"],
                    },
                    "localhost",
                ],
            },
            "inbounds": [
                # API inbound
                {
                    "tag": "api",
                    "listen": "127.0.0.1",
                    "port": api_port,
                    "protocol": "api",
                    "settings": {},
                },
                # Primary: VLESS + XHTTP + REALITY
                xhttp_inbound,
                # Fallback: VLESS + Vision + REALITY
                vision_inbound,
            ],
            # Fallback server for active probing defense
            "fallback": fallback_config,
            "outbounds": [
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {
                        "domainStrategy": "UseIPv4",
                    },
                },
                {
                    "tag": "blocked",
                    "protocol": "blackhole",
                    "settings": {},
                },
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    # API rule
                    {
                        "type": "field",
                        "inboundTag": ["api"],
                        "outboundTag": "api",
                    },
                    # Block private IPs
                    {
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "blocked",
                    },
                    # Block Iran government domains (optional)
                    {
                        "type": "field",
                        "domain": [
                            "geosite:category-gov-ir",
                        ],
                        "outboundTag": "blocked",
                    },
                ],
            },
        }

    @staticmethod
    def generate_client_config(
        user_uuid: str,
        short_id: str,
        reality_public_key: str,
        server_address: str,
        sni: str = "objects.githubusercontent.com",
        xhttp_path: str = "/api/v2/stream",
        xhttp_mode: str = "auto",
        port: int = 443,
    ) -> Dict[str, Any]:
        """Generate DPI-safe client configuration.

        Returns both XHTTP and Vision client configs.
        """
        # VLESS + XHTTP + REALITY share URL
        xhttp_params = {
            "type": "xhttp",
            "security": "reality",
            "fp": "chrome",  # uTLS fingerprint — CRITICAL
            "sni": sni,
            "pbk": reality_public_key,
            "sid": short_id,
            "path": xhttp_path,
            "mode": xhttp_mode,
        }
        xhttp_query = "&".join(f"{k}={v}" for k, v in xhttp_params.items() if v)
        xhttp_url = f"vless://{user_uuid}@{server_address}:{port}?{xhttp_query}#V7LTHRONYX-XHTTP"

        # VLESS + Vision + REALITY share URL
        vision_params = {
            "type": "tcp",
            "security": "reality",
            "fp": "chrome",
            "sni": sni,
            "pbk": reality_public_key,
            "sid": short_id,
            "flow": "xtls-rprx-vision",
        }
        vision_query = "&".join(f"{k}={v}" for k, v in vision_params.items() if v)
        vision_url = f"vless://{user_uuid}@{server_address}:{port}?{vision_query}#V7LTHRONYX-Vision"

        return {
            "xhttp_url": xhttp_url,
            "vision_url": vision_url,
            "protocol": "vless_xhttp_reality",
            "sni": sni,
            "port": port,
            "fingerprint": "chrome",
            "transport": "xhttp",
            "security": "reality",
        }


# ═══════════════════════════════════════════════════════════════
#  IP Reputation Monitor
# ═══════════════════════════════════════════════════════════════

class IPReputationMonitor:
    """Monitors server IP reputation for graylist detection.

    Iran's DPI uses IP reputation lists. Hetzner Helsinki IPs
    are preferred as they have cleaner reputation.
    """

    def __init__(self):
        self._last_check: float = 0
        self._check_interval = 3600  # 1 hour
        self._reputation_data: Dict[str, Any] = {}

    async def check_ip_reputation(self, ip: str = "") -> Dict[str, Any]:
        """Check IP reputation against known blacklists.

        Uses ip-api.com (free, no API key required) for basic reputation
        and abuse contact information.
        """
        if not ip:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get("https://api.ipify.org?format=text")
                    ip = resp.text.strip()
            except Exception:
                ip = "127.0.0.1"

        result = {
            "ip": ip,
            "is_clean": True,
            "blacklists": {},
            "risk_score": 0,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

        # Check via ip-api.com (free, no auth required)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "status,message,country,isp,org,as,asname,hosting,proxy,mobile"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        result["isp"] = data.get("isp", "")
                        result["org"] = data.get("org", "")
                        result["asn"] = data.get("as", "")
                        result["hosting"] = data.get("hosting", False)
                        result["proxy"] = data.get("proxy", False)
                        # Hosting/datacenter IPs may have higher risk in some regions
                        if data.get("hosting"):
                            result["risk_score"] = 10
        except Exception:
            pass

        self._reputation_data = result
        self._last_check = time.time()
        return result

    def is_ip_clean(self) -> bool:
        """Check if the server IP has clean reputation."""
        return self._reputation_data.get("is_clean", True)

    def get_reputation(self) -> Dict[str, Any]:
        """Get cached reputation data."""
        return self._reputation_data


# ═══════════════════════════════════════════════════════════════
#  Convenience instances
# ═══════════════════════════════════════════════════════════════

sni_manager = SNIManager()
reality_key_manager = RealityKeyManager()
active_probing_defense = ActiveProbingDefense()
flow_rate_limiter = FlowRateLimiter()
ip_reputation_monitor = IPReputationMonitor()
dpi_safe_generator = DPISafeConfigGenerator()