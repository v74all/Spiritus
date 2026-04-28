# 🔐 Spiritus v2.0 - Security Architecture

## Overview

Spiritus v2.0 implements defense-in-depth security with multiple layers of protection:

1. **Authentication & Authorization**
2. **Network Security**
3. **Data Protection**
4. **Operational Security**
5. **Monitoring & Detection**

---

## 1️⃣ Authentication & Authorization

### Multi-Factor Authentication (MFA)

#### TOTP (Time-based One-Time Password)
- **Algorithm**: HMAC-SHA1, 6-digit codes
- **Setup**: Admin generates secret → User scans QR code with authenticator app
- **Verification**: Sliding window of ±1 time steps (30-second tokens)
- **Tools**: Google Authenticator, Authy, Microsoft Authenticator

```python
# Enable 2FA for admin user
TOTP Secret: JBSWY3DPEBLW64TMMQQ======
Provisioning URI: otpauth://totp/admin%40spiritus?secret=JBSWY3DPEBLW64TMMQQ%3D%3D%3D%3D&issuer=Spiritus
```

#### WebAuthn (Passwordless - Future)
- Support for FIDO2 hardware keys
- Face/Fingerprint recognition
- Backup codes

### Password Policy

**Argon2id Hashing**
```
Memory Cost: 65536 KB
Time Cost: 3 iterations
Parallelism: 4 threads
Hash Length: 32 bytes
Salt Length: 16 bytes
```

**Pepper**: Additional secret kept separate from database
```
Stored: hash(password + pepper + salt)
If DB compromised, pepper remains secret in app config
```

### JWT Token Management

#### Access Tokens
- **Expiration**: 30 minutes
- **Algorithm**: HS256
- **Claims**: `sub`, `exp`, `type`, `iat`

#### Refresh Tokens
- **Expiration**: 7 days
- **Rotation**: New refresh token issued with each access token refresh
- **Revocation**: Tracked in Redis with TTL

```python
access_token = create_access_token({"sub": "user123"})
refresh_token = create_refresh_token({"sub": "user123"})

# Token refresh
new_access = refresh_access_token(old_refresh)
new_refresh = create_refresh_token({"sub": "user123"})
```

#### Revocation List
- Stored in Redis with TTL matching token expiration
- Checked on every API call
- Automatic cleanup after expiry

---

## 2️⃣ Network Security

### TLS/mTLS

#### HTTPS Enforcement
- HSTS: `max-age=31536000; includeSubDomains`
- Preload list eligible
- Force redirect HTTP → HTTPS

#### Admin Panel mTLS (Optional)
- Client certificate validation
- Server certificate pinning
- Mutual authentication

### Security Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-XSS-Protection` | `1; mode=block` | XSS protection |
| `HSTS` | `max-age=31536000` | Enforce HTTPS |
| `CSP` | Restrictive policy | Prevent injection attacks |
| `COOP` | `same-origin` | Cross-origin opener policy |
| `CORP` | `cross-origin` | Cross-origin resource policy |
| `COEP` | `require-corp` | Cross-origin embedder policy |

### IP Allowlist

```python
# For admin endpoints (/api/admin/*)
ADMIN_IP_ALLOWLIST = [
    "10.0.0.0/8",
    "192.168.0.0/16",
    "YOUR_OFFICE_IP/32",
]

# Request from non-allowlisted IP → 403 Forbidden
```

### GeoIP Blocking

```python
# Optional: Block access from certain countries
ENABLE_GEO_BLOCKING = True
BLOCKED_COUNTRIES = ["KP", "IR", "SY"]  # ISO country codes

# Uses MaxMind GeoLite2 database
```

### Rate Limiting

- **Per IP**: 100 requests/minute
- **Per User**: 1000 requests/hour
- **Per Endpoint**: Custom thresholds for sensitive endpoints
- **Storage**: Redis with sliding window

```python
@app.post("/api/auth/login")
@rate_limit(requests=5, period=300)  # 5 attempts/5 minutes
async def login(credentials):
    pass
```

---

## 3️⃣ Data Protection

### Audit Logging with Hash-Chain

Inspired by Sigstore transparency logs, preventing retroactive tampering:

```python
# Each log entry contains hash of previous entry
Entry 1: {action: "login", prev_hash: "genesis", ...} → hash_1
Entry 2: {action: "create_user", prev_hash: hash_1, ...} → hash_2
Entry 3: {action: "delete_user", prev_hash: hash_2, ...} → hash_3

# If attacker modifies Entry 2, hash_2 changes, breaking Entry 3's chain
```

**Fields Logged**:
- Timestamp
- Admin ID + IP address
- Action + resource type
- Before/after state
- Success/failure + error details

**Retention**: 90 days (configurable)

### Honey Tokens

Decoy accounts for intrusion detection:

```python
HONEY_USERS = [
    {"username": "admin_backup", "uuid": "honey-admin-001"},
    {"username": "system_test", "uuid": "honey-test-001"},
]

# If attacker tries to login with honey account:
# 1. Accept login (appears successful)
# 2. Trigger alert in monitoring system
# 3. Log detailed intrusion info (IP, timestamp, attempts)
# 4. Optional: Honeypot routing (limited access)
```

### Secret Management

**Production Deployment**:
```bash
# Use HashiCorp Vault or cloud provider
$ vault kv put secret/spiritus/jwt_secret value="..."
$ vault kv put secret/spiritus/db_password value="..."

# Or use sops + age encryption
$ sops secrets.yml  # Edit encrypted YAML
```

**Development**:
```bash
# Use .env.local (git-ignored)
cp .env.example .env.local
export $(cat .env.local | xargs)
```

---

## 4️⃣ Operational Security

### Fail2ban Integration

Monitor audit logs and automatically block malicious IPs:

```python
# /etc/fail2ban/filter.d/spiritus.conf
[Definition]
failregex = .*admin_ip=<HOST>.*action=login.*success=false
ignoreregex =
maxretry = 5
findtime = 300
bantime = 3600
```

### Anomaly Detection

Detect suspicious user behavior:

```python
# Port Scan Detection
if destination_port in [22, 3306, 5432, 27017]:  # SSH, MySQL, PostgreSQL, MongoDB
    alert("User attempting database reconnaissance")

# Brute Force
if failed_login_attempts > 10 in past_hour:
    suspend_account("suspicious_activity")

# Unusual IP
if user_ip not in user.known_ips:
    require_2fa("new_location_detected")
```

### Egress Filtering

Block outbound connections to prevent abuse:

| Port | Service | Risk | Action |
|------|---------|------|--------|
| 25 | SMTP | Spam relay | Block |
| 23 | Telnet | Unencrypted | Block |
| 445 | SMB | Ransomware | Block |
| 139 | NetBIOS | Worm vector | Block |
| 3389 | RDP | Brute force | Block |

---

## 5️⃣ Monitoring & Detection

### Security Scanning

#### CI/CD Pipeline
```bash
# Code analysis
bandit -r app/  # Security issues in Python code
semgrep -f rules/ app/  # Pattern-based security scanning

# Dependency scanning
pip-audit  # Known vulnerabilities
trivy scan --severity HIGH,CRITICAL .  # Container image scanning

# Type checking
mypy app/ --strict  # Catch type-related bugs
```

#### Dependency Monitoring
- GitHub Dependabot: Automatic vulnerability alerts
- SBOM (Software Bill of Materials): CycloneDX format
- Supply chain verification

### Audit Log Monitoring

```python
# Prometheus metrics
spiritus_failed_logins_total  # Track login failures
spiritus_honey_token_triggered  # Intrusion alerts
spiritus_unauthorized_access_total  # Access control violations
spiritus_admin_actions_total  # All admin actions
```

### Incident Response

**Procedure**:
1. Alert triggered (threshold exceeded, honey token hit)
2. Automatic: Rate limit / IP block / account suspend
3. Manual: Alert sent to admin (email, Slack, PagerDuty)
4. Investigation: Query audit logs with hash-chain integrity
5. Remediation: Revoke tokens, reset passwords, update firewall rules

---

## 6️⃣ API Security Best Practices

### Input Validation

```python
from pydantic import BaseModel, Field, validator

class CreateUserRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=255, regex="^[a-zA-Z0-9_-]+$")
    traffic_limit_gb: float = Field(..., ge=0, le=10000)
    expire_days: int = Field(..., ge=1, le=365)
    
    @validator('name')
    def validate_name(cls, v):
        if v in HONEY_USERS:
            raise ValueError("Reserved username")
        return v
```

### Output Sanitization

```python
# Never expose internal details
class UserResponse(BaseModel):
    id: str
    name: str
    traffic_limit_gb: float
    expire_at: datetime
    
    # Don't include: password_hash, pepper, internal_notes
```

### CORS & CSRF

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://panel.example.com"],  # Whitelist only
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# CSRF Protection: SameSite=Strict cookies
response.set_cookie(
    "session",
    value=session_id,
    httponly=True,
    secure=True,
    samesite="strict",
)
```

---

## 7️⃣ Security Checklist

Before Production Deployment:

- [ ] HTTPS/TLS enabled with valid certificate
- [ ] DATABASE_URL using strong password
- [ ] SECRET_KEY & JWT_SECRET_KEY rotated to unique values
- [ ] Database user: least-privilege permissions
- [ ] Admin accounts: 2FA enabled
- [ ] IP allowlist configured for /api/admin
- [ ] Audit logging: enabled and monitored
- [ ] Backups: encrypted and air-gapped
- [ ] Fail2ban: configured and active
- [ ] SIEM: logs forwarded to ELK/Splunk
- [ ] Code scanning: passed security gates
- [ ] Dependency audit: no critical vulnerabilities
- [ ] Rate limiting: adjusted for your traffic patterns
- [ ] Monitoring: alerts configured
- [ ] Incident response plan: documented

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Sigstore Transparency Log](https://docs.sigstore.dev/)
- [TOTP RFC 6238](https://tools.ietf.org/html/rfc6238)
