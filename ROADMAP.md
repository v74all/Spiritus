# Spiritus Enhancement Roadmap

## 🔐 امنیت (اولویت ۱)

### Authentication & Authorization
- [ ] 2FA/TOTP برای ورود ادمین
- [ ] WebAuthn (Passkey) support
- [ ] Argon2id password hashing
- [ ] JWT + refresh token rotation
- [ ] Session revocation list
- [ ] IP allowlist for admin endpoints
- [ ] GeoIP blocking

### Network Security
- [ ] mTLS برای پنل ادمین
- [ ] HSTS + Preload
- [ ] Content Security Policy (CSP) سخت‌گیرانه
- [ ] COOP/CORP/COEP headers
- [ ] Fail2ban integration

### Data Protection
- [ ] Secret management (Vault/SOPS)
- [ ] Audit log با hash-chain
- [ ] Honey-tokens for intrusion detection
- [ ] Encrypted backup

### Security Scanning
- [ ] Bandit + Semgrep
- [ ] pip-audit + Trivy
- [ ] GitHub Dependabot
- [ ] CI/CD security gates

---

## 🛰️ پروتکل‌های جدید (اولویت ۲)

### Protocol Support
- [ ] Hysteria 2
- [ ] TUIC v5
- [ ] AmneziaWG
- [ ] WireGuard with obfuscation
- [ ] Sing-box backend
- [ ] ECH (Encrypted Client Hello)

### Traffic Obfuscation
- [ ] uTLS fingerprint rotation
- [ ] Auto protocol rotation
- [ ] Traffic morphing (WhatsApp/Zoom patterns)
- [ ] Snowflake/meek bridge fallback

---

## 🏗️ معماری و مقیاس‌پذیری (اولویت ۱)

### Framework Upgrade
- [ ] Flask → FastAPI
- [ ] Async/await support
- [ ] WebSocket support
- [ ] Automatic API docs

### Database Layer
- [ ] PostgreSQL migration
- [ ] SQLAlchemy 2.0
- [ ] Alembic migrations
- [ ] Litestream for SQLite replication

### Caching & Sessions
- [ ] Redis integration
- [ ] Session management
- [ ] Rate limiting
- [ ] Analytics caching

### Scalability
- [ ] Multi-node architecture
- [ ] gRPC communication
- [ ] Config synchronization
- [ ] Central panel + agent nodes

### Deployment
- [ ] Docker Compose setup
- [ ] Helm charts
- [ ] Kubernetes support
- [ ] CI/CD pipelines

### Background Jobs
- [ ] Celery/ARQ integration
- [ ] Task queue
- [ ] Scheduled jobs
- [ ] Job monitoring

---

## 📊 Observability (اولویت ۲)

### Metrics & Monitoring
- [ ] Prometheus `/metrics` endpoint
- [ ] Grafana dashboard
- [ ] Performance monitoring
- [ ] Alert system

### Logging & Tracing
- [ ] OpenTelemetry integration
- [ ] Structured logging (JSON)
- [ ] ELK/Loki integration
- [ ] Request tracing

### Health Checks
- [ ] Kubernetes liveness probe
- [ ] Readiness probe
- [ ] Startup probe
- [ ] Health endpoint

---

## 👥 Userland Features (اولویت ۲)

### Self-Service Portal
- [ ] Telegram bot integration
- [ ] Self-service renewal
- [ ] Config generation
- [ ] Traffic checking

### Payment Integration
- [ ] Zarinpal gateway
- [ ] IDPay gateway
- [ ] USDT TRC20 crypto
- [ ] Payment tracking

### Reseller System
- [ ] Multi-level reseller
- [ ] Commission management
- [ ] Reseller wallet
- [ ] Sub-affiliate system

### Per-User Controls
- [ ] Per-user IP limits
- [ ] Per-user device limits
- [ ] Custom DNS per user
- [ ] Traffic cap enforcement
- [ ] Update token revocation

---

## 🧪 کیفیت کد (اولویت ۲)

### Code Quality
- [ ] Full type hints
- [ ] mypy strict mode
- [ ] Ruff linter
- [ ] Pre-commit hooks

### Testing
- [ ] Unit tests (pytest)
- [ ] Integration tests
- [ ] Property-based tests (Hypothesis)
- [ ] E2E tests (Playwright)
- [ ] Coverage > 80%

### CI/CD
- [ ] GitHub Actions
- [ ] Python 3.10/3.11/3.12 matrix
- [ ] Docker build
- [ ] Security scanning
- [ ] Automatic releases

### Documentation
- [ ] Conventional Commits
- [ ] Automated CHANGELOG
- [ ] SBOM generation
- [ ] API documentation

---

## 🚨 ضد سواستفاده (اولویت ۲)

### Anomaly Detection
- [ ] Traffic pattern analysis
- [ ] Port scan detection
- [ ] Brute force detection
- [ ] Auto-suspend mechanism

### Egress Filtering
- [ ] Block SMTP (port 25)
- [ ] Block Telnet (port 23)
- [ ] Block SMB (445/139)
- [ ] Spam prevention
- [ ] Worm prevention

---

## Implementation Plan

### Phase 1 (Weeks 1-2): Security & Database
1. Setup PostgreSQL + SQLAlchemy
2. Implement Argon2id password hashing
3. Add 2FA/TOTP support
4. Setup audit logging

### Phase 2 (Weeks 3-4): Architecture
1. Migrate Flask → FastAPI
2. Setup Redis
3. Implement background jobs
4. Multi-node setup

### Phase 3 (Weeks 5-6): Protocols
1. Add Hysteria 2 support
2. Add TUIC v5 support
3. Implement uTLS rotation
4. Traffic morphing

### Phase 4 (Weeks 7-8): Features
1. Telegram bot
2. Payment gateway
3. Reseller system
4. Per-user limits

### Phase 5 (Weeks 9+): Quality
1. Comprehensive testing
2. CI/CD pipelines
3. Observability setup
4. Documentation

---

## Dependencies to Add

### Security
```
pyotp>=2.8.0              # TOTP support
python-jose>=3.3.0        # JWT handling
argon2-cffi>=21.3.0       # Argon2id hashing
cryptography>=41.0.0      # Encryption
```

### Database
```
sqlalchemy>=2.0.0
alembic>=1.12.0
psycopg[binary]>=3.1.0    # PostgreSQL driver
```

### Async/Cache
```
fastapi>=0.104.0
redis>=5.0.0
celery>=5.3.0             # Or ARQ
```

### Monitoring
```
prometheus-client>=0.18.0
opentelemetry-api>=1.20.0
opentelemetry-sdk>=1.20.0
```

### Testing
```
pytest>=7.4.0
pytest-cov>=4.1.0
hypothesis>=6.90.0
playwright>=1.40.0
```

### Linting/Format
```
ruff>=0.1.0
mypy>=1.7.0
bandit>=1.7.5
semgrep>=1.45.0
```

---

## نکات مهم

1. **Backward Compatibility**: تمام تغییرات باید current users رو بریک نکنن
2. **Migration Path**: Clear upgrade guide برای existing installations
3. **Documentation**: هر feature باید خوب documented باشه
4. **Testing**: Before/after هر major change
5. **Staged Rollout**: Features رو به‌صورت gradual release کن

