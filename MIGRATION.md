# 📦 Spiritus v2.0 Migration Guide

## Overview

Spiritus v2.0 is a major version upgrade with breaking changes:
- **Framework**: Flask → FastAPI
- **Database**: SQLite → PostgreSQL (optional, SQLite still supported with limitations)
- **Authentication**: Password only → Password + 2FA
- **Architecture**: Single node → Multi-node ready

This guide helps migrate from v1.x to v2.0.

---

## ⚠️ Pre-Migration

### Backup Everything
```bash
# SQLite backup
cp vpn_users.db vpn_users.db.backup.$(date +%s)

# Config backup
tar -czf config_backup.tar.gz config/

# Full system backup
tar -czf spiritus_backup_$(date +%Y%m%d).tar.gz \
  vpn_users.db* \
  vpn-panel-password \
  config/ \
  static/ \
  templates/
```

### Check Requirements
```bash
python3 --version  # Must be 3.10+
pip3 --version
git --version

# Test database (if using PostgreSQL)
psql -h localhost -U spiritus -d spiritus -c "SELECT version();"
```

---

## 🔄 Migration Path

### Option A: Fresh Installation (Recommended for new servers)

```bash
# 1. Clone v2.0
git clone https://github.com/v74all/Spiritus.git
cd Spiritus
git checkout v2.0

# 2. Setup PostgreSQL (Docker)
docker run -d \
  --name spiritus-db \
  -e POSTGRES_USER=spiritus \
  -e POSTGRES_PASSWORD=secure_password \
  -e POSTGRES_DB=spiritus \
  -v spiritus_db:/var/lib/postgresql/data \
  postgres:16-alpine

# 3. Setup Redis (Docker)
docker run -d \
  --name spiritus-redis \
  -v spiritus_redis:/data \
  redis:7-alpine

# 4. Install dependencies
pip3 install -r requirements.txt

# 5. Configure
cp .env.example .env
# Edit .env with your settings

# 6. Initialize database
alembic upgrade head

# 7. Create admin user
python3 -c "
from models import User, Session
from security import hash_password
import uuid

session = Session()
admin = User(
    id=str(uuid.uuid4()),
    name='admin',
    uuid=str(uuid.uuid4()),
    active=True,
)
admin.password_hash = hash_password('initial_password')
session.add(admin)
session.commit()
print('Admin user created. Change password immediately!')
"

# 8. Run
uvicorn main:app --host 0.0.0.0 --port 38471
```

### Option B: Migrate from v1.x (SQLite → PostgreSQL)

```bash
# 1. Install migration tools
pip3 install sqlalchemy alembic psycopg2-binary

# 2. Export data from v1.x SQLite
python3 << 'EXPORT_SCRIPT'
import sqlite3
import json

conn = sqlite3.connect('vpn_users.db')
cursor = conn.cursor()

# Export users
cursor.execute('SELECT * FROM users')
users = cursor.fetchall()

# Export configs (if exist)
cursor.execute('SELECT * FROM configs')
configs = cursor.fetchall()

# Save to JSON for easy review
export_data = {
    'users': [dict(zip([d[0] for d in cursor.description], row)) for row in users],
    'configs': [dict(zip([d[0] for d in cursor.description], row)) for row in configs],
}

with open('v1_export.json', 'w') as f:
    json.dump(export_data, f, indent=2, default=str)

print(f"Exported {len(users)} users")
EXPORT_SCRIPT

# 3. Setup PostgreSQL
docker-compose up -d db redis

# 4. Create schema
alembic upgrade head

# 5. Import data
python3 << 'IMPORT_SCRIPT'
import json
import uuid
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import User, Base

engine = create_engine('postgresql://spiritus:spiritus@localhost/spiritus')

with open('v1_export.json') as f:
    data = json.load(f)

session = Session(engine)

for user_data in data['users']:
    user = User(
        id=str(uuid.uuid4()),
        name=user_data.get('name', 'imported_user'),
        uuid=user_data.get('uuid', str(uuid.uuid4())),
        traffic_limit_gb=float(user_data.get('traffic_limit', 0)) / 1024 / 1024 / 1024,
        traffic_used_gb=float(user_data.get('traffic_used', 0)) / 1024 / 1024 / 1024,
        active=bool(user_data.get('active', True)),
        expire_at=datetime.fromisoformat(user_data.get('expire_at')) if user_data.get('expire_at') else None,
    )
    session.add(user)

session.commit()
print(f"Imported {len(data['users'])} users")
IMPORT_SCRIPT

# 6. Verify data
python3 << 'VERIFY_SCRIPT'
from sqlalchemy import create_engine, func
from sqlalchemy.orm import Session
from models import User

engine = create_engine('postgresql://spiritus:spiritus@localhost/spiritus')
session = Session(engine)

user_count = session.query(func.count(User.id)).scalar()
print(f"✓ {user_count} users in PostgreSQL")
VERIFY_SCRIPT

# 7. Update credentials in v1.x format (if needed)
# Convert plaintext → hashed passwords
python3 << 'UPDATE_PASSWORDS'
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import User
from security import hash_password

engine = create_engine('postgresql://spiritus:spiritus@localhost/spiritus')
session = Session(engine)

for user in session.query(User).all():
    # If password_hash is plaintext, convert it
    if not user.password_hash.startswith('$argon2'):
        user.password_hash = hash_password(user.password_hash)
        session.add(user)

session.commit()
print("✓ Passwords migrated to Argon2id")
UPDATE_PASSWORDS
```

### Option C: Keep SQLite (Limited Mode)

```bash
# For small deployments (<100 users)
# Install Litestream for replication

pip3 install litestream

# Configure Litestream (litestream.yml)
cat > litestream.yml << 'LITESTREAM_CONFIG'
dbs:
  - path: vpn_users.db
    replicas:
      - type: s3
        bucket: your-s3-bucket
        path: spiritus/vpn_users.db
        access-key-id: YOUR_KEY
        secret-access-key: YOUR_SECRET
LITESTREAM_CONFIG

# Run with replication
litestream replicate &
uvicorn main:app --host 0.0.0.0 --port 38471
```

---

## 🔐 Enable 2FA

After migration, enable TOTP for all admins:

```bash
python3 << 'ENABLE_2FA'
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from models import User
from security import generate_totp_secret, get_totp_uri

engine = create_engine('postgresql://spiritus:spiritus@localhost/spiritus')
session = Session(engine)

# Get admin user
admin = session.query(User).filter_by(name='admin').first()

if admin:
    secret = generate_totp_secret('admin')
    admin.totp_secret = secret
    admin.totp_enabled = True
    
    session.add(admin)
    session.commit()
    
    print(f"TOTP Secret: {secret}")
    print(f"QR Code URL: {get_totp_uri(secret, 'admin')}")
    print("Scan QR code with authenticator app")
ENABLE_2FA
```

---

## 🐳 Docker Compose Migration

```bash
# Start services
docker-compose up -d

# Run migrations
docker-compose exec app alembic upgrade head

# Create admin user
docker-compose exec app python3 create_admin.py

# View logs
docker-compose logs -f app
```

---

## 📊 API Changes

### v1.x → v2.0 Endpoint Changes

| v1.x | v2.0 | Status |
|------|------|--------|
| `/api/users` | `/api/admin/users` | Moved to admin namespace |
| `/api/user/<id>` | `/api/user/profile` | User self-endpoint |
| `/api/stats` | `/api/admin/analytics` | Enhanced |
| `/api/config/subscribe` | `/api/user/subscribe` | Changed |
| `/login` | `/api/auth/login` | New format, returns JWT |

### Authentication Example

**v1.x** (Session-based):
```python
POST /login
Body: {"username": "admin", "password": "pass"}
Response: Set-Cookie: session=abc123...
```

**v2.0** (JWT-based):
```python
POST /api/auth/login
Body: {"username": "admin", "password": "pass"}
Response: {
  "access_token": "eyJ0eXAi...",
  "refresh_token": "eyJ0eXAi...",
  "token_type": "bearer"
}

# Send with requests:
headers = {"Authorization": "Bearer eyJ0eXAi..."}
```

---

## 🔄 Rollback Plan

If something goes wrong:

```bash
# Stop v2.0
docker-compose down

# Restore v1.x
cd ../spiritus-v1
docker-compose up -d

# Restore database
cp vpn_users.db.backup vpn_users.db
systemctl restart vpn-web

# Alert: Check what went wrong
tail -f vpn-panel.log
```

---

## ✅ Post-Migration Checklist

- [ ] Database backup verified
- [ ] All users imported correctly
- [ ] Admin 2FA setup completed
- [ ] IP allowlist configured (if using)
- [ ] GeoIP blocking configured (if needed)
- [ ] Audit logging enabled
- [ ] Redis running and connected
- [ ] Monitoring/Prometheus configured
- [ ] Backup strategy updated
- [ ] Documentation updated for team
- [ ] Test user access from panel
- [ ] Test subscription endpoint
- [ ] Test API endpoints
- [ ] Monitor logs for errors

---

## 🆘 Troubleshooting

### Issue: "Connection refused" to PostgreSQL

```bash
# Check if postgres is running
docker ps | grep spiritus-db

# Check connection
psql -h localhost -U spiritus -d spiritus -c "SELECT 1;"

# Check env vars
cat .env | grep DATABASE_URL
```

### Issue: "ModuleNotFoundError: No module named 'fastapi'"

```bash
# Reinstall dependencies
pip3 install --upgrade -r requirements.txt

# Or use venv
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

### Issue: "Admin token invalid" during login

```bash
# Regenerate JWT secrets
# Edit .env:
JWT_SECRET_KEY=<new-random-value>

# Restart app
docker-compose restart app
```

### Issue: "Audit logs not showing"

```bash
# Check Redis connection
redis-cli ping

# Check audit logging is enabled
grep AUDIT_LOG_ENABLED .env

# Query database
psql -U spiritus -d spiritus -c "SELECT COUNT(*) FROM audit_logs;"
```

---

## 📞 Support

- **Issues**: https://github.com/v74all/Spiritus/issues
- **Discussions**: https://github.com/v74all/Spiritus/discussions
- **Documentation**: [README.md](README.md)
