# Spiritus API Documentation

## Base URL
```
http://your-server-ip:38471/api
```

## Authentication
All API endpoints require authentication except login/logout.

### Session-based Authentication
```bash
# Login
curl -X POST http://localhost:38471/api/login \
  -H "Content-Type: application/json" \
  -d '{"password":"your_password"}' \
  -c cookies.txt

# Use session cookie for subsequent requests
curl http://localhost:38471/api/users \
  -b cookies.txt
```

## Endpoints

### Authentication

#### Login
```http
POST /api/login
Content-Type: application/json

{
  "password": "your_password"
}
```

**Response:**
```json
{
  "ok": true
}
```

#### Logout
```http
POST /api/logout
```

**Response:**
```json
{
  "ok": true
}
```

#### Change Password
```http
POST /api/change-password
Content-Type: application/json

{
  "current_pw": "old_password",
  "new_pw": "new_password"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Password changed. Please login again."
}
```

### User Management

#### List All Users
```http
GET /api/users
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "user1",
    "uuid": "uuid-string",
    "traffic_limit_gb": 10.0,
    "traffic_used_gb": 2.5,
    "expire_at": "2026-05-27T00:00:00",
    "active": 1,
    "created_at": "2026-04-27T00:00:00",
    "note": ""
  }
]
```

#### Create User
```http
POST /api/users
Content-Type: application/json

{
  "name": "user1",
  "traffic_limit_gb": 10,
  "expire_days": 30,
  "note": "Optional note"
}
```

**Response:**
```json
{
  "ok": true,
  "user": {
    "id": 1,
    "name": "user1",
    "uuid": "uuid-string",
    ...
  }
}
```

#### Delete User
```http
DELETE /api/users/{name}
```

**Response:**
```json
{
  "ok": true
}
```

#### Toggle User Status
```http
POST /api/users/{name}/toggle
```

**Response:**
```json
{
  "ok": true,
  "active": true
}
```

#### Renew User
```http
POST /api/users/{name}/renew
Content-Type: application/json

{
  "days": 30
}
```

**Response:**
```json
{
  "ok": true,
  "expire_at": "2026-05-27T00:00:00"
}
```

#### Add Traffic
```http
POST /api/users/{name}/add-traffic
Content-Type: application/json

{
  "traffic_gb": 5.0
}
```

**Response:**
```json
{
  "ok": true,
  "new_limit": 15.0
}
```

#### Update Note
```http
POST /api/users/{name}/update-note
Content-Type: application/json

{
  "note": "Updated note"
}
```

**Response:**
```json
{
  "ok": true
}
```

#### Set Speed Limit
```http
POST /api/users/{name}/speed-limit
Content-Type: application/json

{
  "up": 200,
  "down": 200
}
```

**Response:**
```json
{
  "ok": true
}
```

#### Get User Activity
```http
GET /api/users/{name}/activity
```

**Response:**
```json
{
  "activity": [
    {
      "timestamp": "2026-04-27 10:30:00",
      "action": "connection",
      "details": "Connected from 192.168.1.1"
    }
  ]
}
```

#### Get User Statistics
```http
GET /api/users/{user_id}/stats
```

**Response:**
```json
{
  "id": 1,
  "name": "user1",
  "traffic_limit_gb": 10.0,
  "traffic_used_gb": 2.5,
  "remaining_traffic_gb": 7.5,
  "days_until_expiry": 30,
  "activity_history": [...]
}
```

### Search & Analytics

#### Search Users
```http
GET /api/search?q={query}
```

**Parameters:**
- `q` (required): Search query (name, UUID, or note)

**Response:**
```json
{
  "users": [...],
  "count": 5
}
```

#### Get Statistics Report
```http
GET /api/report
```

**Response:**
```json
{
  "total_users": 100,
  "active_users": 85,
  "inactive_users": 15,
  "total_traffic_gb": 500.5,
  "total_limit_gb": 1000.0,
  "expiring_soon": 10,
  "top_users": [...]
}
```

#### Get Traffic Analytics
```http
GET /api/analytics?days={n}
```

**Parameters:**
- `days` (optional): Number of days (default: 7)

**Response:**
```json
{
  "daily_traffic": [
    {
      "date": "2026-04-27",
      "total_traffic": 50.5,
      "user_count": 85
    }
  ],
  "top_users": [...],
  "period_days": 7
}
```

### Backup & Export

#### Create Backup
```http
POST /api/backup/create
```

**Response:**
```json
{
  "ok": true,
  "backup_path": "/root/backups/vpn_backup_20260427_103000.zip"
}
```

#### Restore Backup
```http
POST /api/backup/restore
Content-Type: application/json

{
  "backup_path": "/root/backups/vpn_backup_20260427_103000.zip"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "Backup restored successfully"
}
```

#### List Backups
```http
GET /api/backup/list
```

**Response:**
```json
{
  "backups": [
    {
      "name": "vpn_backup_20260427_103000.zip",
      "path": "/root/backups/vpn_backup_20260427_103000.zip",
      "size": 1048576,
      "created": "2026-04-27T10:30:00"
    }
  ]
}
```

#### Cleanup Backups
```http
POST /api/backup/cleanup
Content-Type: application/json

{
  "retention_days": 7
}
```

**Response:**
```json
{
  "ok": true,
  "removed": 5
}
```

#### Export Data
```http
GET /api/export/{format}
```

**Parameters:**
- `format`: Either `csv` or `json`

**Response:** File download

### System Monitoring

#### Get System Health
```http
GET /api/health
```

**Response:**
```json
{
  "cpu_percent": 45.5,
  "memory_percent": 62.3,
  "disk_percent": 78.9,
  "connections": 150,
  "status": "healthy"
}
```

#### Sync Traffic
```http
POST /api/sync
```

**Response:**
```json
{
  "ok": true,
  "disabled": 2
}
```

### Settings

#### Get Settings
```http
GET /api/settings
```

**Response:**
```json
{
  "reality_public_key": "...",
  "reality_short_id": "...",
  "reality_dest": "www.google.com:443",
  "reality_sni": "www.google.com",
  "vless_port": 2053,
  "cdn_enabled": false,
  ...
}
```

#### Update Settings
```http
POST /api/settings
Content-Type: application/json

{
  "cdn_enabled": true,
  "cdn_domain": "cdn.example.com",
  "cdn_port": 2082
}
```

**Response:**
```json
{
  "ok": true,
  "rebuild": true
}
```

#### Regenerate Reality Keys
```http
POST /api/settings/regenerate-reality
```

**Response:**
```json
{
  "ok": true,
  "public_key": "...",
  "short_id": "..."
}
```

#### Generate ShadowSocks 2022 Key
```http
POST /api/settings/generate-ss2022-key
```

**Response:**
```json
{
  "ok": true,
  "ss2022_server_key": "..."
}
```

### Bulk Operations

#### Bulk Update Users
```http
POST /api/bulk-update
Content-Type: application/json

{
  "user_ids": [1, 2, 3],
  "updates": {
    "active": true,
    "traffic_limit_gb": 20
  }
}
```

**Response:**
```json
{
  "ok": true,
  "updated": 3
}
```

### Groups

#### List Groups
```http
GET /api/groups
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "Premium",
    "traffic_limit_gb": 50,
    "expire_days": 90
  }
]
```

#### Create Group
```http
POST /api/groups
Content-Type: application/json

{
  "name": "Premium",
  "traffic_limit_gb": 50,
  "expire_days": 90
}
```

**Response:**
```json
{
  "ok": true,
  "group": {...}
}
```

#### Delete Group
```http
DELETE /api/groups/{group_id}
```

**Response:**
```json
{
  "ok": true
}
```

#### Get Group Users
```http
GET /api/groups/{group_id}/users
```

**Response:**
```json
{
  "users": [...]
}
```

### Live Monitoring

#### Get Live Stats
```http
GET /api/live
```

**Response:**
```json
{
  "total_users": 100,
  "active_users": 85,
  "online_users": 45,
  "total_traffic_gb": 500.5
}
```

## Error Responses

All endpoints may return error responses:

```json
{
  "error": "Error message"
}
```

### Common HTTP Status Codes
- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Permission denied
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

## Rate Limiting

API requests are rate limited to prevent abuse:
- 100 requests per minute per IP
- 1000 requests per hour per IP

Exceeding limits will result in `429 Too Many Requests` response.

## Examples

### Python Example
```python
import requests

# Login
session = requests.Session()
session.post('http://localhost:38471/api/login', json={
    'password': 'your_password'
})

# Get users
response = session.get('http://localhost:38471/api/users')
users = response.json()

# Create user
response = session.post('http://localhost:38471/api/users', json={
    'name': 'new_user',
    'traffic_limit_gb': 10,
    'expire_days': 30
})
```

### cURL Example
```bash
# Login
curl -X POST http://localhost:38471/api/login \
  -H "Content-Type: application/json" \
  -d '{"password":"your_password"}' \
  -c cookies.txt

# Get users
curl http://localhost:38471/api/users -b cookies.txt

# Create user
curl -X POST http://localhost:38471/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"new_user","traffic_limit_gb":10,"expire_days":30}' \
  -b cookies.txt
```

### JavaScript Example
```javascript
// Login
const login = async () => {
  const response = await fetch('http://localhost:38471/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ password: 'your_password' })
  });
  return response.json();
};

// Get users
const getUsers = async () => {
  const response = await fetch('http://localhost:38471/api/users', {
    credentials: 'include'
  });
  return response.json();
};
```

## WebSocket Support

For real-time updates, WebSocket support is available:

```javascript
const ws = new WebSocket('ws://localhost:38471/ws');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Update:', data);
};
```

## SDKs

Official SDKs are available for:
- Python: `pip install vpn-panel-sdk`
- JavaScript: `npm install vpn-panel-sdk`
- Go: `go get github.com/example/vpn-panel-go`

---

For more information, visit: [GitHub Repository](https://github.com/example/vpn-panel)