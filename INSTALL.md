# 🚀 Spiritus - Quick Installation Guide

## One-Command Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/v74all/Spiritus/main/install.sh)"
```

## Manual Install

### Step 1: Clone & Install

```bash
sudo git clone https://github.com/v74all/Spiritus.git /opt/spiritus
cd /opt/spiritus
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Configure Xray

```bash
bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
```

### Step 3: Set Environment Variables

```bash
export VPN_SERVER_IP="your-server-ip"
export VPN_SERVER_PORT="443"
export VPN_SNI_HOST="www.google.com"
export VPN_WEB_PORT="38471"
```

### Step 4: Start

```bash
# Direct
python3 vpn-web.py

# Or as systemd service
sudo cp vpn-panel.service /etc/systemd/system/spiritus.service
sudo systemctl enable spiritus
sudo systemctl start spiritus
```

## Auto-Update

Spiritus automatically checks for updates daily at 4:00 AM.

To manually update:
```bash
cd /opt/spiritus
git pull origin main
pip install -r requirements.txt
sudo systemctl restart spiritus
```

## Access

```
URL: http://your-server-ip:38471
```

```bash
# Via the panel UI
# Settings -> Change Password

# Or via API
curl -X POST http://localhost:38471/api/change-password \
  -H "Content-Type: application/json" \
  -d '{"current_pw":"old_password","new_pw":"new_strong_password"}'
```

## 🔧 Systemd Service (Optional)

Create a systemd service for auto-start:

```bash
sudo nano /etc/systemd/system/vpn-panel.service
```

Add this content:

```ini
[Unit]
Description=VPN Management Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/vpn-panel
ExecStart=/usr/bin/python3 /root/vpn-panel/vpn-web.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable vpn-panel
sudo systemctl start vpn-panel
sudo systemctl status vpn-panel
```

## 📊 Monitor Logs

```bash
# View panel logs
tail -f /root/vpn-panel.log

# View systemd service logs
journalctl -u vpn-panel -f
```

## 🔒 Firewall Configuration

```bash
# Allow panel port
sudo ufw allow 38471/tcp

# Allow Xray API port
sudo ufw allow 10085/tcp

# Enable firewall
sudo ufw enable
```

## ✅ Verification

Test the installation:

```bash
# Check if panel is running
curl http://localhost:38471/api/users

# Check system health
curl http://localhost:38471/api/health

# Check Xray status
systemctl status xray
```

## 🎯 First Steps After Installation

1. **Login to the panel**
   - URL: http://your-server-ip:38471
   - Password: Check `/root/vpn-panel-password`

2. **Create your first user**
   - Click "+ Add User"
   - Enter user details
   - Set traffic limit and expiration

3. **Generate configuration**
   - Click "Config" on user card
   - Copy the configuration
   - Import into your VPN client

4. **Monitor traffic**
   - View real-time statistics
   - Check user activity
   - Analyze traffic patterns

## 📱 Client Configuration

### V2Ray/Xray Client
1. Download V2Ray/Xray client
2. Import configuration from panel
3. Connect and enjoy!

### Supported Clients
- **Windows**: V2RayN, Clash for Windows
- **macOS**: V2RayU, ClashX
- **Linux**: Qv2ray, Clash
- **Android**: V2RayNG, Clash for Android
- **iOS**: Shadowrocket, Quantumult X

## 🆘 Troubleshooting

### Panel Not Accessible
```bash
# Check if panel is running
ps aux | grep vpn-web.py

# Check if port is open
netstat -tlnp | grep 38471

# Restart panel
sudo systemctl restart vpn-panel
```

### Database Errors
```bash
# Check database file
ls -la /root/vpn_users.db

# Backup database
cp /root/vpn_users.db /root/vpn_users.db.backup

# Restore from backup
cp /root/vpn_users.db.backup /root/vpn_users.db
```

### Xray Connection Issues
```bash
# Check Xray status
systemctl status xray

# Restart Xray
systemctl restart xray

# Check Xray config
cat /usr/local/etc/v2ray/config.json
```

## 📞 Support

If you encounter any issues:
- Check logs: `/root/vpn-panel.log`
- Review documentation: `README.md`
- Contact support: support@example.com

---

**Happy VPN Management! 🎉**