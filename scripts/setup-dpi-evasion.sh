#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# V7LTHRONYX VPN Panel — DPI Evasion Setup Script
# ═══════════════════════════════════════════════════════════════
# This script sets up:
# 1. Nginx fallback website (active probing defense)
# 2. Self-signed SSL cert for fallback
# 3. Firewall rules (iptables)
# 4. Xray systemd service
# 5. iran.dat for geo-routing
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

PANEL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG_DIR="$PANEL_DIR/config"
XRAY_BIN="/usr/local/bin/xray"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
NGINX_CONF="/etc/nginx/sites-available/vpn-fallback"
FALLBACK_DIR="/var/www/fallback"
SSL_DIR="/etc/nginx/ssl"

echo "═══════════════════════════════════════════════════════════"
echo "  V7LTHRONYX DPI Evasion Setup"
echo "═══════════════════════════════════════════════════════════"

# ── 1. Install Xray ──────────────────────────────────────
echo "[1/7] Installing Xray..."
if ! command -v xray &>/dev/null; then
    curl -L -o /tmp/Xray-linux-64.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
    sudo unzip -o /tmp/Xray-linux-64.zip -d /usr/local/bin xray
    sudo chmod +x /usr/local/bin/xray
    rm -f /tmp/Xray-linux-64.zip
fi
echo "  ✅ Xray $(xray version 2>/dev/null | head -1)"

# ── 2. Download geosite.dat, geoip.dat, iran.dat ─────────
echo "[2/7] Downloading geo databases..."
sudo curl -sL -o /usr/local/bin/geosite.dat https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat
sudo curl -sL -o /tmp/v2ray.zip https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-linux-64.zip
sudo unzip -o /tmp/v2ray.zip -d /usr/local/bin/ geoip.dat
rm -f /tmp/v2ray.zip
sudo curl -sL -o /usr/local/bin/iran.dat https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/iran.dat
echo "  ✅ geosite.dat, geoip.dat, iran.dat installed"

# ── 3. Generate REALITY keypair ──────────────────────────
echo "[3/7] Generating REALITY X25519 keypair..."
KEYS=$($XRAY_BIN x25519 2>/dev/null)
REALITY_PRIVATE=$(echo "$KEYS" | grep "Private key:" | awk '{print $3}')
REALITY_PUBLIC=$(echo "$KEYS" | grep "Public key:" | awk -F': ' '{print $2}')
echo "  ✅ Private Key: ${REALITY_PRIVATE:0:10}..."
echo "  ✅ Public Key:  ${REALITY_PUBLIC:0:10}..."

# ── 4. Deploy Xray config ─────────────────────────────────
echo "[4/7] Deploying Xray configuration..."
sudo mkdir -p /usr/local/etc/xray
sudo mkdir -p /var/log/xray

# Generate shortIds
SHORT_IDS=$(python3 -c "import secrets; print(','.join(secrets.token_hex(8) for _ in range(5)))")

# Generate UUID
USER_UUID=$(python3 -c "import uuid; print(uuid.uuid4())")

# Create config from template
cat "$CONFIG_DIR/xray-config.json" | \
    python3 -c "
import sys, json
config = json.load(sys.stdin)
# Update keys
for inbound in config.get('inbounds', []):
    if inbound.get('streamSettings', {}).get('realitySettings'):
        inbound['streamSettings']['realitySettings']['privateKey'] = '$REALITY_PRIVATE'
        inbound['streamSettings']['realitySettings']['shortIds'] = [s for s in '$SHORT_IDS'.split(',')]
    if inbound.get('settings', {}).get('clients'):
        for client in inbound['settings']['clients']:
            client['id'] = '$USER_UUID'
print(json.dumps(config, indent=2))
" | sudo tee "$XRAY_CONFIG" > /dev/null

# Test config
$XRAY_BIN run -test -c "$XRAY_CONFIG" 2>&1 | grep -q "Configuration OK" && echo "  ✅ Xray config valid" || echo "  ⚠️  Xray config test failed"

# ── 5. Setup nginx fallback ──────────────────────────────
echo "[5/7] Setting up nginx fallback..."

# Deploy fallback website
sudo mkdir -p "$FALLBACK_DIR"
sudo cp -r "$CONFIG_DIR/fallback-site/"* "$FALLBACK_DIR/"
sudo chown -R www-data:www-data "$FALLBACK_DIR"

# Generate self-signed SSL cert for fallback
sudo mkdir -p "$SSL_DIR"
if [ ! -f "$SSL_DIR/fallback.crt" ]; then
    sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_DIR/fallback.key" \
        -out "$SSL_DIR/fallback.crt" \
        -subj "/C=US/ST=Delaware/L=Wilmington/O=Global Solutions Inc./CN=global-solutions.example.com" \
        2>/dev/null
    echo "  ✅ Self-signed SSL cert generated"
else
    echo "  ✅ SSL cert already exists"
fi

# Deploy nginx config
sudo cp "$CONFIG_DIR/nginx-fallback.conf" "$NGINX_CONF"
sudo ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/vpn-fallback 2>/dev/null || true
sudo nginx -t 2>&1 | grep -q "successful" && echo "  ✅ Nginx config valid" || echo "  ⚠️  Nginx config test failed"

# ── 6. Firewall rules ────────────────────────────────────
echo "[6/7] Configuring firewall rules..."

# Allow essential services
sudo iptables -P INPUT DROP 2>/dev/null || true
sudo iptables -P FORWARD DROP 2>/dev/null || true
sudo iptables -P OUTPUT ACCEPT 2>/dev/null || true

# Allow established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
sudo iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true

# Allow SSH (custom port or 22)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true

# Allow Xray (443/tcp ONLY — no UDP)
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true

# Allow nginx fallback (80/tcp)
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true

# Allow VPN panel
sudo iptables -A INPUT -p tcp --dport 38471 -j ACCEPT 2>/dev/null || true

# Block outbound to Iran IPs (prevent abuse-as-SNI-proxy)
sudo iptables -A OUTPUT -d 5.0.0.0/8 -j DROP 2>/dev/null || true   # MCI
sudo iptables -A OUTPUT -d 31.0.0.0/8 -j DROP 2>/dev/null || true  # Iran range
sudo iptables -A OUTPUT -d 37.0.0.0/8 -j DROP 2>/dev/null || true  # Iran range
sudo iptables -A OUTPUT -d 46.0.0.0/8 -j DROP 2>/dev/null || true  # Iran range
sudo iptables -A OUTPUT -d 78.0.0.0/8 -j DROP 2>/dev/null || true  # Iran range
sudo iptables -A OUTPUT -d 91.0.0.0/8 -j DROP 2>/dev/null || true  # Iran range
sudo iptables -A OUTPUT -d 185.0.0.0/8 -j DROP 2>/dev/null || true # Iran range

# Block egress on dangerous ports
for PORT in 25 465 587 23 445 139 3389; do
    sudo iptables -A OUTPUT -p tcp --dport $PORT -j DROP 2>/dev/null || true
    sudo iptables -A OUTPUT -p udp --dport $PORT -j DROP 2>/dev/null || true
done

echo "  ✅ Firewall rules configured"

# ── 7. Systemd services ──────────────────────────────────
echo "[7/7] Setting up systemd services..."

# Xray service
sudo tee /etc/systemd/system/xray.service > /dev/null << 'XRAYEOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
Group=nogroup
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
XRAYEOF

sudo systemctl daemon-reload
sudo systemctl enable xray 2>/dev/null || true
echo "  ✅ Xray service configured"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ✅ DPI Evasion Setup Complete!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  REALITY Private Key: $REALITY_PRIVATE"
echo "  REALITY Public Key:  $REALITY_PUBLIC"
echo "  User UUID:          $USER_UUID"
echo "  Short IDs:          $SHORT_IDS"
echo ""
echo "  Client Config (VLESS + XHTTP + REALITY):"
echo "  vless://${USER_UUID}@<SERVER_IP>:443?type=xhttp&security=reality&fp=chrome&sni=objects.githubusercontent.com&pbk=${REALITY_PUBLIC}&sid=${SHORT_IDS%%,*}&path=/api/v2/stream&mode=auto#V7LTHRONYX"
echo ""
echo "  To start services:"
echo "    sudo systemctl start xray"
echo "    sudo systemctl start nginx"
echo ""
echo "  To verify:"
echo "    openssl s_client -connect <SERVER_IP>:443 -servername objects.githubusercontent.com"
echo "    curl -s http://<SERVER_IP>/ | head -5"
echo ""