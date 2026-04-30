#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

BANNER='
 __      ________ _   _______ _    _ _____   ____  _   ___     ____   __
 \ \    / /____  | | |__   __| |  | |  __ \ / __ \| \ | \ \   / /\ \ / /
  \ \  / /    / /| |    | |  | |__| | |__) | |  | |  \| |\ \_/ /  \ V /
   \ \/ /    / / | |    | |  |  __  |  _  /| |  | | . ` | \   /    > <
    \  /    / /  | |____| |  | |  | | | \ \| |__| | |\  |  | |    / . \
     \/    /_/   |______|_|  |_|  |_|_|  \_\\____/|_| \_|  |_|   /_/ \_\
'

REPO_URL="https://github.com/v74all/Spiritus.git"
INSTALL_DIR="/opt/spiritus"
SERVICE_NAME="spiritus"
VERSION="1.0.0"

print_banner() { echo -e "${CYAN}${BANNER}${NC}"; }
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (sudo)"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/debian_version ]]; then
        PKG_MANAGER="apt"
        print_info "Detected Debian/Ubuntu system"
    elif [[ -f /etc/centos-release ]] || [[ -f /etc/redhat-release ]]; then
        PKG_MANAGER="yum"
        print_info "Detected CentOS/RHEL system"
    else
        PKG_MANAGER="apt"
        print_warning "Unknown OS, defaulting to apt"
    fi
}

install_dependencies() {
    print_info "Installing system dependencies..."
    
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        apt update -y
        apt install -y python3 python3-pip python3-venv curl wget unzip postgresql postgresql-contrib redis-server
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        yum install -y python3 python3-pip curl wget unzip postgresql-server redis
    fi
    
    print_success "System dependencies installed"
}

install_xray() {
    if command -v xray &> /dev/null; then
        print_success "Xray already installed: $(xray version 2>&1 | head -1)"
        return
    fi
    
    print_info "Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    print_success "Xray installed"
}

clone_or_update() {
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        print_info "Updating V7LTHRONYX..."
        cd "$INSTALL_DIR"
        git fetch origin
        LOCAL=$(git rev-parse HEAD)
        REMOTE=$(git rev-parse origin/main 2>/dev/null || git rev-parse origin/master 2>/dev/null)
        
        if [[ "$LOCAL" != "$REMOTE" ]]; then
            print_info "New version available! Updating..."
            git stash 2>/dev/null || true
            git pull origin main 2>/dev/null || git pull origin master 2>/dev/null
            git stash pop 2>/dev/null || true
            print_success "V7LTHRONYX updated to latest version"
        else
            print_success "V7LTHRONYX is already up to date"
        fi
    else
        print_info "Cloning Spiritus from GitHub..."
        rm -rf "$INSTALL_DIR" 2>/dev/null || true
        git clone "$REPO_URL" "$INSTALL_DIR"
        print_success "V7LTHRONYX cloned successfully"
    fi
}

setup_python() {
    print_info "Setting up Python environment..."
    cd "$INSTALL_DIR"
    
    python3 -m venv venv 2>/dev/null || python3 -m venv venv
    source venv/bin/activate
    
    pip install --upgrade pip
    pip install -r requirements.txt
    
    print_success "Python environment configured"
}

setup_postgresql() {
    print_info "Setting up PostgreSQL..."
    
    if systemctl is-active --quiet postgresql; then
        print_success "PostgreSQL is already running"
    else
        # Initialize and start PostgreSQL
        if [[ "$PKG_MANAGER" == "apt" ]]; then
            systemctl start postgresql
            systemctl enable postgresql
        elif [[ "$PKG_MANAGER" == "yum" ]]; then
            postgresql-setup initdb 2>/dev/null || true
            systemctl start postgresql
            systemctl enable postgresql
        fi
        print_success "PostgreSQL started"
    fi
    
    # Create database and user
    DB_USER="vpnadmin"
    DB_PASS="securepassword"
    DB_NAME="vpnpanel"
    
    # Check if database already exists
    DB_EXISTS=$(sudo -u postgres psql -lqt 2>/dev/null | grep -c "^ ${DB_NAME} " || echo "0")
    if [[ "$DB_EXISTS" == "0" ]]; then
        sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';" 2>/dev/null || true
        sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" 2>/dev/null || true
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" 2>/dev/null || true
        print_success "PostgreSQL database created"
    else
        print_success "PostgreSQL database already exists"
    fi
}

setup_redis() {
    print_info "Setting up Redis..."
    
    if systemctl is-active --quiet redis-server || systemctl is-active --quiet redis; then
        print_success "Redis is already running"
    else
        if [[ "$PKG_MANAGER" == "apt" ]]; then
            systemctl start redis-server
            systemctl enable redis-server
        elif [[ "$PKG_MANAGER" == "yum" ]]; then
            systemctl start redis
            systemctl enable redis
        fi
        print_success "Redis started"
    fi
}

setup_env() {
    print_info "Setting up environment configuration..."
    cd "$INSTALL_DIR"
    
    if [[ ! -f .env ]]; then
        cp .env.example .env
        
        # Generate a random secret key
        SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        sed -i "s/change-me-to-a-random-secret-key/${SECRET}/" .env
        
        # Set database URL
        sed -i "s|postgresql://vpnadmin:securepassword@localhost:5432/vpnpanel|postgresql://vpnadmin:securepassword@localhost:5432/vpnpanel|" .env
        
        print_success "Environment configuration created (.env)"
    else
        print_success "Environment configuration already exists"
    fi
}

configure_systemd() {
    print_info "Configuring systemd service..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=V7LTHRONYX VPN Management Panel
After=network.target xray.service postgresql.service redis-server.service
Wants=xray.service postgresql.service redis-server.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
Environment="PYTHONUNBUFFERED=1"
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${INSTALL_DIR}/venv/bin/python3 -m uvicorn app.main:app --host 0.0.0.0 --port 38471 --workers 2
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3

PrivateTmp=true
ProtectSystem=full
ReadWritePaths=${INSTALL_DIR} /usr/local/etc/xray /var/log/xray /tmp
LimitNOFILE=65536

StandardOutput=append:${INSTALL_DIR}/vpn-panel.log
StandardError=append:${INSTALL_DIR}/vpn-panel.log
SyslogIdentifier=v7lthronyx

[Install]
WantedBy=multi-user.target
EOF

    # Celery worker service
    cat > /etc/systemd/system/${SERVICE_NAME}-worker.service << EOF
[Unit]
Description=V7LTHRONYX Celery Worker
After=network.target redis-server.service
Wants=redis-server.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
Environment="PYTHONUNBUFFERED=1"
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${INSTALL_DIR}/venv/bin/celery -A app.celery_tasks worker --loglevel=info --concurrency=2
Restart=always
RestartSec=10

StandardOutput=append:${INSTALL_DIR}/celery-worker.log
StandardError=append:${INSTALL_DIR}/celery-worker.log
SyslogIdentifier=v7lthronyx-worker

[Install]
WantedBy=multi-user.target
EOF

    # Celery beat scheduler
    cat > /etc/systemd/system/${SERVICE_NAME}-beat.service << EOF
[Unit]
Description=V7LTHRONYX Celery Beat Scheduler
After=network.target redis-server.service
Wants=redis-server.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
Environment="PYTHONUNBUFFERED=1"
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${INSTALL_DIR}/venv/bin/celery -A app.celery_tasks beat --loglevel=info
Restart=always
RestartSec=10

StandardOutput=append:${INSTALL_DIR}/celery-beat.log
StandardError=append:${INSTALL_DIR}/celery-beat.log
SyslogIdentifier=v7lthronyx-beat

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl enable ${SERVICE_NAME}-worker 2>/dev/null || true
    systemctl enable ${SERVICE_NAME}-beat 2>/dev/null || true
    print_success "Systemd services configured"
}

setup_auto_update() {
    print_info "Setting up automatic updates..."
    
    cat > /etc/cron.d/spiritus-update << EOF
# Spiritus auto-update check - runs daily at 4:00 AM
0 4 * * * root ${INSTALL_DIR}/scripts/auto-update.sh >> ${INSTALL_DIR}/update.log 2>&1
EOF

    mkdir -p "${INSTALL_DIR}/scripts"
    cat > "${INSTALL_DIR}/scripts/auto-update.sh" << 'UPDATEEOF'
#!/bin/bash
set -e
INSTALL_DIR="/opt/spiritus"
SERVICE_NAME="spiritus"
LOG_FILE="${INSTALL_DIR}/update.log"

echo "$(date): Checking for updates..." >> "$LOG_FILE"

cd "$INSTALL_DIR"
git fetch origin 2>/dev/null

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main 2>/dev/null || git rev-parse origin/master 2>/dev/null)

if [[ "$LOCAL" != "$REMOTE" ]]; then
    echo "$(date): Update found! Updating..." >> "$LOG_FILE"
    git stash 2>/dev/null || true
    git pull origin main 2>/dev/null || git pull origin master 2>/dev/null
    git stash pop 2>/dev/null || true
    
    source venv/bin/activate
    pip install -r requirements.txt -q
    
    systemctl restart "$SERVICE_NAME"
    echo "$(date): Update completed and service restarted" >> "$LOG_FILE"
else
    echo "$(date): No update available" >> "$LOG_FILE"
fi
UPDATEEOF

    chmod +x "${INSTALL_DIR}/scripts/auto-update.sh"
    print_success "Auto-update configured (daily check at 4:00 AM)"
}

start_panel() {
    print_info "Starting V7LTHRONYX panel..."
    systemctl restart ${SERVICE_NAME}
    systemctl restart ${SERVICE_NAME}-worker 2>/dev/null || true
    systemctl restart ${SERVICE_NAME}-beat 2>/dev/null || true
    sleep 3
    
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        print_success "V7LTHRONYX is running!"
    else
        print_error "Failed to start V7LTHRONYX. Check logs: journalctl -u ${SERVICE_NAME} -f"
        exit 1
    fi
}

show_info() {
    # Wait for password file to be generated by the app
    PANEL_PASSWORD="N/A"
    for i in $(seq 1 10); do
        if [[ -f "${INSTALL_DIR}/vpn-panel-password" ]]; then
            PANEL_PASSWORD=$(cat "${INSTALL_DIR}/vpn-panel-password")
            break
        fi
        sleep 1
    done
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  V7LTHRONYX VPN Panel v2.0 - Installation Complete!${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${YELLOW}Panel URL:${NC}     http://$(hostname -I | awk '{print $1}'):38471"
    echo -e "  ${YELLOW}API Docs:${NC}     http://$(hostname -I | awk '{print $1}'):38471/api/docs"
    echo -e "  ${YELLOW}Password:${NC}     ${PANEL_PASSWORD}"
    echo -e "  ${YELLOW}Config Dir:${NC}    ${INSTALL_DIR}"
    echo -e "  ${YELLOW}Log File:${NC}     ${INSTALL_DIR}/vpn-panel.log"
    echo -e "  ${YELLOW}Database:${NC}     PostgreSQL (vpnpanel)"
    echo -e "  ${YELLOW}Cache:${NC}        Redis (localhost:6379)"
    echo -e "  ${YELLOW}Services:${NC}     ${SERVICE_NAME} + ${SERVICE_NAME}-worker + ${SERVICE_NAME}-beat"
    echo -e "  ${YELLOW}Auto Update:${NC}   Daily at 4:00 AM"
    echo ""
    echo -e "  ${BLUE}Commands:${NC}"
    echo -e "    ${GREEN}Start:${NC}    systemctl start ${SERVICE_NAME}"
    echo -e "    ${GREEN}Stop:${NC}     systemctl stop ${SERVICE_NAME}"
    echo -e "    ${GREEN}Restart:${NC}  systemctl restart ${SERVICE_NAME}"
    echo -e "    ${GREEN}Logs:${NC}     journalctl -u ${SERVICE_NAME} -f"
    echo -e "    ${GREEN}Update:${NC}   ${INSTALL_DIR}/scripts/auto-update.sh"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

main() {
    print_banner
    echo -e "${YELLOW}  V7LTHRONYX v${VERSION} - Easy Installer${NC}"
    echo ""
    
    check_root
    check_os
    
    echo -e "${CYAN}[1/10]${NC} Installing system dependencies..."
    install_dependencies
    
    echo -e "${CYAN}[2/10]${NC} Installing Xray..."
    install_xray
    
    echo -e "${CYAN}[3/10]${NC} Downloading V7LTHRONYX..."
    clone_or_update
    
    echo -e "${CYAN}[4/10]${NC} Setting up PostgreSQL..."
    setup_postgresql
    
    echo -e "${CYAN}[5/10]${NC} Setting up Redis..."
    setup_redis
    
    echo -e "${CYAN}[6/10]${NC} Setting up Python environment..."
    setup_python
    
    echo -e "${CYAN}[7/10]${NC} Setting up environment config..."
    setup_env
    
    echo -e "${CYAN}[8/10]${NC} Configuring services..."
    configure_systemd
    
    echo -e "${CYAN}[9/10]${NC} Setting up auto-update..."
    setup_auto_update
    
    echo -e "${CYAN}[10/10]${NC} Starting panel..."
    start_panel
    
    show_info
}

main "$@"