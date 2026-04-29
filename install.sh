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
        apt install -y python3 python3-pip python3-venv curl wget unzip
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        yum install -y python3 python3-pip curl wget unzip
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

configure_systemd() {
    print_info "Configuring systemd service..."
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=V7LTHRONYX VPN Management Panel
After=network.target xray.service
Wants=xray.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
Environment="PYTHONUNBUFFERED=1"
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/vpn-web.py
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

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    print_success "Systemd service configured"
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
    sleep 2
    
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        print_success "V7LTHRONYX is running!"
    else
        print_error "Failed to start V7LTHRONYX. Check logs: journalctl -u ${SERVICE_NAME} -f"
        exit 1
    fi
}

show_info() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  V7LTHRONYX VPN Panel - Installation Complete!${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${YELLOW}Panel URL:${NC}     http://$(hostname -I | awk '{print $1}'):38471"
    echo -e "  ${YELLOW}Config Dir:${NC}    ${INSTALL_DIR}"
    echo -e "  ${YELLOW}Log File:${NC}     ${INSTALL_DIR}/vpn-panel.log"
    echo -e "  ${YELLOW}Service:${NC}       systemctl status ${SERVICE_NAME}"
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
    
    echo -e "${CYAN}[1/7]${NC} Installing system dependencies..."
    install_dependencies
    
    echo -e "${CYAN}[2/7]${NC} Installing Xray..."
    install_xray
    
    echo -e "${CYAN}[3/7]${NC} Downloading Spiritus..."
    clone_or_update
    
    echo -e "${CYAN}[4/7]${NC} Setting up Python environment..."
    setup_python
    
    echo -e "${CYAN}[5/7]${NC} Configuring service..."
    configure_systemd
    
    echo -e "${CYAN}[6/7]${NC} Setting up auto-update..."
    setup_auto_update
    
    echo -e "${CYAN}[7/7]${NC} Starting panel..."
    start_panel
    
    show_info
}

main "$@"
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is not installed"
        exit 1
    fi
    
    print_success "System requirements met"
}

# Install Python dependencies
install_dependencies() {
    print_info "Installing Python dependencies..."
    
    if [ -f "requirements.txt" ]; then
        pip3 install -r requirements.txt
        print_success "Dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Install Xray
install_xray() {
    print_info "Installing Xray..."
    
    if command -v xray &> /dev/null; then
        print_warning "Xray is already installed"
        return
    fi
    
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
    
    if command -v xray &> /dev/null; then
        print_success "Xray installed successfully"
    else
        print_error "Failed to install Xray"
        exit 1
    fi
}

# Create necessary directories
create_directories() {
    print_info "Creating necessary directories..."
    
    mkdir -p /root/backups
    mkdir -p /root/vpn-panel/static/downloads
    mkdir -p /var/log/v2ray
    
    print_success "Directories created"
}

# Setup systemd service
setup_systemd() {
    print_info "Setting up systemd service..."
    
    if [ -f "vpn-panel.service" ]; then
        cp vpn-panel.service /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable vpn-panel
        print_success "Systemd service configured"
    else
        print_warning "vpn-panel.service not found, skipping systemd setup"
    fi
}

# Configure firewall
configure_firewall() {
    print_info "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 38471/tcp
        ufw allow 10085/tcp
        print_success "Firewall configured"
    else
        print_warning "ufw not found, skipping firewall configuration"
    fi
}

# Start the panel
start_panel() {
    print_info "Starting VPN Panel..."
    
    if systemctl is-active --quiet vpn-panel; then
        print_warning "VPN Panel is already running"
        systemctl restart vpn-panel
    else
        systemctl start vpn-panel
    fi
    
    sleep 2
    
    if systemctl is-active --quiet vpn-panel; then
        print_success "VPN Panel started successfully"
    else
        print_error "Failed to start VPN Panel"
        systemctl status vpn-panel
        exit 1
    fi
}

# Display installation summary
display_summary() {
    echo ""
    echo "=========================================="
    print_success "Installation Complete!"
    echo "=========================================="
    echo ""
    echo "Panel URL: http://$(hostname -I | awk '{print $1}'):38471"
    echo "Password: Check /root/vpn-panel-password"
    echo ""
    echo "Useful Commands:"
    echo "  Start Panel:   systemctl start vpn-panel"
    echo "  Stop Panel:    systemctl stop vpn-panel"
    echo "  Restart Panel: systemctl restart vpn-panel"
    echo "  View Logs:     tail -f /root/vpn-panel.log"
    echo "  Check Status:  systemctl status vpn-panel"
    echo ""
    echo "Documentation:"
    echo "  README:        cat README.md"
    echo "  Install Guide: cat INSTALL.md"
    echo ""
    echo "=========================================="
}

# Main installation
main() {
    echo ""
    echo "=========================================="
    echo "  VPN Management Panel Installer"
    echo "=========================================="
    echo ""
    
    check_root
    check_requirements
    install_dependencies
    install_xray
    create_directories
    setup_systemd
    configure_firewall
    start_panel
    display_summary
    
    print_success "Installation completed successfully!"
}

# Run main function
main "$@"