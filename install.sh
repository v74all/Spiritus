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
    # Defensive: also add INSTALL_DIR to root's global safe.directory list.
    # This is a belt-and-suspenders alongside the per-command `git -c` wrap
    # in clone_or_update — if a future code path forgets the wrap, git still
    # works. Marking a single, root-controlled path safe doesn't widen the
    # CVE-2022-24765 attack surface.
    git config --global --add safe.directory "${INSTALL_DIR}" 2>/dev/null || true
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
        apt install -y python3 python3-pip python3-venv curl wget unzip postgresql postgresql-contrib redis-server fail2ban
    elif [[ "$PKG_MANAGER" == "yum" ]]; then
        yum install -y python3 python3-pip curl wget unzip postgresql-server redis fail2ban
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
    # The install dir gets chowned to `vpnpanel` later (setup_panel_user).
    # When the operator re-runs this script as root, modern git refuses to
    # touch a repo it sees as owned by a different user ("dubious ownership"),
    # so we mark this specific path as safe — narrow scope, no global config
    # change, no permission relaxation.
    local GIT="git -c safe.directory=${INSTALL_DIR}"

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        print_info "Updating V7LTHRONYX..."
        cd "$INSTALL_DIR"
        $GIT fetch origin
        LOCAL=$($GIT rev-parse HEAD)
        REMOTE=$($GIT rev-parse origin/main 2>/dev/null || $GIT rev-parse origin/master 2>/dev/null)

        if [[ "$LOCAL" != "$REMOTE" ]]; then
            print_info "New version available! Updating..."
            $GIT stash 2>/dev/null || true
            $GIT pull origin main 2>/dev/null || $GIT pull origin master 2>/dev/null
            $GIT stash pop 2>/dev/null || true
            print_success "V7LTHRONYX updated to latest version"
        else
            print_success "V7LTHRONYX is already up to date"
        fi
        # Ensure the freshly pulled files end up owned by the panel user if
        # the user already exists (re-install path). The first-time install
        # path will chown later in setup_panel_user.
        if id "${PANEL_USER:-vpnpanel}" >/dev/null 2>&1; then
            chown -R "${PANEL_USER:-vpnpanel}:${PANEL_USER:-vpnpanel}" "$INSTALL_DIR" 2>/dev/null || true
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
    
    # Create database and user. Password is generated per-install and persisted
    # only in the DB-secrets file (chmod 600) and the .env (also chmod 600).
    DB_USER="vpnadmin"
    DB_NAME="vpnpanel"
    DB_SECRET_FILE="${INSTALL_DIR}/.db-secret"

    if [[ -f "$DB_SECRET_FILE" ]]; then
        DB_PASS=$(cat "$DB_SECRET_FILE")
    else
        DB_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
        mkdir -p "${INSTALL_DIR}"
        umask 077
        echo -n "$DB_PASS" > "$DB_SECRET_FILE"
        chmod 600 "$DB_SECRET_FILE"
    fi

    # Always ensure user exists and password is correct
    sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';" || true
    sudo -u postgres psql -c "ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASS}';" || true

    # Always try to create the database (will harmlessly error if it already exists)
    sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};" || true
    print_success "PostgreSQL database initialized"

    # Ensure privileges and schema access for PostgreSQL 15+
    sudo -u postgres psql -d ${DB_NAME} -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" || true
    sudo -u postgres psql -d ${DB_NAME} -c "GRANT ALL ON SCHEMA public TO ${DB_USER};" || true

    # Export for later setup steps.
    export DB_USER DB_PASS DB_NAME
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

setup_fail2ban() {
    print_info "Setting up Fail2ban..."
    
    if ! command -v fail2ban-client &> /dev/null; then
        print_warning "Fail2ban not installed, skipping"
        return
    fi
    
    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2ban is already running"
    else
        systemctl start fail2ban
        systemctl enable fail2ban
        print_success "Fail2ban started"
    fi
    
    # Install panel-specific filters and jails
    cd "$INSTALL_DIR"
    source venv/bin/activate 2>/dev/null || true
    
    python3 -c "
from app.security import fail2ban_manager
results = fail2ban_manager.install_all()
print('Fail2ban setup:', results)
" 2>/dev/null || true
    
    systemctl reload fail2ban 2>/dev/null || true
    print_success "Fail2ban configured"
}

setup_env() {
    print_info "Setting up environment configuration..."
    cd "$INSTALL_DIR"

    if [[ ! -f .env ]]; then
        cp .env.example .env

        # Generate strong, per-install secrets. Each is at least 32 chars so
        # app/config.py will accept them (the validator rejects shorter).
        SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
        JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
        CSRF=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        ARGON_SALT=$(python3 -c "import secrets; print(secrets.token_hex(16))")
        BOOTSTRAP_PW=$(python3 -c "
import secrets, string
alphabet = string.ascii_letters + string.digits + '!@#%^*-_=+'
print(''.join(secrets.choice(alphabet) for _ in range(20)))
")

        sed -i "s|^SECRET_KEY=.*|SECRET_KEY=${SECRET}|" .env
        sed -i "s|^JWT_SECRET_KEY=.*|JWT_SECRET_KEY=${JWT_SECRET}|" .env || echo "JWT_SECRET_KEY=${JWT_SECRET}" >> .env
        sed -i "s|^CSRF_SECRET=.*|CSRF_SECRET=${CSRF}|" .env || echo "CSRF_SECRET=${CSRF}" >> .env
        sed -i "s|^ARGON2_SALT=.*|ARGON2_SALT=${ARGON_SALT}|" .env || echo "ARGON2_SALT=${ARGON_SALT}" >> .env
        sed -i "s|^ADMIN_BOOTSTRAP_PASSWORD=.*|ADMIN_BOOTSTRAP_PASSWORD=${BOOTSTRAP_PW}|" .env || \
            echo "ADMIN_BOOTSTRAP_PASSWORD=${BOOTSTRAP_PW}" >> .env

        SERVER_IP=$(hostname -I | awk '{print $1}')
        sed -i "s|VPN_SERVER_IP=your-server-ip|VPN_SERVER_IP=${SERVER_IP}|" .env

        # Default the app to bind loopback only; the reverse proxy fronts it.
        sed -i "s|^HOST=.*|HOST=127.0.0.1|" .env

        print_success "Environment configuration created (.env)"
        echo
        echo "─────────────────────────────────────────────────────────────"
        echo "  Initial admin credentials (write these down — shown ONCE):"
        echo "    user:     admin"
        echo "    password: ${BOOTSTRAP_PW}"
        echo "  After first login, REMOVE ADMIN_BOOTSTRAP_PASSWORD from .env."
        echo "─────────────────────────────────────────────────────────────"
        echo
    else
        print_success "Environment configuration already exists"
    fi

    # Ensure DATABASE_URL has the random per-install password.
    if [[ -n "${DB_PASS:-}" ]]; then
        DB_URL="postgresql+asyncpg://${DB_USER:-vpnadmin}:${DB_PASS}@127.0.0.1:5432/${DB_NAME:-vpnpanel}"
        if grep -q "^DATABASE_URL=" .env; then
            sed -i "s|^DATABASE_URL=.*|DATABASE_URL=${DB_URL}|" .env
        else
            echo "DATABASE_URL=${DB_URL}" >> .env
        fi
    fi

    # Wire the generated TLS cert paths into .env (only if setup_tls_cert ran).
    if [[ -n "${TLS_CERT_FILE:-}" && -n "${TLS_KEY_FILE:-}" ]]; then
        if grep -q "^TLS_CERT_FILE=" .env; then
            sed -i "s|^TLS_CERT_FILE=.*|TLS_CERT_FILE=${TLS_CERT_FILE}|" .env
        else
            echo "TLS_CERT_FILE=${TLS_CERT_FILE}" >> .env
        fi
        if grep -q "^TLS_KEY_FILE=" .env; then
            sed -i "s|^TLS_KEY_FILE=.*|TLS_KEY_FILE=${TLS_KEY_FILE}|" .env
        else
            echo "TLS_KEY_FILE=${TLS_KEY_FILE}" >> .env
        fi
    fi

    # OpenTelemetry off by default — operators flip this on when a collector
    # actually exists. Avoids the journal-spam from the OTLP gRPC retry loop.
    if grep -q "^OTEL_ENABLED=" .env; then
        sed -i "s|^OTEL_ENABLED=.*|OTEL_ENABLED=false|" .env
    else
        echo "OTEL_ENABLED=false" >> .env
    fi

    # Lock down .env permissions — secrets at rest must be operator-only.
    chmod 600 .env || true
    chown "${PANEL_USER:-root}:${PANEL_USER:-root}" .env 2>/dev/null || true
}

setup_tls_cert() {
    # Generate a self-signed cert so Xray's TLS-bearing inbounds boot on a
    # fresh server. Operators are expected to swap this for a real cert
    # (Let's Encrypt / Cloudflare Origin) once a domain is pointed at the
    # box; the .env keeps the override knobs (TLS_CERT_FILE / TLS_KEY_FILE).
    local TLS_DIR="${INSTALL_DIR}/tls"
    local CERT="${TLS_DIR}/spiritus.crt"
    local KEY="${TLS_DIR}/spiritus.key"
    mkdir -p "${TLS_DIR}"
    if [[ ! -s "${CERT}" || ! -s "${KEY}" ]]; then
        print_info "Generating self-signed TLS cert at ${TLS_DIR}/ (10-year validity)..."
        # SAN includes hostname + a wildcard so it works for IP-only access too.
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout "${KEY}" -out "${CERT}" \
            -subj "/CN=$(hostname || echo spiritus)" \
            -addext "subjectAltName=DNS:$(hostname || echo localhost),DNS:localhost,IP:127.0.0.1" \
            >/dev/null 2>&1 || {
                print_warning "openssl missing? Skipping self-signed cert generation."
                return 0
            }
        chmod 644 "${CERT}"
        chmod 640 "${KEY}"
    fi
    # Cert is world-readable; key is group-readable. Group must contain
    # whichever user xray runs as. Try the common ones.
    local XRAY_USER=""
    for _u in xray nobody root; do
        id "${_u}" >/dev/null 2>&1 && { XRAY_USER="${_u}"; break; }
    done
    if [[ -n "${XRAY_USER}" ]]; then
        chgrp "${XRAY_USER}" "${KEY}" 2>/dev/null || true
    fi
    export TLS_CERT_FILE="${CERT}"
    export TLS_KEY_FILE="${KEY}"
    print_success "TLS cert ready (${CERT})"
}


setup_panel_user() {
    print_info "Creating dedicated unprivileged service user..."
    PANEL_USER="${PANEL_USER:-vpnpanel}"
    if ! id "$PANEL_USER" >/dev/null 2>&1; then
        useradd --system --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin \
            --comment "V7LTHRONYX VPN Panel" "$PANEL_USER" 2>/dev/null || \
            useradd --system --home "${INSTALL_DIR}" --shell /usr/sbin/nologin "$PANEL_USER"
    fi
    # Tighten ownership of the panel install dir.
    chown -R "${PANEL_USER}:${PANEL_USER}" "${INSTALL_DIR}" 2>/dev/null || true
    # Pre-create log files with the right ownership. Python's FileHandler and
    # systemd's StandardOutput=append: both need them writable before the
    # service starts. Stale root-owned log files from earlier installs would
    # otherwise survive the chown -R if any sub-tool created them late.
    for _log in vpn-panel.log celery-worker.log celery-beat.log update.log; do
        : > "${INSTALL_DIR}/${_log}" 2>/dev/null || true
        chown "${PANEL_USER}:${PANEL_USER}" "${INSTALL_DIR}/${_log}" 2>/dev/null || true
        chmod 640 "${INSTALL_DIR}/${_log}" 2>/dev/null || true
    done
    # Allow ONLY the narrow systemctl restart needed for live config push.
    cat > /etc/sudoers.d/${PANEL_USER} <<EOF
${PANEL_USER} ALL=(root) NOPASSWD: /bin/systemctl restart xray, /bin/systemctl reload xray, /bin/systemctl status xray
EOF
    chmod 440 /etc/sudoers.d/${PANEL_USER}
    print_success "Service user '${PANEL_USER}' created with minimal sudo"
    export PANEL_USER
}


configure_systemd() {
    print_info "Configuring systemd service..."
    PANEL_USER="${PANEL_USER:-vpnpanel}"

    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=V7LTHRONYX VPN Management Panel
After=network.target xray.service postgresql.service redis-server.service
Wants=xray.service postgresql.service redis-server.service

[Service]
Type=simple
User=${PANEL_USER}
Group=${PANEL_USER}
WorkingDirectory=${INSTALL_DIR}
Environment="PYTHONUNBUFFERED=1"
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin"
# Bind to loopback only. External access goes through a TLS-terminating
# reverse proxy (nginx/Caddy) on 80/443.
ExecStart=${INSTALL_DIR}/venv/bin/python3 -m uvicorn app.main:app --host 127.0.0.1 --port 38471 --workers 2 --proxy-headers --forwarded-allow-ips=127.0.0.1
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3

# ── Sandboxing ──
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
PrivateDevices=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0027
ReadWritePaths=${INSTALL_DIR} /usr/local/etc/xray /var/log/xray
LimitNOFILE=65536

StandardOutput=journal
StandardError=journal
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
User=${PANEL_USER}
Group=${PANEL_USER}
WorkingDirectory=${INSTALL_DIR}
Environment="PYTHONUNBUFFERED=1"
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${INSTALL_DIR}/venv/bin/celery -A app.celery_tasks worker --loglevel=info --concurrency=2
Restart=always
RestartSec=10

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0027
ReadWritePaths=${INSTALL_DIR} /tmp

StandardOutput=journal
StandardError=journal
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
User=${PANEL_USER}
Group=${PANEL_USER}
WorkingDirectory=${INSTALL_DIR}
Environment="PYTHONUNBUFFERED=1"
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${INSTALL_DIR}/venv/bin/celery -A app.celery_tasks beat --loglevel=info
Restart=always

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0027
ReadWritePaths=${INSTALL_DIR}
RestartSec=10

StandardOutput=journal
StandardError=journal
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

    # NOTE: the legacy plaintext password file has been removed as part of
    # the 2026-05 security hardening pass. The initial admin user is now
    # bootstrapped from the ADMIN_BOOTSTRAP_PASSWORD env var in .env on first
    # boot, then the env var must be deleted by the operator.

    systemctl restart ${SERVICE_NAME}
    systemctl restart ${SERVICE_NAME}-worker 2>/dev/null || true
    systemctl restart ${SERVICE_NAME}-beat 2>/dev/null || true
    
    print_info "Waiting for web application to start (this may take up to 20s)..."
    HEALTH_STATUS="Failed"
    for i in $(seq 1 10); do
        if curl -s http://127.0.0.1:38471/api/health | grep -q "healthy"; then
            HEALTH_STATUS="OK"
            break
        fi
        sleep 2
    done
    
    # Save the health status to a temporary file to be read by show_info
    echo "$HEALTH_STATUS" > /tmp/vpn_panel_health_status
    
    if systemctl is-active --quiet ${SERVICE_NAME}; then
        print_success "V7LTHRONYX service is running!"
        if [[ "$HEALTH_STATUS" != "OK" ]]; then
            print_error "Web application did not respond to health check."
            print_info "Last 20 lines of log:"
            tail -n 20 ${INSTALL_DIR}/vpn-panel.log
        fi
    else
        print_error "Failed to start V7LTHRONYX service. Check logs: journalctl -u ${SERVICE_NAME} -f"
        tail -n 20 ${INSTALL_DIR}/vpn-panel.log
        exit 1
    fi
}

show_info() {
    # Pull the one-shot bootstrap password from the .env, then hint that it
    # should be removed after the first login.
    PANEL_PASSWORD=$(grep '^ADMIN_BOOTSTRAP_PASSWORD=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
    if [[ -z "$PANEL_PASSWORD" ]]; then
        PANEL_PASSWORD="(consumed — change at /change-password)"
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  V7LTHRONYX VPN Panel v2.0 - Installation Complete!${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    HEALTH_STATUS=$(cat /tmp/vpn_panel_health_status 2>/dev/null || echo "Failed")
    if [[ "$HEALTH_STATUS" == "OK" ]]; then
        HEALTH_MSG="${GREEN}✔ Web Application is UP and Healthy${NC}"
    else
        HEALTH_MSG="${RED}✖ Web Application Failed to Start (Check logs)${NC}"
    fi

    echo -e "  ${YELLOW}Panel URL:${NC}     http://$(hostname -I | awk '{print $1}'):38471"
    echo -e "  ${YELLOW}API Docs:${NC}     http://$(hostname -I | awk '{print $1}'):38471/api/docs"
    echo -e "  ${YELLOW}Password:${NC}     ${PANEL_PASSWORD}"
    echo -e "  ${YELLOW}System Health:${NC} ${HEALTH_MSG}"
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
    
    echo -e "${CYAN}[1/13]${NC} Installing system dependencies..."
    install_dependencies
    
    echo -e "${CYAN}[2/13]${NC} Installing Xray..."
    install_xray
    
    echo -e "${CYAN}[3/13]${NC} Downloading V7LTHRONYX..."
    clone_or_update
    
    echo -e "${CYAN}[4/13]${NC} Setting up PostgreSQL..."
    setup_postgresql
    
    echo -e "${CYAN}[5/13]${NC} Setting up Redis..."
    setup_redis
    
    echo -e "${CYAN}[6/13]${NC} Setting up Fail2ban..."
    setup_fail2ban
    
    echo -e "${CYAN}[7/13]${NC} Setting up Python environment..."
    setup_python

    echo -e "${CYAN}[8/13]${NC} Creating unprivileged service user..."
    setup_panel_user

    echo -e "${CYAN}[9/13]${NC} Generating self-signed TLS cert..."
    setup_tls_cert

    echo -e "${CYAN}[10/13]${NC} Setting up environment config..."
    setup_env

    echo -e "${CYAN}[11/13]${NC} Configuring services..."
    configure_systemd

    echo -e "${CYAN}[12/13]${NC} Setting up auto-update..."
    setup_auto_update

    echo -e "${CYAN}[13/13]${NC} Starting panel..."
    start_panel

    show_info
}

main "$@"