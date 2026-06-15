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

# Web panel port. Override with `--port N` or WEB_PORT=N env. Persisted
# to .env as VPN_WEB_PORT so the app and the systemd unit agree.
WEB_PORT="${WEB_PORT:-38471}"

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

install_acme() {
    # The panel's domain manager issues real Let's Encrypt certs via
    # acme.sh (preferred) or certbot. Detection is `shutil.which("acme.sh")`
    # / `shutil.which("certbot")`, so the binary MUST be on PATH — the
    # stock acme.sh installer hides it under ~/.acme.sh, which `which`
    # never sees. We install it and symlink it onto PATH.
    if command -v acme.sh &>/dev/null; then
        print_success "acme.sh already on PATH"
        return
    fi

    print_info "Installing acme.sh (Let's Encrypt client)..."
    local acme_home="/etc/v7lthronyx/acme"   # matches LE_WORKING_DIR used by domain_manager
    mkdir -p "$acme_home"
    local tmp; tmp=$(mktemp -d)
    if curl -fsSL --max-time 60 -o "$tmp/acme-install.sh" https://get.acme.sh 2>/dev/null; then
        # --nocron: the panel's Celery task handles renewal; --home pins
        # the working dir to the one domain_manager exports as HOME.
        if HOME="$acme_home" sh "$tmp/acme-install.sh" --home "$acme_home" --nocron >/dev/null 2>&1 \
           && [[ -f "$acme_home/acme.sh" ]]; then
            ln -sf "$acme_home/acme.sh" /usr/local/bin/acme.sh
            print_success "acme.sh installed (symlinked to /usr/local/bin/acme.sh)"
        else
            print_warning "acme.sh install failed — falling back to certbot"
        fi
    else
        print_warning "Could not download acme.sh — falling back to certbot"
    fi
    rm -rf "$tmp"

    # certbot as a fallback ACME client (domain_manager uses it if
    # acme.sh is absent). Best-effort; don't fail the whole install.
    if ! command -v acme.sh &>/dev/null && ! command -v certbot &>/dev/null; then
        if [[ "$PKG_MANAGER" == "apt" ]]; then
            apt install -y certbot >/dev/null 2>&1 || true
        elif [[ "$PKG_MANAGER" == "yum" ]]; then
            yum install -y certbot >/dev/null 2>&1 || true
        fi
        command -v certbot &>/dev/null && print_success "certbot installed (ACME fallback)"
    fi

    if ! command -v acme.sh &>/dev/null && ! command -v certbot &>/dev/null; then
        print_warning "No ACME client available — only self-signed certs will be issued."
        print_warning "Install acme.sh or certbot, then use the Domain tab to get a real cert."
    fi
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

install_singbox() {
    # sing-box hosts the standalone protocols (Hysteria2, TUIC,
    # ShadowTLS, NaiveProxy) that are not Xray inbounds. The panel
    # writes /usr/local/etc/sing-box/config.json and reloads this unit.
    if command -v sing-box &> /dev/null; then
        print_success "sing-box already installed: $(sing-box version 2>&1 | head -1)"
        return
    fi

    print_info "Installing sing-box..."
    local arch
    case "$(uname -m)" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l)  arch="armv7" ;;
        *)       arch="amd64" ;;
    esac

    # Resolve the latest release tag, fall back to a known-good version.
    local ver
    ver=$(curl -fsSL --max-time 20 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null \
          | grep -oP '"tag_name":\s*"v\K[^"]+' | head -1)
    [[ -z "$ver" ]] && ver="1.10.7"

    local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${arch}.tar.gz"
    local tmp; tmp=$(mktemp -d)
    if curl -fsSL --max-time 120 -o "$tmp/sb.tar.gz" "$url" && tar xzf "$tmp/sb.tar.gz" -C "$tmp"; then
        install -m 0755 "$tmp"/sing-box-*/sing-box /usr/local/bin/sing-box
        mkdir -p /usr/local/etc/sing-box
        # Minimal valid config so the unit can start before the panel
        # writes the real one on first protocol sync.
        if [[ ! -f /usr/local/etc/sing-box/config.json ]]; then
            echo '{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}]}' \
                > /usr/local/etc/sing-box/config.json
        fi
        # systemd unit
        cat > /etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=sing-box service
After=network.target nss-lookup.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable sing-box 2>/dev/null || true
        print_success "sing-box ${ver} installed"
    else
        print_warning "sing-box download failed — standalone protocols (Hysteria2/TUIC/ShadowTLS/Naive) will be unavailable until installed"
    fi
    rm -rf "$tmp"
}

install_mieru() {
    # Mieru ships its own `mita` server daemon. The panel writes a mita
    # JSON config and applies it via `mita apply config`.
    if command -v mita &> /dev/null; then
        print_success "mieru (mita) already installed: $(mita version 2>&1 | head -1)"
        return
    fi

    print_info "Installing mieru (mita)..."
    local arch
    case "$(uname -m)" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)       arch="amd64" ;;
    esac

    local ver
    ver=$(curl -fsSL --max-time 20 https://api.github.com/repos/enfein/mieru/releases/latest 2>/dev/null \
          | grep -oP '"tag_name":\s*"v\K[^"]+' | head -1)
    [[ -z "$ver" ]] && ver="3.19.0"

    # mieru publishes a .deb for the mita server; fall back to tar.gz.
    local tmp; tmp=$(mktemp -d)
    local deb="mita_${ver}_linux_${arch}.deb"
    local deb_url="https://github.com/enfein/mieru/releases/download/v${ver}/${deb}"
    if curl -fsSL --max-time 120 -o "$tmp/$deb" "$deb_url" && dpkg -i "$tmp/$deb" >/dev/null 2>&1; then
        mkdir -p /usr/local/etc/mieru
        systemctl enable mita 2>/dev/null || true
        print_success "mieru (mita) ${ver} installed"
    else
        print_warning "mieru download failed — Mieru protocol will be unavailable until installed"
    fi
    rm -rf "$tmp"
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

run_migrations() {
    # Apply Alembic migrations. Two cases must both work:
    #  1. Fresh DB  → upgrade head runs 001 (create) + 002 (alter).
    #  2. Existing DB created by the app's Base.metadata.create_all
    #     (no alembic_version table) → `upgrade head` would fail on
    #     001's CREATE TABLE ("already exists"); we stamp the base
    #     revision and then upgrade so only the additive ALTERs run.
    print_info "Applying database migrations..."
    cd "$INSTALL_DIR"
    # shellcheck disable=SC1091
    source venv/bin/activate

    local err=/tmp/v7-alembic.err
    if alembic upgrade head 2>"$err"; then
        print_success "Database migrations applied"
    elif grep -qiE "already exists|DuplicateTable" "$err"; then
        print_info "Existing schema detected — stamping baseline then upgrading..."
        if alembic stamp 001 >/dev/null 2>&1 && alembic upgrade head 2>"$err"; then
            print_success "Database migrations applied (stamped baseline)"
        else
            print_warning "Migration after stamp failed: $(tail -1 "$err" 2>/dev/null)"
        fi
    else
        print_warning "Database migration failed: $(tail -1 "$err" 2>/dev/null)"
        print_warning "The app will fall back to create_all on startup; manual 'alembic upgrade head' may be needed for schema changes."
    fi
    rm -f "$err"
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
    
    # Install panel-specific filters and jails. Capture stderr instead
    # of discarding it — a swallowed failure here used to leave the panel
    # with NO brute-force protection while the installer claimed success.
    cd "$INSTALL_DIR"
    # shellcheck disable=SC1091
    source venv/bin/activate 2>/dev/null || true

    local f2b_err=/tmp/v7-fail2ban.err
    if python3 -c "
from app.security import fail2ban_manager
results = fail2ban_manager.install_all()
print('Fail2ban setup:', results)
" 2>"$f2b_err"; then
        if systemctl reload fail2ban 2>>"$f2b_err"; then
            print_success "Fail2ban configured"
        else
            print_warning "Fail2ban filters installed but reload failed: $(tail -1 "$f2b_err" 2>/dev/null)"
        fi
    else
        print_warning "Fail2ban filter install failed — panel brute-force jails are NOT active:"
        print_warning "  $(tail -1 "$f2b_err" 2>/dev/null)"
        print_warning "  Re-run after fixing, or check 'app.security.fail2ban_manager'."
    fi
    rm -f "$f2b_err"
}

# Idempotent .env upsert. `_env_set KEY value` replaces an existing
# `^KEY=...` line or appends one if missing. Always writes the key — no
# silent skips because sed-with-`||` was a sharp edge:  sed returns 0
# even when nothing matched, so the fallback `|| echo` never fired.
_env_set() {
    local key="$1" val="$2" file="${3:-.env}"
    if [[ ! -f "$file" ]]; then touch "$file"; fi
    if grep -q "^${key}=" "$file"; then
        # Use | as delimiter so values containing / are safe.
        # Escape & and | in the replacement.
        local esc; esc=$(printf '%s' "$val" | sed -e 's/[\\&|]/\\&/g')
        sed -i "s|^${key}=.*|${key}=${esc}|" "$file"
    else
        printf '%s=%s\n' "$key" "$val" >> "$file"
    fi
}

# Read current value of KEY from .env (empty if missing).
_env_get() {
    local key="$1" file="${2:-.env}"
    [[ -f "$file" ]] || { echo ""; return; }
    sed -n "s|^${key}=\(.*\)$|\1|p" "$file" | head -1
}

setup_env() {
    print_info "Setting up environment configuration..."
    cd "$INSTALL_DIR"

    local is_new_env=0
    if [[ ! -f .env ]]; then
        cp .env.example .env
        is_new_env=1
        print_info "Created .env from template"
    fi

    # ── Per-install secrets ───────────────────────────────────────────
    # All of these are upserted so re-runs that inherit a partial .env
    # from an earlier install (missing JWT_SECRET_KEY, CSRF_SECRET,
    # ADMIN_BOOTSTRAP_PASSWORD, ...) get backfilled. Existing values are
    # preserved when present and non-trivial — we never blow away a
    # working secret on a re-install.
    _maybe_gen_secret() {
        local key="$1" len="${2:-48}" current
        current=$(_env_get "$key")
        if [[ -z "$current" || "$current" == "change-me"* || ${#current} -lt 32 ]]; then
            _env_set "$key" "$(python3 -c "import secrets; print(secrets.token_urlsafe(${len}))")"
        fi
    }
    _maybe_gen_secret SECRET_KEY 48
    _maybe_gen_secret JWT_SECRET_KEY 48
    _maybe_gen_secret CSRF_SECRET 32
    if [[ -z "$(_env_get ARGON2_SALT)" ]]; then
        _env_set ARGON2_SALT "$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
    fi

    # ── Bootstrap admin password ──────────────────────────────────────
    # Generated once and persisted in .env so the first /api/login
    # actually has something to authenticate against. We surface the
    # value at the end of install (and again here on re-runs) — the
    # operator is responsible for unsetting it after first login.
    local bootstrap_pw
    bootstrap_pw=$(_env_get ADMIN_BOOTSTRAP_PASSWORD)
    if [[ -z "$bootstrap_pw" ]]; then
        bootstrap_pw=$(python3 -c "
import secrets, string, re

# Guarantee every character class required by validate_password_strength:
#   1+ uppercase, 1+ lowercase, 1+ digit, 1+ symbol, total >= 16
upper   = string.ascii_uppercase
lower   = string.ascii_lowercase
digits  = string.digits
symbols = '!@#%^*-_=+'
alphabet = upper + lower + digits + symbols

while True:
    pw = ''.join(secrets.choice(alphabet) for _ in range(20))
    if (re.search(r'[A-Z]', pw) and re.search(r'[a-z]', pw) and
            re.search(r'[0-9]', pw) and re.search(r'[^A-Za-z0-9]', pw)):
        print(pw)
        break
")
        _env_set ADMIN_BOOTSTRAP_PASSWORD "$bootstrap_pw"
    fi
    _env_set ADMIN_BOOTSTRAP_USERNAME "$(_env_get ADMIN_BOOTSTRAP_USERNAME)"
    if [[ -z "$(_env_get ADMIN_BOOTSTRAP_USERNAME)" ]]; then
        _env_set ADMIN_BOOTSTRAP_USERNAME admin
    fi
    export BOOTSTRAP_PW="$bootstrap_pw"

    # ── Server binding ────────────────────────────────────────────────
    # Default to 0.0.0.0 so a fresh install is reachable from a browser
    # without a reverse proxy. We also OVERWRITE the legacy 127.0.0.1
    # default left behind by earlier installer versions (the previous
    # hardening pass shipped HOST=127.0.0.1 by default and that breaks
    # browser access on boxes without a reverse proxy — which is the
    # vast majority of installs). Operators who *do* run nginx/Caddy in
    # front of the panel can set HOST to a non-loopback non-wildcard
    # value (e.g. a private IP) and that gets preserved.
    local cur_host; cur_host=$(_env_get HOST)
    if [[ -z "$cur_host" || "$cur_host" == "127.0.0.1" || "$cur_host" == "localhost" ]]; then
        _env_set HOST "0.0.0.0"
    fi

    # ── Web port ──────────────────────────────────────────────────────
    # Persist the chosen port so the app's settings.web_port matches the
    # systemd ExecStart --port. On a re-run that didn't pass --port, honour
    # the value already in .env (so we don't silently revert an operator's
    # custom port back to the default).
    local cur_port; cur_port=$(_env_get VPN_WEB_PORT)
    if [[ "$WEB_PORT" != "38471" ]]; then
        _env_set VPN_WEB_PORT "$WEB_PORT"          # explicit --port wins
    elif [[ -n "$cur_port" ]]; then
        WEB_PORT="$cur_port"                        # keep existing custom port
    else
        _env_set VPN_WEB_PORT "$WEB_PORT"
    fi

    # Server's primary IP (best-effort autodetect; can be overridden).
    local server_ip; server_ip=$(hostname -I | awk '{print $1}')
    if [[ -n "$server_ip" ]] && [[ "$(_env_get VPN_SERVER_IP)" == "" || "$(_env_get VPN_SERVER_IP)" == "your-server-ip" ]]; then
        _env_set VPN_SERVER_IP "$server_ip"
    fi

    # ── Database URL with per-install random password ────────────────
    if [[ -n "${DB_PASS:-}" ]]; then
        _env_set DATABASE_URL "postgresql+asyncpg://${DB_USER:-vpnadmin}:${DB_PASS}@127.0.0.1:5432/${DB_NAME:-vpnpanel}"
    fi

    # ── TLS cert paths (set by setup_tls_cert) ───────────────────────
    if [[ -n "${TLS_CERT_FILE:-}" && -n "${TLS_KEY_FILE:-}" ]]; then
        _env_set TLS_CERT_FILE "${TLS_CERT_FILE}"
        _env_set TLS_KEY_FILE  "${TLS_KEY_FILE}"
    fi

    # ── OpenTelemetry off unless operator turns it on ────────────────
    _env_set OTEL_ENABLED "false"

    # ── DEBUG never on by default ────────────────────────────────────
    _env_set DEBUG "false"

    # Lock down .env permissions — secrets at rest must be operator-only.
    chmod 600 .env || true
    chown "${PANEL_USER:-root}:${PANEL_USER:-root}" .env 2>/dev/null || true

    print_success "Environment configuration ready (.env)"
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

# Detect whether stdin is connected to an interactive terminal. We
# need this so the domain prompt below doesn't block unattended
# installs (CI, kickstart, etc.) — an unattended install just
# skips the prompt and uses the IP-based defaults.
_is_interactive() {
    [[ -t 0 ]]
}

# Ask the operator for a domain. Optional: pressing Enter (or
# piping /dev/null) means "skip — use the IP-based defaults".
# We do this BEFORE the panel starts so the very first config
# render uses the right SNI; a late set_domain() would mean the
# initial share URLs handed out in the first few minutes had
# stale SNIs.
prompt_domain() {
    if ! _is_interactive; then
        print_info "Non-interactive install detected — skipping domain prompt."
        return 1
    fi
    print_info "Domain setup (optional — press Enter to use the IP address)"
    print_info "If you have a domain pointed at this server, we can issue a"
    print_info "Let's Encrypt cert automatically and set every TLS-bearing"
    print_info "protocol's SNI to it. The panel UI also has a Domain tab"
    print_info "where you can change or disable the domain at any time."
    local input=""
    read -r -p "$(echo -e "${YELLOW}Domain [leave blank to skip]:${NC} ")" input
    input="${input// /}"
    if [[ -z "$input" ]]; then
        print_info "No domain entered; the panel will use the IP address."
        return 1
    fi
    # Persist immediately so the .env / startup sees the value
    # even if the panel's set_domain() step fails (operator can
    # retry from the UI).
    _env_set "PANEL_DOMAIN" "$input"
    export PANEL_DOMAIN="$input"
    return 0
}

# Run the panel's domain manager once, in --prefer-self-signed
# mode, to write the Setting rows + cert files BEFORE the
# systemd unit starts. This way:
#   - The very first Xray render uses the right SNI (no
#     share-URL churn on the operator's first batch of users).
#   - The first request to /api/health sees the cert files
#     in place, so the TLS-bearing inbounds boot cleanly
#     instead of Xray logging "cert missing" and falling
#     back to the panel's IP.
#
# If DNS isn't pointed at the server yet, or acme.sh/certbot
# isn't installed, the panel will silently fall back to a
# self-signed cert — exactly the same fallback the
# prefer_self_signed=True path uses in the UI.
apply_domain_on_install() {
    local domain="${PANEL_DOMAIN:-}"
    if [[ -z "$domain" ]]; then return 0; fi
    cd "$INSTALL_DIR"
    source venv/bin/activate 2>/dev/null || true
    print_info "Applying domain '${domain}' to the panel database..."
    # The DomainManager writes the cert + Setting rows, then
    # triggers a sync of the Xray config. We don't reload
    # Xray here (the panel's systemd unit hasn't started
    # yet on a first install); the first reload happens
    # when start_panel() runs systemctl restart below.
    python3 -c "
import asyncio
from app.database import AsyncSessionLocal
from app.domain_manager import set_domain

async def _run():
    async with AsyncSessionLocal() as db:
        # prefer_self_signed on first boot: DNS often isn't
        # pointed yet, and a clean self-signed cert is
        # better than a half-failed LE attempt. The UI's
        # 'Renew now' button can re-issue as a real LE
        # cert later.
        result = await set_domain(
            db, '$domain', '',
            prefer_self_signed=True,
        )
        if result.success:
            print('DOMAIN_APPLIED')
            for step in result.steps:
                print(f'  - {step}')
        else:
            print(f'DOMAIN_FAILED: {result.error}')

asyncio.run(_run())
" || {
        print_warning "Domain setup failed; the panel will use the IP address."
        print_warning "You can retry from the Domain tab in the UI."
    }
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

    # Grant the panel user write access to the xray config directory so it
    # can push updated configs without running as root.
    mkdir -p /usr/local/etc/xray
    chown -R root:"${PANEL_USER}" /usr/local/etc/xray
    chmod -R 775 /usr/local/etc/xray
    # Ensure existing config.json is writable by the group
    [[ -f /usr/local/etc/xray/config.json ]] && chmod 664 /usr/local/etc/xray/config.json || true
    print_success "Xray config dir writable by ${PANEL_USER}"

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
ExecStart=${INSTALL_DIR}/venv/bin/python3 -m uvicorn app.main:app --host 0.0.0.0 --port ${WEB_PORT} --workers 2 --proxy-headers --forwarded-allow-ips='127.0.0.1'
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

open_firewall_port() {
    # The Fail2ban + per-IP rate limiter + CSRF middleware harden the public
    # bind, but if the host has a firewall up the port still has to be open.
    # Best-effort across ufw / firewalld / nftables / iptables — silent
    # failures are fine (the operator may not have a firewall at all).
    local port="${1:-38471}"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${port}/tcp" >/dev/null 2>&1 || true
        print_info "ufw: allowed ${port}/tcp"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        print_info "firewalld: allowed ${port}/tcp"
    fi
}

start_panel() {
    print_info "Starting V7LTHRONYX panel..."

    # NOTE: the legacy plaintext password file has been removed as part of
    # the 2026-05 security hardening pass. The initial admin user is now
    # bootstrapped from the ADMIN_BOOTSTRAP_PASSWORD env var in .env on first
    # boot, then the env var must be deleted by the operator.

    # Open the panel port in the local firewall (idempotent, best-effort).
    open_firewall_port "${WEB_PORT}"

    systemctl restart ${SERVICE_NAME}
    systemctl restart ${SERVICE_NAME}-worker 2>/dev/null || true
    systemctl restart ${SERVICE_NAME}-beat 2>/dev/null || true
    
    print_info "Waiting for web application to start (this may take up to 20s)..."
    HEALTH_STATUS="Failed"
    for i in $(seq 1 10); do
        if curl -s "http://127.0.0.1:${WEB_PORT}/api/health" | grep -q "healthy"; then
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

    echo -e "  ${YELLOW}Panel URL:${NC}     http://$(hostname -I | awk '{print $1}'):${WEB_PORT}"
    echo -e "  ${YELLOW}API Docs:${NC}     http://$(hostname -I | awk '{print $1}'):${WEB_PORT}/api/docs"
    echo -e "  ${YELLOW}Username:${NC}     admin"
    echo -e "  ${YELLOW}Password:${NC}     ${PANEL_PASSWORD}"
    echo ""
    echo -e "  ${RED}IMPORTANT:${NC} after first login, change the password in the panel,"
    echo -e "             then remove ADMIN_BOOTSTRAP_PASSWORD from .env and restart."
    echo ""
    echo -e "  ${YELLOW}System Health:${NC} ${HEALTH_MSG}"
    echo -e "  ${YELLOW}Config Dir:${NC}    ${INSTALL_DIR}"
    echo -e "  ${YELLOW}Logs:${NC}         journalctl -u ${SERVICE_NAME} -f"
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

uninstall() {
    print_banner
    echo -e "${RED}  V7LTHRONYX v${VERSION} - Uninstaller${NC}"
    echo ""
    check_root

    local purge_data=0
    if [[ "${1:-}" == "--purge" ]]; then
        purge_data=1
    fi

    # Confirm unless --yes was passed.
    if [[ "${UNINSTALL_ASSUME_YES:-0}" != "1" ]]; then
        echo -e "${YELLOW}This will stop and remove the V7LTHRONYX panel services and files.${NC}"
        if [[ $purge_data -eq 1 ]]; then
            echo -e "${RED}--purge: the PostgreSQL database and Redis keys will ALSO be deleted.${NC}"
        else
            echo -e "${YELLOW}The database is kept (use --purge to also drop it).${NC}"
        fi
        read -r -p "$(echo -e "${YELLOW}Type 'yes' to continue: ${NC}")" confirm
        [[ "$confirm" == "yes" ]] || { print_info "Aborted."; exit 0; }
    fi

    print_info "Stopping and disabling services..."
    for svc in "${SERVICE_NAME}" "${SERVICE_NAME}-worker" "${SERVICE_NAME}-beat"; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done
    # sing-box / mita are shared backends — stop the panel-managed units too.
    systemctl stop sing-box mita 2>/dev/null || true

    # Remove the daily auto-update cron/timer if present.
    rm -f /etc/cron.d/spiritus-update /etc/systemd/system/spiritus-update.* 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    if [[ $purge_data -eq 1 ]]; then
        print_info "Dropping PostgreSQL database and role..."
        sudo -u postgres psql -c "DROP DATABASE IF EXISTS ${DB_NAME:-vpnpanel};" 2>/dev/null || true
        sudo -u postgres psql -c "DROP ROLE IF EXISTS ${DB_USER:-vpnadmin};" 2>/dev/null || true
        print_info "Flushing Redis keys for the panel..."
        redis-cli FLUSHDB 2>/dev/null || true
    fi

    print_info "Removing installed files..."
    rm -rf "${INSTALL_DIR}"
    rm -f /usr/local/bin/acme.sh 2>/dev/null || true

    # Best-effort: leave Xray/sing-box/mita binaries in place (operator may
    # use them elsewhere); only the panel-owned config dirs go.
    echo ""
    print_success "V7LTHRONYX uninstalled."
    if [[ $purge_data -eq 0 ]]; then
        print_info "Database preserved. Re-run with 'uninstall --purge' to drop it."
    fi
    print_info "Xray/sing-box/mita binaries were left installed; remove manually if unwanted."
}

usage() {
    cat <<USAGE
V7LTHRONYX installer v${VERSION}

Usage: $0 [command] [options]

Commands:
  (no command)        Install or update the panel
  uninstall           Stop services and remove the panel (keeps the DB)
  uninstall --purge   Also drop the PostgreSQL DB and flush Redis

Options (install):
  --port N            Web panel port (default 38471; persisted to .env)

Environment:
  WEB_PORT=N              Same as --port N
  UNINSTALL_ASSUME_YES=1  Skip the uninstall confirmation prompt
USAGE
}

main() {
    print_banner
    echo -e "${YELLOW}  V7LTHRONYX v${VERSION} - Easy Installer${NC}"
    echo -e "${YELLOW}  Web port: ${WEB_PORT}${NC}"
    echo ""

    check_root
    check_os
    
    echo -e "${CYAN}[1/13]${NC} Installing system dependencies..."
    install_dependencies
    
    echo -e "${CYAN}[2/13]${NC} Installing Xray..."
    install_xray
    install_singbox
    install_mieru
    install_acme

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

    echo -e "${CYAN}[10a/13]${NC} Prompting for domain (optional)..."
    prompt_domain || true

    echo -e "${CYAN}[10b/13]${NC} Applying domain to panel database..."
    apply_domain_on_install || true

    echo -e "${CYAN}[10/13]${NC} Setting up environment config..."
    setup_env

    echo -e "${CYAN}[10c/13]${NC} Applying database migrations..."
    run_migrations

    echo -e "${CYAN}[11/13]${NC} Configuring services..."
    configure_systemd

    echo -e "${CYAN}[12/13]${NC} Setting up auto-update..."
    setup_auto_update

    echo -e "${CYAN}[13/13]${NC} Starting panel..."
    start_panel

    show_info
}

# ── Argument dispatch ────────────────────────────────────────────────
COMMAND="install"
_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        uninstall|--uninstall)
            COMMAND="uninstall"; shift ;;
        --purge)
            _args+=("--purge"); shift ;;
        --port)
            WEB_PORT="${2:?--port needs a value}"; shift 2 ;;
        --port=*)
            WEB_PORT="${1#*=}"; shift ;;
        -h|--help|help)
            usage; exit 0 ;;
        *)
            print_warning "Unknown argument: $1"; shift ;;
    esac
done

# Validate port is numeric and in range.
if ! [[ "$WEB_PORT" =~ ^[0-9]+$ ]] || (( WEB_PORT < 1 || WEB_PORT > 65535 )); then
    print_error "Invalid --port '$WEB_PORT' (must be 1-65535)"; exit 1
fi

case "$COMMAND" in
    uninstall) uninstall "${_args[@]}" ;;
    *)         main ;;
esac