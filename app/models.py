"""
SQLAlchemy ORM models for V7LTHRONYX VPN Panel.

Tables:
- admins          Panel administrators (login, 2FA, WebAuthn)
- vpn_users       VPN user accounts (traffic, expiry, speed)
- agents          Backend agents (Xray/sing-box/WG nodes)
- protocols       Protocol configurations per agent
- payments        Payment transactions (Zarinpal/IDPay/USDT)
- resellers       Reseller accounts with commission
- reseller_users  Users created by resellers
- settings        Key-value app settings
- audit_log       Immutable audit trail
"""

from sqlalchemy import (
    Column, Integer, BigInteger, String, Float, Boolean,
    DateTime, Text, JSON, ForeignKey, Enum, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from .database import Base


# ═══════════════════════════════════════════════════════════════
#  Enums
# ═══════════════════════════════════════════════════════════════

class UserRole(str, enum.Enum):
    superadmin = "superadmin"
    admin = "admin"
    reseller = "reseller"

class AgentBackend(str, enum.Enum):
    xray = "xray"
    singbox = "singbox"
    wireguard = "wireguard"
    openvpn = "openvpn"

class AgentStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    syncing = "syncing"

class PaymentGateway(str, enum.Enum):
    zarinpal = "zarinpal"
    idpay = "idpay"
    usdt_trc20 = "usdt_trc20"

class PaymentStatus(str, enum.Enum):
    pending = "pending"
    paid = "paid"
    failed = "failed"
    expired = "expired"
    refunded = "refunded"

class ProtocolCategory(str, enum.Enum):
    xray = "xray"
    standalone = "standalone"
    wireguard = "wireguard"


# ═══════════════════════════════════════════════════════════════
#  Admin Users
# ═══════════════════════════════════════════════════════════════

class Admin(Base):
    __tablename__ = "admins"
    __table_args__ = (UniqueConstraint("username"),)

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.admin, nullable=False)

    # 2FA/TOTP
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False)

    # WebAuthn (Passkey) credentials stored as JSON array
    webauthn_credentials = Column(JSON, default=list)

    # mTLS certificate CN (Common Name) for client-cert auth
    mtls_cn = Column(String(255), nullable=True, unique=True)

    # Session / security
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    failed_login_count = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    audit_entries = relationship("AuditLog", back_populates="admin")


# ═══════════════════════════════════════════════════════════════
#  VPN Users
# ═══════════════════════════════════════════════════════════════

class VpnUser(Base):
    __tablename__ = "vpn_users"
    __table_args__ = (
        Index("ix_vpn_users_agent_id", "agent_id"),
        Index("ix_vpn_users_active", "active"),
        Index("ix_vpn_users_reseller_id", "reseller_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), nullable=False, unique=True, index=True)
    name = Column(String(100), nullable=False)

    # Traffic (bytes)
    traffic_limit = Column(BigInteger, default=0)  # 0 = unlimited
    traffic_used = Column(BigInteger, default=0)
    traffic_upload = Column(BigInteger, default=0)
    traffic_download = Column(BigInteger, default=0)

    # Speed (Mbps, 0 = unlimited)
    speed_limit_up = Column(Integer, default=0)
    speed_limit_down = Column(Integer, default=0)

    # Expiry
    expire_at = Column(DateTime, nullable=True)  # NULL = never expires
    active = Column(Integer, default=1)  # 1=active, 0=disabled, -1=expired

    # Agent assignment
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=True)
    agent = relationship("Agent", back_populates="users")

    # Reseller
    reseller_id = Column(Integer, ForeignKey("resellers.id"), nullable=True)
    reseller = relationship("Reseller", back_populates="users")

    # Protocol-specific config overrides (JSON)
    protocol_config = Column(JSON, default=dict)

    # Note
    note = Column(Text, default="")

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


# ═══════════════════════════════════════════════════════════════
#  Agents (Multi-backend orchestrator)
# ═══════════════════════════════════════════════════════════════

class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (UniqueConstraint("name"),)

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    backend = Column(Enum(AgentBackend), nullable=False)
    status = Column(Enum(AgentStatus), default=AgentStatus.offline)

    # Connection
    address = Column(String(255), nullable=False)  # IP or hostname
    api_port = Column(Integer, default=10085)
    api_key = Column(String(255), nullable=True)

    # Xray / sing-box specific
    config_path = Column(String(500), nullable=True)
    bin_path = Column(String(500), nullable=True)
    service_name = Column(String(100), nullable=True)

    # WireGuard specific
    wg_interface = Column(String(50), nullable=True)
    wg_private_key = Column(String(100), nullable=True)
    wg_public_key = Column(String(100), nullable=True)
    wg_address = Column(String(50), nullable=True)
    wg_dns = Column(String(100), nullable=True)
    wg_listen_port = Column(Integer, nullable=True)
    wg_mtu = Column(Integer, default=1280)

    # OpenVPN specific
    ovpn_config_path = Column(String(500), nullable=True)

    # Health
    last_heartbeat = Column(DateTime, nullable=True)
    cpu_usage = Column(Float, default=0)
    mem_usage = Column(Float, default=0)
    active_connections = Column(Integer, default=0)

    # ECH (Encrypted Client Hello) support
    ech_enabled = Column(Boolean, default=False)
    ech_config = Column(JSON, default=dict)  # ECH keys, public_name, etc.

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    users = relationship("VpnUser", back_populates="agent")
    protocols = relationship("ProtocolConfig", back_populates="agent")


# ═══════════════════════════════════════════════════════════════
#  Protocol Configurations (per agent)
# ═══════════════════════════════════════════════════════════════

class ProtocolConfig(Base):
    __tablename__ = "protocol_configs"
    __table_args__ = (
        UniqueConstraint("agent_id", "protocol_key", name="uq_agent_protocol"),
    )

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    agent = relationship("Agent", back_populates="protocols")

    protocol_key = Column(String(50), nullable=False)  # e.g. "vless_xhttp_reality"
    category = Column(Enum(ProtocolCategory), default=ProtocolCategory.xray)

    enabled = Column(Boolean, default=False)
    config = Column(JSON, default=dict)  # Protocol-specific settings

    # Runtime status
    running = Column(Boolean, default=False)
    connections = Column(Integer, default=0)
    last_started_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


# ═══════════════════════════════════════════════════════════════
#  Payments
# ═══════════════════════════════════════════════════════════════

class Payment(Base):
    __tablename__ = "payments"
    __table_args__ = (
        Index("ix_payments_user_id", "user_id"),
        Index("ix_payments_status", "status"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("vpn_users.id"), nullable=True)
    reseller_id = Column(Integer, ForeignKey("resellers.id"), nullable=True)

    gateway = Column(Enum(PaymentGateway), nullable=False)
    status = Column(Enum(PaymentStatus), default=PaymentStatus.pending)

    # Amount in IRR (Iranian Rial) or USDT cents
    amount = Column(BigInteger, nullable=False)
    currency = Column(String(10), default="IRR")  # IRR or USDT

    # Gateway-specific
    gateway_authority = Column(String(255), nullable=True)  # Zarinpal authority
    gateway_ref_id = Column(String(255), nullable=True)    # Gateway reference
    gateway_callback_url = Column(String(500), nullable=True)

    # USDT-specific
    usdt_wallet_address = Column(String(100), nullable=True)
    usdt_tx_hash = Column(String(255), nullable=True)

    # Plan details (what the payment buys)
    plan_traffic_gb = Column(Float, default=0)
    plan_days = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    paid_at = Column(DateTime, nullable=True)
    expired_at = Column(DateTime, nullable=True)


# ═══════════════════════════════════════════════════════════════
#  Resellers
# ═══════════════════════════════════════════════════════════════

class Reseller(Base):
    __tablename__ = "resellers"
    __table_args__ = (UniqueConstraint("username"),)

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)

    # Commission (percentage)
    commission_rate = Column(Float, default=10.0)  # 10%
    balance = Column(BigInteger, default=0)  # In IRR

    # Limits
    max_users = Column(Integer, default=100)
    max_traffic_gb = Column(Float, default=1000)

    # Status
    active = Column(Boolean, default=True)

    # Self-service portal settings
    portal_enabled = Column(Boolean, default=True)
    portal_custom_domain = Column(String(255), nullable=True)
    portal_branding = Column(JSON, default=dict)  # Logo, colors, etc.

    # Timestamps
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    users = relationship("VpnUser", back_populates="reseller")
    payments = relationship("Payment", back_populates="reseller")


# ═══════════════════════════════════════════════════════════════
#  Settings (Key-Value)
# ═══════════════════════════════════════════════════════════════

class Setting(Base):
    __tablename__ = "settings"
    __table_args__ = (UniqueConstraint("key"),)

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), nullable=False, unique=True)
    value = Column(Text, nullable=True)
    value_type = Column(String(20), default="string")  # string|int|bool|json
    description = Column(Text, nullable=True)

    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


# ═══════════════════════════════════════════════════════════════
#  Audit Log (Immutable)
# ═══════════════════════════════════════════════════════════════

class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_admin_id", "admin_id"),
        Index("ix_audit_log_action", "action"),
        Index("ix_audit_log_created_at", "created_at"),
    )

    id = Column(BigInteger, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("admins.id"), nullable=True)
    admin = relationship("Admin", back_populates="audit_entries")

    action = Column(String(100), nullable=False)  # login, create_user, etc.
    target_type = Column(String(50), nullable=True)  # user, agent, setting
    target_id = Column(Integer, nullable=True)
    details = Column(JSON, default=dict)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    created_at = Column(DateTime, server_default=func.now(), index=True)


# ═══════════════════════════════════════════════════════════════
#  Fail2ban Bans
# ═══════════════════════════════════════════════════════════════

class Fail2banBan(Base):
    __tablename__ = "fail2ban_bans"

    id = Column(BigInteger, primary_key=True, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    service = Column(String(50), nullable=False)  # panel, ssh, xray
    reason = Column(String(255), nullable=True)
    ban_count = Column(Integer, default=1)
    banned_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())