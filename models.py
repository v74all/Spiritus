"""Database models for Spiritus with audit logging"""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, Float, DateTime,
    Boolean, Text, ForeignKey, Table, JSON, Index,
    create_engine, event, BigInteger
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func

Base = declarative_base()


# ═══ Association Tables ═══
user_groups = Table(
    "user_groups",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("users.id"), primary_key=True),
    Column("group_id", String(36), ForeignKey("groups.id"), primary_key=True),
)

user_agents = Table(
    "user_agents",
    Base.metadata,
    Column("user_id", String(36), ForeignKey("users.id"), primary_key=True),
    Column("agent_id", String(36), ForeignKey("agents.id"), primary_key=True),
)


# ═══ Models ═══
class User(Base):
    """VPN User model"""
    
    __tablename__ = "users"
    __table_args__ = (
        Index("idx_users_name", "name"),
        Index("idx_users_active", "active"),
        Index("idx_users_expire_at", "expire_at"),
    )
    
    id = Column(String(36), primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    uuid = Column(String(36), unique=True, nullable=False)
    
    # Traffic
    traffic_limit_gb = Column(Float, default=0.0)  # 0 = unlimited
    traffic_used_gb = Column(Float, default=0.0)
    
    # Expiration
    created_at = Column(DateTime, server_default=func.now())
    expire_at = Column(DateTime, nullable=True)
    last_activity = Column(DateTime, nullable=True)
    
    # Status
    active = Column(Boolean, default=True)
    suspended = Column(Boolean, default=False)
    
    # Limits
    max_connections = Column(Integer, default=1)
    max_devices = Column(Integer, default=1)
    
    # Protocols
    protocols = Column(JSON, default={})  # {"vmess": true, "vless": false, ...}
    custom_dns = Column(String(255), nullable=True)
    
    # Notes & Tags
    notes = Column(Text, nullable=True)
    tags = Column(JSON, default=[])
    
    # Relations
    groups = relationship(
        "Group",
        secondary=user_groups,
        back_populates="users",
    )
    agents = relationship(
        "Agent",
        secondary=user_agents,
        back_populates="users",
    )
    audit_logs = relationship("AuditLog", back_populates="user")
    stats = relationship("UserStats", back_populates="user", uselist=False)
    
    # Metadata
    metadata_extra = Column(JSON, default={})
    updated_at = Column(DateTime, onupdate=func.now())


class Group(Base):
    """User group for bulk management"""
    
    __tablename__ = "groups"
    
    id = Column(String(36), primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    
    # Default settings for group members
    traffic_limit_gb = Column(Float, default=10.0)
    expire_days = Column(Integer, default=30)
    protocols = Column(JSON, default={})
    
    # Relations
    users = relationship(
        "User",
        secondary=user_groups,
        back_populates="groups",
    )


class Agent(Base):
    """Multi-node agent for distributed architecture"""
    
    __tablename__ = "agents"
    
    id = Column(String(36), primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    
    # Connection
    rpc_host = Column(String(255), nullable=False)
    rpc_port = Column(Integer, default=50051)
    rpc_tls = Column(Boolean, default=True)
    rpc_cert_path = Column(String(512), nullable=True)
    
    # Status
    active = Column(Boolean, default=True)
    last_seen = Column(DateTime, nullable=True)
    online = Column(Boolean, default=False)
    
    # Capacity
    max_users = Column(Integer, nullable=True)  # None = unlimited
    current_users = Column(Integer, default=0)
    cpu_usage = Column(Float, default=0.0)
    memory_usage = Column(Float, default=0.0)
    
    # Relations
    users = relationship(
        "User",
        secondary=user_agents,
        back_populates="agents",
    )
    
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())


class AuditLog(Base):
    """Audit log with hash-chain for tamper detection"""
    
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("idx_audit_user_id", "user_id"),
        Index("idx_audit_admin_id", "admin_id"),
        Index("idx_audit_timestamp", "timestamp"),
    )
    
    id = Column(String(36), primary_key=True)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False)
    
    # Actor
    admin_id = Column(String(36), nullable=True)
    admin_ip = Column(String(45), nullable=False)  # IPv4/IPv6
    
    # Target
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="audit_logs")
    
    # Action
    action = Column(String(50), nullable=False)  # "login", "create", "delete", etc.
    resource = Column(String(50), nullable=False)  # "user", "admin", "config", etc.
    details = Column(JSON, nullable=True)
    
    # Hash Chain (like Sigstore transparency log)
    prev_hash = Column(String(64), nullable=True)
    hash = Column(String(64), nullable=False, unique=True)
    
    # Status
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)


class UserStats(Base):
    """User statistics and activity tracking"""
    
    __tablename__ = "user_stats"
    __table_args__ = (
        Index("idx_stats_user_id", "user_id"),
        Index("idx_stats_date", "date"),
    )
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), unique=True, nullable=False)
    user = relationship("User", back_populates="stats")
    
    # Daily tracking
    date = Column(DateTime, server_default=func.now())
    
    # Traffic
    upload_bytes = Column(BigInteger, default=0)
    download_bytes = Column(BigInteger, default=0)
    total_bytes = Column(BigInteger, default=0)
    
    # Activity
    connections = Column(Integer, default=0)
    unique_ips = Column(JSON, default=[])  # For anomaly detection
    
    # Performance
    avg_latency_ms = Column(Float, default=0.0)
    packet_loss = Column(Float, default=0.0)


class PaymentRecord(Base):
    """Payment tracking"""
    
    __tablename__ = "payments"
    __table_args__ = (
        Index("idx_payments_user_id", "user_id"),
        Index("idx_payments_date", "created_at"),
    )
    
    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="USD")  # or "IRR", "USDT"
    
    gateway = Column(String(50), nullable=False)  # "zarinpal", "idpay", "usdt"
    transaction_id = Column(String(255), nullable=True)
    
    status = Column(String(20), default="pending")  # "pending", "completed", "failed"
    
    # What it's for
    service = Column(String(50), nullable=False)  # "subscription", "extra_traffic"
    duration_days = Column(Integer, nullable=True)
    extra_gb = Column(Float, nullable=True)
    
    created_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    
    # Metadata
    metadata = Column(JSON, default={})


class Configuration(Base):
    """Application configurations"""
    
    __tablename__ = "configurations"
    
    id = Column(String(36), primary_key=True)
    key = Column(String(255), unique=True, nullable=False)
    value = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class IpBlacklist(Base):
    """IP allowlist/blocklist"""
    
    __tablename__ = "ip_blacklist"
    
    id = Column(String(36), primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False)
    ip_range = Column(String(50), nullable=True)  # CIDR notation
    
    reason = Column(String(255), nullable=False)
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    
    created_at = Column(DateTime, server_default=func.now())
    expire_at = Column(DateTime, nullable=True)  # Auto-remove after expiry
    
    permanent = Column(Boolean, default=False)


# ═══ Database Connection ═══
def get_database_url() -> str:
    """Get database URL from settings"""
    from app_config import settings
    return settings.DATABASE_URL


def create_db_engine(database_url: str = None):
    """Create SQLAlchemy engine"""
    if database_url is None:
        database_url = get_database_url()
    
    return create_engine(
        database_url,
        echo=False,
        future=True,
        pool_size=20,
        max_overflow=40,
        pool_pre_ping=True,
    )


def get_session_maker(engine=None):
    """Get session factory"""
    if engine is None:
        engine = create_db_engine()
    
    return sessionmaker(
        bind=engine,
        expire_on_commit=False,
        future=True,
    )


# ═══ Initialization ═══
def init_db(engine=None):
    """Create all tables"""
    if engine is None:
        engine = create_db_engine()
    
    Base.metadata.create_all(bind=engine)
