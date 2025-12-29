"""
AI SSO Agent - Database Models
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean,
    ForeignKey, Text, Float, Enum
)
from sqlalchemy.orm import declarative_base, relationship
import enum

Base = declarative_base()


class MFAMethod(enum.Enum):
    """MFA method types"""
    TOTP = "totp"
    EMAIL = "email"
    SMS = "sms"
    NONE = "none"


class RiskLevel(enum.Enum):
    """Risk level categories"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class User(Base):
    """User account"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    # MFA
    totp_secret = Column(String(255), nullable=True)  # Encrypted
    totp_enabled = Column(Boolean, default=False)
    backup_codes = Column(Text, nullable=True)  # JSON array of encrypted codes

    # Account status
    is_active = Column(Boolean, default=True)
    is_locked = Column(Boolean, default=False)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

    # Entra ID integration
    entra_id = Column(String(255), nullable=True, unique=True)
    entra_sync_enabled = Column(Boolean, default=False)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    profiles = relationship("UserProfile", back_populates="user", cascade="all, delete-orphan")
    login_attempts = relationship("LoginAttempt", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")


class UserProfile(Base):
    """User behavioral profile for risk assessment"""
    __tablename__ = "user_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Location patterns
    usual_locations = Column(Text, nullable=True)  # JSON array of common IP/city
    usual_countries = Column(Text, nullable=True)  # JSON array

    # Device patterns
    known_devices = Column(Text, nullable=True)  # JSON array of device fingerprints
    known_user_agents = Column(Text, nullable=True)  # JSON array

    # Time patterns
    usual_login_hours = Column(Text, nullable=True)  # JSON array [0-23]
    usual_days_of_week = Column(Text, nullable=True)  # JSON array [0-6]

    # Behavior
    average_session_duration = Column(Integer, nullable=True)  # Minutes
    total_logins = Column(Integer, default=0)

    # Risk history
    highest_risk_score = Column(Integer, default=0)
    average_risk_score = Column(Float, default=0.0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="profiles")


class LoginAttempt(Base):
    """Login attempt tracking"""
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Nullable for failed username attempts

    # Attempt details
    username_attempted = Column(String(255), nullable=False)
    success = Column(Boolean, nullable=False)

    # Risk assessment
    risk_score = Column(Integer, nullable=True)  # 0-100
    risk_level = Column(Enum(RiskLevel), nullable=True)
    risk_factors = Column(Text, nullable=True)  # JSON array of risk factors

    # MFA
    mfa_required = Column(Boolean, default=False)
    mfa_method = Column(Enum(MFAMethod), nullable=True)
    mfa_success = Column(Boolean, nullable=True)

    # Context
    ip_address = Column(String(45), nullable=True)  # IPv6 max length
    user_agent = Column(String(500), nullable=True)
    device_fingerprint = Column(String(255), nullable=True)
    location_country = Column(String(100), nullable=True)
    location_city = Column(String(100), nullable=True)

    # Timestamps
    attempted_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="login_attempts")


class Session(Base):
    """Active user sessions"""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Session details
    token = Column(String(255), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    # Status
    is_active = Column(Boolean, default=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="sessions")


class AuditLog(Base):
    """Security audit log"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)  # Nullable for system events

    # Event details
    event_type = Column(String(100), nullable=False)  # e.g., "login", "mfa_enabled", "password_change"
    event_description = Column(Text, nullable=True)
    severity = Column(String(20), default="info")  # info, warning, error, critical

    # Context
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    event_metadata = Column(Text, nullable=True)  # JSON for additional data

    # Timestamp
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
