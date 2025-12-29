"""
AI SSO Agent - Pydantic Schemas for API
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


# ===== User Schemas =====

class UserCreate(BaseModel):
    """User registration"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=12)


class UserResponse(BaseModel):
    """User response (safe, no password)"""
    id: int
    email: str
    username: str
    totp_enabled: bool
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


# ===== Authentication Schemas =====

class LoginRequest(BaseModel):
    """Login request"""
    username: str
    password: str
    totp_code: Optional[str] = None


class LoginResponse(BaseModel):
    """Login response"""
    success: bool
    message: str
    token: Optional[str] = None
    user: Optional[UserResponse] = None
    mfa_required: bool = False
    risk_score: Optional[int] = None


# ===== TOTP Enrollment Schemas =====

class TOTPEnrollmentResponse(BaseModel):
    """TOTP enrollment response"""
    secret: str  # Plain secret (only shown once!)
    qr_code: str  # Base64 PNG
    backup_codes: list[str]


class TOTPVerifyRequest(BaseModel):
    """TOTP verification during enrollment"""
    code: str = Field(..., min_length=6, max_length=6)


class TOTPVerifyResponse(BaseModel):
    """TOTP verification response"""
    success: bool
    message: str


# ===== Session Schemas =====

class SessionResponse(BaseModel):
    """Active session"""
    id: int
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: Optional[str] = None

    class Config:
        from_attributes = True


# ===== Risk Assessment Schemas =====

class RiskAssessmentResponse(BaseModel):
    """Risk assessment result"""
    risk_score: int
    risk_level: str
    risk_factors: list[str]
    mfa_required: bool
    mfa_method: str
