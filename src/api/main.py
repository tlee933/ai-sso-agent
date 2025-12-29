"""
AI SSO Agent - Main FastAPI Application
"""
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets

from config.settings import settings
from src.db.database import get_db, init_db
from src.db.models import User, UserProfile, LoginAttempt, Session as DBSession, AuditLog
from src.auth.totp import totp_manager
from src.auth.password import password_manager
from src.risk.assessor import risk_assessor, LoginContext
from src.api.schemas import (
    UserCreate, UserResponse, LoginRequest, LoginResponse,
    TOTPEnrollmentResponse, TOTPVerifyRequest, TOTPVerifyResponse,
    SessionResponse, RiskAssessmentResponse
)

# Create FastAPI app
app = FastAPI(
    title="AI SSO Agent",
    description="Intelligent Single Sign-On with AI Risk Assessment",
    version="0.1.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===== Startup/Shutdown =====

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    init_db()
    print("Database initialized")


# ===== Helper Functions =====

def get_client_info(request: Request) -> dict:
    """Extract client information from request"""
    return {
        "ip_address": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
    }


def create_session_token(user_id: int, db: Session, request: Request) -> str:
    """Create new session token"""
    token = secrets.token_urlsafe(32)
    client_info = get_client_info(request)

    session = DBSession(
        user_id=user_id,
        token=token,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        expires_at=datetime.utcnow() + timedelta(hours=settings.session_lifetime_hours)
    )
    db.add(session)
    db.commit()

    return token


def log_audit(db: Session, user_id: Optional[int], event_type: str, description: str, request: Request, severity: str = "info"):
    """Log audit event"""
    client_info = get_client_info(request)
    log = AuditLog(
        user_id=user_id,
        event_type=event_type,
        event_description=description,
        severity=severity,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    db.add(log)
    db.commit()


# ===== Authentication Endpoints =====

@app.post("/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, request: Request, db: Session = Depends(get_db)):
    """Register a new user"""

    # Check if user already exists
    existing_user = db.query(User).filter(
        (User.email == user_data.email) | (User.username == user_data.username)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email or username already registered"
        )

    # Validate password strength
    valid, errors = password_manager.validate_password_strength(user_data.password)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"errors": errors}
        )

    # Hash password
    password_hash = password_manager.hash_password(user_data.password)

    # Create user
    user = User(
        email=user_data.email,
        username=user_data.username,
        password_hash=password_hash
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Create user profile
    profile = UserProfile(user_id=user.id)
    db.add(profile)
    db.commit()

    # Log audit
    log_audit(db, user.id, "user_registered", f"New user registered: {user.username}", request)

    return user


@app.post("/auth/login", response_model=LoginResponse)
async def login(credentials: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Login with username/password (and optional TOTP)"""

    # Find user
    user = db.query(User).filter(User.username == credentials.username).first()

    client_info = get_client_info(request)

    # Create login context for risk assessment
    login_context = LoginContext(
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )

    if not user:
        # Log failed attempt (no user_id)
        attempt = LoginAttempt(
            username_attempted=credentials.username,
            success=False,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        db.add(attempt)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Check if account is locked
    if user.is_locked and user.locked_until and datetime.utcnow() < user.locked_until:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account locked until {user.locked_until}"
        )

    # Verify password
    if not password_manager.verify_password(credentials.password, user.password_hash):
        # Increment failed attempts
        user.failed_login_attempts += 1

        # Lock account if too many attempts
        if user.failed_login_attempts >= settings.max_login_attempts:
            user.is_locked = True
            user.locked_until = datetime.utcnow() + timedelta(minutes=settings.lockout_duration_minutes)

        db.commit()

        # Log failed attempt
        attempt = LoginAttempt(
            user_id=user.id,
            username_attempted=credentials.username,
            success=False,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )
        db.add(attempt)
        db.commit()

        log_audit(db, user.id, "login_failed", "Invalid password", request, severity="warning")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Get user profile for risk assessment
    user_profile = db.query(UserProfile).filter(UserProfile.user_id == user.id).first()

    # Assess risk
    risk_score, risk_level, risk_factors = risk_assessor.assess_risk(login_context, user_profile)

    # Determine MFA requirement
    mfa_method = risk_assessor.get_mfa_requirement(risk_score, user.totp_enabled)

    # Check if MFA is required
    if mfa_method.value == "totp" and user.totp_enabled:
        if not credentials.totp_code:
            # MFA required but not provided
            attempt = LoginAttempt(
                user_id=user.id,
                username_attempted=credentials.username,
                success=False,
                risk_score=risk_score,
                risk_level=risk_level,
                mfa_required=True,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"]
            )
            db.add(attempt)
            db.commit()

            return LoginResponse(
                success=False,
                message="MFA required",
                mfa_required=True,
                risk_score=risk_score
            )

        # Validate TOTP
        if not totp_manager.validate_totp(user.totp_secret, credentials.totp_code, encrypted=True):
            # Invalid TOTP
            user.failed_login_attempts += 1
            db.commit()

            attempt = LoginAttempt(
                user_id=user.id,
                username_attempted=credentials.username,
                success=False,
                risk_score=risk_score,
                risk_level=risk_level,
                mfa_required=True,
                mfa_method=mfa_method,
                mfa_success=False,
                ip_address=client_info["ip_address"],
                user_agent=client_info["user_agent"]
            )
            db.add(attempt)
            db.commit()

            log_audit(db, user.id, "login_failed", "Invalid TOTP code", request, severity="warning")

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code"
            )

    # ===== Successful login =====

    # Reset failed attempts
    user.failed_login_attempts = 0
    user.is_locked = False
    user.locked_until = None
    user.last_login = datetime.utcnow()
    db.commit()

    # Create session
    token = create_session_token(user.id, db, request)

    # Update user profile
    if user_profile:
        risk_assessor.update_profile(user_profile, login_context, success=True)
        db.commit()

    # Log successful attempt
    attempt = LoginAttempt(
        user_id=user.id,
        username_attempted=credentials.username,
        success=True,
        risk_score=risk_score,
        risk_level=risk_level,
        mfa_required=(mfa_method.value == "totp"),
        mfa_method=mfa_method if mfa_method.value == "totp" else None,
        mfa_success=(mfa_method.value == "totp"),
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )
    db.add(attempt)
    db.commit()

    log_audit(db, user.id, "login_success", f"Successful login (risk: {risk_score})", request)

    return LoginResponse(
        success=True,
        message="Login successful",
        token=token,
        user=UserResponse.model_validate(user),
        mfa_required=False,
        risk_score=risk_score
    )


# ===== TOTP Endpoints =====

@app.post("/auth/totp/enroll", response_model=TOTPEnrollmentResponse)
async def enroll_totp(request: Request, db: Session = Depends(get_db)):
    """
    Enroll in TOTP (requires authenticated session)
    For MVP, we'll use a simple token parameter. In production, use proper session management.
    """
    # TODO: Add proper session authentication
    # For now, accept user_id as parameter (INSECURE - MVP only)
    user_id = request.query_params.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if already enrolled
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="TOTP already enabled")

    # Generate TOTP secret and QR code
    secret, encrypted_secret, qr_code = totp_manager.enroll_user(user.email)

    # Generate backup codes
    backup_codes = totp_manager.generate_backup_codes()

    # Store encrypted secret (but don't enable yet - user must verify)
    user.totp_secret = encrypted_secret
    db.commit()

    log_audit(db, user.id, "totp_enrollment_started", "User started TOTP enrollment", request)

    return TOTPEnrollmentResponse(
        secret=secret,  # Return plain secret ONCE for user to save
        qr_code=qr_code,
        backup_codes=backup_codes
    )


@app.post("/auth/totp/verify", response_model=TOTPVerifyResponse)
async def verify_totp_enrollment(
    verify_data: TOTPVerifyRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Verify TOTP enrollment by validating a code"""
    # TODO: Add proper session authentication
    user_id = request.query_params.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP not enrolled")

    # Validate code
    if totp_manager.validate_totp(user.totp_secret, verify_data.code, encrypted=True):
        # Enable TOTP
        user.totp_enabled = True
        db.commit()

        log_audit(db, user.id, "totp_enabled", "TOTP successfully enabled", request)

        return TOTPVerifyResponse(
            success=True,
            message="TOTP enabled successfully"
        )
    else:
        log_audit(db, user.id, "totp_verification_failed", "Invalid TOTP code during enrollment", request, severity="warning")

        return TOTPVerifyResponse(
            success=False,
            message="Invalid TOTP code"
        )


# ===== Health Check =====

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "AI SSO Agent",
        "version": "0.1.0"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
