"""
AI SSO Agent - Configuration Settings
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )

    # Application
    app_name: str = "AI SSO Agent"
    debug: bool = False
    secret_key: str  # Required - generate with: openssl rand -hex 32

    # Database
    database_url: str = "sqlite:///./ai_sso_agent.db"  # Default to SQLite for dev

    # TOTP Settings
    totp_issuer: str = "AI SSO Agent"
    totp_window: int = 1  # Allow 1 step before/after (30 seconds tolerance)
    totp_interval: int = 30  # Standard 30-second window

    # Security
    password_min_length: int = 12
    session_lifetime_hours: int = 24
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15

    # Risk Assessment
    risk_threshold_low: int = 30
    risk_threshold_high: int = 70
    enable_ai_risk: bool = True

    # Microsoft Entra ID (Azure AD)
    entra_client_id: Optional[str] = None
    entra_tenant_id: Optional[str] = None
    entra_client_secret: Optional[str] = None
    entra_redirect_uri: str = "http://localhost:8000/auth/callback"

    # Redis (for sessions and rate limiting)
    redis_url: str = "redis://localhost:6379/0"

    # Rate Limiting
    rate_limit_login: int = 10  # Max login attempts per minute per IP
    rate_limit_api: int = 100   # Max API calls per minute per user

    # Encryption
    fernet_key: Optional[str] = None  # For encrypting TOTP secrets in DB

    # Logging
    log_level: str = "INFO"
    log_file: str = "ai_sso_agent.log"


# Global settings instance
settings = Settings()
