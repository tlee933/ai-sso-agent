"""
AI SSO Agent - Password Hashing and Validation
"""
from passlib.context import CryptContext
from config.settings import settings


# Password hashing context using Argon2
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__rounds=4,
    argon2__memory_cost=65536,  # 64 MB
)


class PasswordManager:
    """Manages password hashing and validation"""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using Argon2"""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception:
            return False

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, list[str]]:
        """
        Validate password meets security requirements
        Returns: (is_valid, list of error messages)
        """
        errors = []

        if len(password) < settings.password_min_length:
            errors.append(f"Password must be at least {settings.password_min_length} characters")

        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")

        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")

        return len(errors) == 0, errors


# Global password manager instance
password_manager = PasswordManager()
