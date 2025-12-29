"""
AI SSO Agent - TOTP (Time-based One-Time Password) Implementation
RFC 6238 compliant
"""
import pyotp
import qrcode
import io
import base64
from typing import Tuple, Optional
from cryptography.fernet import Fernet

from config.settings import settings


class TOTPManager:
    """Manages TOTP generation, validation, and QR code creation"""

    def __init__(self):
        self.issuer = settings.totp_issuer
        self.window = settings.totp_window
        self.interval = settings.totp_interval

        # Initialize encryption for secrets storage
        if settings.fernet_key:
            self.cipher = Fernet(settings.fernet_key.encode())
        else:
            # Generate one for development (INSECURE - should be in .env)
            key = Fernet.generate_key()
            self.cipher = Fernet(key)
            print(f"WARNING: Using ephemeral encryption key. Set FERNET_KEY in .env")
            print(f"Generated key (add to .env): FERNET_KEY={key.decode()}")

    def generate_secret(self) -> str:
        """Generate a new TOTP secret (base32 encoded)"""
        return pyotp.random_base32()

    def encrypt_secret(self, secret: str) -> str:
        """Encrypt TOTP secret for database storage"""
        return self.cipher.encrypt(secret.encode()).decode()

    def decrypt_secret(self, encrypted_secret: str) -> str:
        """Decrypt TOTP secret from database"""
        return self.cipher.decrypt(encrypted_secret.encode()).decode()

    def generate_provisioning_uri(self, user_email: str, secret: str) -> str:
        """
        Generate provisioning URI for QR code
        Format: otpauth://totp/ISSUER:EMAIL?secret=SECRET&issuer=ISSUER
        """
        totp = pyotp.TOTP(secret, interval=self.interval)
        return totp.provisioning_uri(
            name=user_email,
            issuer_name=self.issuer
        )

    def generate_qr_code(self, provisioning_uri: str) -> str:
        """
        Generate QR code as base64-encoded PNG image
        Returns: base64 string that can be embedded in HTML as:
                 <img src="data:image/png;base64,{qr_code}">
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        # Create image
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()

        return img_base64

    def enroll_user(self, user_email: str) -> Tuple[str, str, str]:
        """
        Complete enrollment flow
        Returns: (secret, encrypted_secret, qr_code_base64)
        """
        # Generate new secret
        secret = self.generate_secret()

        # Encrypt for storage
        encrypted_secret = self.encrypt_secret(secret)

        # Generate provisioning URI
        uri = self.generate_provisioning_uri(user_email, secret)

        # Generate QR code
        qr_code = self.generate_qr_code(uri)

        return secret, encrypted_secret, qr_code

    def validate_totp(self, secret: str, code: str, encrypted: bool = False) -> bool:
        """
        Validate TOTP code
        Args:
            secret: TOTP secret (plain or encrypted)
            code: 6-digit code from user
            encrypted: Whether the secret is encrypted
        Returns:
            True if valid, False otherwise
        """
        try:
            # Decrypt if needed
            if encrypted:
                secret = self.decrypt_secret(secret)

            # Create TOTP object
            totp = pyotp.TOTP(secret, interval=self.interval)

            # Validate with window (allows for clock drift)
            return totp.verify(code, valid_window=self.window)

        except Exception as e:
            print(f"TOTP validation error: {e}")
            return False

    def get_current_code(self, secret: str, encrypted: bool = False) -> str:
        """
        Get current TOTP code (for testing purposes)
        DO NOT expose this in production API!
        """
        if encrypted:
            secret = self.decrypt_secret(secret)

        totp = pyotp.TOTP(secret, interval=self.interval)
        return totp.now()

    def generate_backup_codes(self, count: int = 10) -> list[str]:
        """
        Generate backup codes for emergency access
        Returns: List of 8-character alphanumeric codes
        """
        import secrets
        import string

        codes = []
        alphabet = string.ascii_uppercase + string.digits
        for _ in range(count):
            code = ''.join(secrets.choice(alphabet) for _ in range(8))
            # Format as XXXX-XXXX for readability
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)

        return codes

    def hash_backup_code(self, code: str) -> str:
        """Hash backup code for storage (use argon2)"""
        from passlib.hash import argon2

        # Remove formatting
        clean_code = code.replace("-", "").upper()
        return argon2.hash(clean_code)

    def verify_backup_code(self, code: str, hashed: str) -> bool:
        """Verify backup code against hash"""
        from passlib.hash import argon2

        clean_code = code.replace("-", "").upper()
        try:
            return argon2.verify(clean_code, hashed)
        except Exception:
            return False


# Global TOTP manager instance
totp_manager = TOTPManager()
