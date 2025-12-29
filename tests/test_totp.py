"""
Unit tests for TOTP functionality
"""
import pytest
from src.auth.totp import TOTPManager


class TestTOTPManager:
    """Test TOTP manager"""

    def setup_method(self):
        """Set up test fixtures"""
        self.totp_manager = TOTPManager()

    def test_generate_secret(self):
        """Test secret generation"""
        secret = self.totp_manager.generate_secret()
        assert len(secret) == 32  # Base32 encoding
        assert secret.isalnum()
        assert secret.isupper()

    def test_encrypt_decrypt_secret(self):
        """Test secret encryption/decryption"""
        secret = "JBSWY3DPEHPK3PXP"
        encrypted = self.totp_manager.encrypt_secret(secret)
        decrypted = self.totp_manager.decrypt_secret(encrypted)
        assert decrypted == secret
        assert encrypted != secret  # Ensure it's actually encrypted

    def test_generate_provisioning_uri(self):
        """Test provisioning URI generation"""
        secret = "JBSWY3DPEHPK3PXP"
        email = "test@example.com"
        uri = self.totp_manager.generate_provisioning_uri(email, secret)

        assert uri.startswith("otpauth://totp/")
        # Email is URL-encoded in URI (@ becomes %40)
        assert "test%40example.com" in uri or email in uri
        assert secret in uri
        # Issuer is URL-encoded (spaces become %20)
        assert "AI%20SSO%20Agent" in uri or self.totp_manager.issuer in uri

    def test_generate_qr_code(self):
        """Test QR code generation"""
        secret = "JBSWY3DPEHPK3PXP"
        email = "test@example.com"
        uri = self.totp_manager.generate_provisioning_uri(email, secret)
        qr_code = self.totp_manager.generate_qr_code(uri)

        # Should be base64 encoded
        assert isinstance(qr_code, str)
        assert len(qr_code) > 100  # QR codes are reasonably large

    def test_enroll_user(self):
        """Test complete enrollment flow"""
        email = "test@example.com"
        secret, encrypted_secret, qr_code = self.totp_manager.enroll_user(email)

        assert len(secret) == 32
        assert encrypted_secret != secret
        assert len(qr_code) > 100

        # Verify decryption works
        decrypted = self.totp_manager.decrypt_secret(encrypted_secret)
        assert decrypted == secret

    def test_validate_totp_current_code(self):
        """Test TOTP validation with current code"""
        secret = self.totp_manager.generate_secret()
        current_code = self.totp_manager.get_current_code(secret)

        # Should validate successfully
        assert self.totp_manager.validate_totp(secret, current_code) is True

    def test_validate_totp_invalid_code(self):
        """Test TOTP validation with invalid code"""
        secret = self.totp_manager.generate_secret()

        # Should fail
        assert self.totp_manager.validate_totp(secret, "000000") is False

    def test_validate_totp_encrypted_secret(self):
        """Test TOTP validation with encrypted secret"""
        secret = self.totp_manager.generate_secret()
        encrypted_secret = self.totp_manager.encrypt_secret(secret)
        current_code = self.totp_manager.get_current_code(secret)

        # Should validate with encrypted secret
        assert self.totp_manager.validate_totp(encrypted_secret, current_code, encrypted=True) is True

    def test_generate_backup_codes(self):
        """Test backup code generation"""
        codes = self.totp_manager.generate_backup_codes(count=5)

        assert len(codes) == 5
        for code in codes:
            assert len(code) == 9  # XXXX-XXXX format
            assert "-" in code

    def test_backup_code_hashing(self):
        """Test backup code hashing and verification"""
        code = "ABCD-1234"
        hashed = self.totp_manager.hash_backup_code(code)

        # Should verify correctly
        assert self.totp_manager.verify_backup_code(code, hashed) is True

        # Should fail with wrong code
        assert self.totp_manager.verify_backup_code("WRONG-CODE", hashed) is False

    def test_backup_code_case_insensitive(self):
        """Test that backup codes are case-insensitive"""
        code = "ABCD-1234"
        hashed = self.totp_manager.hash_backup_code(code)

        # Should work with lowercase
        assert self.totp_manager.verify_backup_code("abcd-1234", hashed) is True
