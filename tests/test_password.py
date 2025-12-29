"""
Unit tests for password management
"""
import pytest
from src.auth.password import PasswordManager


class TestPasswordManager:
    """Test password manager"""

    def setup_method(self):
        """Set up test fixtures"""
        self.password_manager = PasswordManager()

    def test_hash_password(self):
        """Test password hashing"""
        password = "SuperSecret123!@#"
        hashed = self.password_manager.hash_password(password)

        # Should not match plain password
        assert hashed != password
        # Should start with Argon2 identifier
        assert hashed.startswith("$argon2")

    def test_verify_password_correct(self):
        """Test password verification with correct password"""
        password = "SuperSecret123!@#"
        hashed = self.password_manager.hash_password(password)

        assert self.password_manager.verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password"""
        password = "SuperSecret123!@#"
        hashed = self.password_manager.hash_password(password)

        assert self.password_manager.verify_password("WrongPassword!", hashed) is False

    def test_password_strength_valid(self):
        """Test password strength validation - valid password"""
        password = "ValidPassword123!@#"
        valid, errors = self.password_manager.validate_password_strength(password)

        assert valid is True
        assert len(errors) == 0

    def test_password_strength_too_short(self):
        """Test password strength - too short"""
        password = "Short1!"
        valid, errors = self.password_manager.validate_password_strength(password)

        assert valid is False
        assert any("at least" in err for err in errors)

    def test_password_strength_no_uppercase(self):
        """Test password strength - no uppercase"""
        password = "lowercase123!@#"
        valid, errors = self.password_manager.validate_password_strength(password)

        assert valid is False
        assert any("uppercase" in err for err in errors)

    def test_password_strength_no_lowercase(self):
        """Test password strength - no lowercase"""
        password = "UPPERCASE123!@#"
        valid, errors = self.password_manager.validate_password_strength(password)

        assert valid is False
        assert any("lowercase" in err for err in errors)

    def test_password_strength_no_digit(self):
        """Test password strength - no digit"""
        password = "NoDigitsHere!@#"
        valid, errors = self.password_manager.validate_password_strength(password)

        assert valid is False
        assert any("digit" in err for err in errors)

    def test_password_strength_no_special(self):
        """Test password strength - no special character"""
        password = "NoSpecialChar123"
        valid, errors = self.password_manager.validate_password_strength(password)

        assert valid is False
        assert any("special" in err for err in errors)

    def test_password_strength_multiple_errors(self):
        """Test password strength - multiple errors"""
        password = "weak"
        valid, errors = self.password_manager.validate_password_strength(password)

        assert valid is False
        assert len(errors) > 1
