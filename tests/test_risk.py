"""
Unit tests for risk assessment
"""
import pytest
import json
from datetime import datetime
from src.risk.assessor import RiskAssessor, LoginContext
from src.db.models import UserProfile, RiskLevel, MFAMethod


class TestRiskAssessor:
    """Test risk assessor"""

    def setup_method(self):
        """Set up test fixtures"""
        self.assessor = RiskAssessor()

    def test_assess_risk_no_profile(self):
        """Test risk assessment with no user profile"""
        context = LoginContext(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0"
        )

        risk_score, risk_level, risk_factors = self.assessor.assess_risk(context, None)

        # Should have baseline risk for no profile
        assert risk_score > 0
        assert risk_level == RiskLevel.LOW
        assert "no behavioral profile" in risk_factors[0].lower()

    def test_assess_risk_known_location(self):
        """Test risk assessment with known location"""
        profile = UserProfile(
            usual_locations=json.dumps(["192.168.1.1"]),
            usual_countries=json.dumps(["US"]),
            known_devices=json.dumps(["device123"]),
            usual_login_hours=json.dumps([9, 10, 11, 12, 13, 14, 15, 16, 17]),
            usual_days_of_week=json.dumps([0, 1, 2, 3, 4])  # Mon-Fri
        )

        context = LoginContext(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            device_fingerprint="device123",
            location_country="US",
            timestamp=datetime(2024, 1, 8, 10, 0)  # Monday, 10 AM
        )

        risk_score, risk_level, risk_factors = self.assessor.assess_risk(context, profile)

        # Should be low risk - everything matches
        assert risk_score < 30
        assert risk_level == RiskLevel.LOW
        assert len(risk_factors) == 0

    def test_assess_risk_unknown_location(self):
        """Test risk assessment with unknown location"""
        profile = UserProfile(
            usual_locations=json.dumps(["192.168.1.1"]),
            usual_countries=json.dumps(["US"])
        )

        context = LoginContext(
            ip_address="10.0.0.1",  # Unknown IP
            user_agent="Mozilla/5.0",
            location_country="CN"  # Unknown country
        )

        risk_score, risk_level, risk_factors = self.assessor.assess_risk(context, profile)

        # Should have elevated risk
        assert risk_score >= 25  # Unknown location + unknown country
        assert any("Unknown IP" in factor for factor in risk_factors)
        assert any("Unknown country" in factor for factor in risk_factors)

    def test_assess_risk_unknown_device(self):
        """Test risk assessment with unknown device"""
        profile = UserProfile(
            known_devices=json.dumps(["device123"])
        )

        context = LoginContext(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            device_fingerprint="device999"  # Unknown device
        )

        risk_score, risk_level, risk_factors = self.assessor.assess_risk(context, profile)

        assert risk_score >= 25
        assert any("Unknown device" in factor for factor in risk_factors)

    def test_assess_risk_unusual_time(self):
        """Test risk assessment with unusual time"""
        profile = UserProfile(
            usual_login_hours=json.dumps([9, 10, 11, 12]),  # Business hours
            usual_days_of_week=json.dumps([0, 1, 2, 3, 4])  # Weekdays
        )

        context = LoginContext(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            timestamp=datetime(2024, 1, 8, 3, 0)  # 3 AM Monday
        )

        risk_score, risk_level, risk_factors = self.assessor.assess_risk(context, profile)

        assert risk_score >= 15
        assert any("Unusual hour" in factor for factor in risk_factors)

    def test_assess_risk_unusual_day(self):
        """Test risk assessment with unusual day"""
        profile = UserProfile(
            usual_days_of_week=json.dumps([0, 1, 2, 3, 4])  # Mon-Fri
        )

        context = LoginContext(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            timestamp=datetime(2024, 1, 6, 10, 0)  # Saturday
        )

        risk_score, risk_level, risk_factors = self.assessor.assess_risk(context, profile)

        assert risk_score >= 10
        assert any("Unusual day" in factor for factor in risk_factors)

    def test_get_risk_level(self):
        """Test risk level categorization"""
        assert self.assessor._get_risk_level(10) == RiskLevel.LOW
        assert self.assessor._get_risk_level(40) == RiskLevel.MEDIUM
        assert self.assessor._get_risk_level(60) == RiskLevel.HIGH
        assert self.assessor._get_risk_level(90) == RiskLevel.CRITICAL

    def test_get_mfa_requirement_low_risk_no_totp(self):
        """Test MFA requirement - low risk, no TOTP enabled"""
        mfa = self.assessor.get_mfa_requirement(20, totp_enabled=False)
        assert mfa == MFAMethod.NONE

    def test_get_mfa_requirement_low_risk_with_totp(self):
        """Test MFA requirement - low risk, TOTP enabled"""
        mfa = self.assessor.get_mfa_requirement(20, totp_enabled=True)
        assert mfa == MFAMethod.TOTP

    def test_get_mfa_requirement_medium_risk(self):
        """Test MFA requirement - medium risk"""
        mfa_with_totp = self.assessor.get_mfa_requirement(50, totp_enabled=True)
        assert mfa_with_totp == MFAMethod.TOTP

        mfa_without_totp = self.assessor.get_mfa_requirement(50, totp_enabled=False)
        assert mfa_without_totp == MFAMethod.EMAIL

    def test_get_mfa_requirement_high_risk(self):
        """Test MFA requirement - high risk"""
        mfa_with_totp = self.assessor.get_mfa_requirement(80, totp_enabled=True)
        assert mfa_with_totp == MFAMethod.TOTP

        mfa_without_totp = self.assessor.get_mfa_requirement(80, totp_enabled=False)
        assert mfa_without_totp == MFAMethod.EMAIL

    def test_update_profile(self):
        """Test profile updating after successful login"""
        profile = UserProfile()

        context = LoginContext(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            device_fingerprint="device123",
            location_country="US",
            timestamp=datetime(2024, 1, 8, 10, 0)  # Monday, 10 AM
        )

        self.assessor.update_profile(profile, context, success=True)

        # Check that patterns were recorded
        assert "192.168.1.1" in json.loads(profile.usual_locations)
        assert "US" in json.loads(profile.usual_countries)
        assert "device123" in json.loads(profile.known_devices)
        assert 10 in json.loads(profile.usual_login_hours)
        assert 0 in json.loads(profile.usual_days_of_week)  # Monday = 0
        assert profile.total_logins == 1

    def test_update_profile_limits_history(self):
        """Test that profile update limits history size"""
        profile = UserProfile(
            usual_locations=json.dumps(["ip1", "ip2", "ip3", "ip4", "ip5", "ip6", "ip7", "ip8", "ip9", "ip10"])
        )

        context = LoginContext(
            ip_address="new_ip",
            user_agent="Mozilla/5.0"
        )

        self.assessor.update_profile(profile, context, success=True)

        locations = json.loads(profile.usual_locations)
        # Should keep only last 10
        assert len(locations) == 10
        assert "new_ip" in locations
        assert "ip1" not in locations  # Oldest should be dropped

    def test_update_profile_no_update_on_failure(self):
        """Test that profile is not updated on failed login"""
        profile = UserProfile()

        context = LoginContext(
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0"
        )

        self.assessor.update_profile(profile, context, success=False)

        # Should not update anything
        assert profile.usual_locations is None
        assert profile.total_logins == 0
