"""
AI SSO Agent - Risk Assessment Engine
"""
from dataclasses import dataclass
from datetime import datetime, time
from typing import Optional
import json
from src.db.models import UserProfile, RiskLevel, MFAMethod


@dataclass
class LoginContext:
    """Context for a login attempt"""
    ip_address: str
    user_agent: str
    device_fingerprint: Optional[str] = None
    location_country: Optional[str] = None
    location_city: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class RiskAssessor:
    """Assesses risk for login attempts based on behavioral patterns"""

    def __init__(self):
        self.weights = {
            "unknown_location": 25,
            "unknown_country": 20,
            "unknown_device": 25,
            "unusual_time": 15,
            "unusual_day": 10,
            "no_profile": 5,
        }

    def assess_risk(
        self,
        context: LoginContext,
        user_profile: Optional[UserProfile] = None
    ) -> tuple[int, RiskLevel, list[str]]:
        """
        Assess risk for a login attempt
        Returns: (risk_score, risk_level, risk_factors)
        risk_score: 0-100 (higher = more risky)
        """
        risk_score = 0
        risk_factors = []

        # If no profile exists, assign baseline risk
        if not user_profile:
            risk_score += self.weights["no_profile"]
            risk_factors.append("New user - no behavioral profile")
            return risk_score, self._get_risk_level(risk_score), risk_factors

        # Check location patterns
        if user_profile.usual_locations:
            usual_locations = json.loads(user_profile.usual_locations)
            if context.ip_address not in usual_locations:
                risk_score += self.weights["unknown_location"]
                risk_factors.append(f"Unknown IP: {context.ip_address}")

        if user_profile.usual_countries and context.location_country:
            usual_countries = json.loads(user_profile.usual_countries)
            if context.location_country not in usual_countries:
                risk_score += self.weights["unknown_country"]
                risk_factors.append(f"Unknown country: {context.location_country}")

        # Check device patterns
        if user_profile.known_devices and context.device_fingerprint:
            known_devices = json.loads(user_profile.known_devices)
            if context.device_fingerprint not in known_devices:
                risk_score += self.weights["unknown_device"]
                risk_factors.append("Unknown device fingerprint")

        if user_profile.known_user_agents and context.user_agent:
            known_agents = json.loads(user_profile.known_user_agents)
            if context.user_agent not in known_agents:
                # Don't add full weight for user agent (can change with updates)
                risk_score += self.weights["unknown_device"] // 2
                risk_factors.append("Unknown user agent")

        # Check time patterns
        if user_profile.usual_login_hours:
            usual_hours = json.loads(user_profile.usual_login_hours)
            current_hour = context.timestamp.hour
            if current_hour not in usual_hours:
                risk_score += self.weights["unusual_time"]
                risk_factors.append(f"Unusual hour: {current_hour}:00")

        if user_profile.usual_days_of_week:
            usual_days = json.loads(user_profile.usual_days_of_week)
            current_day = context.timestamp.weekday()
            if current_day not in usual_days:
                risk_score += self.weights["unusual_day"]
                risk_factors.append(f"Unusual day of week: {current_day}")

        # Cap at 100
        risk_score = min(risk_score, 100)

        risk_level = self._get_risk_level(risk_score)

        return risk_score, risk_level, risk_factors

    def _get_risk_level(self, score: int) -> RiskLevel:
        """Convert risk score to risk level enum"""
        if score < 30:
            return RiskLevel.LOW
        elif score < 50:
            return RiskLevel.MEDIUM
        elif score < 80:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def get_mfa_requirement(
        self,
        risk_score: int,
        totp_enabled: bool = False
    ) -> MFAMethod:
        """
        Determine MFA requirement based on risk score
        """
        if risk_score < 30:
            # Low risk - no MFA required unless enabled
            return MFAMethod.TOTP if totp_enabled else MFAMethod.NONE

        elif risk_score < 70:
            # Medium risk - TOTP if available
            return MFAMethod.TOTP if totp_enabled else MFAMethod.EMAIL

        else:
            # High/Critical risk - TOTP + additional verification
            # For MVP, just require TOTP or email
            return MFAMethod.TOTP if totp_enabled else MFAMethod.EMAIL

    def update_profile(
        self,
        user_profile: UserProfile,
        context: LoginContext,
        success: bool = True
    ):
        """
        Update user profile with successful login patterns
        Only call this after successful authentication
        """
        if not success:
            return

        # Update locations
        if user_profile.usual_locations:
            locations = json.loads(user_profile.usual_locations)
        else:
            locations = []

        if context.ip_address not in locations:
            locations.append(context.ip_address)
            # Keep last 10 locations
            locations = locations[-10:]
            user_profile.usual_locations = json.dumps(locations)

        # Update countries
        if context.location_country:
            if user_profile.usual_countries:
                countries = json.loads(user_profile.usual_countries)
            else:
                countries = []

            if context.location_country not in countries:
                countries.append(context.location_country)
                user_profile.usual_countries = json.dumps(countries)

        # Update devices
        if context.device_fingerprint:
            if user_profile.known_devices:
                devices = json.loads(user_profile.known_devices)
            else:
                devices = []

            if context.device_fingerprint not in devices:
                devices.append(context.device_fingerprint)
                # Keep last 5 devices
                devices = devices[-5:]
                user_profile.known_devices = json.dumps(devices)

        # Update user agents
        if context.user_agent:
            if user_profile.known_user_agents:
                agents = json.loads(user_profile.known_user_agents)
            else:
                agents = []

            if context.user_agent not in agents:
                agents.append(context.user_agent)
                # Keep last 5
                agents = agents[-5:]
                user_profile.known_user_agents = json.dumps(agents)

        # Update time patterns
        current_hour = context.timestamp.hour
        if user_profile.usual_login_hours:
            hours = json.loads(user_profile.usual_login_hours)
        else:
            hours = []

        if current_hour not in hours:
            hours.append(current_hour)
            user_profile.usual_login_hours = json.dumps(hours)

        # Update day patterns
        current_day = context.timestamp.weekday()
        if user_profile.usual_days_of_week:
            days = json.loads(user_profile.usual_days_of_week)
        else:
            days = []

        if current_day not in days:
            days.append(current_day)
            user_profile.usual_days_of_week = json.dumps(days)

        # Update login count
        if user_profile.total_logins is None:
            user_profile.total_logins = 1
        else:
            user_profile.total_logins += 1

        # Updated timestamp handled by SQLAlchemy


# Global risk assessor instance
risk_assessor = RiskAssessor()
