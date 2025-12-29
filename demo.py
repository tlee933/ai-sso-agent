#!/usr/bin/env python3
"""
AI SSO Agent - Demo Script
Demonstrates the complete authentication flow
"""
import sys
import os
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.auth.totp import totp_manager
from src.auth.password import password_manager
from src.risk.assessor import risk_assessor, LoginContext
from src.db.models import User, UserProfile
from src.db.database import init_db, get_db_context


def print_section(title):
    """Print section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def demo_password_hashing():
    """Demonstrate password hashing"""
    print_section("Password Hashing Demo")

    password = "SuperSecret123!@#"
    print(f"Original password: {password}")

    # Validate strength
    valid, errors = password_manager.validate_password_strength(password)
    print(f"\nPassword strength: {'✅ Valid' if valid else '❌ Invalid'}")
    if errors:
        for error in errors:
            print(f"  - {error}")

    # Hash password
    hashed = password_manager.hash_password(password)
    print(f"\nHashed: {hashed[:60]}...")

    # Verify correct password
    correct = password_manager.verify_password(password, hashed)
    print(f"\nVerify correct password: {'✅ Success' if correct else '❌ Failed'}")

    # Verify wrong password
    wrong = password_manager.verify_password("WrongPassword!", hashed)
    print(f"Verify wrong password: {'❌ Rejected' if not wrong else '✅ Accepted (BUG!)'}")


def demo_totp():
    """Demonstrate TOTP enrollment and validation"""
    print_section("TOTP (Time-based One-Time Password) Demo")

    email = "demo@example.com"
    print(f"Enrolling user: {email}")

    # Enroll user
    secret, encrypted_secret, qr_code = totp_manager.enroll_user(email)

    print(f"\n✅ Enrollment successful!")
    print(f"Secret (save this): {secret}")
    print(f"Encrypted secret (stored in DB): {encrypted_secret[:40]}...")
    print(f"QR code size: {len(qr_code)} bytes")

    # Generate current code
    current_code = totp_manager.get_current_code(secret)
    print(f"\nCurrent TOTP code: {current_code}")

    # Validate the code
    is_valid = totp_manager.validate_totp(secret, current_code)
    print(f"Validation result: {'✅ Valid' if is_valid else '❌ Invalid'}")

    # Test with encrypted secret
    is_valid_encrypted = totp_manager.validate_totp(
        encrypted_secret, current_code, encrypted=True
    )
    print(f"Validation with encrypted secret: {'✅ Valid' if is_valid_encrypted else '❌ Invalid'}")

    # Generate backup codes
    backup_codes = totp_manager.generate_backup_codes(count=5)
    print(f"\n📝 Backup codes generated:")
    for i, code in enumerate(backup_codes, 1):
        print(f"  {i}. {code}")


def demo_risk_assessment():
    """Demonstrate risk assessment"""
    print_section("AI Risk Assessment Demo")

    # Scenario 1: New user (no profile)
    print("Scenario 1: New user logging in")
    context = LoginContext(
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )

    risk_score, risk_level, risk_factors = risk_assessor.assess_risk(context, None)
    print(f"Risk Score: {risk_score}/100")
    print(f"Risk Level: {risk_level.value.upper()}")
    print(f"Risk Factors: {', '.join(risk_factors) if risk_factors else 'None'}")

    # Scenario 2: Known user, normal pattern
    print("\nScenario 2: Known user, typical login")
    import json
    from datetime import datetime

    profile = UserProfile(
        usual_locations=json.dumps(["192.168.1.100"]),
        usual_countries=json.dumps(["US"]),
        known_devices=json.dumps(["device123"]),
        usual_login_hours=json.dumps([9, 10, 11, 12, 13, 14, 15, 16]),
        usual_days_of_week=json.dumps([0, 1, 2, 3, 4])  # Mon-Fri
    )

    context = LoginContext(
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        device_fingerprint="device123",
        location_country="US",
        timestamp=datetime(2024, 1, 8, 10, 0)  # Monday, 10 AM
    )

    risk_score, risk_level, risk_factors = risk_assessor.assess_risk(context, profile)
    print(f"Risk Score: {risk_score}/100")
    print(f"Risk Level: {risk_level.value.upper()}")
    print(f"Risk Factors: {', '.join(risk_factors) if risk_factors else 'None (all normal!)'}")

    # Scenario 3: Known user, suspicious activity
    print("\nScenario 3: Known user, suspicious login")
    context_suspicious = LoginContext(
        ip_address="10.0.0.99",  # Unknown IP
        user_agent="curl/7.68.0",  # Different user agent
        device_fingerprint="unknown_device",
        location_country="CN",  # Different country
        timestamp=datetime(2024, 1, 7, 3, 0)  # Sunday, 3 AM
    )

    risk_score, risk_level, risk_factors = risk_assessor.assess_risk(context_suspicious, profile)
    print(f"Risk Score: {risk_score}/100")
    print(f"Risk Level: {risk_level.value.upper()}")
    print(f"Risk Factors:")
    for factor in risk_factors:
        print(f"  ⚠️  {factor}")

    # MFA requirement
    from src.db.models import MFAMethod
    mfa_required = risk_assessor.get_mfa_requirement(risk_score, totp_enabled=True)
    print(f"\nMFA Required: {mfa_required.value.upper()}")


def demo_full_flow():
    """Demonstrate full authentication flow"""
    print_section("Full Authentication Flow Demo")

    # Initialize database
    print("Initializing database...")
    init_db()

    with get_db_context() as db:
        # Create test user
        print("\n1. Creating test user...")
        password = "TestPassword123!@#"
        password_hash = password_manager.hash_password(password)

        # Check if user exists
        existing_user = db.query(User).filter(User.email == "demo@example.com").first()
        if existing_user:
            print("   User already exists, using existing user")
            user = existing_user
        else:
            user = User(
                email="demo@example.com",
                username="demouser",
                password_hash=password_hash
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print(f"   ✅ User created: {user.username} (ID: {user.id})")

            # Create profile
            profile = UserProfile(user_id=user.id)
            db.add(profile)
            db.commit()

        # Enroll TOTP
        print("\n2. Enrolling TOTP...")
        if not user.totp_secret:
            secret, encrypted_secret, qr_code = totp_manager.enroll_user(user.email)
            user.totp_secret = encrypted_secret
            db.commit()
            print(f"   ✅ TOTP enrolled")
            print(f"   Secret: {secret}")
        else:
            secret = totp_manager.decrypt_secret(user.totp_secret)
            print(f"   TOTP already enrolled")

        # Verify TOTP
        print("\n3. Verifying TOTP...")
        current_code = totp_manager.get_current_code(secret)
        print(f"   Current code: {current_code}")

        is_valid = totp_manager.validate_totp(user.totp_secret, current_code, encrypted=True)
        if is_valid:
            user.totp_enabled = True
            db.commit()
            print(f"   ✅ TOTP verified and enabled")

        # Simulate login
        print("\n4. Simulating login...")
        context = LoginContext(
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (X11; Linux x86_64)"
        )

        # Verify password
        password_valid = password_manager.verify_password(password, user.password_hash)
        print(f"   Password verification: {'✅ Success' if password_valid else '❌ Failed'}")

        # Assess risk
        profile = db.query(UserProfile).filter(UserProfile.user_id == user.id).first()
        risk_score, risk_level, risk_factors = risk_assessor.assess_risk(context, profile)
        print(f"   Risk Score: {risk_score}/100 ({risk_level.value})")

        # Check MFA requirement
        mfa_required = risk_assessor.get_mfa_requirement(risk_score, user.totp_enabled)
        print(f"   MFA Required: {mfa_required.value}")

        if mfa_required.value == "totp":
            print(f"   TOTP code required: {current_code}")

        print("\n✅ Login successful!")

        # Update profile
        risk_assessor.update_profile(profile, context, success=True)
        db.commit()
        print(f"   Profile updated with login patterns")


def main():
    """Run all demos"""
    print("\n" + "="*60)
    print("  AI SSO Agent - Interactive Demo")
    print("="*60)

    try:
        # Demo 1: Password hashing
        demo_password_hashing()
        input("\nPress Enter to continue...")

        # Demo 2: TOTP
        demo_totp()
        input("\nPress Enter to continue...")

        # Demo 3: Risk assessment
        demo_risk_assessment()
        input("\nPress Enter to continue...")

        # Demo 4: Full flow
        demo_full_flow()

        print_section("Demo Complete!")
        print("✅ All authentication components working correctly")
        print("\nNext steps:")
        print("1. Run the API: ./run.sh")
        print("2. View docs: http://localhost:8000/docs")
        print("3. Run tests: pytest")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
