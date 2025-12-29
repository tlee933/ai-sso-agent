# Getting Started with AI SSO Agent

## 🚀 Quick Start (3 minutes)

### Option 1: Run the Demo (Recommended First)
```bash
cd /home/hashcat/TheRock/ai-sso-agent
python3 demo.py
```

This will interactively demonstrate:
- ✅ Password hashing and validation
- ✅ TOTP enrollment and QR code generation
- ✅ Risk assessment scenarios
- ✅ Complete authentication flow

### Option 2: Run the API Server
```bash
cd /home/hashcat/TheRock/ai-sso-agent
./run.sh
```

Then visit:
- **API**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### Option 3: Run Tests
```bash
cd /home/hashcat/TheRock/ai-sso-agent

# Create venv and install deps
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
pytest -v

# With coverage
pytest --cov=src --cov-report=html
```

---

## 📱 Testing with a Real Authenticator App

### Step 1: Start the API
```bash
./run.sh
```

### Step 2: Register a User
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser",
    "password": "SuperSecret123!@#"
  }'
```

Response includes user ID (e.g., `"id": 1`)

### Step 3: Enroll TOTP
```bash
curl -X POST "http://localhost:8000/auth/totp/enroll?user_id=1"
```

Response includes:
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "base64-encoded-image...",
  "backup_codes": ["ABCD-1234", "EFGH-5678", ...]
}
```

### Step 4: Scan QR Code
1. Save the QR code to a file:
   ```bash
   echo "{response.qr_code}" | base64 -d > qr.png
   ```
2. Open on your phone
3. Scan with Google Authenticator or Microsoft Authenticator

### Step 5: Verify TOTP
Get the 6-digit code from your authenticator app, then:
```bash
curl -X POST "http://localhost:8000/auth/totp/verify?user_id=1" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "123456"
  }'
```

### Step 6: Login with MFA
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SuperSecret123!@#",
    "totp_code": "123456"
  }'
```

---

## 🧪 Example Usage: Python Client

```python
import requests

BASE_URL = "http://localhost:8000"

# 1. Register
response = requests.post(f"{BASE_URL}/auth/register", json={
    "email": "user@example.com",
    "username": "myuser",
    "password": "SecurePass123!@#"
})
user = response.json()
user_id = user["id"]

# 2. Enroll TOTP
response = requests.post(f"{BASE_URL}/auth/totp/enroll?user_id={user_id}")
enrollment = response.json()
print(f"Secret: {enrollment['secret']}")
print(f"Backup codes: {enrollment['backup_codes']}")

# Save QR code
import base64
qr_data = base64.b64decode(enrollment['qr_code'])
with open('qr_code.png', 'wb') as f:
    f.write(qr_data)

# 3. Get TOTP code (in real app, this comes from authenticator)
from src.auth.totp import totp_manager
code = totp_manager.get_current_code(enrollment['secret'])

# 4. Verify TOTP
response = requests.post(f"{BASE_URL}/auth/totp/verify?user_id={user_id}", json={
    "code": code
})
print(response.json())

# 5. Login
response = requests.post(f"{BASE_URL}/auth/login", json={
    "username": "myuser",
    "password": "SecurePass123!@#",
    "totp_code": code
})
login = response.json()
print(f"Login successful: {login['success']}")
print(f"Risk score: {login['risk_score']}")
print(f"Token: {login['token']}")
```

---

## 🔍 Understanding the Output

### Risk Score Interpretation
```
0-29:   ✅ LOW - Normal behavior
30-69:  ⚠️  MEDIUM - Some anomalies detected
70-99:  🚨 HIGH - Suspicious activity
100:    ⛔ CRITICAL - Highly suspicious
```

### MFA Requirements
- **Low risk** + TOTP disabled = No MFA
- **Low risk** + TOTP enabled = TOTP required
- **Medium risk** = TOTP or Email required
- **High risk** = TOTP + Additional verification

### Login Patterns Tracked
The AI learns:
- ✅ Your usual IP addresses (last 10)
- ✅ Your usual countries
- ✅ Your known devices (last 5)
- ✅ Your login hours (0-23)
- ✅ Your login days (Mon-Sun)

Each successful login updates the profile!

---

## 🐛 Troubleshooting

### "No module named 'src'"
```bash
# Make sure you're in the project directory
cd /home/hashcat/TheRock/ai-sso-agent

# And have activated the venv
source venv/bin/activate
```

### "FERNET_KEY not set"
The app will generate one automatically, but for production:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Add to .env: FERNET_KEY=<generated-key>
```

### "Database locked" (SQLite)
SQLite doesn't handle concurrent access well. For production:
```bash
# In .env, use PostgreSQL:
DATABASE_URL=postgresql://user:password@localhost/ai_sso_agent
```

### Tests failing
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Clear test database
rm ai_sso_agent.db
```

---

## 📚 Next Steps

### Learning Path
1. ✅ Run `demo.py` to understand components
2. ✅ Read `README.md` for architecture
3. ✅ Review `src/auth/totp.py` for TOTP implementation
4. ✅ Review `src/risk/assessor.py` for AI risk logic
5. ✅ Check `tests/` to see how to test

### Customization
1. Adjust risk weights in `src/risk/assessor.py`
2. Change password requirements in `config/settings.py`
3. Add new risk factors (e.g., device fingerprint improvements)
4. Implement email MFA in addition to TOTP

### Integration
1. Add Redis for session storage
2. Integrate with Microsoft Entra ID
3. Build admin dashboard
4. Add monitoring/metrics

---

## 🎯 Key Files to Understand

| File | Purpose |
|------|---------|
| `src/api/main.py` | FastAPI endpoints |
| `src/auth/totp.py` | TOTP implementation |
| `src/auth/password.py` | Password hashing |
| `src/risk/assessor.py` | AI risk engine |
| `src/db/models.py` | Database schema |
| `config/settings.py` | Configuration |
| `tests/test_*.py` | Unit tests |

---

**Have questions?** Check the main `README.md` or the code comments!

**Ready to build something awesome?** 🚀
