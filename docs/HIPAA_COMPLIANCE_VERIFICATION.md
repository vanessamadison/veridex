# HIPAA Compliance Verification Guide

## How to Verify This Tool is HIPAA Compliant

### 1. Data Minimization - No PHI Processing

**Verification:**
- The system processes only email **metadata**, never email body content
- Open `src/core/mdo_field_extractor.py` and verify no body extraction
- Check exported CSVs contain only: Subject, Sender, Domain, Authentication results
- No recipient email addresses are stored (only anonymized placeholders)

**Evidence:**
```python
# From data_processor.py - only metadata fields
item = {
    "submission_name": row.get("Submission name"),  # Subject line only
    "sender": row.get("Sender"),                    # External sender
    "verdict": self._derive_verdict_from_result(row),
    "risk_score": self._calculate_risk_score(row)
}
# NO email body content is processed
```

**Test:** Export simulation data and verify no email body content exists.

---

### 2. Local Processing - No Cloud Transmission

**Verification:**
- All AI inference runs via **Ollama** on localhost:11434
- No external API calls to OpenAI, Azure, or other cloud services
- Data never leaves the network

**Evidence:**
```python
# From ollama_client.py
self.base_url = "http://localhost:11434"  # Local only

# From api/main.py - no external calls
# All processing happens within the FastAPI server
```

**Test:**
1. Disconnect from internet
2. Run simulation
3. System continues to function
4. Monitor network traffic - no external requests

---

### 3. Authentication & Access Control

**Verification:**
- JWT tokens with expiration (30 minutes)
- Role-Based Access Control (RBAC)
- Three roles: analyst, admin, auditor
- Password hashing with SHA-256

**Evidence:**
```python
# From security.py
ROLES = {
    "analyst": {"can_view_queue": True, "can_triage": True, "can_view_audit": False},
    "admin": {"can_view_queue": True, "can_triage": True, "can_view_audit": True},
    "auditor": {"can_view_queue": True, "can_triage": False, "can_view_audit": True}
}

ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Short-lived tokens
pwd_context = CryptContext(schemes=["sha256_crypt"])  # Secure hashing
```

**Test:**
1. Login with admin credentials
2. Verify JWT token expires after 30 minutes
3. Attempt to access audit logs as analyst (should be denied)
4. Verify password is hashed in `config/users.yaml`

---

### 4. Immutable Audit Logging

**Verification:**
- SHA-256 hash chain prevents tampering
- Every action logged with timestamp and user
- 6-year retention capability (2190 days)
- Logs stored in `results/auth_audit.json`

**Evidence:**
```python
# From security.py - AuditLogger class
def _compute_hash(self, entry: dict) -> str:
    data = json.dumps(entry, sort_keys=True) + self.previous_hash
    return hashlib.sha256(data.encode()).hexdigest()

def log_event(self, event_type: str, username: str, details: dict = None):
    entry["previous_hash"] = self.previous_hash
    entry["entry_hash"] = self._compute_hash(entry)
```

**Test:**
1. Login multiple times
2. View `results/auth_audit.json`
3. Verify each entry has: timestamp, event_type, username, previous_hash, entry_hash
4. Verify hash chain integrity: each entry's previous_hash matches prior entry_hash

**Verification Command:**
```python
# Verify audit log integrity
import json
import hashlib

with open('results/auth_audit.json', 'r') as f:
    entries = json.load(f)

for i, entry in enumerate(entries):
    if i == 0:
        assert entry['previous_hash'] == 'GENESIS'
    else:
        assert entry['previous_hash'] == entries[i-1]['entry_hash']

    # Recompute hash
    entry_copy = {k: v for k, v in entry.items() if k != 'entry_hash'}
    data = json.dumps(entry_copy, sort_keys=True) + entry['previous_hash']
    computed_hash = hashlib.sha256(data.encode()).hexdigest()
    assert entry['entry_hash'] == computed_hash

print("Audit log integrity verified!")
```

---

### 5. Encryption & Secure Storage

**Verification:**
- JWT tokens encrypted with HS256 algorithm
- Secret keys from environment variables or auto-generated
- User credentials stored with hashed passwords

**Evidence:**
```python
# From security.py
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", Fernet.generate_key().decode())
ALGORITHM = "HS256"

# Passwords are never stored in plaintext
hashed_password = get_password_hash("password")  # SHA-256 hash
```

**Test:**
1. Check `config/users.yaml` - passwords are hashed
2. Decode JWT token - contains only username, role, not password
3. Set `JWT_SECRET_KEY` environment variable for production

---

### 6. 45 CFR 164.312(d) Compliance

This regulation requires person or entity authentication. The system complies through:

1. **Unique User Identification** - Each user has unique username
2. **Emergency Access Procedure** - Admin can reset passwords
3. **Automatic Logoff** - JWT expires after 30 minutes
4. **Encryption** - All passwords hashed, tokens encrypted

**Verification:**
- Admin can create users with `user_store.create_user()`
- Tokens expire automatically
- No shared accounts (unique credentials per user)

---

## HIPAA Technical Safeguards Checklist

| Requirement | Implementation | Verified |
|-------------|---------------|----------|
| Access Control (164.312(a)(1)) | JWT + RBAC | [ ] |
| Unique User ID (164.312(a)(2)(i)) | Username field in users.yaml | [ ] |
| Emergency Access (164.312(a)(2)(ii)) | Admin role with full access | [ ] |
| Automatic Logoff (164.312(a)(2)(iii)) | 30-minute token expiry | [ ] |
| Encryption (164.312(a)(2)(iv)) | HS256 JWT, SHA-256 passwords | [ ] |
| Audit Controls (164.312(b)) | Immutable hash chain logs | [ ] |
| Integrity (164.312(c)(1)) | SHA-256 audit hashes | [ ] |
| Person Authentication (164.312(d)) | Username/password auth | [ ] |
| Transmission Security (164.312(e)(1)) | Local processing only | [ ] |

---

## What This Tool Does NOT Do (Gaps to Address)

1. **No Database Encryption at Rest**
   - Users stored in YAML file
   - Recommendation: Use encrypted database (PostgreSQL with pgcrypto)

2. **No TLS/HTTPS**
   - API runs on HTTP (localhost)
   - Recommendation: Enable HTTPS with valid certificates for production

3. **No Multi-Factor Authentication**
   - Only password authentication
   - Recommendation: Add TOTP or hardware key support

4. **No Session Revocation**
   - Cannot invalidate active tokens
   - Recommendation: Implement token blacklist

5. **No Backup Encryption**
   - Audit logs stored as plain JSON
   - Recommendation: Encrypt backup files

---

## Production Deployment Requirements

Before deploying to production with real PHI:

1. **Enable HTTPS/TLS**
   ```bash
   uvicorn src.api.main:app --ssl-keyfile=key.pem --ssl-certfile=cert.pem
   ```

2. **Set Secure JWT Secret**
   ```bash
   export JWT_SECRET_KEY=$(openssl rand -hex 32)
   ```

3. **Change Default Password**
   ```python
   user_store.create_user(UserInDB(
       username="admin",
       email="admin@domain.com",
       role="admin",
       hashed_password=get_password_hash("SecureP@ssw0rd!")
   ))
   ```

4. **Enable Audit Log Retention Policy**
   - Archive logs after 30 days
   - Maintain for 6 years (HIPAA requirement)
   - Store in encrypted, immutable storage

5. **Implement Network Segmentation**
   - Isolate system from general network
   - Restrict access to SOC team only

6. **Document Risk Assessment**
   - Conduct formal HIPAA risk analysis
   - Document all PHI data flows
   - Establish incident response procedures

---

## Comparison to Defender Requirements

| Feature | Microsoft Defender | This Tool | Match |
|---------|-------------------|-----------|-------|
| SPF/DKIM/DMARC | Yes | Yes | Full |
| BCL (Bulk Complaint Level) | 0-9 scale | 0-9 scale | Full |
| URL Detonation | Yes | Simulated | Partial |
| Attachment Analysis | Yes | Simulated | Partial |
| Threat Types | Multiple | CLEAN/SUSPICIOUS/MALICIOUS/BULK | Simplified |
| Incident ID | Yes | INC-# format | Full |
| Composite Authentication | Yes | Yes | Full |
| Detection Technology | Multiple | Machine learning, URL detonation, Bulk filter | Simplified |
| Sender IP | Yes | Yes | Full |
| Directionality | Inbound/Outbound | Inbound | Partial |

---

## Data Export Validation

To verify simulated data matches real Defender exports:

1. **Run Simulation**
   - Click "Start 5-Min Simulation"
   - Let it complete

2. **Export Data**
   - Click "Export Data" button
   - Download `simulation_data.csv`

3. **Compare Columns**
   ```
   Simulation CSV:                  Defender Export:
   - Incident ID                    - Incident Id
   - Subject                        - Subject / Submission name
   - Sender                         - Sender address
   - Domain                         - Sender domain
   - Verdict                        - Threats / Result
   - Risk Score                     - (Calculated field)
   - BCL                            - Bulk complaint level
   - SPF/DKIM/DMARC                 - Authentication details
   - URL Count                      - Url Count
   - Attachment Count               - Attachment Count
   - Detection Technology           - Detection technologies
   ```

4. **Verify Field Mapping**
   - Compare `data/user-reported-anonymized.csv` with exported simulation
   - Check field types match (strings, numbers, dates)
   - Verify BCL ranges (0-9)
   - Confirm authentication results match Defender patterns

---

## Annual HIPAA Review Checklist

- [ ] Review access control policies
- [ ] Audit user accounts (remove inactive)
- [ ] Verify audit log integrity
- [ ] Test backup restoration
- [ ] Update risk assessment
- [ ] Retrain staff on procedures
- [ ] Review and update this documentation
- [ ] Verify Ollama is running locally (no cloud calls)
- [ ] Check for security patches in dependencies

---

**Document Version:** 1.0
**Last Updated:** 2025-11-16
**Review Schedule:** Annually or after security incidents
