# Email Triage Automation System

**SOC Automation Platform for Internal Use - 68% Automation Rate**

**Status: Research/Internal Deployment Ready | NOT for Production PHI**

---

## Simulation Results

```
388 Total Processed    |    68% Automation Rate    |    78 Emails/Min
266 Auto-Resolved      |    123 Need Review        |    0.3s Avg Time
```

---

## Overview

Automated email triage system that processes Microsoft Defender user-reported emails using an ensemble approach:
- **40% Ollama LLM** - Local inference (no cloud API calls)
- **30% Rule-Based** - Analyst SOP logic
- **30% Defender Signals** - Microsoft threat intelligence (BCL, authentication)

**Key Features:**
- Multi-select bulk actions for analyst efficiency
- Configurable email simulation (1-15 minutes, 30-200 emails/min)
- Confidence-based auto-routing (>=75% auto-resolve, <75% analyst review)
- BCL (Bulk Complaint Level) scoring matching Defender (0-9 scale)
- Microsoft Defender-style dashboard
- Audit logging with SHA-256 hash chain
- JWT authentication with Role-Based Access Control (RBAC)

**Security Features (Phase 1 Implemented):**
- Password policy enforcement (12+ characters, complexity requirements)
- Account lockout protection (5 failed attempts, 30-minute lock)
- Export rate limiting (10 exports/hour with audit trail)
- Common password blocking
- Password expiration tracking (90 days)

---

## Quick Start

### 1. Launch Dashboard

```bash
./start.sh
```

This will:
- Check Python 3.8+ and dependencies
- Verify/start Ollama service
- Create virtual environment if needed
- Start FastAPI server on port 8000
- Open dashboard at http://127.0.0.1:8000/dashboard

### 2. Login

- **URL:** http://127.0.0.1:8000/dashboard
- **Default Credentials:**
  - Username: `admin`
  - Password: `changeme123`

**IMPORTANT: Change default password immediately!**
- New passwords must meet policy: 12+ characters, uppercase, lowercase, number, special character
- System enforces password complexity and blocks common passwords
- Accounts lock after 5 failed login attempts (30-minute auto-unlock)

### 3. Dashboard Features

**Active Triage Tab**
- View incoming emails being processed in real-time
- Multi-select with checkboxes for bulk actions
- Risk scores and confidence levels displayed
- Click email for detailed metadata view

**Analyst Review Tab**
- Low-confidence verdicts (<75%) requiring human review
- Incident IDs (INC-#) for tracking
- Assign to self or other analysts
- Mark as CLEAN or MALICIOUS after investigation
- Bulk assignment and resolution

**Completed Tab**
- All resolved emails (auto and manual)
- Final verdicts and timestamps
- Audit trail for compliance

**Simulation Mode**
- Configurable duration: 1, 3, 5, 10, or 15 minutes
- Configurable volume: Low (30/min), Medium (60/min), High (120/min), Surge (200/min)
- Generates realistic mix: phishing (all auth fail), bulk (BCL 7-9), clean (auth pass)
- Realistic authentication patterns (15% phishing from compromised legitimate accounts)
- BCL scoring matches Microsoft Defender (0-9 scale)
- Export functionality with CSV download and audit logging

---

## Architecture

```
src/
├── api/
│   └── main.py                    # FastAPI backend (627+ lines)
│                                  # JWT auth, RBAC, real data endpoints
│
├── auth/
│   └── security.py                # HIPAA authentication (309 lines)
│                                  # SHA-256 audit chain, user management
│
├── core/
│   ├── ollama_client.py           # Local LLM interface
│   ├── mdo_field_extractor.py     # Defender field parsing
│   ├── ensemble_verdict_engine.py # Verdict calculation engine
│   ├── data_processor.py          # Real CSV data processing
│   └── triage_orchestrator.py     # CLI batch processor
│
├── generators/
│   └── ollama_email_generator.py  # Synthetic email generation
│
└── frontend/
    └── templates/index.html       # Defender-style dashboard UI

data/
├── user-reported-anonymized.csv   # 373 user reports
├── explorer-anonymized.csv        # 14,555 Defender emails
├── incidents-anonymized.csv       # Unworked incident queue
└── analyst-reported-anonymized.csv

config/
├── users.yaml                     # User credentials (auto-created)
└── defender_features.yaml         # Feature mappings

results/
└── auth_audit.json                # Immutable audit log
```

---

## How It Works

### 1. Email Processing Pipeline

```
Incoming Email → MDO Field Extractor → Ensemble Engine → Verdict
                        ↓
              [Subject, Sender, SPF/DKIM, URLs, Attachments...]
                        ↓
              [Ollama 40% + Rules 30% + Defender 30%]
                        ↓
              [CLEAN | SUSPICIOUS | MALICIOUS]
                        ↓
              Confidence >= 75%? → Auto-Resolve
              Confidence < 75%  → Analyst Review Queue
```

### 2. Confidence-Based Routing

- **High Confidence (>=75%)**: Auto-resolved to completed queue
  - CLEAN emails marked safe
  - MALICIOUS emails auto-blocked
- **Low Confidence (<75%)**: Routed to analyst review
  - Assigned incident ID (INC-#)
  - Requires human verification

### 3. Analyst Workflow

1. View emails in "Analyst Review" tab
2. Select multiple emails with checkboxes
3. Click "Assign to Me" for investigation
4. Review metadata in detail panel (24px padding for readability)
5. Mark as "Clean" or "Block" based on analysis
6. Bulk actions available for efficiency

---

## Security Status

**IMPORTANT: This system demonstrates good security patterns but is NOT fully HIPAA compliant for production use with real PHI.**

### What Works (Good Patterns)
- **Metadata Only**: No email body content processed
- **Local Processing**: All Ollama inference runs locally (no cloud calls)
- **JWT Authentication**: Token-based with HS256 encryption
- **Audit Logging**: SHA-256 hash chain for tamper detection
- **RBAC**: Role-based permissions (analyst/admin/auditor)
- **Password Policy**: Enforced complexity (12+ chars, uppercase, lowercase, number, special)
- **Account Lockout**: Brute-force protection (5 attempts, 30-min lock)
- **Export Rate Limiting**: Data exfiltration prevention (10/hour limit)

### What's Missing (Phase 2)
- **No HTTPS/TLS**: API runs on HTTP (credentials in plaintext on network)
- **No MFA**: Single-factor authentication only
- **No Database Encryption**: Users stored in YAML file
- **Network Binding**: Not restricted to specific subnet yet
- **No External Audit**: Hash chain can theoretically be regenerated

### Access Control (RBAC)
```python
ROLES = {
    "analyst": {
        "can_view_queue": True,
        "can_triage": True,
        "can_view_audit": False,
        "can_override_verdicts": True
    },
    "admin": {
        "can_view_queue": True,
        "can_triage": True,
        "can_view_audit": True,
        "can_manage_users": True
    },
    "auditor": {
        "can_view_queue": True,
        "can_triage": False,
        "can_view_audit": True,
        "can_export_data": True
    }
}
```

**For full security assessment, see:** `docs/SECURITY_STATUS.md`

---

## Real Data Processing

The system processes actual Microsoft Defender CSV exports:

### User-Reported Queue
```python
# Maps real column names (not anonymized placeholders)
item = {
    "submission_name": row.get("Submission name"),  # Actual subject
    "sender": row.get("Sender"),
    "reason": row.get("Reason for submitting"),
    "result": row.get("Result"),
    "verdict": self._derive_verdict_from_result(row),
    "risk_score": self._calculate_risk_score(row)
}
```

### Incident Queue
```python
# Processes unworked incidents with severity scoring
item = {
    "incident_id": row.get("Incident Id"),
    "severity": row.get("Severity"),  # high/medium/low
    "categories": row.get("Categories"),
    "assigned_to": row.get("Assigned to"),
    "risk_score": self._calculate_incident_risk(row)
}
```

### Explorer Emails
```python
# 30-minute sample of email flow (14,555 emails)
item = {
    "threats": row.get("Threats"),
    "delivery_action": row.get("Delivery action"),
    "detection_technologies": row.get("Detection technologies"),
    "spf_aligned": sender_domain == mail_from_domain
}
```

---

## API Endpoints

### Authentication
- `POST /auth/login` - Get JWT access token
- `POST /auth/refresh` - Refresh expired token
- `POST /auth/change-password` - Change user password (enforces policy)
- `POST /auth/unlock-account/{username}` - Admin unlock locked account

### Export Control (Rate Limited)
- `POST /export/check` - Check if user can export (rate limit)
- `POST /export/record` - Record export event to audit log

### Real Data (Protected)
- `GET /triage/real-stats` - Overall statistics
- `GET /triage/user-reports` - User-reported email queue
- `GET /triage/incidents` - Incident queue
- `GET /triage/explorer` - Explorer email sample
- `GET /triage/combined` - Prioritized combined queue

### Triage Actions
- `POST /triage/emails` - Process emails with verdicts
- `POST /triage/generate` - Generate synthetic test emails
- `POST /triage/verdict/{id}` - Override verdict (analyst action)

### Dashboard
- `GET /dashboard` - Main dashboard UI
- `GET /health` - System health check

**API Documentation:** http://127.0.0.1:8000/docs

---

## Testing

### Run Integration Tests

```bash
python3 test_system.py
```

Expected output:
```
Testing imports...           ✓ Core modules imported
Testing email generator...   ✓ Generated phishing email
Testing MDO extractor...     ✓ Extracted 30+ features
Testing authentication...    ✓ Admin user exists
Testing Ollama connection... ✓ Ollama running
Testing data files...        ✓ User reports: 373 emails

Total: 6/6 tests passed
```

### Run Dashboard Simulation

1. Start server: `./start.sh`
2. Login to dashboard
3. Click "Start Simulation"
4. Observe 5-minute email influx
5. Monitor automation rate and throughput

---

## Performance Metrics

### Achieved Results (5-min simulation)
- **Total Processed:** 388 emails
- **Automation Rate:** 68%
- **Throughput:** 78 emails/minute
- **Auto-Resolved:** 266 emails
- **Analyst Review:** 123 emails
- **Average Time:** 0.3 seconds per email

### Target Metrics
- Automation Rate: >70% (achieved 68%)
- False Positive Rate: <5%
- False Negative Rate: <2%
- Average Latency: <3 seconds (achieved 0.3s)
- Analyst Time Saved: >60%

---

## Ollama Setup

```bash
# Check available models
ollama list

# Start Ollama service
ollama serve

# Pull recommended model
ollama pull mistral:latest

# Test model
ollama run mistral "Analyze: Urgent account verification"
```

The system works without Ollama (rule-based only) but achieves better accuracy with LLM analysis.

---

## Dependencies

```
fastapi>=0.104.0       # Web framework
uvicorn>=0.24.0        # ASGI server
python-jose>=3.3.0     # JWT tokens
passlib>=1.7.4         # Password hashing
pandas>=2.0.0          # Data processing
scikit-learn>=1.3.0    # ML utilities
httpx>=0.25.0          # HTTP client
pydantic>=2.5.0        # Data validation
PyYAML>=6.0            # Config parsing
cryptography>=41.0    # Encryption
```

Install: `pip install -r requirements.txt`

---

## Files

| File | Purpose |
|------|---------|
| `start.sh` | One-command startup script |
| `test_system.py` | Integration test suite |
| `requirements.txt` | Python dependencies |
| `src/api/main.py` | FastAPI backend with auth and rate limiting |
| `src/auth/security.py` | Security module (password policy, lockout, exports) |
| `src/core/data_processor.py` | Real CSV data processing |
| `src/frontend/templates/index.html` | Dashboard UI with configurable simulation |
| `src/generators/ollama_email_generator.py` | Email simulation |
| `docs/SECURITY_STATUS.md` | Security assessment and gaps |
| `docs/RESEARCH_AND_DEPLOYMENT.md` | Organizational deployment guide |
| `docs/RESEARCH_CONSIDERATIONS.md` | Research methodology |

---

## Deployment Checklist

### Before Internal Deployment (Current State):

- [x] Password policy enforcement (12+ chars, complexity)
- [x] Account lockout protection (5 attempts, 30-min lock)
- [x] Export rate limiting (10/hour with audit trail)
- [x] Common password blocking
- [x] RBAC with three roles
- [x] Audit logging with hash chain
- [ ] Change default admin password
- [ ] Configure JWT secret key: `export JWT_SECRET_KEY=$(openssl rand -hex 32)`
- [ ] Train analysts on dashboard workflow

### Phase 2 Enhancements (Recommended):

- [ ] Enable HTTPS/TLS with valid certificates
- [ ] Network interface binding (restrict to SOC subnet)
- [ ] Set up database for user storage (replace YAML with encrypted DB)
- [ ] Add MFA (TOTP support)
- [ ] External SIEM integration for audit logs
- [ ] Configure proper backup procedures

### NOT Required for Internal Use:

- Microsoft BAA not needed (you own your Defender data)
- Cloud provider agreements not needed (everything local)
- Third-party processor contracts not needed (no external services)

---

## License

Internal use only - SOC Automation Research

---

**Version:** 3.0 (Phase 1 Security Hardening)
**Last Updated:** 2025-11-16
**Status:** Research/Internal Deployment Ready
**Production PHI Ready:** No (requires Phase 2 enhancements)
**Simulation Results:** 68% automation, 78 emails/min
