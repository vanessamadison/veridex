# VERIDEX

![Version](https://img.shields.io/badge/Version-v1.0.0-000000?style=for-the-badge&logo=github&logoColor=white)

[![Python](https://img.shields.io/badge/Python-000000?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-000000?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Ollama](https://img.shields.io/badge/Ollama-000000?style=for-the-badge&logo=ai&logoColor=white)](https://ollama.ai)
[![Research Phase](https://img.shields.io/badge/Research_Phase-000000?style=for-the-badge&logo=science&logoColor=white)](https://github.com/nessakodo/veridex)
[![License](https://img.shields.io/badge/License-MIT-000000?style=for-the-badge)](LICENSE)

---

## Overview

VERIDEX is a research-phase concept for metadata-first phishing triage in regulated environments. It was designed to explore whether analyst workflow could be accelerated through explainable scoring, routing, and analyst-in-the-loop review before any production handling of sensitive communications.

---

## Research Boundary

All evaluation inputs in this public repository are simulated, synthetic, or publicly available. This repository does not include patient records, PHI, live email bodies, or attachment contents. It is intended for feasibility research, interface demonstration, and sandbox testing only.

---

## What This Repository Demonstrates

- Metadata-first triage logic for phishing-related email review
- Analyst-in-the-loop escalation and override workflow
- Explainable decision factors for routing and prioritization
- Local model plus rules-based experimentation
- A lower-risk path to testing workflow automation before sensitive communications enter scope

---

## Simulated Evaluation Results

Tested on **SpamAssassin Spam Corpus 2** (N=500 emails sampled from 1,396 total):

| Metric | Value | Note |
|:---|:---|:---|
| **F1 Score** | **91.74%** | Exceeds target (>=85%) |
| **Precision** | **100.00%** | Zero false positives in this simulated evaluation |
| **Recall** | **84.74%** | Exceeds target (>=70%) |
| **Accuracy** | **84.74%** | Strong detection |
| **Processing Time (LLM)** | **0.3s** | Real-time capable |
| **Processing Time (Rules)** | **0.007s** | 140 emails/second |
| **Automation Rate** | **68%** | Operational feasibility signal |
| **False Positive Rate** | **0.00%** | Zero false positives in this simulated evaluation |

The results included in this repository come from the public evaluation setup documented here and should be interpreted as feasibility signals, not production performance guarantees.

---

## Key Features

- **Metadata-First**: Designed to evaluate workflow automation without using patient records or PHI in the public research setup
- **Zero False Positives**: 100% precision in simulated evaluation protects against unnecessary escalation
- **Real-Time Processing**: Sub-second verdict latency (0.3s with LLM, 0.007s rules-only)
- **Explainable AI**: Transparent Decision Factors Analysis shows weighted reasoning
- **68% Automation**: Simulated automation rate suggests analyst workload reduction potential
- **Security Controls**: JWT authentication, RBAC, SHA-256 audit logging
- **Ensemble Architecture**: Local Ollama LLM + Rules-Based Logic

---

## VERIDEX User Workflow

The VERIDEX dashboard is designed for intuitive email triage, echoing the familiar styling of Microsoft Defender to ease analyst adoption. This section illustrates the typical workflow: from initial simulation to analyst review and final resolution.

#### 1. Simulation & Ingest

Incoming emails are first processed through the VERIDEX engine. The simulation dashboard provides an overview of this initial intake and processing phase.

![Simulation Dashboard](assets/simulation.png)
*Figure: The Simulation dashboard shows emails being processed by VERIDEX, with an interface reminiscent of Microsoft Defender's security portals.*

#### 2. Analyst Review Queue

Emails that require human intervention (e.g., those with confidence scores below the automation threshold) are routed to the Analyst Review queue. Here, security analysts can investigate suspicious emails.

![Analyst Review Dashboard](assets/analyst-review.png)
*Figure: The Analyst Review dashboard displays emails awaiting human analysis, highlighting the integration of risk scores and decision factors within a clear, actionable interface.*

#### 3. Completed Triage

Once an email has been thoroughly analyzed and a final verdict rendered---either automatically or through analyst review---it moves to the Completed Triage view.

![Completed Triage Dashboard](assets/completed.png)
*Figure: The Completed Triage dashboard provides a summary of resolved incidents, offering transparency and a historical record of actions taken, all within a consistent Microsoft Defender-like design.*

---

## Architecture

```
┌─────────────────┐
│ User-Reported   │
│ Emails          │
└────────┬────────┘
         │
         v
┌─────────────────────────────────┐
│ Microsoft Defender Signals      │
│ (SPF/DKIM/DMARC, BCL, URLs)     │
└────────┬────────────────────────┘
         │
    ┌────┴────┐
    │         │
    v         v
┌───────┐ ┌─────────┐
│ Rules │ │Local LLM│
│  50%  │ │   50%   │
└───┬───┘ └───┬─────┘
    │         │
    └────┬────┘
         v
┌─────────────────┐
│ Ensemble Engine │
│ 75% Threshold   │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    v         v
┌────────┐ ┌──────────┐
│Auto-   │ │ Analyst  │
│Resolve │ │ Review   │
│  68%   │ │   32%    │
└────────┘ └──────────┘
```

**Components:**
- **LLM Ensemble Engine**: Local Ollama (mistral) for metadata-first analysis without cloud exposure
- **Rule-Based Logic**: Microsoft Defender signals (SPF, DKIM, DMARC, BCL)
- **Analyst Dashboard**: Real-time triage with Decision Factors Analysis
- **Security Layer**: JWT auth, RBAC, password policies, audit logging

---

## Quick Start

### Prerequisites

- Python 3.9+
- Ollama (for local LLM)
- Virtual environment

### Installation

```bash
# Clone repository
git clone https://github.com/nessakodo/veridex.git
cd veridex

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Ollama and pull model
# macOS/Linux: https://ollama.ai
ollama pull mistral
```

### Initial Setup

Veridex supports two roles out of the box: **admin** and **analyst**. Run the setup script once per user. The first run typically creates the admin. Subsequent runs create one or more analysts.

```bash
# Run the user setup script for each user you need
python3 scripts/setup_admin.py
```

The script walks you through:

1. **Choose a role**
   - `admin`: full permissions. Can manage users, view the security audit log, view the queue, triage, override verdicts, and export data.
   - `analyst`: least-privilege operator. Can view the queue, triage, override verdicts, and export data. **Cannot** create users or read the security audit log (the system still logs every action an analyst takes).
2. **Choose a username and email** (defaults are `admin` / `analyst`).
3. **Choose a password**
   - Option 1: auto-generate a secure password. Shown once on screen, save it immediately.
   - Option 2: set your own. Must meet length and complexity requirements (12+ characters, mixed case, number, special char).

The script writes the user to `data/users.yaml` and logs a `USER_CREATED` event to the immutable audit log at `results/auth_audit.json`.

**Typical setup for a demo or a small team:**

```bash
# 1. Create the admin
python3 scripts/setup_admin.py
# Choose role: 1 (admin), username: admin

# 2. Create one or more analysts
python3 scripts/setup_admin.py
# Choose role: 2 (analyst), username: john

python3 scripts/setup_admin.py
# Choose role: 2 (analyst), username: priya
```

#### Role permissions reference

| Permission              | admin | analyst |
|-------------------------|:-----:|:-------:|
| `can_view_queue`        |  ✓    |   ✓     |
| `can_triage`            |  ✓    |   ✓     |
| `can_override_verdicts` |  ✓    |   ✓     |
| `can_generate_data`     |  ✓    |   ✓     |
| `can_export_data`       |  ✓    |   ✓     |
| `can_manage_users`      |  ✓    |         |
| `can_view_audit`        |  ✓    |         |

Permissions are enforced server-side. When an analyst attempts an admin-only action, the request is rejected and a `PERMISSION_DENIED` row is appended to the audit log. There is no client-side bypass.

#### A third role (auditor)

A read-only `auditor` role also exists in `src/auth/security.py` for compliance scenarios. It can view the queue and the audit log and export data, but cannot triage or override. The setup script does not expose it as an interactive option because most deployments do not need a separate auditor account, but it can be added by editing `data/users.yaml` directly and setting `role: auditor`.

### Running VERIDEX

```bash
# Start the API server
python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload

# Access the dashboard
open http://127.0.0.1:8000/dashboard

# Login with credentials from setup script
Username: admin
Password: [generated during setup]
```

---

## Usage

### Dashboard

1. **Login**: Use credentials created during setup (scripts/setup_admin.py)
2. **Active Triage**: View incoming emails with risk scores and Decision Factors
3. **Analyst Review**: Review low-confidence emails (< 75% threshold)
4. **Decision Factors**: Click any email to see transparent XAI reasoning

### Standalone Testing

```bash
# Test on SpamAssassin corpus
python3 standalone_triage.py \
    --dataset data/spamassassin/spam_2 \
    --ground-truth data/spamassassin/ground_truth.csv \
    --output results/test.json

# Test without LLM (faster, rules-only)
python3 standalone_triage.py \
    --dataset data/spamassassin/spam_2 \
    --ground-truth data/spamassassin/ground_truth.csv \
    --no-llm

# Run comprehensive validation
bash scripts/validate_all_datasets.sh
```

---

## Decision Factors Analysis

VERIDEX provides transparent, explainable AI reasoning for each verdict:

```
Decision Factors Analysis

SPF Authentication: Pass (+15)
DKIM Signature: Pass (+15)
DMARC Policy: Fail (-30)
Bulk Complaint Level: 8/9 High Spam (-40)
URL Analysis: 3 URLs - All Clean (+5)
Attachment Scan: 1 file - No threats (+5)

Final Verdict: SUSPICIOUS (Confidence: 68%)
Action: Route to Analyst Review
```

**Weighted Impact Scores:**
- SPF Pass: +15, Fail: -25
- DKIM Pass: +15, Fail: -25
- DMARC Pass: +20, Fail: -30
- BCL High (7-9): -40, Medium (4-6): -20, Low (0-3): +10
- Malicious URLs: -30 each
- Malicious Attachments: -35 each
- Defender Detection: -50

---

## Current Maturity

This repository reflects research and internal testing, not production deployment. Any real-world use involving sensitive healthcare communications would require formal security review, approved data handling, encryption, identity controls, environment hardening, compliance review, and organization-specific validation.

### Security Controls Implemented

- JWT Token Authentication with RBAC (Admin, Analyst, Viewer roles)
- Password policies (12+ characters, complexity requirements)
- Account lockout protection
- SHA-256 hash-chained audit logging
- Export rate limiting
- Local LLM processing (no cloud-based content analysis)
- Metadata-only processing (no access to email body, subject content, or attachments)

### Not Yet Implemented (Required for Production)

- HTTPS/TLS encryption
- Database encryption at rest
- Multi-factor authentication (MFA)
- Secure key management (HSM or cloud KMS)
- Network segmentation
- Formal risk assessment and incident response plan

---

## Why It May Matter Operationally

For teams managing high volumes of inbound email in a regulated environment, the point of this work is not to claim that simulated data mirrors production. The point is to test whether a metadata-first triage model can reduce manual review burden, improve analyst prioritization, and generate measurable workflow insight in a controlled setting---before more sensitive integrations are considered.

---

## Performance Benchmarks

### Processing Speed

| Configuration | Time per Email | Throughput | Use Case |
|:---|:---|:---|:---|
| Rules-Only | 0.007s | 140 emails/sec | High-volume triage |
| LLM + Rules (Ensemble) | 0.3s | 3.3 emails/sec | Balanced accuracy |
| Full Analysis | 0.3s | 3.3 emails/sec | Maximum precision |

### Comparison with Related Research

| System | F1 Score | Precision | Recall | Approach | Metadata-Only |
|:---|:---|:---|:---|:---|:---|
| **VERIDEX** | **91.74%** | **100.00%** | **84.74%** | Metadata-Only | Yes |
| PhishLang (2024) | ~96% | 96% | ~96% | Full-Content ML | No |
| EXPLICATE (2025) | ~98% | ~98% | ~98% | Full-Content ML | No |
| Transformer Models | ~96% | ~94% | ~98% | Full-Content ML | No |

VERIDEX demonstrates competitive performance with metadata-only analysis. The 100% precision in this simulated evaluation is notable for environments where false positives carry operational cost.

---

## Research Notes

### Findings from Simulated Evaluation

1. **Metadata sufficiency**: 91.74% F1 achieved without content access
2. **Zero false positives**: Reduces unnecessary analyst escalation in simulation
3. **68% automation rate**: Suggests significant workload reduction potential
4. **Real-time processing**: 0.3s latency enables operational feasibility
5. **Ensemble necessity**: LLM required to filter rule-based false positives

### Hypothesis Validation

| Hypothesis | Target | Achieved | Status |
|:---|:---|:---|:---|
| H1: Alignment Rate | >=75% | 84.74% | Validated |
| H2: Precision | >=85% | 100% | Exceeded |
| H2: Recall | >=70% | 84.74% | Exceeded |
| H3: MTTR Reduction | >=35% | TBD | Requires live deployment |
| H4: Automation Coverage | 15-25% | 68% | Exceeded |

H3 and H4 require live deployment for full validation.

---

## API Endpoints

### Authentication

```bash
# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YOUR_PASSWORD"}'
```

### Email Triage

```bash
# Triage single email
curl -X POST http://localhost:8000/api/triage \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "email_id": "test-001",
    "authentication": {
      "spf": "Fail",
      "dkim": "Pass",
      "dmarc": "Fail"
    },
    "bcl": 8
  }'
```

### Dashboard Data

```bash
# Get active incidents
curl -X GET http://localhost:8000/api/incidents/active \
  -H "Authorization: Bearer <token>"

# Get analyst review queue
curl -X GET http://localhost:8000/api/incidents/review \
  -H "Authorization: Bearer <token>"
```

---

## Testing + Validation

### Run Unit Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest --cov=src --cov-report=term-missing tests/

# Run specific test module
pytest tests/test_auth_security.py -v
pytest tests/test_ensemble_engine.py -v
pytest tests/test_mdo_extractor.py -v
pytest tests/test_metrics.py -v
```

### Validate on SpamAssassin

```bash
# Full validation (500 emails)
python3 standalone_triage.py \
    --dataset data/spamassassin/spam_2 \
    --ground-truth data/spamassassin/ground_truth.csv

# Quick validation (100 emails)
python3 standalone_triage.py \
    --dataset data/spamassassin/spam_2 \
    --ground-truth data/spamassassin/ground_truth.csv \
    --limit 100
```

---

## Contributing

This is a research project. Contributions welcome via GitHub Issues or pull requests.

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

This project is provided for research and educational purposes. Any use involving sensitive healthcare communications requires formal compliance validation and security hardening beyond what is included here.

---

## Acknowledgments

- **SpamAssassin Project**: Validation corpus
- **Microsoft Defender for Office 365**: Signals integration
- **Ollama**: Local LLM inference
- **VICEROY Scholar Program**: Research support
- **FastAPI**: Modern Python web framework

---

## Contact

- **Author**: Vanessa Madison
- **Program**: VICEROY Scholar Cohort Fall 2025
- **Repository**: [GitHub](https://github.com/nessakodo/veridex)

For questions about the research, see [documentation](docs/) or open an issue.

---

## References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [HIPAA Privacy Rule (45 CFR 164.506)](https://www.hhs.gov/hipaa/for-professionals/privacy/index.html)
- [HIPAA Security Rule (45 CFR 164.306)](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/)
- PhishLang (2024): Real-time client-side phishing detection
- EXPLICATE (2025): LLM-powered explainable phishing detection

---

*Last Updated: March 16, 2026*
*Version: 1.0.0 (Research Phase)*
