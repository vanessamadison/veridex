# Defender Automation Triage - HIPAA-Compliant Email Security

**Microsoft Defender for Office 365 automated triage system using local Ollama LLM**

---

## Overview

Automated email triage system that processes Microsoft Defender user-reported emails and generates verdicts using an ensemble approach:
- **40% Ollama LLM** (local, HIPAA-compliant inference)
- **30% Rule-based** (analyst SOP logic)
- **30% Defender signals** (Microsoft threat intelligence)

**Key Features:**
- ✅ HIPAA-compliant (local processing, metadata-only)
- ✅ 70%+ automation target
- ✅ Comprehensive audit trails
- ✅ Extensible for new Defender features
- ✅ Production-ready

---

## Quick Start

### 1. Prerequisites

```bash
# Verify Ollama is running
ollama list

# Pull recommended model
ollama pull mistral:latest
```

### 2. Configure

```bash
# Copy and edit configuration
cp config/config.example.yaml config/config.yaml
nano config/config.yaml
```

### 3. Run Triage

```bash
# Process emails
python3 src/core/triage_orchestrator.py \
    --input data/user-reported-anonymized.csv \
    --output results/$(date +%Y%m%d_%H%M%S) \
    --config config/config.yaml
```

### 4. Review Results

```bash
# Check summary
cat results/latest/summary_*.json

# Review analyst queue
cat results/latest/analyst_queue_*.csv
```

---

## Directory Structure

```
defender-automation-triage/
├── src/
│   ├── core/                          # Core triage engines
│   │   ├── ollama_client.py          # Ollama LLM interface
│   │   ├── mdo_field_extractor.py    # Defender email entity parser
│   │   ├── ensemble_verdict_engine.py # Ensemble decision engine
│   │   └── triage_orchestrator.py    # Main orchestrator
│   │
│   ├── integrations/                  # External integrations
│   │   ├── graph_api_client.py       # Microsoft Graph API
│   │   └── [future integrations]     # Cherwell, Power BI, etc.
│   │
│   └── utils/                         # Utilities
│       ├── hipaa_validator.py        # HIPAA compliance validator
│       └── [other utilities]
│
├── data/                              # Data directory
│   ├── analyst-reported-anonymized.csv
│   ├── user-reported-anonymized.csv
│   ├── explorer-anonymized.csv
│   └── incidents-anonymized.csv
│
├── results/                           # Output directory
│   └── YYYYMMDD_HHMMSS/              # Timestamped runs
│       ├── verdicts_*.csv
│       ├── analyst_queue_*.csv
│       ├── audit_log_*.json
│       └── summary_*.json
│
├── config/                            # Configuration
│   ├── config.yaml                   # Main config
│   ├── prompts/                      # Ollama system prompts
│   └── defender_features.yaml        # Defender feature mappings
│
├── tests/                             # Test suite
├── docs/                              # Documentation
│   ├── SOP.md                        # Analyst SOP
│   ├── HIPAA_COMPLIANCE.md           # Compliance documentation
│   ├── DEFENDER_FEATURES.md          # Defender feature support
│   └── DEPLOYMENT.md                 # Deployment guide
│
└── README.md                          # This file
```

---

## Core Components

### 1. Ollama Client (`src/core/ollama_client.py`)
- Local LLM interface (HIPAA-compliant)
- System prompt based on analyst SOP
- Handles failures gracefully
- Configurable temperature and timeouts

### 2. MDO Field Extractor (`src/core/mdo_field_extractor.py`)
- Extracts 30+ Microsoft Defender email entity fields
- Parses authentication results (SPF/DKIM/DMARC)
- Analyzes URLs and attachments
- HIPAA-safe (body content excluded)

### 3. Ensemble Verdict Engine (`src/core/ensemble_verdict_engine.py`)
- Combines Ollama + Rules + Defender signals
- Configurable weights and thresholds
- Confidence-based action recommendations
- Comprehensive reasoning generation

### 4. Triage Orchestrator (`src/core/triage_orchestrator.py`)
- Main application entry point
- Batch processing with progress tracking
- Generates all outputs (verdicts, queue, audit logs)
- HIPAA-compliant audit trail

---

## Configuration

### Main Configuration (`config/config.yaml`)

```yaml
# Ollama LLM settings
ollama:
  model: "mistral:latest"
  base_url: "http://localhost:11434"
  temperature: 0.1
  timeout: 30

# Ensemble weights
ensemble:
  weights:
    ollama: 0.40
    rules: 0.30
    defender: 0.30

  thresholds:
    auto_block: 0.90
    malicious: 0.75
    suspicious: 0.40
    auto_resolve_clean: 0.10

# HIPAA compliance
hipaa:
  enforce: true
  audit_retention_days: 2190  # 6 years
  exclude_body: true

# Defender feature mappings
defender:
  features_config: "config/defender_features.yaml"
```

### Defender Features (`config/defender_features.yaml`)

```yaml
# Microsoft Defender email entity fields
# Reference: https://learn.microsoft.com/en-us/defender-office-365/mdo-email-entity-page

email_entity_fields:
  version: "2025-01"

  header_fields:
    - SenderFromAddress
    - SenderDisplayName
    - Subject
    - ReceivedDateTime
    - AuthenticationDetails

  threat_intelligence:
    - ThreatTypes
    - DetectionTechnologies
    - DeliveryAction
    - DeliveryLocation

  urls:
    - Urls[]
    - ClickedUrls[]

  attachments:
    - Attachments[]
    - FileType
    - SHA256

# Feature version tracking
feature_updates:
  - version: "2025-01"
    date: "2025-01-11"
    changes:
      - "Baseline implementation"

  # Future updates will be tracked here
  # - version: "2025-02"
  #   date: "2025-02-01"
  #   changes:
  #     - "Added new ThreatType: AIGenerated"
  #     - "New field: SenderReputation"
```

---

## HIPAA Compliance

### Data Minimization
- ✅ Email body content **EXCLUDED**
- ✅ Only metadata processed (subject, sender, headers)
- ✅ BodyPreview limited to 50 characters

### Local Processing
- ✅ All Ollama inference runs **locally** (no cloud calls)
- ✅ No data leaves network
- ✅ Models on encrypted storage

### Audit Logging
- ✅ Every decision logged with timestamp
- ✅ System version tracking
- ✅ Analyst overrides tracked
- ✅ 6-year retention

### Access Control
- Role-based access (analyst, admin, auditor)
- Audit log review procedures
- Change management process

---

## Extensibility for New Defender Features

### Adding New Email Entity Fields

1. **Update Defender feature config:**
```yaml
# config/defender_features.yaml
email_entity_fields:
  version: "2025-02"

  # Add new field
  ai_detection:
    - AIGeneratedContent
    - AIConfidenceScore
```

2. **Update MDO field extractor:**
```python
# src/core/mdo_field_extractor.py

def extract(self, email_entity):
    # ... existing code ...

    # Add new field extraction
    features["ai_generated"] = email_entity.get("AIGeneratedContent")
    features["ai_confidence"] = email_entity.get("AIConfidenceScore")

    return features
```

3. **Update ensemble engine (if needed):**
```python
# src/core/ensemble_verdict_engine.py

def _calculate_rule_based_score(self, features):
    # ... existing code ...

    # Add new rule
    if features.get("ai_generated"):
        risk_score += 15
        indicators.append("AI-generated content detected")

    return {"risk_score": risk_score, "indicators": indicators}
```

4. **Document the change:**
```yaml
# config/defender_features.yaml
feature_updates:
  - version: "2025-02"
    date: "2025-02-01"
    changes:
      - "Added AI-generated content detection"
      - "New fields: AIGeneratedContent, AIConfidenceScore"
```

5. **Test:**
```bash
python3 tests/test_new_features.py --feature ai_detection
```

---

## Usage Examples

### Example 1: Daily Triage
```bash
# Process overnight user reports
python3 src/core/triage_orchestrator.py \
    --input data/user-reported-$(date +%Y%m%d).csv \
    --output results/$(date +%Y%m%d_%H%M%S) \
    --config config/config.yaml
```

### Example 2: Batch Processing
```bash
# Process all user-reported emails
python3 src/core/triage_orchestrator.py \
    --input data/user-reported-anonymized.csv \
    --output results/batch_$(date +%Y%m%d) \
    --parallel
```

### Example 3: Fast Mode (No Ollama)
```bash
# Rules + Defender only (faster)
python3 src/core/triage_orchestrator.py \
    --input data/user-reported-anonymized.csv \
    --output results/fast_$(date +%Y%m%d) \
    --no-ollama
```

---

## Output Files

### 1. Verdicts CSV (`verdicts_*.csv`)
All emails with final verdicts, confidence scores, risk scores, and actions.

### 2. Analyst Queue CSV (`analyst_queue_*.csv`)
Emails requiring human review, sorted by priority (risk score descending).

### 3. Audit Log JSON (`audit_log_*.json`)
HIPAA-compliant audit trail with timestamps, decisions, and system metadata.

### 4. Summary JSON (`summary_*.json`)
Statistics: automation rate, verdict distribution, average confidence, processing time.

---

## Performance Metrics

### Targets
- **Automation Rate:** >70%
- **False Positive Rate:** <5%
- **False Negative Rate:** <2%
- **Average Latency:** <3 seconds per email
- **Analyst Time Saved:** >60%

### Monitoring
Track metrics in `summary_*.json` and compare across runs.

---

## Ollama Management

```bash
# Check status
ollama list

# Start Ollama
ollama serve

# Stop Ollama
killall ollama

# Pull model
ollama pull mistral:latest

# Test model
ollama run mistral "Analyze this subject: Urgent account verification"
```

---

## Development

### Adding Tests
```bash
# Add test to tests/
cp tests/test_template.py tests/test_new_feature.py

# Run tests
python3 -m pytest tests/
```

### Updating SOP Logic
Edit `src/core/ensemble_verdict_engine.py` → `_calculate_rule_based_score()`

### Updating Ollama Prompts
Edit system prompt in `config/prompts/analyst_sop_prompt.txt`

---

## Git Workflow

```bash
# Check status
git status

# Add changes
git add src/ config/ docs/

# Commit (HIPAA-compliant message)
git commit -m "feat: add support for Defender feature X

- Added X field extraction
- Updated ensemble scoring
- HIPAA compliance maintained
- Version: config/defender_features.yaml v2025-02"

# Push
git push
```

---

## Documentation

- **[SOP.md](docs/SOP.md)** - Analyst standard operating procedure
- **[HIPAA_COMPLIANCE.md](docs/HIPAA_COMPLIANCE.md)** - Compliance documentation
- **[DEFENDER_FEATURES.md](docs/DEFENDER_FEATURES.md)** - Supported Defender features
- **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Production deployment guide

---

## Support

**Issues:**
1. Check Ollama status: `ollama list`
2. Review configuration: `config/config.yaml`
3. Check logs: `results/latest/*.json`
4. Review documentation: `docs/`

---

## License

Internal use only - University Medical Campus

---

**Version:** 1.0 (Focused Defender Automation)
**Last Updated:** 2025-01-11
**HIPAA Compliant:** ✅ Yes
**Microsoft Defender:** Fully integrated
