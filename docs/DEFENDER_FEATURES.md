# Microsoft Defender for Office 365 - Feature Support

**Comprehensive guide to supported Defender email entity fields and how to add new features**

---

## Overview

This system extracts and analyzes 30+ Microsoft Defender for Office 365 (MDO) email entity fields. All field definitions are maintained in `config/defender_features.yaml` for easy updates when Microsoft adds new features.

**Reference:** https://learn.microsoft.com/en-us/defender-office-365/mdo-email-entity-page

---

## Currently Supported Fields

### Header Information (13 fields)
| Field | Description | Used in Analysis |
|-------|-------------|------------------|
| SenderFromAddress | Sender email address | ✅ Yes |
| SenderFromDomain | Sender domain | ✅ Yes |
| SenderDisplayName | Display name | ✅ Yes |
| SenderIPv4 | Sender IP address | ✅ Yes |
| ReturnPath | Email return path | ✅ Yes (spoofing detection) |
| ReplyTo | Reply-To address | ✅ Yes (spoofing detection) |
| Subject | Email subject line | ✅ Yes |
| InternetMessageId | Message ID | ℹ️  Tracking only |
| NetworkMessageId | Network message ID | ℹ️  Tracking only |
| Recipients | To recipients | ℹ️  Context only |
| RecipientsCc | CC recipients | ℹ️  Context only |
| RecipientsBcc | BCC recipients | ℹ️  Context only |
| ReceivedDateTime | When received | ✅ Yes (SLA tracking) |

### Authentication Results (3 fields)
| Field | Description | Used in Analysis |
|-------|-------------|------------------|
| SPF | SPF authentication result | ✅ Yes (high weight) |
| DKIM | DKIM authentication result | ✅ Yes (high weight) |
| DMARC | DMARC authentication result | ✅ Yes (high weight) |

### Threat Intelligence (5 fields)
| Field | Description | Used in Analysis |
|-------|-------------|------------------|
| ThreatTypes | Array of detected threats | ✅ Yes (defender signals) |
| DetectionTechnologies | How threats were detected | ✅ Yes |
| DeliveryAction | Delivered/Blocked/Quarantined | ✅ Yes |
| DeliveryLocation | Inbox/Junk/Quarantine | ✅ Yes |
| OriginalDeliveryLocation | Original destination | ℹ️  Context only |

### URLs (4 fields)
| Field | Description | Used in Analysis |
|-------|-------------|------------------|
| Urls | Array of URL objects | ✅ Yes |
| Urls[].Url | URL string | ✅ Yes |
| Urls[].ThreatVerdict | Malicious/Suspicious/Clean | ✅ Yes (high weight) |
| Urls[].ClickCount | Number of clicks | ✅ Yes |

### Attachments (4 fields)
| Field | Description | Used in Analysis |
|-------|-------------|------------------|
| Attachments | Array of attachment objects | ✅ Yes |
| Attachments[].FileName | File name | ✅ Yes |
| Attachments[].FileType | File extension | ✅ Yes (risky types) |
| Attachments[].SHA256 | File hash | ✅ Yes (reputation) |
| Attachments[].ThreatNames | Detected threats | ✅ Yes (high weight) |

### Content Signals (2 fields - HIPAA-safe)
| Field | Description | Used in Analysis |
|-------|-------------|------------------|
| Language | Email language | ℹ️  Context only |
| Directionality | Inbound/Outbound/Intra-org | ✅ Yes |

### User Reporting (4 fields)
| Field | Description | Used in Analysis |
|-------|-------------|------------------|
| IsUserReported | User reported as suspicious | ✅ Yes |
| UserReportClassification | User's classification | ℹ️  Context only |
| AnalystComments | Previous analyst notes | ℹ️  Context only |
| ReportedDateTime | When reported | ✅ Yes (SLA tracking) |

---

## How Features Are Used

### High-Weight Features (Critical for Verdicts)

**Authentication Failures:**
- SPF Fail: +15 risk score
- DKIM Fail/None: +10 risk score
- DMARC Fail/None: +10 risk score

**Threat Intelligence:**
- Malicious URL: +25 risk score
- Malicious Attachment: +30 risk score
- Defender ThreatTypes: 0-100 risk score

**Spoofing Indicators:**
- Return-Path mismatch: +10 risk score
- Reply-To mismatch: +8 risk score

### Medium-Weight Features

**Content Analysis:**
- Shortened URLs: +12 risk score
- Risky file types: +15 risk score
- External sender: +5 risk score
- Urgency keywords: +10 risk score

### Low-Weight Features (Context)

- User reported: +12 risk score
- Directionality: Context for other rules

---

## Adding New Defender Features

### Example: Microsoft Adds "AIGeneratedContent" Field

**Step 1: Update Feature Config**

Edit `config/defender_features.yaml`:

```yaml
email_entity_fields:
  version: "2025-02"  # Increment version

  # Add new category
  ai_detection:
    - AIGeneratedContent      # Boolean
    - AIConfidenceScore       # 0.0-1.0
    - AIModel                 # Which model detected it

feature_updates:
  - version: "2025-02"
    date: "2025-02-01"
    changes:
      - "Added AI-generated content detection"
      - "New fields: AIGeneratedContent, AIConfidenceScore, AIModel"
      - "Risk scoring: AI-generated + external sender = +20"
```

**Step 2: Update MDO Field Extractor**

Edit `src/core/mdo_field_extractor.py`:

```python
def extract(self, email_entity: Dict[str, Any]) -> Dict[str, Any]:
    features = {}

    # ... existing code ...

    # === AI DETECTION (NEW) ===
    features["ai_generated"] = email_entity.get("AIGeneratedContent") or False
    features["ai_confidence"] = email_entity.get("AIConfidenceScore") or 0.0
    features["ai_model"] = email_entity.get("AIModel")

    # Derived feature
    features["ai_external_combo"] = (
        features["ai_generated"] and features["is_external"]
    )

    return features
```

**Step 3: Update Ensemble Scoring (Optional)**

Edit `src/core/ensemble_verdict_engine.py`:

```python
def _calculate_rule_based_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
    risk_score = 0.0
    indicators = []

    # ... existing rules ...

    # === AI-GENERATED CONTENT (NEW) ===
    if features.get("ai_generated", False):
        risk_score += 15
        indicators.append(
            f"AI-generated content detected "
            f"(confidence: {features.get('ai_confidence', 0):.2f})"
        )

        # Higher risk if external + AI-generated
        if features.get("ai_external_combo", False):
            risk_score += 20
            indicators.append("External AI-generated email (high risk)")

    return {"risk_score": risk_score, "indicators": indicators}
```

**Step 4: Test**

Create test case in `tests/test_new_features.py`:

```python
def test_ai_detection():
    """Test AI-generated content detection"""

    # Test email with AI detection
    email_with_ai = {
        "SenderFromAddress": "external@example.com",
        "AIGeneratedContent": True,
        "AIConfidenceScore": 0.95,
        "AIModel": "GPT4-Phishing-Detector"
    }

    extractor = MDOFieldExtractor()
    features = extractor.extract(email_with_ai)

    assert features["ai_generated"] == True
    assert features["ai_confidence"] == 0.95
    assert features["ai_external_combo"] == True

    # Test ensemble scoring
    engine = EnsembleVerdictEngine(...)
    result = engine._calculate_rule_based_score(features)

    # Should have AI-related risk
    assert result["risk_score"] >= 35  # 15 + 20
    assert any("AI-generated" in ind for ind in result["indicators"])
```

Run test:
```bash
python3 -m pytest tests/test_new_features.py::test_ai_detection -v
```

**Step 5: Document**

Update `docs/DEFENDER_FEATURES.md` (this file):

```markdown
### AI Detection (3 fields) - NEW in v2025-02
| Field | Description | Used in Analysis |
|-------|-------------|------------------|
| AIGeneratedContent | Boolean, AI-generated | ✅ Yes |
| AIConfidenceScore | Confidence 0.0-1.0 | ✅ Yes |
| AIModel | Detection model name | ℹ️  Context only |
```

**Step 6: Deploy**

```bash
# Test on sample data
python3 src/core/triage_orchestrator.py \
    --input data/test_ai_detection.csv \
    --output results/test_ai_$(date +%Y%m%d)

# Review results
cat results/test_ai_*/summary_*.json

# If successful, deploy to production
git add config/ src/ docs/ tests/
git commit -m "feat: add AI-generated content detection

- Added AIGeneratedContent, AIConfidenceScore, AIModel fields
- Updated risk scoring for AI + external combination
- Tested with sample data
- Version: config/defender_features.yaml v2025-02"
```

---

## Feature Version History

### v2025-01 (2025-01-11) - Baseline

**Initial Implementation:**
- All standard MDO email entity fields
- Authentication analysis (SPF/DKIM/DMARC)
- URL and attachment threat detection
- User reporting context
- HIPAA-compliant metadata-only processing

**Fields Added:** 30+
**Risk Scoring Rules:** 12
**Ensemble Components:** 3 (Ollama, Rules, Defender)

### v2025-02 (Future) - Example

**Planned Additions:**
- AI-generated content detection
- Sender reputation scoring
- Enhanced URL analysis

---

## Field Extraction Pipeline

```
1. Email Entity (from Defender API or CSV)
   ↓
2. MDOFieldExtractor.extract()
   ↓
3. Normalized Feature Dictionary (30+ fields)
   ↓
4. Derived Features (e.g., auth_passed, external_with_urgency)
   ↓
5. Ensemble Verdict Engine
   ├── Ollama Analysis (uses features as context)
   ├── Rule-Based Scoring (explicit rules on features)
   └── Defender Signals (ThreatTypes, DeliveryAction)
   ↓
6. Final Verdict
```

---

## Feature Request Process

### Requesting a New Feature

1. **Identify Need:**
   - New Defender field available
   - Improved detection opportunity
   - Analyst feedback

2. **Document:**
   - Field name and type
   - When/how it's populated
   - Use case for triage

3. **Submit Request:**
   - Create GitHub issue (if using GitHub)
   - Or: Email IT security team
   - Include: Field name, use case, priority

4. **Review:**
   - Feasibility assessment
   - HIPAA impact review
   - Priority assignment

5. **Implementation:**
   - Follow steps above
   - Test thoroughly
   - Document changes

---

## Microsoft Defender Feature Roadmap

**Known Upcoming Features** (as of 2025-01):
- AI-generated content detection
- Enhanced sender reputation
- Behavioral analysis signals
- Campaign correlation IDs
- User risk scoring

**Stay Updated:**
- Microsoft 365 Admin Center → Message Center
- Microsoft Defender blog
- Email security updates mailing list

---

## Questions?

**Feature Support:**
- Check `config/defender_features.yaml` for current version
- Review this document for usage examples
- Test new features with sample data before production

**Contact:**
- IT Security Team
- System Administrator
- HIPAA Compliance Officer

---

**Document Version:** 1.0
**Last Updated:** 2025-01-11
**Defender Features Version:** 2025-01
**Next Review:** Monthly (when Microsoft updates MDO)
