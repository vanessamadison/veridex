# Integration Guide
## Connecting Phishing Analyst to Your Existing Systems

**Last Updated:** December 1, 2025

---

## Overview

This tool can integrate with your existing security stack in **three ways**:

1. **Standalone validation** - Test accuracy on your own emails (works offline)
2. **API integration** - Real-time verdict calls from other systems
3. **Data pipeline** - Batch process Defender exports for analysis

---

## Option 1: Standalone Validation (Easiest - Works Now)

**Use case:** Test the tool on your own email dataset before committing to integration.

### Step 1: Export Your Emails

**From Microsoft Defender:**
```
1. Security Center → Incidents
2. Filter: User-reported emails
3. Export → Download as .eml files
```

**From Outlook:**
```
1. Select email
2. File → Save As → .eml format
```

### Step 2: Organize Emails

```bash
# Create directories
mkdir -p my_test_data/spam
mkdir -p my_test_data/ham

# Move emails based on what they really are
mv phishing*.eml my_test_data/spam/
mv legitimate*.eml my_test_data/ham/
```

### Step 3: Create Labels

```bash
python scripts/create_ground_truth.py \
  --spam-dir my_test_data/spam \
  --ham-dir my_test_data/ham \
  --output my_test_data/ground_truth.csv
```

### Step 4: Run Validation

```bash
# Rules-only (fast, no Ollama needed)
python standalone_triage.py \
  --dataset my_test_data \
  --ground-truth my_test_data/ground_truth.csv \
  --no-llm \
  --output results/my_test.json

# View results
cat results/my_test.json | jq '.metrics'
```

**Expected output:**
```json
{
  "precision": 0.95,
  "recall": 0.88,
  "f1_score": 0.91
}
```

**Decision point:** If F1 score > 0.85, consider API integration.

---

## Option 2: Microsoft Defender Integration (Production)

### A. Manual Process (Simplest)

**How it works:**
```
1. Export user-reported emails from Defender (daily CSV)
2. Run batch triage: python standalone_triage.py --dataset exports/today
3. Review high-confidence verdicts in output CSV
4. Manually update Defender (mark as phish/clean)
```

**Pros:** No API setup, works immediately
**Cons:** Manual, not real-time

### B. API Integration (Automated)

**Prerequisites:**
- Azure App Registration with SecurityEvents.Read.All permission
- Client ID, Tenant ID, Client Secret

**Step 1: Fetch User-Reported Emails**

```python
# Use Microsoft Graph API
import requests

# Get access token
token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
token_data = {
    "client_id": client_id,
    "client_secret": client_secret,
    "scope": "https://graph.microsoft.com/.default",
    "grant_type": "client_credentials"
}
token_response = requests.post(token_url, data=token_data)
access_token = token_response.json()["access_token"]

# Fetch user submissions
api_url = "https://graph.microsoft.com/v1.0/security/threatSubmission/emailThreats"
headers = {"Authorization": f"Bearer {access_token}"}
response = requests.get(api_url, headers=headers)
submissions = response.json()["value"]

# For each submission, call your triage API
for submission in submissions:
    verdict = requests.post("http://localhost:8000/triage/single", json={
        "email_id": submission["id"],
        "subject": submission["subject"],
        "sender_address": submission["sender"],
        # ... other fields
    })

    # If high confidence, submit verdict back to Defender
    if verdict["confidence"] > 0.90:
        requests.post(
            "https://graph.microsoft.com/v1.0/security/threatSubmission/emailThreatSubmission",
            headers=headers,
            json={
                "category": "spam" if verdict["verdict"] == "MALICIOUS" else "notJunk",
                "recipientEmailAddress": submission["recipient"],
                "subject": submission["subject"]
            }
        )
```

**Step 2: Schedule Daily Sync**

```bash
# Add to cron (run daily at 2 AM)
0 2 * * * /path/to/sync_defender.sh
```

**Automation rate:** Expect 60-70% of emails to get auto-resolved (confidence > 0.75)

---

## Option 3: SIEM Integration (Logging & Alerting)

### Splunk Integration

**Forward verdicts to Splunk via Syslog (CEF format):**

```python
# Add to your verdict processing
import syslog

def send_to_splunk(verdict):
    cef_message = f"CEF:0|PhishingAnalyst|Triage|2.0|VERDICT|{verdict['verdict']}|{severity}|" \
                  f"src={verdict['sender_ip']} dst={verdict['recipient']} " \
                  f"msg={verdict['subject']} confidence={verdict['confidence']}"

    syslog.openlog("PhishingAnalyst", syslog.LOG_PID, syslog.LOG_LOCAL0)
    syslog.syslog(syslog.LOG_INFO, cef_message)
```

**Splunk search:**
```
index=security sourcetype=syslog source=PhishingAnalyst
| eval verdict=case(confidence>0.75, "AUTO_BLOCK", confidence>0.40, "REVIEW", 1=1, "CLEAN")
| stats count by verdict, src, dst
```

### Microsoft Sentinel Integration

**Forward to Sentinel Log Analytics workspace:**

```python
import requests
import hmac
import hashlib
import base64
from datetime import datetime

def send_to_sentinel(verdict, workspace_id, shared_key):
    # Build JSON body
    body = [{
        "TimeGenerated": datetime.utcnow().isoformat(),
        "EmailSender": verdict["sender_address"],
        "Subject": verdict["subject"],
        "Verdict": verdict["verdict"],
        "Confidence": verdict["confidence"],
        "RiskScore": verdict["risk_score"]
    }]

    # Build signature
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

    string_to_hash = f"{method}\n{len(json.dumps(body))}\n{content_type}\nx-ms-date:{date}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()

    authorization = f"SharedKey {workspace_id}:{encoded_hash}"

    # POST to Sentinel
    url = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    headers = {
        "Content-Type": content_type,
        "Authorization": authorization,
        "Log-Type": "PhishingTriage",  # Creates PhishingTriage_CL table
        "x-ms-date": date
    }

    response = requests.post(url, headers=headers, json=body)
    return response.status_code == 200
```

**Sentinel KQL query:**
```kql
PhishingTriage_CL
| where Verdict_s == "MALICIOUS" and Confidence_d > 0.75
| summarize count() by EmailSender_s, bin(TimeGenerated, 1h)
| where count_ > 5  // Alert if same sender > 5 malicious emails per hour
```

---

## Option 4: Email Gateway Integration (Proofpoint, Mimecast)

### Webhook Approach

**How it works:**
```
1. Gateway receives user-reported email
2. Gateway calls: POST http://your-server:8000/triage/single
3. Tool returns verdict within 0.3 seconds
4. Gateway auto-quarantines if verdict = MALICIOUS
```

**Proofpoint example:**

```python
# Configure webhook in Proofpoint console
# URL: https://your-server.com/api/proofpoint-webhook
# Method: POST

@app.post("/api/proofpoint-webhook")
async def proofpoint_webhook(data: dict):
    # Extract email metadata from Proofpoint format
    email_metadata = {
        "email_id": data["messageID"],
        "subject": data["subject"],
        "sender_address": data["sender"],
        "spf_result": data.get("spf", "None"),
        "dkim_result": data.get("dkim", "None"),
        # ... other fields
    }

    # Get verdict
    verdict = triage_email(email_metadata)

    # Return action to Proofpoint
    if verdict["confidence"] > 0.90 and verdict["verdict"] == "MALICIOUS":
        return {
            "action": "quarantine",
            "reason": verdict["reasoning"]
        }
    else:
        return {
            "action": "deliver",
            "tag": f"PhishingAnalyst: {verdict['verdict']} ({verdict['confidence']:.2f})"
        }
```

---

## Option 5: Ticketing System Integration (ServiceNow, Jira)

### Auto-Create Tickets for Analyst Review

**ServiceNow example:**

```python
import requests

def create_servicenow_ticket(verdict):
    """Create ticket for emails requiring analyst review (confidence < 0.75)"""

    if verdict["confidence"] >= 0.75:
        return  # High confidence, no ticket needed

    # ServiceNow API
    url = "https://your-instance.service-now.com/api/now/table/incident"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Basic {base64_credentials}"
    }

    data = {
        "short_description": f"Phishing Review: {verdict['subject'][:100]}",
        "description": f"""
Automated triage requires analyst review.

Email ID: {verdict['email_id']}
Sender: {verdict['sender_address']}
Subject: {verdict['subject']}

AI Verdict: {verdict['verdict']}
Confidence: {verdict['confidence']:.2f}
Risk Score: {verdict['risk_score']}

Reasoning:
{verdict['reasoning']}

Primary Indicators:
{', '.join(verdict['primary_indicators'])}
        """,
        "urgency": "3" if verdict["verdict"] == "SUSPICIOUS" else "4",
        "category": "Security",
        "subcategory": "Phishing",
        "assignment_group": "SOC Tier 1"
    }

    response = requests.post(url, headers=headers, json=data)
    return response.json()["result"]["number"]  # Returns INC0012345
```

**Bidirectional sync:**
```python
# When analyst closes ticket with verdict
@app.post("/api/servicenow-callback")
async def servicenow_callback(data: dict):
    ticket_number = data["number"]
    analyst_verdict = data["resolution_code"]  # "Phishing" or "Not Phishing"

    # Update your database
    update_verdict(
        email_id=data["u_email_id"],
        verdict="MALICIOUS" if analyst_verdict == "Phishing" else "CLEAN",
        source="analyst_override"
    )

    # Future ML model can learn from these overrides
```

---

## Testing Your Integration

### 1. Health Check

```bash
curl http://localhost:8000/health
```

**Expected:**
```json
{
  "status": "healthy",
  "components": {
    "api": "running",
    "ollama": "available",
    "authentication": "enabled"
  }
}
```

### 2. Test Single Email Triage

```bash
curl -X POST http://localhost:8000/triage/single \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email_id": "test123",
    "subject": "URGENT: Verify your account",
    "sender_address": "support@paypa1.com",
    "sender_domain": "paypa1.com",
    "received_datetime": "2025-12-01T10:00:00Z",
    "spf_result": "Fail",
    "dkim_result": "Fail",
    "url_count": 1
  }'
```

**Expected:**
```json
{
  "verdict": "MALICIOUS",
  "action": "analyst_review",
  "confidence": 0.85,
  "risk_score": 75,
  "reasoning": "SPF failure, DKIM failure, suspicious domain (typosquatting)",
  "processing_time": 0.3
}
```

### 3. Batch Processing Test

```bash
# Process 100 emails from CSV
curl -X POST "http://localhost:8000/triage/batch?csv_path=data/test_100_emails.csv&max_emails=100" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Expected:**
```json
{
  "total_processed": 100,
  "verdicts": {
    "MALICIOUS": 25,
    "SUSPICIOUS": 30,
    "CLEAN": 45
  },
  "automation_rate": 0.70,
  "average_confidence": 0.82
}
```

---

## Performance Expectations

| Integration Type | Latency | Throughput | Accuracy |
|------------------|---------|------------|----------|
| **Standalone validation** | N/A (batch) | 140 emails/sec | F1: 91.74% |
| **API (rules-only)** | 0.05 seconds | 20 req/sec | F1: ~90% |
| **API (with Ollama)** | 0.3 seconds | 3 req/sec | F1: ~93% |
| **Defender sync (daily)** | N/A (scheduled) | 1,000+ emails/day | F1: 91.74% |

**Bottleneck:** Ollama LLM (0.3 sec/email). For high volume, use rules-only mode or deploy multiple Ollama instances.

---

## Security Considerations

### Current State (Research/Internal Use)

**Safe for:**
- ✅ Synthetic/test data
- ✅ Internal network access only
- ✅ SOC analyst training

**NOT safe for:**
- ❌ Production PHI without HTTPS
- ❌ Internet-facing deployment
- ❌ Multi-tenant access without encryption

### Production Deployment Checklist

Before integrating with live systems:
- [ ] Enable HTTPS/TLS (see SECURITY_GAPS_AND_ENCRYPTION.md for details)
- [ ] Restrict to SOC subnet (firewall rules)
- [ ] Implement rate limiting (10 req/sec default)
- [ ] Add monitoring (Prometheus + Grafana)
- [ ] Conduct penetration test
- [ ] Document incident response plan

---

## Quick Start: Integration in 30 Minutes

**For Defender users:**

```bash
# 1. Export emails from Defender (manual)
# Save to: defender_exports/today/

# 2. Run batch triage
python standalone_triage.py \
  --dataset defender_exports/today \
  --ground-truth defender_exports/today/labels.csv \
  --no-llm \
  --output results/defender_$(date +%Y%m%d).json

# 3. Review results
cat results/defender_$(date +%Y%m%d).json | jq '.metrics'

# 4. Check high-confidence verdicts
cat results/defender_$(date +%Y%m%d).csv | grep ",MALICIOUS," | grep "confidence.*0.9"

# 5. Manually update Defender with verdicts
```

**Done!** You've integrated the tool without writing any code.

---

## Support

**Questions about integration?**
- Check: SYSTEM_ARCHITECTURE.md (technical details)
- Check: HOW_TO_USE.md (usage examples)
- Check: RESEARCH_PAPER_UPDATE.md (performance expectations)

**API documentation:**
- OpenAPI/Swagger: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

**Bottom line:** This tool is designed to **augment** your existing security stack, not replace it. Start with standalone validation, then integrate incrementally.
