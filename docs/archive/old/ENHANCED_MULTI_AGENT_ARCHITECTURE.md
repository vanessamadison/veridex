# Enhanced Multi-Agent Phishing Analyst

**Version:** 3.0 (Proposed)
**Date:** 2025-11-19
**Architecture:** Specialized Ollama-powered agents for comprehensive phishing analysis

---

## 🚨 Addressing Critical Gaps

### Gaps Identified

1. **Attachment Analysis:** Currently non-functional in standalone mode
2. **IP Reputation:** Not checking sender IP reputation
3. **URL Analysis:** Not checking URLhaus/PhishTank/VirusTotal
4. **Dataset Quality:** Testing on obvious spam, not subtle phishing
5. **Multi-Agent Reasoning:** Single LLM call, not specialized agents

---

## 🎯 Enhanced Architecture: 6 Specialized Agents

### Agent Orchestration Flow

```
Email Input (.eml file)
    ↓
┌───────────────────────────────────────────────────────────┐
│              ORCHESTRATOR AGENT (Ollama)                  │
│  Coordinates all agents, manages context, combines verdicts│
└───────────────────────────────────────────────────────────┘
    ↓
    ├─→ [Agent 1: Email Parser]
    ├─→ [Agent 2: Reputation Checker]
    ├─→ [Agent 3: Attachment Analyzer]
    ├─→ [Agent 4: Content Analyzer]
    ├─→ [Agent 5: Behavioral Analyst]
    └─→ [Agent 6: Verdict Synthesizer]
    ↓
Final Verdict + Confidence + Detailed Reasoning
```

---

## Agent 1: Email Parser Agent

**Purpose:** Extract and structure email metadata

**Tools:**
- RFC 822 email parser
- Header analyzer (SPF/DKIM/DMARC)
- URL extractor (including obfuscated URLs)
- Attachment metadata extractor
- Sender IP extractor

**Output:**
```json
{
  "sender": {
    "email": "support@paypal.com.phishing.evil",
    "display_name": "PayPal Support",
    "domain": "paypal.com.phishing.evil",
    "ip": "185.220.101.42"
  },
  "authentication": {
    "spf": "Fail",
    "dkim": "None",
    "dmarc": "None"
  },
  "urls": [
    {
      "original": "https://bit.ly/3xY9k2L",
      "expanded": "http://paypal-verify.xyz/login",
      "is_shortened": true,
      "domain_age_days": 3
    }
  ],
  "attachments": [
    {
      "filename": "invoice.pdf.exe",
      "declared_type": "application/pdf",
      "actual_type": "application/x-msdownload",
      "size": 245760,
      "sha256": "d2b4c5a..."
    }
  ]
}
```

**No changes needed - already functional**

---

## Agent 2: Reputation Checker Agent ⭐ NEW

**Purpose:** Check reputation of IPs, domains, URLs, file hashes

**Tools to Implement:**

### Tool 1: IP Reputation Checker
```python
# src/agents/tools/ip_reputation.py

import requests
from typing import Dict

def check_ip_reputation(ip: str) -> Dict:
    """
    Check IP reputation across multiple sources

    Free APIs:
    - AbuseIPDB (free 1,000 checks/day)
    - IPQualityScore (free tier)
    - IPVoid

    Returns:
    {
        "ip": "185.220.101.42",
        "is_malicious": true,
        "abuse_confidence": 95,
        "reports_count": 147,
        "country": "Russia",
        "asn": "AS12345",
        "is_vpn": true,
        "is_tor": false,
        "is_proxy": true,
        "last_seen": "2025-11-19",
        "categories": ["spam", "phishing", "bot"]
    }
    """
    results = {}

    # AbuseIPDB check
    abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
    if abuseipdb_key:
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']
            results['abuseipdb'] = {
                "abuse_confidence": data['abuseConfidenceScore'],
                "reports": data['totalReports'],
                "is_whitelisted": data['isWhitelisted'],
                "country": data['countryCode']
            }

    # IPQualityScore check (free tier)
    ipqs_key = os.getenv("IPQS_API_KEY", "")
    if ipqs_key:
        url = f"https://ipqualityscore.com/api/json/ip/{ipqs_key}/{ip}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            results['ipqs'] = {
                "fraud_score": data['fraud_score'],
                "is_vpn": data['vpn'],
                "is_tor": data['tor'],
                "is_proxy": data['proxy'],
                "recent_abuse": data['recent_abuse']
            }

    # Combine results
    return aggregate_ip_reputation(results)
```

### Tool 2: URL Reputation Checker
```python
# src/agents/tools/url_reputation.py

def check_url_reputation(url: str) -> Dict:
    """
    Check URL across threat intelligence feeds

    Free APIs:
    - URLhaus (HIPAA-safe, no URL submission)
    - PhishTank (free, 10k checks/day)
    - Google Safe Browsing (free)

    Returns:
    {
        "url": "http://paypal-verify.xyz/login",
        "is_malicious": true,
        "threat_types": ["phishing", "malware"],
        "first_seen": "2025-11-17",
        "last_seen": "2025-11-19",
        "confidence": 0.95,
        "sources": ["urlhaus", "phishtank"]
    }
    """
    results = {}

    # URLhaus check
    response = requests.post(
        "https://urlhaus-api.abuse.ch/v1/url/",
        data={"url": url},
        timeout=5
    )
    if response.status_code == 200:
        data = response.json()
        if data['query_status'] == 'ok':
            results['urlhaus'] = {
                "threat": data['threat'],
                "first_seen": data['date_added'],
                "tags": data['tags']
            }

    # PhishTank check
    # ... similar implementation

    return aggregate_url_reputation(results)
```

### Tool 3: File Hash Reputation
```python
# src/agents/tools/hash_reputation.py

def check_file_hash(sha256: str) -> Dict:
    """
    Check file hash against malware databases

    HIPAA-Safe: Only sends hash, not file content

    Free APIs:
    - VirusTotal (free 4 requests/min)
    - MalwareBazaar (free)
    - Hybrid Analysis (free tier)

    Returns:
    {
        "sha256": "d2b4c5a...",
        "is_malicious": true,
        "detections": 45,
        "total_engines": 70,
        "detection_ratio": 0.64,
        "malware_families": ["Emotet", "TrickBot"],
        "first_submission": "2025-11-15"
    }
    """
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not vt_key:
        return {"error": "No VirusTotal API key"}

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": vt_key}

    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200:
        data = response.json()['data']['attributes']
        return {
            "sha256": sha256,
            "is_malicious": data['last_analysis_stats']['malicious'] > 5,
            "detections": data['last_analysis_stats']['malicious'],
            "total_engines": sum(data['last_analysis_stats'].values()),
            "detection_ratio": data['last_analysis_stats']['malicious'] / sum(data['last_analysis_stats'].values()),
            "malware_families": list(data.get('popular_threat_classification', {}).get('suggested_threat_label', [])),
            "first_submission": data['first_submission_date']
        }

    return {"error": f"Hash not found: {sha256}"}
```

**Agent 2 Ollama Prompt:**
```
You are a Reputation Checker Agent specializing in threat intelligence.

Given email metadata, analyze:
1. Sender IP reputation (AbuseIPDB, IPQualityScore)
2. Domain reputation (age, SSL cert, WHOIS)
3. URL reputation (URLhaus, PhishTank, Safe Browsing)
4. File hash reputation (VirusTotal, MalwareBazaar)

For each indicator, provide:
- Risk score (0-100)
- Threat categories
- Confidence level
- Recommendation (block/review/allow)

Focus on:
- Recent abuse reports
- Tor/VPN/proxy usage
- Domain age < 30 days
- URL shorteners
- Known malware families

Return structured JSON with risk scores.
```

---

## Agent 3: Attachment Analyzer Agent ⭐ NEW

**Purpose:** Deeply analyze email attachments for malware

**Current Gap:** We only extract filename/hash. No actual analysis.

**Tools to Implement:**

### Tool 1: File Type Verification
```python
# src/agents/tools/file_analyzer.py

import magic
from typing import Dict

def verify_file_type(attachment_path: str, declared_type: str) -> Dict:
    """
    Detect actual file type vs declared MIME type

    Catches:
    - invoice.pdf.exe (declares PDF, actually executable)
    - document.docx (declares Word, actually ZIP with macros)

    Returns:
    {
        "declared_type": "application/pdf",
        "actual_type": "application/x-msdownload",
        "mismatch": true,
        "risk": "CRITICAL",
        "reason": "EXE disguised as PDF"
    }
    """
    mime = magic.Magic(mime=True)
    actual_type = mime.from_file(attachment_path)

    mismatch = (declared_type != actual_type)

    # High-risk file types
    dangerous_types = [
        'application/x-msdownload',  # .exe
        'application/x-dosexec',     # .exe
        'application/x-msi',         # .msi
        'application/vnd.ms-htmlhelp',  # .chm
        'application/x-javascript',  # .js
        'application/x-sh',          # shell script
        'application/x-perl'         # perl script
    ]

    risk = "CRITICAL" if actual_type in dangerous_types else "LOW"

    return {
        "declared_type": declared_type,
        "actual_type": actual_type,
        "mismatch": mismatch,
        "risk": risk,
        "reason": f"{actual_type.split('/')[-1].upper()} file" +
                 (f" disguised as {declared_type.split('/')[-1].upper()}" if mismatch else "")
    }
```

### Tool 2: Macro Detection
```python
def check_for_macros(attachment_path: str) -> Dict:
    """
    Detect VBA macros in Office documents

    Returns:
    {
        "has_macros": true,
        "macro_count": 3,
        "auto_execute": true,
        "suspicious_keywords": ["CreateObject", "Shell", "Powershell"],
        "risk": "HIGH"
    }
    """
    from oletools.olevba import VBA_Parser

    try:
        vba = VBA_Parser(attachment_path)
        if vba.detect_vba_macros():
            results = vba.analyze_macros()
            suspicious_keywords = [
                "CreateObject", "Shell", "Powershell", "WScript",
                "cmd.exe", "URLDownloadToFile", "Eval"
            ]

            found_keywords = []
            for kw, desc in results:
                if kw in suspicious_keywords:
                    found_keywords.append(kw)

            return {
                "has_macros": True,
                "suspicious_keywords": found_keywords,
                "risk": "HIGH" if found_keywords else "MEDIUM"
            }
    except Exception as e:
        return {"error": str(e)}

    return {"has_macros": False, "risk": "LOW"}
```

### Tool 3: YARA Rules Scanner
```python
def scan_with_yara(attachment_path: str) -> Dict:
    """
    Scan file with YARA rules for malware signatures

    Rules detect:
    - Emotet, TrickBot, Dridex, Qakbot
    - Ransomware (Ryuk, Conti, LockBit)
    - RATs (Cobalt Strike, Metasploit)

    Returns:
    {
        "matches": ["emotet_loader", "powershell_downloader"],
        "risk": "CRITICAL",
        "malware_family": "Emotet"
    }
    """
    import yara

    # Load YARA rules from rules/ directory
    rules = yara.compile(filepath='rules/malware.yar')
    matches = rules.match(attachment_path)

    if matches:
        return {
            "matches": [m.rule for m in matches],
            "risk": "CRITICAL",
            "malware_family": matches[0].meta.get('family', 'Unknown')
        }

    return {"matches": [], "risk": "LOW"}
```

**Agent 3 Ollama Prompt:**
```
You are an Attachment Analyzer Agent specializing in malware detection.

Given attachment metadata and scan results:
1. File type verification results
2. Macro detection results
3. YARA rule matches
4. File hash reputation (from Agent 2)

Analyze for:
- File type mismatches (exe as pdf)
- Dangerous file extensions (.exe, .scr, .js, .vbs)
- Macro-enabled documents with auto-execute
- Known malware signatures (YARA matches)
- Suspicious filenames (invoice.pdf.exe, urgent_payment.docx.js)

Provide:
- Risk assessment (CRITICAL/HIGH/MEDIUM/LOW)
- Detailed explanation
- IOCs (Indicators of Compromise)
- Remediation advice

Return structured analysis with evidence.
```

---

## Agent 4: Content Analyzer Agent

**Purpose:** Analyze email body for social engineering tactics

**Tools:**
- NLP sentiment analysis
- Urgency keyword detection
- Brand impersonation detection
- Grammatical analysis (poor grammar = phishing indicator)

**Agent 4 Ollama Prompt:**
```
You are a Content Analyzer Agent specializing in social engineering detection.

Analyze email subject + body (first 500 chars) for:

1. Urgency/Fear tactics:
   - "Account suspended", "Verify immediately", "Expires in 24 hours"
   - Threats of consequences
   - Time-limited offers

2. Authority impersonation:
   - Claims to be from IT, HR, CEO, bank
   - Uses official-sounding language
   - Requests sensitive information

3. Brand impersonation:
   - PayPal, Microsoft, Amazon, IRS
   - Logo/branding mentions
   - "Click here to verify account"

4. Grammar/spelling errors:
   - Poor English (non-native speaker)
   - Inconsistent capitalization
   - Generic greetings ("Dear Customer")

5. Suspicious requests:
   - Password/credential requests
   - Payment/wire transfer
   - Download attachment urgently

Rate each category 0-10 and provide overall social engineering score.
```

---

## Agent 5: Behavioral Analyst Agent ⭐ NEW

**Purpose:** Detect anomalous sender behavior patterns

**Tools:**

### Tool 1: Sender History Checker
```python
def analyze_sender_history(sender_email: str, db_connection) -> Dict:
    """
    Check if sender has sent similar emails before

    Detects:
    - First-time sender (no history)
    - Sudden change in behavior (CEO now sends password resets?)
    - Unusual send time (3am local time)
    - High volume (100+ emails in 1 hour)

    Returns:
    {
        "is_first_time_sender": true,
        "previous_emails_count": 0,
        "avg_emails_per_day": 0,
        "usual_send_times": [],
        "current_send_time": "03:14 AM",
        "anomaly_score": 0.85
    }
    """
    pass
```

### Tool 2: Domain Age Checker
```python
def check_domain_age(domain: str) -> Dict:
    """
    Check WHOIS for domain age

    Phishing domains are typically < 30 days old

    Returns:
    {
        "domain": "paypal-verify.xyz",
        "age_days": 3,
        "created_date": "2025-11-16",
        "registrar": "Namecheap",
        "privacy_protected": true,
        "risk": "CRITICAL"
    }
    """
    import whois

    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        age_days = (datetime.now() - created).days

        return {
            "domain": domain,
            "age_days": age_days,
            "created_date": created.strftime("%Y-%m-%d"),
            "registrar": w.registrar,
            "privacy_protected": w.name is None,
            "risk": "CRITICAL" if age_days < 30 else "LOW"
        }
    except Exception as e:
        return {"error": str(e)}
```

**Agent 5 Ollama Prompt:**
```
You are a Behavioral Analyst Agent detecting anomalies.

Analyze sender behavior:
1. Is this first-time sender to this recipient?
2. Domain age (new domains = high risk)
3. Sender IP geolocation vs claimed organization
4. Email send time (unusual hours?)
5. Volume anomalies (spam burst?)

Look for:
- Brand-new domain (<30 days)
- First email from "CEO" (account compromise)
- Sending from unexpected country (PayPal email from Russia)
- High volume in short time

Provide behavioral risk score 0-1.
```

---

## Agent 6: Verdict Synthesizer Agent

**Purpose:** Combine all agent outputs into final verdict

**Input:** Outputs from Agents 1-5
**Output:** Final verdict with detailed reasoning

**Agent 6 Ollama Prompt:**
```
You are the Verdict Synthesizer Agent making final phishing determinations.

You receive reports from 5 specialized agents:
1. Email Parser: SPF/DKIM/DMARC, headers, URLs, attachments
2. Reputation Checker: IP/URL/hash reputation scores
3. Attachment Analyzer: Malware detection, file analysis
4. Content Analyzer: Social engineering tactics score
5. Behavioral Analyst: Sender behavior anomalies

Combine evidence using weighted scoring:
- CRITICAL attachment (malware detected): Auto-verdict MALICIOUS
- High IP reputation risk (>80) + auth failures: MALICIOUS
- Multiple red flags (3+): SUSPICIOUS
- Social engineering (>7/10) + new domain (<30 days): MALICIOUS
- Auth passes + known sender + no threats: CLEAN

Provide:
1. Final verdict: MALICIOUS / SUSPICIOUS / CLEAN
2. Confidence: 0.0 - 1.0
3. Primary risk factors (top 3)
4. Detailed reasoning (2-3 sentences)
5. Recommended action (quarantine/review/allow)

Be conservative: When in doubt, flag for review (SUSPICIOUS).
```

---

## 🔧 Implementation Plan

### Phase 1: Add Reputation Checking (Week 1)

**Files to create:**
```
src/agents/
├── tools/
│   ├── ip_reputation.py       # AbuseIPDB + IPQualityScore
│   ├── url_reputation.py      # URLhaus + PhishTank
│   ├── hash_reputation.py     # VirusTotal
│   └── domain_age.py          # WHOIS checker
└── reputation_agent.py        # Agent 2 orchestrator
```

**API Keys needed (all have free tiers):**
```bash
# .env
ABUSEIPDB_API_KEY=your_key      # Free 1,000/day
IPQS_API_KEY=your_key           # Free tier
VIRUSTOTAL_API_KEY=your_key    # Free 4/min
```

**Test:**
```python
python -m src.agents.reputation_agent \
  --ip 185.220.101.42 \
  --url http://paypal-verify.xyz/login \
  --hash d2b4c5a...
```

---

### Phase 2: Add Attachment Analysis (Week 2)

**Files to create:**
```
src/agents/
└── attachment_agent.py         # Agent 3

src/agents/tools/
├── file_analyzer.py            # File type verification
├── macro_detector.py           # OLE tools for macros
└── yara_scanner.py             # YARA malware signatures

rules/
└── malware.yar                 # YARA rules (Emotet, Ryuk, etc.)
```

**Dependencies:**
```bash
pip install python-magic oletools yara-python
```

**Test:**
```python
python -m src.agents.attachment_agent \
  --file data/test_attachments/invoice.pdf.exe
```

---

### Phase 3: Multi-Agent Orchestrator (Week 3)

**File to create:**
```
src/agents/orchestrator.py      # Coordinates all 6 agents
```

**Architecture:**
```python
class PhishingOrchestratorAgent:
    def __init__(self):
        self.agents = {
            'parser': EmailParserAgent(),
            'reputation': ReputationCheckerAgent(),
            'attachment': AttachmentAnalyzerAgent(),
            'content': ContentAnalyzerAgent(),
            'behavioral': BehavioralAnalystAgent(),
            'synthesizer': VerdictSynthesizerAgent()
        }

    def analyze_email(self, email_path: str) -> Dict:
        # Step 1: Parse email
        parsed = self.agents['parser'].parse(email_path)

        # Step 2: Run parallel agents
        with ThreadPoolExecutor(max_workers=3) as executor:
            reputation_future = executor.submit(
                self.agents['reputation'].check, parsed
            )
            attachment_future = executor.submit(
                self.agents['attachment'].analyze, parsed['attachments']
            )
            content_future = executor.submit(
                self.agents['content'].analyze, parsed['body']
            )

        reputation = reputation_future.result()
        attachment = attachment_future.result()
        content = content_future.result()

        # Step 3: Behavioral analysis (needs reputation data)
        behavioral = self.agents['behavioral'].analyze(
            parsed, reputation
        )

        # Step 4: Synthesize verdict
        verdict = self.agents['synthesizer'].synthesize({
            'parsed': parsed,
            'reputation': reputation,
            'attachment': attachment,
            'content': content,
            'behavioral': behavioral
        })

        return verdict
```

---

### Phase 4: Enhanced UI with Reputation Data (Week 4)

**Dashboard email preview should show:**

```
┌─────────────────────────────────────────────────────┐
│  INC-100010  ×  [STICKY TOP BAR]                    │
├─────────────────────────────────────────────────────┤
│  From: support@paypal-verify.xyz                    │
│  Subject: Your account has been suspended           │
│                                                      │
│  🔴 Sender IP: 185.220.101.42                       │
│     ├─ Country: Russia 🇷🇺                          │
│     ├─ ASN: AS12345 (Hosting Provider)              │
│     ├─ Abuse Score: 95/100 (147 reports) ⚠️         │
│     ├─ Proxy: Yes | VPN: Yes | Tor: No              │
│     └─ Recommendation: BLOCK                         │
│                                                      │
│  🔴 Domain: paypal-verify.xyz                       │
│     ├─ Age: 3 days (Created 2025-11-16) ⚠️          │
│     ├─ Registrar: Namecheap                         │
│     └─ WHOIS Privacy: Enabled                       │
│                                                      │
│  🔴 URL: http://paypal-verify.xyz/login             │
│     ├─ PhishTank: Confirmed phishing ⚠️             │
│     ├─ URLhaus: Malware distribution                │
│     ├─ First Seen: 2025-11-17                       │
│     └─ Threat: Credential harvesting                │
│                                                      │
│  🔴 Attachment: invoice.pdf.exe (240 KB)            │
│     ├─ Declared: application/pdf                    │
│     ├─ Actual: application/x-msdownload ⚠️          │
│     ├─ VirusTotal: 45/70 engines (64% detection)    │
│     ├─ Malware Family: Emotet                       │
│     └─ YARA Match: emotet_loader ⚠️                 │
│                                                      │
│  📊 Risk Breakdown:                                  │
│     Authentication: FAIL (SPF/DKIM/DMARC all fail)  │
│     Reputation: CRITICAL (IP + URL + Hash malicious)│
│     Attachment: CRITICAL (Malware detected)         │
│     Content: HIGH (Urgency + impersonation)         │
│     Behavioral: HIGH (New domain + first sender)    │
│                                                      │
│  🎯 Verdict: MALICIOUS (Confidence: 0.98)           │
│     Primary Risks:                                   │
│     1. Malware-laden attachment (Emotet)            │
│     2. Malicious sender IP (95 abuse score)         │
│     3. Phishing URL (confirmed by PhishTank)        │
│                                                      │
│  💡 Recommendation: QUARANTINE + Block sender IP    │
└─────────────────────────────────────────────────────┘
```

**UI Improvements:**
1. ✅ Sticky top bar with close button + INC number
2. ✅ Auto-close side panel when switching tabs
3. ✅ Expandable sections for reputation data
4. ✅ Visual risk indicators (🔴🟡🟢)
5. ✅ Actionable recommendations

---

## 📊 Better Datasets for Testing

### Problem with Current Datasets

**SpamAssassin (2005):**
- ❌ Obvious spam ("Get Rich Quick")
- ❌ No modern evasion techniques
- ❌ Primitive URL schemes
- ❌ No targeted social engineering

**What we need:**

### Dataset 1: APWG Phishing Dataset
**Source:** Anti-Phishing Working Group
**URL:** https://apwg.org/trendsreports/

**Contains:**
- Modern phishing attacks (2020-2025)
- Sophisticated social engineering
- Brand impersonation (Microsoft, PayPal, banks)
- Compromised legitimate accounts (passes SPF/DKIM)

### Dataset 2: PhishTank Verified Phishing
**Source:** PhishTank database
**URL:** https://www.phishtank.com/developer_info.php

**Download:**
```bash
wget http://data.phishtank.com/data/online-valid.json
```

**Contains:**
- User-verified phishing URLs
- Constantly updated (daily)
- Subtle attacks (not obvious)

### Dataset 3: Enron + Synthetic Phishing
**Approach:** Inject realistic phishing into Enron corpus

**Process:**
```python
# Take legitimate Enron emails
# Modify to create subtle phishing:
# - Change 1 character in URL (microsoft.com → micr0soft.com)
# - Add urgency to subject
# - Keep everything else legitimate

# Result: Hard-to-detect phishing that SHOULD challenge the system
```

### Dataset 4: EMBER Malware Dataset
**Source:** Endgame EMBER (malware binaries)
**URL:** https://github.com/elastic/ember

**Contains:**
- 1.1M malware samples
- PE file hashes for VirusTotal lookup
- Test attachment analysis

---

## 🚀 Using Ollama to Power the Agent

### Ollama Multi-Agent Architecture

**Run 6 specialized Ollama instances:**

```python
# src/agents/ollama_agents.py

from ollama import Client

class OllamaAgentPool:
    def __init__(self):
        self.client = Client(host='http://localhost:11434')

        # Load specialized models
        self.models = {
            'reputation': 'mistral:7b-instruct',      # Fast, good at structured tasks
            'attachment': 'llama3:8b',                # Better reasoning
            'content': 'mistral:7b-instruct',         # NLP analysis
            'behavioral': 'mistral:7b-instruct',      # Pattern detection
            'synthesizer': 'llama3:8b'                # Final reasoning
        }

    def run_agent(self, agent_name: str, prompt: str, context: Dict) -> Dict:
        """Run specialized Ollama agent"""
        model = self.models[agent_name]

        # Build prompt with context
        full_prompt = f"""
{prompt}

Context:
{json.dumps(context, indent=2)}

Provide your analysis as JSON.
"""

        response = self.client.generate(
            model=model,
            prompt=full_prompt,
            format='json',
            options={
                'temperature': 0.1,  # Low temp for deterministic results
                'top_p': 0.9,
                'num_predict': 500
            }
        )

        return json.loads(response['response'])
```

**Usage:**
```python
# Analyze email with multi-agent system
agent_pool = OllamaAgentPool()

# Agent 2: Reputation Check
reputation_prompt = """
You are a Reputation Checker Agent.
Analyze the IP, URL, and domain reputation data.
Return JSON with risk scores.
"""

reputation_result = agent_pool.run_agent(
    'reputation',
    reputation_prompt,
    {
        'ip_data': ip_reputation,
        'url_data': url_reputation,
        'domain_data': domain_age
    }
)

# Agent 3: Attachment Analysis
attachment_prompt = """
You are an Attachment Analyzer Agent.
Analyze the file type verification, macro detection, and YARA results.
Return JSON with malware assessment.
"""

attachment_result = agent_pool.run_agent(
    'attachment',
    attachment_prompt,
    {
        'file_type': file_verification,
        'macros': macro_detection,
        'yara': yara_matches,
        'virustotal': hash_reputation
    }
)

# ... continue for all agents

# Agent 6: Synthesize
final_verdict = agent_pool.run_agent(
    'synthesizer',
    synthesizer_prompt,
    {
        'reputation': reputation_result,
        'attachment': attachment_result,
        'content': content_result,
        'behavioral': behavioral_result
    }
)
```

---

## 📈 Expected Performance Improvements

| Metric | Current (Rules Only) | Enhanced (Multi-Agent) |
|--------|---------------------|------------------------|
| **Attachment Detection** | 0% (not analyzed) | 90%+ (YARA + VT) |
| **Subtle Phishing** | 70% (obvious only) | 95%+ (multi-factor) |
| **False Positives** | 0% (too conservative) | <2% (better precision) |
| **IP Reputation** | Not checked | 98% (AbuseIPDB) |
| **URL Phishing** | Basic regex | 99% (PhishTank verified) |
| **Overall F1 Score** | 91.74% | **97%+ (estimated)** |

---

## 🎯 Next Steps

1. **Week 1:** Implement reputation checking tools
2. **Week 2:** Add attachment analysis (YARA, macros, file type)
3. **Week 3:** Build multi-agent orchestrator
4. **Week 4:** Update dashboard UI with reputation data
5. **Week 5:** Test on APWG/PhishTank datasets
6. **Week 6:** Fine-tune ensemble weights based on results

---

**This addresses ALL gaps:**
- ✅ Attachment analysis (YARA, VirusTotal, macro detection)
- ✅ IP reputation (AbuseIPDB, IPQualityScore)
- ✅ URL reputation (URLhaus, PhishTank)
- ✅ Better datasets (APWG, PhishTank verified)
- ✅ Multi-agent architecture (6 specialized Ollama agents)
- ✅ Enhanced UI (sticky headers, reputation data in previews)

**Version:** 3.0 (Proposed)
**Date:** 2025-11-19
