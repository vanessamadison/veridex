# Attachment Analysis Documentation

**Version:** 1.0
**Last Updated:** 2025-11-19
**Purpose:** Document how email attachments are analyzed for threats

---

## Executive Summary

The phishing analyst system currently **does NOT perform independent attachment detonation**. Instead, it relies on **Microsoft Defender for Office 365 attachment analysis** that is included in the email metadata.

This document:
1. Clarifies how attachment analysis currently works
2. Documents Microsoft Defender's attachment detection capabilities
3. Proposes future enhancements for independent sandboxing
4. Outlines considerations for local attachment detonation

---

## Current Implementation

### Attachment Metadata Extraction

**File:** `src/core/mdo_field_extractor.py:164-188`

```python
# === ATTACHMENTS ===
attachments_raw = email_entity.get("Attachments") or email_entity.get("attachments") or []

if isinstance(attachments_raw, str):
    import json
    try:
        attachments_raw = json.loads(attachments_raw)
    except:
        attachments_raw = []

features["attachments"] = self._parse_attachments(attachments_raw)
features["attachment_count"] = len(features["attachments"])
features["has_attachments"] = features["attachment_count"] > 0

# Risky file types
risky_extensions = [".exe", ".zip", ".rar", ".js", ".vbs", ".html", ".htm", ".bat", ".cmd", ".scr"]
features["has_risky_attachment"] = any(
    any(att.get("filename", "").lower().endswith(ext) for ext in risky_extensions)
    for att in features["attachments"]
)

features["malicious_attachment_count"] = sum(
    1 for att in features["attachments"]
    if len(att.get("threat_names", [])) > 0
)
```

### What This Does

1. **Extracts attachment metadata** from Defender email entity:
   - Filename
   - File type/extension
   - File hash (SHA256)
   - **Threat names** (populated by Defender)
   - Threat verdict (Clean, Suspicious, Malicious)

2. **Classifies risky file types** based on extension:
   - Executable: `.exe`, `.bat`, `.cmd`, `.scr`
   - Scripts: `.js`, `.vbs`
   - Archives: `.zip`, `.rar`
   - HTML: `.html`, `.htm`

3. **Counts malicious attachments** based on Defender's threat names

### What This Does NOT Do

❌ **Download attachments** - Files are never retrieved
❌ **Execute attachments** - No sandboxing or detonation
❌ **Scan files locally** - No antivirus scanning
❌ **Perform static analysis** - No PE parsing, string extraction, etc.
❌ **Detonate in sandbox** - No behavioral analysis

---

## Microsoft Defender Attachment Analysis

The system **relies entirely on Microsoft Defender's attachment analysis**, which includes:

### Defender Safe Attachments

**Technology:** Microsoft Defender for Office 365 Safe Attachments
**Documentation:** https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-about

#### How Defender Analyzes Attachments

1. **Static Analysis**
   - File hash lookup against known malware database
   - File type validation
   - Embedded macro detection

2. **Sandboxing (Detonation)**
   - Executes attachments in isolated virtual environment
   - Monitors for malicious behavior:
     - File system modifications
     - Registry changes
     - Network connections
     - Process creation
     - DLL injection

3. **Machine Learning**
   - Heuristic analysis of file characteristics
   - Pattern matching against known malware families
   - Behavioral anomaly detection

4. **Verdict Generation**
   - **Clean:** No threats detected
   - **Suspicious:** Potentially unwanted program (PUP)
   - **Malicious:** Confirmed malware/threat

### Detection Technologies

**From MDO Email Entity:**

| Detection Tech | Description | Example |
|----------------|-------------|---------|
| **File detonation** | Sandbox execution | Opens .docx in VM, detects macro payload |
| **File reputation** | Hash lookup | SHA256 matches known malware DB |
| **Fingerprint matching** | Signature detection | Matches malware family patterns |
| **Anti-malware engines** | Traditional AV | ClamAV, Windows Defender signatures |

**Example Defender Metadata:**

```json
{
  "Attachments": [
    {
      "FileName": "invoice_2024.docx",
      "FileType": "docx",
      "SHA256": "abc123...",
      "ThreatNames": ["Trojan:W97M/Emotet"],  # <-- From Defender
      "ThreatVerdict": "Malicious",             # <-- From Defender
      "DetectionTechnologies": ["File detonation", "File reputation"]
    }
  ]
}
```

### Defender's Coverage

**Strengths:**
- ✅ Cloud-scale threat intelligence (billions of signals)
- ✅ Zero-day detection via sandboxing
- ✅ Macro-enabled document analysis
- ✅ Archive scanning (zip, rar)
- ✅ URL extraction from documents
- ✅ Integrated with Microsoft ecosystem

**Limitations:**
- ⚠️ Requires Microsoft 365 E5 or Defender for Office 365 Plan 1/2 license
- ⚠️ Sandboxing can be bypassed by time bombs, VM detection
- ⚠️ Limited visibility into sandbox behavior details
- ⚠️ Cannot customize sandbox environment
- ⚠️ No support for analyzing email attachments offline

---

## Rule-Based Attachment Scoring

**File:** `src/core/ensemble_verdict_engine.py:205-213`

The ensemble engine applies rules based on attachment metadata:

```python
# === ATTACHMENT ANALYSIS ===
if features.get("malicious_attachment_count", 0) > 0:
    risk_score += 30
    indicators.append(f"{features['malicious_attachment_count']} malicious attachments")

if features.get("has_risky_attachment", False):
    risk_score += 15
    indicators.append("Risky attachment type (exe, zip, js, html)")
```

### Scoring Logic

| Condition | Risk Score | Indicator |
|-----------|-----------|-----------|
| Malicious attachment (per Defender) | +30 | "N malicious attachments" |
| Risky file type (.exe, .zip, .js, etc.) | +15 | "Risky attachment type" |
| External sender + attachment | +10 | "External sender with attachment" |

### Why This Works

- **Malicious attachments** are flagged by Defender's sandboxing (high confidence)
- **Risky file types** are inherently suspicious (exe, js, vbs)
- **External + attachment** combination is common phishing vector

---

## LLM Attachment Analysis

**File:** `src/core/ollama_client.py:172-182`

The Ollama LLM receives attachment metadata in its prompt:

```python
# Attachment analysis
attachments = email_features.get('attachments', [])
if attachments:
    prompt_parts.append("=== ATTACHMENT ANALYSIS ===")
    prompt_parts.append(f"Total Attachments: {len(attachments)}")
    for i, att in enumerate(attachments, 1):
        prompt_parts.append(
            f"  {i}. {att.get('filename', 'N/A')} "
            f"(Type: {att.get('file_type', 'N/A')}, "
            f"Threats: {', '.join(att.get('threat_names', [])) or 'None'})"
        )
```

### LLM Reasoning

The LLM considers:
1. **Filename plausibility** - Does "invoice_2024.docx" match subject?
2. **File type appropriateness** - Why is exe attached to "password reset" email?
3. **Threat context** - Defender flagged Emotet, high risk
4. **Sender context** - External sender + exe = very suspicious

**Example LLM Analysis:**

```
Subject: "Your Invoice - Payment Due"
Sender: accounts@external-vendor.com
Attachment: invoice_2024.exe (Threats: Trojan:Win32/Generic)

LLM Reasoning:
- Invoice emails should have PDF attachments, not EXE
- External sender with executable is extremely suspicious
- Defender detected Trojan, confirms malicious intent
- Verdict: MALICIOUS, Confidence: 0.95, Action: auto_block
```

---

## Current Limitations and Inconsistencies

### Issue 1: No Independent Verification

**Problem:** System cannot verify Defender's verdicts
- If Defender misses a threat (false negative), system misses it too
- Cannot perform additional analysis beyond Defender's capabilities

**Example Scenario:**
```
Email with password-protected zip (malware.zip)
Defender verdict: Clean (cannot scan encrypted archive)
System verdict: Clean (trusts Defender)
Actual: Malicious (contains ransomware)
```

### Issue 2: Lack of Transparency on Detonation Process

**Problem:** Documentation says "attachment detonation" but doesn't clarify it's Defender's
- Users may think system performs independent sandboxing
- No visibility into Defender's sandbox behavior
- Cannot explain *why* Defender flagged attachment

**Example:**
```
Email: "Q4 Budget Review.docx"
Defender: ThreatNames: ["Trojan:O97M/Suspicious"]
Question: What behavior triggered this verdict?
Answer: Unknown (Defender black box)
```

### Issue 3: Inconsistent Attachment Processing

**Problem:** Some emails may not have Defender attachment analysis
- Emails from synthetic generators don't have real attachment detonation
- Testing requires mocking Defender verdicts
- Cannot test against real malware samples safely

### Issue 4: No Offline Capability

**Problem:** System requires Defender metadata
- Cannot analyze emails independently
- Cannot work in air-gapped environments
- Cannot process historical emails without Defender re-analysis

---

## Future Enhancements: Independent Attachment Analysis

### Option 1: Local Sandboxing Integration

**Proposed Solution:** Integrate open-source sandboxing tools

#### Candidate Technologies

| Tool | Type | Strengths | Limitations |
|------|------|-----------|-------------|
| **Cuckoo Sandbox** | Full sandbox | Open source, mature, Windows support | Resource-intensive, setup complexity |
| **CAPE Sandbox** | Malware sandbox | Cuckoo fork, better malware unpacking | Requires VMs, high CPU/RAM |
| **FileType Analyzer** | Static analysis | Fast, safe (no execution) | Misses runtime behavior |
| **YARA** | Pattern matching | Fast, customizable rules | Requires rule maintenance |
| **ClamAV** | Antivirus | Open source, fast | Lower detection rate than commercial AV |

#### Proposed Architecture

```
Attachment Processing Pipeline:

1. Extract attachment from email (if available)
   ↓
2. Calculate file hash (SHA256)
   ↓
3. Hash lookup (local cache + VirusTotal API)
   ├─ Known malicious → Flag immediately
   ├─ Known clean → Skip detonation
   └─ Unknown → Proceed to analysis
   ↓
4. Static analysis
   ├─ File type validation
   ├─ YARA rule scanning
   ├─ Macro detection (Office docs)
   └─ String extraction (URLs, IPs, suspicious patterns)
   ↓
5. Dynamic analysis (if suspicious)
   ├─ Submit to Cuckoo sandbox
   ├─ Monitor execution (60s timeout)
   ├─ Extract indicators (network, file, registry, process)
   └─ Generate verdict
   ↓
6. Combine with Defender verdict
   ↓
7. Update ensemble score
```

**Implementation File:** `src/analysis/attachment_analyzer.py` (to be created)

```python
class AttachmentAnalyzer:
    """
    Independent attachment analysis using local sandboxing
    """

    def __init__(
        self,
        cuckoo_api_url: str = "http://localhost:8090",
        virustotal_api_key: Optional[str] = None,
        yara_rules_path: str = "config/yara_rules/",
        cache_dir: str = "data/hash_cache/"
    ):
        """Initialize attachment analyzer"""

    def analyze_attachment(
        self,
        attachment: Dict[str, Any],
        email_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze single attachment

        Args:
            attachment: Attachment metadata + content
            email_context: Email features for contextual analysis

        Returns:
            {
                "verdict": "Clean" | "Suspicious" | "Malicious",
                "confidence": float,
                "threat_names": List[str],
                "static_analysis": {...},
                "dynamic_analysis": {...} or None,
                "indicators": List[str]
            }
        """

    def static_analysis(self, file_path: str, file_type: str) -> Dict:
        """
        Perform static analysis

        - File type validation
        - YARA scanning
        - String extraction
        - Entropy calculation
        - PE parsing (if exe)
        - Office macro detection (if docx/xlsx)
        """

    def dynamic_analysis(self, file_path: str, timeout: int = 60) -> Dict:
        """
        Submit to Cuckoo sandbox for detonation

        Returns behavioral indicators:
        - Network connections
        - File system changes
        - Registry modifications
        - Process tree
        - Screenshots
        """

    def virustotal_lookup(self, file_hash: str) -> Dict:
        """
        Query VirusTotal for file reputation

        Returns:
        - Detection ratio (e.g., 45/70 engines flagged)
        - Threat names from multiple AVs
        - First/last seen dates
        """
```

### Option 2: Cloud Sandbox Integration

**Proposed Solution:** Integrate third-party cloud sandboxing APIs

#### Candidate Services

| Service | API | Strengths | Cost |
|---------|-----|-----------|------|
| **VirusTotal** | REST API | 70+ AV engines, large DB | Free tier limited, $500+/mo |
| **Hybrid Analysis** | REST API | Falcon sandbox, detailed reports | Free tier available |
| **Joe Sandbox Cloud** | REST API | Advanced detonation, good reports | $1000+/mo |
| **Any.Run** | REST API | Interactive sandbox, fast | $90+/mo |

**Pros:**
- ✅ No infrastructure to maintain
- ✅ Professional-grade sandboxing
- ✅ Multi-engine detection (VirusTotal)
- ✅ Fast results (typically <5 min)

**Cons:**
- ❌ Costs money (potentially high volume)
- ❌ Data leaves on-premise (HIPAA concerns)
- ❌ API rate limits
- ❌ Dependency on third-party uptime

### Option 3: Hybrid Approach

**Recommended Solution:** Combine multiple methods

```
Attachment Analysis Decision Tree:

1. Check Defender verdict
   ├─ Malicious → Trust Defender, flag immediately
   ├─ Clean → Proceed to step 2
   └─ Unknown → Proceed to step 2

2. Static analysis (YARA, file type)
   ├─ High-risk file type (exe, vbs, js) → Proceed to step 3
   ├─ Suspicious patterns → Proceed to step 3
   └─ Clean → Flag as Clean

3. Hash lookup (local cache + VirusTotal)
   ├─ Known malicious → Flag immediately
   ├─ Known clean → Flag as Clean
   └─ Unknown → Proceed to step 4

4. Sandbox detonation (Cuckoo or cloud API)
   ├─ Malicious behavior → Flag as Malicious
   ├─ Suspicious behavior → Flag as Suspicious
   └─ Clean → Flag as Clean

5. Ensemble verdict
   - Combine Defender verdict (30%)
   - Static analysis score (20%)
   - Sandbox verdict (50%)
   - Generate final verdict
```

---

## Implementation Recommendations

### Phase 1: Documentation and Transparency (Current)

✅ **Completed in this document:**
- Clarify that system relies on Defender attachment analysis
- Document Defender's capabilities and limitations
- Identify gaps in current implementation

### Phase 2: Enhanced Metadata Utilization (Week 1)

**Goal:** Better leverage existing Defender metadata

Tasks:
- [ ] Parse detection technologies to understand *why* Defender flagged attachment
- [ ] Extract behavioral indicators from Defender (if available in API)
- [ ] Improve logging of attachment verdicts for audit trail
- [ ] Add attachment-specific reasoning in LLM prompts

### Phase 3: Static Analysis Integration (Week 2-3)

**Goal:** Add lightweight local analysis

Tasks:
- [ ] Integrate YARA rule scanning
- [ ] Implement file type validation (magic bytes, not just extension)
- [ ] Add entropy calculation (packed executables have high entropy)
- [ ] Extract strings from executables (URLs, IPs, suspicious keywords)
- [ ] Scan Office documents for macros

**Tools:**
- `python-magic` for file type detection
- `yara-python` for YARA scanning
- `oletools` for Office document analysis
- `pefile` for PE executable parsing

### Phase 4: Hash Reputation (Week 3-4)

**Goal:** Leverage threat intelligence databases

Tasks:
- [ ] Implement local hash cache (known good/bad files)
- [ ] Integrate VirusTotal API (hash lookup only, no file upload for HIPAA)
- [ ] Integrate AlienVault OTX for threat intelligence
- [ ] Create hash allowlist for known-safe files (Adobe, Microsoft, etc.)

### Phase 5: Sandbox Integration (Future - Week 8+)

**Goal:** Independent detonation capability

Tasks:
- [ ] Deploy Cuckoo Sandbox (VM infrastructure)
- [ ] Implement Cuckoo API client
- [ ] Create attachment submission queue
- [ ] Parse sandbox reports for behavioral indicators
- [ ] Combine sandbox verdict with Defender verdict

**Infrastructure Requirements:**
- Hypervisor (KVM, VirtualBox, VMware)
- Windows/Linux VMs for detonation
- Network isolation (sandbox VMs should not access production)
- Storage for sandbox reports (~1GB per report)

---

## Security and Compliance Considerations

### HIPAA Compliance

**Issue:** Uploading attachments to third-party sandboxes may violate HIPAA
- Attachments may contain PHI (patient records, insurance info)
- Data processed by third-party violates Business Associate Agreement (BAA) if no BAA signed

**Solutions:**
1. **Use only hash lookups** - Never upload full file
2. **Local sandboxing only** - Keep all detonation on-premise
3. **BAA with cloud sandbox** - Ensure vendor is HIPAA-compliant (expensive)
4. **Strip PHI before analysis** - Redact sensitive data (complex, error-prone)

### Safe Handling of Malware

**Best Practices:**
1. **Isolated network** - Sandbox VMs should not access production network
2. **No internet access** - Prevent malware from communicating with C2
3. **Disk snapshots** - Revert VMs after each detonation
4. **Access controls** - Only authorized personnel can access malware samples
5. **Encrypted storage** - Store malware samples encrypted at rest
6. **Audit logging** - Log every malware analysis event

---

## Success Metrics

After implementing enhanced attachment analysis:

1. ✅ **Independent verification** - Can validate Defender verdicts
2. ✅ **Zero-day detection** - Behavioral analysis catches unknown malware
3. ✅ **Explainability** - Know *why* attachment was flagged
4. ✅ **Offline capability** - Can analyze emails without live Defender connection
5. ✅ **Research support** - Can test against real malware datasets
6. ✅ **Compliance** - HIPAA-safe attachment handling

---

## Conclusion

### Current State

The phishing analyst system:
- ✅ Extracts attachment metadata from Defender
- ✅ Classifies risky file types
- ✅ Uses Defender threat names in verdicts
- ❌ Does NOT perform independent sandboxing
- ❌ Does NOT detonate attachments locally

### Recommended Path Forward

**Short-term (1-2 weeks):**
1. Document current reliance on Defender (this document)
2. Enhance metadata extraction and logging
3. Implement static analysis (YARA, file type, entropy)

**Medium-term (3-4 weeks):**
1. Integrate hash reputation (VirusTotal API, local cache)
2. Improve LLM reasoning with attachment context
3. Add attachment-specific metrics to evaluation framework

**Long-term (2-3 months):**
1. Deploy local Cuckoo sandbox (if resources allow)
2. Implement hybrid analysis (Defender + static + sandbox)
3. Research HIPAA-compliant cloud sandbox options

---

**Document Version:** 1.0
**Status:** Current State Documented - Enhancements Proposed
**Compliance Review:** Pending (HIPAA, security)
**Next Steps:** Implement Phase 2 (Enhanced Metadata Utilization)
