# Third-Party Security Integrations Research

**Version:** 1.0
**Last Updated:** 2025-11-19
**Purpose:** Research and design third-party threat intelligence integrations

---

## Overview

To enhance the phishing analyst system's detection capabilities, this document researches integrations with established third-party threat intelligence platforms:

1. **VirusTotal** - Multi-engine malware and URL scanning
2. **Cisco Talos** - Threat intelligence and IP/domain reputation
3. **AlienVault OTX** - Open Threat Exchange community intelligence
4. **URLhaus** - Malware distribution URL database
5. **PhishTank** - Community-driven phishing URL database
6. **Abuse.ch** - Malware tracking (URLhaus, ThreatFox)
7. **Shodan** - Internet-wide device and service scanning

---

## Integration Categories

### 1. URL Reputation Services

Verify if URLs in emails are malicious, phishing, or spam

### 2. IP Reputation Services

Check sender IP addresses against known malicious sources

### 3. Domain Reputation Services

Validate sender domains and detect typosquatting

### 4. File Hash Reputation Services

Lookup attachment file hashes against malware databases

### 5. Threat Intelligence Feeds

Real-time threat data from security researchers

---

## Detailed Service Research

### 1. VirusTotal

**Website:** https://www.virustotal.com
**Type:** Multi-engine malware, URL, IP, domain scanning
**Provider:** Google (Chronicle Security)

#### Capabilities

| Feature | Description | API Endpoint |
|---------|-------------|--------------|
| **File Scanning** | Submit files to 70+ AV engines | POST /files |
| **Hash Lookup** | Check file hash reputation | GET /files/{hash} |
| **URL Scanning** | Check URL against 90+ scanners | POST /urls |
| **URL Lookup** | Check URL reputation | GET /urls/{url_id} |
| **IP Lookup** | IP address reputation and ASN info | GET /ip_addresses/{ip} |
| **Domain Lookup** | Domain reputation, WHOIS, DNS | GET /domains/{domain} |
| **Comments** | Community comments on threats | GET /comments |
| **Graphs** | Relationship graphs (domain → IPs) | GET /graphs |

#### Pricing

| Plan | Cost | Limits | Best For |
|------|------|--------|----------|
| **Free (Public API)** | $0 | 4 requests/min, 500/day | Testing, low volume |
| **Premium API** | $500+/month | Custom rate limits | Medium volume |
| **Enterprise** | Custom | Unlimited, priority support | High volume, SOC |

#### API Example: URL Lookup

```python
import requests
import hashlib
import base64

VT_API_KEY = "your_api_key_here"
VT_API_URL = "https://www.virustotal.com/api/v3"

def check_url_virustotal(url: str) -> dict:
    """
    Check URL reputation on VirusTotal

    Args:
        url: URL to check

    Returns:
        {
            "malicious": int,  # Number of engines flagging as malicious
            "suspicious": int,
            "clean": int,
            "undetected": int,
            "total_engines": int,
            "verdict": "malicious" | "suspicious" | "clean",
            "threat_names": List[str],
            "last_analysis_date": str
        }
    """
    # URL ID is base64-encoded URL without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(
        f"{VT_API_URL}/urls/{url_id}",
        headers=headers
    )

    if response.status_code == 404:
        # URL not in VT database, submit for scanning
        scan_response = requests.post(
            f"{VT_API_URL}/urls",
            headers=headers,
            data={"url": url}
        )
        return {"verdict": "unknown", "total_engines": 0}

    data = response.json()["data"]["attributes"]
    stats = data["last_analysis_stats"]

    verdict = "clean"
    if stats["malicious"] > 3:  # More than 3 engines flag it
        verdict = "malicious"
    elif stats["malicious"] > 0 or stats["suspicious"] > 0:
        verdict = "suspicious"

    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "clean": stats["harmless"],
        "undetected": stats["undetected"],
        "total_engines": sum(stats.values()),
        "verdict": verdict,
        "threat_names": [
            engine_name for engine_name, result in data["last_analysis_results"].items()
            if result["category"] == "malicious"
        ],
        "last_analysis_date": data["last_analysis_date"]
    }
```

#### API Example: IP Reputation

```python
def check_ip_virustotal(ip: str) -> dict:
    """Check IP address reputation on VirusTotal"""
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(
        f"{VT_API_URL}/ip_addresses/{ip}",
        headers=headers
    )

    if response.status_code == 404:
        return {"verdict": "unknown", "reputation": 0}

    data = response.json()["data"]["attributes"]

    return {
        "reputation": data.get("reputation", 0),  # -100 to +100 score
        "as_owner": data.get("as_owner"),
        "country": data.get("country"),
        "malicious_votes": data["total_votes"].get("malicious", 0),
        "harmless_votes": data["total_votes"].get("harmless", 0),
        "verdict": "malicious" if data.get("reputation", 0) < -50 else "clean"
    }
```

#### Integration with Ensemble Engine

```python
# Add to ensemble_verdict_engine.py

def _enhance_url_scoring_with_virustotal(self, features: Dict) -> Dict:
    """Enhance URL scoring with VirusTotal reputation"""
    for url in features.get("urls", []):
        vt_result = check_url_virustotal(url["url"])

        if vt_result["verdict"] == "malicious":
            url["virustotal_malicious_count"] = vt_result["malicious"]
            features["malicious_url_count"] += 1
        elif vt_result["verdict"] == "suspicious":
            features["suspicious_url_count"] += 1

    return features
```

#### HIPAA Considerations

- ✅ **Hash lookups are safe** - No PHI sent (just SHA256 hash)
- ⚠️ **URL submissions may leak data** - URLs could contain patient IDs
- ⚠️ **File uploads violate HIPAA** - Attachments may contain PHI
- ⚠️ **No BAA available** - VirusTotal does not sign Business Associate Agreements

**Recommendation:** Use ONLY for hash and IP lookups, NOT for file/URL submission

---

### 2. Cisco Talos Intelligence

**Website:** https://talosintelligence.com
**Type:** IP/domain reputation, threat intelligence
**Provider:** Cisco

#### Capabilities

| Feature | Description | Access |
|---------|-------------|--------|
| **IP Reputation** | Sender IP reputation lookup | Web API, free |
| **Domain Reputation** | Domain age, category, reputation | Web API, free |
| **Threat Intelligence** | Malware families, vulnerabilities | Blog, reports |
| **SNORT Rules** | IDS/IPS signatures | Free download |
| **File Reputation** | Malware hash database (AMP) | Commercial only |

#### Pricing

- **Free Web API:** IP/domain reputation lookups (limited)
- **Cisco AMP:** Advanced Malware Protection ($$ commercial)
- **Threat Grid:** Malware sandboxing ($$$ commercial)

#### API Example: IP Reputation

```python
def check_ip_talos(ip: str) -> dict:
    """
    Check IP reputation on Cisco Talos

    Note: Talos does not have official public API
    This uses web scraping (not recommended for production)

    Alternative: Use Talos Threat Intelligence feeds (requires license)
    """
    # Talos IP reputation page
    url = f"https://talosintelligence.com/reputation_center/lookup?search={ip}"

    # Web scraping approach (fragile, use with caution)
    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})

    # Parse HTML to extract reputation score
    # This is illustrative; real implementation needs HTML parsing

    # Better approach: Integrate Talos threat feeds (requires license)
    # Or use Umbrella Investigate API (Cisco commercial product)

    return {
        "verdict": "unknown",  # Placeholder
        "reputation": "neutral",
        "categories": [],
        "note": "Talos integration requires commercial API or threat feed subscription"
    }
```

#### Recommended Integration Path

**Option 1: Cisco Umbrella Investigate API** (commercial)
- Full IP/domain/URL reputation
- Requires Umbrella license ($$$)

**Option 2: Talos Threat Feeds** (free with registration)
- IP reputation lists (CSV format)
- Updated daily
- No API, manual import required

**Option 3: SNORT Integration**
- Run SNORT IDS locally
- Use Talos rules for network traffic analysis
- Not directly applicable to email metadata

#### Integration with Ensemble Engine

```python
# Add to ensemble_verdict_engine.py

def _calculate_ip_reputation_score(self, features: Dict) -> int:
    """Calculate risk score based on sender IP reputation"""
    sender_ip = features.get("sender_ip")

    if not sender_ip:
        return 0

    # Check IP against Talos threat feed (local CSV cache)
    talos_verdict = check_ip_in_talos_feed(sender_ip)

    if talos_verdict == "malicious":
        return 25  # High risk
    elif talos_verdict == "suspicious":
        return 15
    else:
        return 0
```

---

### 3. AlienVault OTX (Open Threat Exchange)

**Website:** https://otx.alienvault.com
**Type:** Community threat intelligence platform
**Provider:** AT&T Cybersecurity (AlienVault)

#### Capabilities

| Feature | Description | API Endpoint |
|---------|-------------|--------------|
| **Pulse Subscriptions** | Subscribe to threat intelligence feeds | GET /pulses/subscribed |
| **Indicator Lookup** | Check IP/domain/hash/URL reputation | GET /indicators/{type}/{indicator} |
| **Domain Reputation** | WHOIS, DNS, geo, reputation | GET /indicators/domain/{domain} |
| **IP Reputation** | Geolocation, reputation, malware | GET /indicators/IPv4/{ip} |
| **URL Reputation** | URL categorization and threat data | GET /indicators/url/{url} |
| **File Hash Lookup** | Malware analysis, family, AV results | GET /indicators/file/{hash} |

#### Pricing

- **Free:** Full API access with registration
- **Rate Limits:** 10 requests/second, reasonable for SOC use

#### API Example: IP Reputation

```python
OTX_API_KEY = "your_otx_api_key"
OTX_API_URL = "https://otx.alienvault.com/api/v1"

def check_ip_otx(ip: str) -> dict:
    """
    Check IP reputation on AlienVault OTX

    Args:
        ip: IP address

    Returns:
        {
            "reputation": int,  # 0 = clean, >0 = suspicious/malicious
            "pulses_count": int,  # Number of threat intel pulses mentioning this IP
            "threat_types": List[str],  # Malware, Phishing, C2, etc.
            "countries": List[str],
            "verdict": "malicious" | "suspicious" | "clean"
        }
    """
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    # General info
    response = requests.get(
        f"{OTX_API_URL}/indicators/IPv4/{ip}/general",
        headers=headers
    )

    data = response.json()

    pulse_count = data.get("pulse_info", {}).get("count", 0)
    reputation = data.get("reputation", 0)

    # Get threat types from pulses
    threat_types = []
    for pulse in data.get("pulse_info", {}).get("pulses", []):
        threat_types.extend(pulse.get("tags", []))

    verdict = "clean"
    if pulse_count > 5 or reputation > 0:
        verdict = "malicious"
    elif pulse_count > 0:
        verdict = "suspicious"

    return {
        "reputation": reputation,
        "pulses_count": pulse_count,
        "threat_types": list(set(threat_types)),
        "countries": data.get("country_name", "Unknown"),
        "verdict": verdict
    }
```

#### API Example: Domain Reputation

```python
def check_domain_otx(domain: str) -> dict:
    """Check domain reputation on AlienVault OTX"""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    response = requests.get(
        f"{OTX_API_URL}/indicators/domain/{domain}/general",
        headers=headers
    )

    data = response.json()

    pulse_count = data.get("pulse_info", {}).get("count", 0)

    return {
        "pulses_count": pulse_count,
        "threat_types": [tag for pulse in data.get("pulse_info", {}).get("pulses", []) for tag in pulse.get("tags", [])],
        "whois": data.get("whois", ""),
        "verdict": "malicious" if pulse_count > 3 else ("suspicious" if pulse_count > 0 else "clean")
    }
```

#### Integration with Ensemble Engine

```python
# Add to ensemble_verdict_engine.py

def _calculate_threat_intel_score(self, features: Dict) -> Dict:
    """Calculate risk score using threat intelligence (OTX)"""
    risk_score = 0
    indicators = []

    # Check sender IP
    sender_ip = features.get("sender_ip")
    if sender_ip:
        otx_ip = check_ip_otx(sender_ip)
        if otx_ip["verdict"] == "malicious":
            risk_score += 30
            indicators.append(f"Sender IP in {otx_ip['pulses_count']} threat intel pulses")
        elif otx_ip["verdict"] == "suspicious":
            risk_score += 15
            indicators.append(f"Sender IP in threat intel (low confidence)")

    # Check sender domain
    sender_domain = features.get("sender_domain")
    if sender_domain:
        otx_domain = check_domain_otx(sender_domain)
        if otx_domain["verdict"] == "malicious":
            risk_score += 25
            indicators.append(f"Sender domain flagged in threat intel")

    # Check URLs
    for url in features.get("urls", []):
        otx_url = check_url_otx(url["url"])  # Similar to IP/domain check
        if otx_url["verdict"] == "malicious":
            risk_score += 20
            indicators.append(f"URL in threat intel database")

    return {"risk_score": risk_score, "indicators": indicators}
```

**Advantages of OTX:**
- ✅ Free and open
- ✅ Community-driven (real-world threat data)
- ✅ Good API documentation
- ✅ Reasonable rate limits
- ✅ No HIPAA concerns (only metadata sent)

**Recommended:** Primary threat intelligence source for this project

---

### 4. URLhaus (Abuse.ch)

**Website:** https://urlhaus.abuse.ch
**Type:** Malware distribution URL database
**Provider:** Abuse.ch (non-profit)

#### Capabilities

- **Malware URL database** - URLs distributing malware
- **Hash lookup** - Malware payload hashes
- **Tag filtering** - Filter by malware family (Emotet, TrickBot, etc.)
- **CSV/JSON exports** - Daily updated feeds

#### Pricing

- **Free:** Full access, no API key required

#### API Example

```python
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"

def check_url_urlhaus(url: str) -> dict:
    """
    Check if URL is in URLhaus malware distribution database

    Args:
        url: URL to check

    Returns:
        {
            "threat": bool,
            "malware_family": str,
            "status": "online" | "offline",
            "tags": List[str]
        }
    """
    response = requests.post(
        f"{URLHAUS_API}url/",
        data={"url": url}
    )

    data = response.json()

    if data["query_status"] == "no_results":
        return {"threat": False}

    return {
        "threat": True,
        "malware_family": data.get("threat", "Unknown"),
        "status": data.get("url_status", "Unknown"),
        "tags": data.get("tags", []),
        "first_seen": data.get("date_added"),
        "reporter": data.get("reporter")
    }
```

#### Integration

```python
# Enhance URL scoring with URLhaus check
def _check_url_malware_distribution(self, url: str) -> int:
    """Check if URL distributes malware"""
    urlhaus_result = check_url_urlhaus(url)

    if urlhaus_result["threat"]:
        return 30  # High risk (known malware URL)
    else:
        return 0
```

**Advantages:**
- ✅ Free, no API key
- ✅ High-quality malware URL data
- ✅ Active community
- ✅ Low false positive rate

**Limitations:**
- ⚠️ Only malware distribution URLs (not phishing)
- ⚠️ No IP/domain reputation

**Recommended:** Use alongside PhishTank for comprehensive URL checking

---

### 5. PhishTank

**Website:** https://www.phishtank.com
**Type:** Community phishing URL database
**Provider:** OpenDNS (Cisco)

#### Capabilities

- **Phishing URL database** - Community-verified phishing URLs
- **API lookup** - Check if URL is in database
- **CSV export** - Daily updated feed
- **Submission** - Report new phishing URLs

#### Pricing

- **Free:** API access with registration
- **Rate Limits:** 1 request/second

#### API Example

```python
PHISHTANK_API_KEY = "your_api_key"

def check_url_phishtank(url: str) -> dict:
    """
    Check if URL is in PhishTank database

    Args:
        url: URL to check

    Returns:
        {
            "phishing": bool,
            "verified": bool,
            "submission_time": str,
            "target": str  # Brand being phished (e.g., "PayPal")
        }
    """
    response = requests.post(
        "https://checkurl.phishtank.com/checkurl/",
        data={
            "url": url,
            "format": "json",
            "app_key": PHISHTANK_API_KEY
        }
    )

    data = response.json()

    if "results" not in data:
        return {"phishing": False}

    result = data["results"]

    return {
        "phishing": result["in_database"],
        "verified": result.get("verified", False),
        "submission_time": result.get("submission_time"),
        "target": result.get("target", "Unknown")
    }
```

#### Integration

```python
# Enhance URL scoring with PhishTank
def _check_url_phishing(self, url: str) -> int:
    """Check if URL is known phishing"""
    phishtank_result = check_url_phishtank(url)

    if phishtank_result["phishing"] and phishtank_result["verified"]:
        return 35  # Very high risk (verified phishing)
    elif phishtank_result["phishing"]:
        return 20  # High risk (unverified phishing report)
    else:
        return 0
```

**Advantages:**
- ✅ Free phishing-specific database
- ✅ Community verification
- ✅ Brand/target information

**Limitations:**
- ⚠️ Rate limit (1 req/sec)
- ⚠️ Coverage gaps (not all phishing URLs reported)

**Recommended:** Primary source for phishing URL detection

---

## Proposed Integration Architecture

### Threat Intelligence Manager

**File to create:** `src/threat_intel/threat_intel_manager.py`

```python
from typing import Dict, Any, List
from dataclasses import dataclass
from datetime import datetime, timedelta
import json

@dataclass
class ThreatIntelResult:
    """Result from threat intelligence lookup"""
    source: str  # "virustotal", "otx", "urlhaus", etc.
    indicator_type: str  # "ip", "domain", "url", "hash"
    indicator_value: str
    verdict: str  # "malicious", "suspicious", "clean", "unknown"
    confidence: float  # 0.0 - 1.0
    details: Dict[str, Any]
    timestamp: datetime


class ThreatIntelManager:
    """
    Unified threat intelligence manager
    Integrates multiple third-party services
    """

    def __init__(
        self,
        virustotal_api_key: str = None,
        otx_api_key: str = None,
        enable_cache: bool = True,
        cache_ttl_hours: int = 24
    ):
        """
        Initialize threat intelligence manager

        Args:
            virustotal_api_key: VirusTotal API key (optional)
            otx_api_key: AlienVault OTX API key (optional)
            enable_cache: Enable local caching of results
            cache_ttl_hours: Cache time-to-live in hours
        """
        self.vt_api_key = virustotal_api_key
        self.otx_api_key = otx_api_key
        self.cache_enabled = enable_cache
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.cache = {}  # In-memory cache (use Redis for production)

    def check_ip(self, ip: str, sources: List[str] = None) -> List[ThreatIntelResult]:
        """
        Check IP address across multiple threat intel sources

        Args:
            ip: IP address to check
            sources: List of sources to check (default: all enabled)

        Returns:
            List of ThreatIntelResult objects
        """
        sources = sources or self._get_enabled_sources()
        results = []

        # Check cache first
        cache_key = f"ip:{ip}"
        if self.cache_enabled and cache_key in self.cache:
            cached = self.cache[cache_key]
            if datetime.now() - cached["timestamp"] < self.cache_ttl:
                return cached["results"]

        # Query each source
        if "virustotal" in sources and self.vt_api_key:
            vt_result = self._check_ip_virustotal(ip)
            results.append(vt_result)

        if "otx" in sources and self.otx_api_key:
            otx_result = self._check_ip_otx(ip)
            results.append(otx_result)

        # Cache results
        if self.cache_enabled:
            self.cache[cache_key] = {
                "results": results,
                "timestamp": datetime.now()
            }

        return results

    def check_domain(self, domain: str, sources: List[str] = None) -> List[ThreatIntelResult]:
        """Check domain reputation across sources"""
        # Similar to check_ip

    def check_url(self, url: str, sources: List[str] = None) -> List[ThreatIntelResult]:
        """
        Check URL across multiple sources

        Checks:
        - VirusTotal (if API key provided)
        - URLhaus (free)
        - PhishTank (free)
        - AlienVault OTX (if API key provided)
        """
        sources = sources or ["urlhaus", "phishtank", "otx", "virustotal"]
        results = []

        # URLhaus check (malware distribution)
        if "urlhaus" in sources:
            urlhaus_result = self._check_url_urlhaus(url)
            results.append(urlhaus_result)

        # PhishTank check (phishing)
        if "phishtank" in sources:
            phishtank_result = self._check_url_phishtank(url)
            results.append(phishtank_result)

        # OTX check
        if "otx" in sources and self.otx_api_key:
            otx_result = self._check_url_otx(url)
            results.append(otx_result)

        # VirusTotal check
        if "virustotal" in sources and self.vt_api_key:
            vt_result = self._check_url_virustotal(url)
            results.append(vt_result)

        return results

    def check_file_hash(self, file_hash: str, sources: List[str] = None) -> List[ThreatIntelResult]:
        """
        Check file hash (SHA256) reputation

        HIPAA-safe: Only hash is sent, not file content
        """
        sources = sources or ["virustotal", "otx"]
        results = []

        if "virustotal" in sources and self.vt_api_key:
            vt_result = self._check_hash_virustotal(file_hash)
            results.append(vt_result)

        if "otx" in sources and self.otx_api_key:
            otx_result = self._check_hash_otx(file_hash)
            results.append(otx_result)

        return results

    def aggregate_verdict(self, results: List[ThreatIntelResult]) -> Dict[str, Any]:
        """
        Aggregate results from multiple sources into single verdict

        Logic:
        - If ANY source says "malicious" → malicious
        - If MULTIPLE sources say "suspicious" → suspicious
        - If ALL sources say "clean" → clean
        - Otherwise → unknown

        Returns:
            {
                "verdict": "malicious" | "suspicious" | "clean" | "unknown",
                "confidence": float,
                "sources_checked": int,
                "malicious_count": int,
                "suspicious_count": int,
                "clean_count": int,
                "details": List[ThreatIntelResult]
            }
        """
        if not results:
            return {"verdict": "unknown", "confidence": 0.0}

        malicious_count = sum(1 for r in results if r.verdict == "malicious")
        suspicious_count = sum(1 for r in results if r.verdict == "suspicious")
        clean_count = sum(1 for r in results if r.verdict == "clean")
        unknown_count = sum(1 for r in results if r.verdict == "unknown")

        # Verdict logic
        if malicious_count > 0:
            verdict = "malicious"
            confidence = min(0.9, 0.5 + (malicious_count * 0.2))  # Higher confidence with more sources
        elif suspicious_count >= 2:
            verdict = "suspicious"
            confidence = 0.6
        elif suspicious_count == 1 and clean_count == 0:
            verdict = "suspicious"
            confidence = 0.4
        elif clean_count == len(results):
            verdict = "clean"
            confidence = 0.8
        else:
            verdict = "unknown"
            confidence = 0.2

        return {
            "verdict": verdict,
            "confidence": confidence,
            "sources_checked": len(results),
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "clean_count": clean_count,
            "unknown_count": unknown_count,
            "details": results
        }
```

### Integration with Ensemble Engine

**File to modify:** `src/core/ensemble_verdict_engine.py`

```python
from src.threat_intel.threat_intel_manager import ThreatIntelManager

class EnsembleVerdictEngine:
    def __init__(
        self,
        ollama_client,
        threat_intel_manager: ThreatIntelManager = None,
        weights: Dict[str, float] = None,
        confidence_thresholds: Dict[str, float] = None
    ):
        # ... existing code ...
        self.threat_intel = threat_intel_manager

    def make_verdict(self, email_features: Dict[str, Any], use_threat_intel: bool = True) -> Dict[str, Any]:
        """Generate ensemble verdict with optional threat intel enrichment"""

        # ... existing component scoring ...

        # NEW: Threat Intelligence Scoring
        if use_threat_intel and self.threat_intel:
            threat_intel_result = self._calculate_threat_intel_score(email_features)
            threat_intel_score = threat_intel_result["risk_score"] / 100.0
        else:
            threat_intel_score = 0.5  # Neutral

        # Updated Weighted Ensemble
        ensemble_score = (
            self.weights["ollama"] * ollama_score +
            self.weights["rules"] * rule_score +
            self.weights["defender"] * defender_score +
            0.10 * threat_intel_score  # NEW: 10% weight for threat intel
        )

        # ... rest of verdict logic ...

    def _calculate_threat_intel_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk score using third-party threat intelligence"""
        risk_score = 0.0
        indicators = []

        # Check sender IP
        if features.get("sender_ip"):
            ip_results = self.threat_intel.check_ip(features["sender_ip"])
            ip_verdict = self.threat_intel.aggregate_verdict(ip_results)

            if ip_verdict["verdict"] == "malicious":
                risk_score += 25
                indicators.append(f"Sender IP flagged by {ip_verdict['malicious_count']} threat intel sources")
            elif ip_verdict["verdict"] == "suspicious":
                risk_score += 12
                indicators.append(f"Sender IP suspicious ({ip_verdict['sources_checked']} sources)")

        # Check sender domain
        if features.get("sender_domain"):
            domain_results = self.threat_intel.check_domain(features["sender_domain"])
            domain_verdict = self.threat_intel.aggregate_verdict(domain_results)

            if domain_verdict["verdict"] == "malicious":
                risk_score += 20
                indicators.append("Sender domain in threat intel databases")

        # Check URLs
        for url in features.get("urls", []):
            url_results = self.threat_intel.check_url(url["url"])
            url_verdict = self.threat_intel.aggregate_verdict(url_results)

            if url_verdict["verdict"] == "malicious":
                risk_score += 30
                indicators.append(f"URL flagged as malicious/phishing")
                break  # One malicious URL is enough

        # Check attachment hashes
        for attachment in features.get("attachments", []):
            if "sha256" in attachment:
                hash_results = self.threat_intel.check_file_hash(attachment["sha256"])
                hash_verdict = self.threat_intel.aggregate_verdict(hash_results)

                if hash_verdict["verdict"] == "malicious":
                    risk_score += 35
                    indicators.append(f"Attachment hash matches known malware")

        # Normalize to 0-100
        risk_score = min(max(risk_score, 0), 100)

        return {
            "risk_score": risk_score,
            "indicators": indicators,
            "indicator_count": len(indicators)
        }
```

---

## Cost-Benefit Analysis

### Free Tier Strategy

**Recommended for initial deployment:**

| Service | Cost | Rate Limit | Coverage |
|---------|------|-----------|----------|
| **AlienVault OTX** | Free | 10 req/s | IP, domain, URL, hash |
| **URLhaus** | Free | Unlimited | Malware URLs |
| **PhishTank** | Free | 1 req/s | Phishing URLs |
| **VirusTotal** | Free | 4 req/min | Hash lookup only |

**Total Cost:** $0/month
**Coverage:** Good for most phishing detection use cases

### Premium Strategy

**For production SOC with high volume:**

| Service | Cost | Rate Limit | Added Value |
|---------|------|-----------|-------------|
| **VirusTotal Premium** | $500/mo | Custom | Multi-engine scanning, graphs |
| **Cisco Umbrella** | $1000/mo | Unlimited | Full Talos integration, DNS security |
| **AlienVault USM** | $2000/mo | Unlimited | SIEM, correlation, automation |

**Total Cost:** ~$3500/month
**Coverage:** Enterprise-grade threat intelligence

### Hybrid Strategy (Recommended)

**Best balance of cost and capability:**

| Service | Cost | Usage |
|---------|------|-------|
| **AlienVault OTX** | Free | Primary threat intel source |
| **URLhaus + PhishTank** | Free | URL-specific checks |
| **VirusTotal Public** | Free | Hash lookups only (HIPAA-safe) |
| **Cisco Talos Feeds** | Free | IP reputation lists (manual import) |

**Total Cost:** $0/month
**Upgrade Path:** Add VirusTotal Premium if free tier limits are hit

---

## Implementation Roadmap

### Phase 1: Free Tier Integration (Week 1)

- [ ] Implement `ThreatIntelManager` class
- [ ] Integrate AlienVault OTX (IP, domain, URL, hash)
- [ ] Integrate URLhaus (malware URL checks)
- [ ] Integrate PhishTank (phishing URL checks)
- [ ] Add local caching (Redis or in-memory)

### Phase 2: Ensemble Integration (Week 2)

- [ ] Add threat intel scoring to ensemble engine
- [ ] Configure weight for threat intel component (10%)
- [ ] Update verdict reasoning to include threat intel indicators
- [ ] Add threat intel metrics to audit logs

### Phase 3: Testing and Validation (Week 3)

- [ ] Test against established phishing datasets
- [ ] Measure accuracy improvement (before/after threat intel)
- [ ] Benchmark performance (API latency, cache hit rate)
- [ ] Tune cache TTL and rate limiting

### Phase 4: Production Deployment (Week 4)

- [ ] Deploy threat intel manager to production
- [ ] Monitor API usage and rate limits
- [ ] Set up alerting for API failures
- [ ] Document API key management (secrets vault)

### Phase 5: Premium Tier Evaluation (Month 2)

- [ ] Analyze free tier limitations (hit rate limits?)
- [ ] Calculate ROI of premium APIs
- [ ] Test VirusTotal Premium trial
- [ ] Make build vs. buy decision for advanced features

---

## Security and Compliance Considerations

### HIPAA Compliance

| Action | HIPAA-Safe? | Rationale |
|--------|-------------|-----------|
| **Send IP address to API** | ✅ Yes | IP is not PHI |
| **Send domain to API** | ✅ Yes | Domain is not PHI (unless patient-specific subdomain) |
| **Send URL to API** | ⚠️ Maybe | URLs may contain patient IDs in query params |
| **Send file hash to API** | ✅ Yes | Hash is not reversible to PHI |
| **Upload file to API** | ❌ No | File may contain PHI (violates HIPAA) |
| **Send email subject to API** | ⚠️ Maybe | Subject may contain patient names |

**Recommendation:**
- ✅ IP, domain, hash lookups are safe
- ⚠️ Sanitize URLs before sending (remove query params)
- ❌ NEVER upload full files or email content

### API Key Management

**Security Best Practices:**

1. **Environment Variables** - Never hardcode API keys
2. **Secrets Vault** - Use HashiCorp Vault, AWS Secrets Manager
3. **Rotation** - Rotate keys every 90 days
4. **Least Privilege** - Use read-only API keys where possible
5. **Monitoring** - Alert on API key usage spikes (potential leak)

**Example Configuration:**

```yaml
# config/threat_intel.yaml
threat_intel:
  virustotal:
    api_key: ${VT_API_KEY}  # From environment variable
    enabled: true
    rate_limit: 4  # requests per minute

  otx:
    api_key: ${OTX_API_KEY}
    enabled: true
    rate_limit: 600  # requests per minute

  urlhaus:
    enabled: true  # No API key required

  phishtank:
    api_key: ${PHISHTANK_API_KEY}
    enabled: true
    rate_limit: 60  # requests per minute
```

---

## Success Metrics

After implementing third-party integrations:

1. ✅ **Improved detection accuracy** - Measure F1 score increase
2. ✅ **Faster triage** - Reduce analyst review time via higher confidence verdicts
3. ✅ **Zero-day detection** - Catch threats not in Defender database
4. ✅ **Explainability** - Know *which* threat intel source flagged indicator
5. ✅ **Cost efficiency** - Achieve enterprise-grade detection with free APIs

### Expected Performance Gains

| Metric | Before Threat Intel | After Threat Intel | Improvement |
|--------|-------------------|-------------------|-------------|
| **Precision** | 90% | 94% | +4% |
| **Recall** | 85% | 91% | +6% |
| **F1 Score** | 87.5% | 92.5% | +5% |
| **False Negative Rate** | 15% | 9% | -6% |

---

## Conclusion

### Recommended Implementation

**Phase 1 (Immediate):**
- AlienVault OTX for IP/domain/URL/hash reputation (free, comprehensive)
- URLhaus for malware URL detection (free, high-quality)
- PhishTank for phishing URL detection (free, community-driven)

**Phase 2 (After validation):**
- VirusTotal Premium if free tier limits are exceeded
- Cisco Umbrella Investigate if budget allows ($$$ but comprehensive)

**Phase 3 (Long-term):**
- Local threat intelligence platform (MISP, OpenCTI)
- Custom threat feeds from industry ISACs
- Machine learning-based reputation scoring

### Next Steps

1. Implement `ThreatIntelManager` class
2. Integrate free tier services (OTX, URLhaus, PhishTank)
3. Add threat intel component to ensemble engine (10% weight)
4. Test on phishing datasets and measure accuracy improvement
5. Deploy to production with monitoring and alerting

---

**Document Version:** 1.0
**Status:** Design Complete - Implementation Pending
**Estimated Implementation Time:** 3-4 weeks
**Dependencies:** API keys (OTX, PhishTank, VirusTotal optional)
**Next Steps:** Implement Phase 1 (Free Tier Integration)
