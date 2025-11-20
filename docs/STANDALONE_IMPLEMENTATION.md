# Standalone Implementation Plan
## Building Without Microsoft Defender Integration

**Version:** 1.0
**Last Updated:** 2025-11-19
**Purpose:** Implement phishing detection system without requiring Microsoft Defender, validate on known datasets, then prepare for future Defender integration

---

## Problem Statement

**Current System Limitation:**
The ensemble engine expects Microsoft Defender metadata fields that may not be available:
- No direct Defender API access
- No trial/test environment with real Defender data
- Need to validate system accuracy BEFORE Defender integration
- Must work in standalone mode for research/testing

**Goal:**
Build a functional phishing detection system that:
1. ✅ Works with PUBLIC phishing datasets (no Defender required)
2. ✅ Validates accuracy against known verdicts
3. ✅ Provides infrastructure for future Defender integration
4. ✅ Supports federal compliance requirements (FISMA/FedRAMP/HIPAA)

---

## Architecture: Three-Tier Deployment Model

### Tier 1: Standalone Dataset Testing (Current Phase)
**No Defender required** - Validate core detection logic

### Tier 2: Simulated Defender Metadata (Transition Phase)
**Synthetic Defender fields** - Test ensemble with mock metadata

### Tier 3: Production Defender Integration (Future Phase)
**Real Defender API** - Full enterprise deployment

---

## Tier 1: Standalone Dataset Testing Implementation

### Overview

Build a **metadata-only detection engine** that analyzes email headers without Defender:

```
Email Dataset (raw .eml files)
    ↓
Email Parser (extract headers, URLs, attachments)
    ↓
Feature Extractor (metadata-only, no Defender)
    ↓
Modified Ensemble Engine:
    - 50% Ollama LLM (local analysis)
    - 50% Rule-Based (SPF/DKIM/DMARC, URLs, attachments)
    - 0% Defender (not available)
    ↓
Verdict + Confidence
    ↓
Compare to Ground Truth
    ↓
Calculate Metrics (Precision, Recall, F1)
```

### Step 1: Email Parser for Public Datasets

**File to create:** `src/datasets/email_parser.py`

```python
#!/usr/bin/env python3
"""
Email Parser - Extract metadata from raw .eml files
Works with public phishing datasets (no Defender required)
"""
import email
import re
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib


class EmailParser:
    """
    Parse raw email files (.eml, .msg, raw RFC822)
    Extract metadata for phishing detection
    """

    def __init__(self):
        self.parser = BytesParser(policy=policy.default)

    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse .eml file and extract all metadata

        Args:
            file_path: Path to .eml file

        Returns:
            Dictionary with email metadata (MDO-compatible format)
        """
        with open(file_path, 'rb') as f:
            msg = self.parser.parse(f)

        return self._extract_metadata(msg, file_path)

    def parse_string(self, email_content: str) -> Dict[str, Any]:
        """Parse email from string (for dataset text files)"""
        msg = email.message_from_string(email_content, policy=policy.default)
        return self._extract_metadata(msg, source="string")

    def _extract_metadata(self, msg, source: str) -> Dict[str, Any]:
        """
        Extract all metadata from email message object

        Returns MDO-compatible dictionary WITHOUT Defender fields
        """
        metadata = {}

        # === IDENTIFIERS ===
        metadata["EmailId"] = self._generate_email_id(msg, source)
        metadata["InternetMessageId"] = msg.get("Message-ID", "")
        metadata["NetworkMessageId"] = hashlib.sha256(
            (metadata["InternetMessageId"] + str(datetime.now())).encode()
        ).hexdigest()[:32]

        # === HEADERS ===
        metadata["Subject"] = msg.get("Subject", "")
        metadata["SenderFromAddress"] = msg.get("From", "")
        metadata["SenderDisplayName"] = self._extract_display_name(msg.get("From", ""))
        metadata["SenderFromDomain"] = self._extract_domain(metadata["SenderFromAddress"])

        # Recipients
        metadata["RecipientAddress"] = msg.get("To", "")
        metadata["RecipientsCc"] = msg.get("Cc", "")
        metadata["RecipientsBcc"] = msg.get("Bcc", "")

        # Return-Path and Reply-To
        metadata["ReturnPath"] = msg.get("Return-Path", "")
        metadata["ReplyTo"] = msg.get("Reply-To", "")

        # === AUTHENTICATION RESULTS ===
        # Parse Authentication-Results header (if present)
        auth_results = msg.get("Authentication-Results", "")
        metadata["SPF"] = self._extract_spf_result(auth_results, msg)
        metadata["DKIM"] = self._extract_dkim_result(auth_results, msg)
        metadata["DMARC"] = self._extract_dmarc_result(auth_results, msg)

        # === RECEIVED HEADERS (IP extraction) ===
        metadata["SenderIPv4"] = self._extract_sender_ip(msg.get_all("Received", []))

        # === TIMESTAMPS ===
        metadata["ReceivedDateTime"] = self._parse_date(msg.get("Date", ""))

        # === URLS ===
        body_text = self._get_body_text(msg)
        metadata["Urls"] = self._extract_urls(body_text)
        metadata["UrlCount"] = len(metadata["Urls"])

        # === ATTACHMENTS ===
        metadata["Attachments"] = self._extract_attachments(msg)
        metadata["AttachmentCount"] = len(metadata["Attachments"])

        # === BODY PREVIEW (HIPAA-SAFE: first 50 chars only) ===
        metadata["BodyPreview"] = body_text[:50] if body_text else ""

        # === DIRECTIONALITY ===
        # Infer from sender domain (no Defender signal available)
        metadata["Directionality"] = "Inbound"  # Assume external for public datasets

        # === METADATA FLAGS ===
        metadata["DatasetSource"] = "public_dataset"
        metadata["HasDefenderMetadata"] = False  # Critical flag
        metadata["ParsedAt"] = datetime.utcnow().isoformat()

        return metadata

    def _extract_display_name(self, from_header: str) -> str:
        """Extract display name from 'From' header"""
        # Example: "John Smith <john@example.com>" -> "John Smith"
        match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
        if match:
            return match.group(1).strip()
        return ""

    def _extract_domain(self, email_addr: str) -> str:
        """Extract domain from email address"""
        match = re.search(r'@([\w\.-]+)', email_addr)
        return match.group(1) if match else ""

    def _extract_spf_result(self, auth_results: str, msg) -> str:
        """
        Extract SPF result from Authentication-Results header

        Examples:
        - "spf=pass" -> "Pass"
        - "spf=fail" -> "Fail"
        - "spf=softfail" -> "SoftFail"
        - No SPF -> "None"
        """
        if not auth_results:
            # Check for separate Received-SPF header
            spf_header = msg.get("Received-SPF", "")
            if "pass" in spf_header.lower():
                return "Pass"
            elif "fail" in spf_header.lower():
                return "Fail"
            elif "softfail" in spf_header.lower():
                return "SoftFail"
            return "None"

        # Parse Authentication-Results
        if "spf=pass" in auth_results.lower():
            return "Pass"
        elif "spf=fail" in auth_results.lower():
            return "Fail"
        elif "spf=softfail" in auth_results.lower():
            return "SoftFail"
        elif "spf=neutral" in auth_results.lower():
            return "Neutral"
        else:
            return "None"

    def _extract_dkim_result(self, auth_results: str, msg) -> str:
        """Extract DKIM result"""
        if not auth_results:
            return "None"

        if "dkim=pass" in auth_results.lower():
            return "Pass"
        elif "dkim=fail" in auth_results.lower():
            return "Fail"
        else:
            return "None"

    def _extract_dmarc_result(self, auth_results: str, msg) -> str:
        """Extract DMARC result"""
        if not auth_results:
            return "None"

        if "dmarc=pass" in auth_results.lower():
            return "Pass"
        elif "dmarc=fail" in auth_results.lower():
            return "Fail"
        else:
            return "None"

    def _extract_sender_ip(self, received_headers: List[str]) -> str:
        """
        Extract sender IP from Received headers

        Example Received header:
        "Received: from mail.example.com (mail.example.com [192.168.1.1]) ..."
        """
        if not received_headers:
            return ""

        # Get the LAST Received header (closest to sender)
        last_received = received_headers[-1] if received_headers else ""

        # Extract IP address (IPv4)
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', last_received)
        if ip_match:
            return ip_match.group(1)

        return ""

    def _parse_date(self, date_header: str) -> str:
        """Parse Date header to ISO format"""
        if not date_header:
            return datetime.utcnow().isoformat()

        try:
            # email.utils.parsedate_to_datetime handles RFC 2822 dates
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_header)
            return dt.isoformat()
        except:
            return datetime.utcnow().isoformat()

    def _get_body_text(self, msg) -> str:
        """Extract plain text body (prefer text/plain over text/html)"""
        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body = part.get_content()
                        break
                    except:
                        pass
        else:
            try:
                body = msg.get_content()
            except:
                pass

        return body if isinstance(body, str) else ""

    def _extract_urls(self, body_text: str) -> List[Dict[str, Any]]:
        """
        Extract URLs from email body

        Returns list of URL dictionaries (without Defender threat verdicts)
        """
        # URL regex pattern
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )

        urls = []
        for match in url_pattern.finditer(body_text):
            url = match.group(0)
            urls.append({
                "Url": url,
                "UrlDomain": self._extract_domain_from_url(url),
                # Note: No ThreatVerdict from Defender
                # Will be enriched by threat intel APIs later
            })

        return urls

    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        match = re.search(r'://([^/]+)', url)
        return match.group(1) if match else ""

    def _extract_attachments(self, msg) -> List[Dict[str, Any]]:
        """
        Extract attachment metadata

        Returns list of attachment dictionaries (without Defender verdicts)
        """
        attachments = []

        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename() or "unknown"
                file_data = part.get_content()

                # Calculate SHA256 hash
                file_hash = hashlib.sha256(
                    file_data if isinstance(file_data, bytes) else file_data.encode()
                ).hexdigest()

                attachments.append({
                    "FileName": filename,
                    "FileType": filename.split('.')[-1] if '.' in filename else "unknown",
                    "SHA256": file_hash,
                    "SizeBytes": len(file_data) if isinstance(file_data, bytes) else len(file_data.encode()),
                    # Note: No ThreatNames from Defender
                    # Will be enriched by hash reputation APIs later
                })

        return attachments

    def _generate_email_id(self, msg, source: str) -> str:
        """Generate unique email ID"""
        message_id = msg.get("Message-ID", "")
        timestamp = datetime.utcnow().timestamp()
        return hashlib.sha256(f"{message_id}{source}{timestamp}".encode()).hexdigest()[:16]
```

### Step 2: Standalone Ensemble Engine

**File to create:** `src/core/standalone_ensemble_engine.py`

```python
#!/usr/bin/env python3
"""
Standalone Ensemble Engine - Works WITHOUT Microsoft Defender metadata
Uses only email headers, authentication results, and threat intelligence
"""
import logging
from typing import Dict, Any
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StandaloneEnsembleEngine:
    """
    Ensemble verdict engine that works without Microsoft Defender

    Components:
    - 50% Ollama LLM (local threat analysis)
    - 50% Rule-Based (authentication, URLs, attachments, threat intel)
    - 0% Defender (not available in standalone mode)
    """

    def __init__(
        self,
        ollama_client,
        threat_intel_manager=None,
        weights: Dict[str, float] = None,
        confidence_thresholds: Dict[str, float] = None
    ):
        """
        Initialize standalone ensemble engine

        Args:
            ollama_client: OllamaSecurityAnalyst instance
            threat_intel_manager: Optional ThreatIntelManager for URL/IP/hash checks
            weights: Component weights (default: {ollama: 0.50, rules: 0.50})
            confidence_thresholds: Verdict thresholds
        """
        self.ollama = ollama_client
        self.threat_intel = threat_intel_manager

        # Default weights: 50/50 without Defender
        self.weights = weights or {
            "ollama": 0.50,
            "rules": 0.50
        }

        # Normalize weights
        total_weight = sum(self.weights.values())
        if abs(total_weight - 1.0) > 0.01:
            logger.warning(f"Weights sum to {total_weight}, normalizing...")
            self.weights = {k: v/total_weight for k, v in self.weights.items()}

        self.confidence_thresholds = confidence_thresholds or {
            "auto_block": 0.90,
            "malicious": 0.75,
            "suspicious": 0.40,
            "clean": 0.15,
            "auto_resolve_clean": 0.10
        }

        logger.info(f"Standalone Ensemble Engine initialized")
        logger.info(f"Weights: Ollama={self.weights['ollama']:.0%}, Rules={self.weights['rules']:.0%}")

    def make_verdict(
        self,
        email_features: Dict[str, Any],
        use_ollama: bool = True
    ) -> Dict[str, Any]:
        """
        Generate ensemble verdict WITHOUT Defender metadata

        Args:
            email_features: Extracted features from EmailParser
            use_ollama: If False, skip Ollama (faster but less accurate)

        Returns:
            Dict with verdict, confidence, action, reasoning, etc.
        """
        start_time = datetime.now()

        # Check if Defender metadata is present (should be False in standalone mode)
        has_defender = email_features.get("HasDefenderMetadata", False)
        if has_defender:
            logger.warning("Defender metadata detected but using standalone engine!")

        # Component 1: Ollama LLM Analysis
        if use_ollama:
            ollama_result = self.ollama.analyze_email(email_features)
            ollama_score = ollama_result.get("risk_score", 50) / 100.0
            ollama_confidence = ollama_result.get("confidence", 0.5)
        else:
            ollama_result = {"verdict": "UNKNOWN", "confidence": 0.0, "risk_score": 50}
            ollama_score = 0.5
            ollama_confidence = 0.0

        # Component 2: Enhanced Rule-Based Scoring
        # (includes authentication, URLs, attachments, threat intel)
        rule_result = self._calculate_standalone_rule_score(email_features)
        rule_score = rule_result["risk_score"] / 100.0

        # Weighted Ensemble (50/50 without Defender)
        ensemble_score = (
            self.weights["ollama"] * ollama_score +
            self.weights["rules"] * rule_score
        )

        # Determine verdict
        verdict, action = self._determine_verdict(ensemble_score, ollama_confidence, email_features)

        # Calculate confidence
        confidence = self._calculate_confidence(
            ensemble_score,
            ollama_confidence,
            rule_result,
            email_features
        )

        # Build reasoning
        reasoning = self._build_reasoning(
            verdict,
            ensemble_score,
            ollama_result,
            rule_result,
            email_features
        )

        # Collect indicators
        indicators = self._collect_indicators(
            ollama_result,
            rule_result,
            email_features
        )

        processing_time = (datetime.now() - start_time).total_seconds()

        return {
            "verdict": verdict,
            "action": action,
            "confidence": confidence,
            "ensemble_score": round(ensemble_score, 3),
            "risk_score": int(ensemble_score * 100),
            "component_scores": {
                "ollama": round(ollama_score, 3),
                "rules": round(rule_score, 3),
                "defender": None  # Not available
            },
            "component_weights": self.weights,
            "reasoning": reasoning,
            "primary_indicators": indicators,
            "ollama_verdict": ollama_result.get("verdict", "UNKNOWN"),
            "processing_time_seconds": round(processing_time, 2),
            "timestamp": datetime.now().isoformat(),
            "standalone_mode": True  # Flag for tracking
        }

    def _calculate_standalone_rule_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score WITHOUT Defender signals
        Enhanced rules compensate for missing Defender data
        """
        risk_score = 0.0
        indicators = []

        # === AUTHENTICATION FAILURES (Higher weight without Defender) ===
        spf_result = features.get("SPF", "None")
        dkim_result = features.get("DKIM", "None")
        dmarc_result = features.get("DMARC", "None")

        if spf_result == "Fail":
            risk_score += 20  # Higher than original 15
            indicators.append("SPF authentication failed")
        elif spf_result in ["SoftFail", "Neutral"]:
            risk_score += 10
            indicators.append(f"SPF {spf_result}")

        if dkim_result == "Fail":
            risk_score += 15  # Higher than original 10
            indicators.append("DKIM authentication failed")
        elif dkim_result == "None":
            risk_score += 8
            indicators.append("DKIM not present")

        if dmarc_result == "Fail":
            risk_score += 15  # Higher than original 10
            indicators.append("DMARC authentication failed")
        elif dmarc_result == "None":
            risk_score += 8
            indicators.append("DMARC not present")

        # Compound: All auth failed
        if spf_result in ["Fail", "None"] and dkim_result in ["Fail", "None"] and dmarc_result in ["Fail", "None"]:
            risk_score += 10
            indicators.append("All authentication checks failed/missing (high risk)")

        # === SENDER ANALYSIS ===
        sender_domain = features.get("SenderFromDomain", "")
        return_path = features.get("ReturnPath", "")
        reply_to = features.get("ReplyTo", "")

        # Return-Path mismatch (spoofing)
        if return_path and sender_domain:
            return_path_domain = self._extract_domain_from_email(return_path)
            if return_path_domain and return_path_domain != sender_domain:
                risk_score += 15
                indicators.append(f"Return-Path mismatch (spoofing indicator)")

        # Reply-To mismatch
        if reply_to and sender_domain:
            reply_to_domain = self._extract_domain_from_email(reply_to)
            if reply_to_domain and reply_to_domain != sender_domain:
                risk_score += 12
                indicators.append("Reply-To mismatch")

        # === URL ANALYSIS (with threat intel if available) ===
        urls = features.get("Urls", [])
        if urls:
            risk_score += 5  # Base risk for having URLs
            indicators.append(f"{len(urls)} URLs in email")

            # Check for shortened URLs
            shortened_domains = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co"]
            has_shortened = any(
                any(domain in url.get("UrlDomain", "").lower() for domain in shortened_domains)
                for url in urls
            )
            if has_shortened:
                risk_score += 15
                indicators.append("Shortened URLs (common in phishing)")

            # Threat intel enrichment (if available)
            if self.threat_intel:
                for url in urls:
                    url_str = url.get("Url", "")
                    if url_str:
                        threat_results = self.threat_intel.check_url(url_str)
                        verdict = self.threat_intel.aggregate_verdict(threat_results)

                        if verdict["verdict"] == "malicious":
                            risk_score += 35
                            indicators.append(f"URL flagged as malicious by threat intel")
                            break  # One malicious URL is enough
                        elif verdict["verdict"] == "suspicious":
                            risk_score += 20
                            indicators.append("URL flagged as suspicious")

        # === ATTACHMENT ANALYSIS (with hash lookup if available) ===
        attachments = features.get("Attachments", [])
        if attachments:
            risk_score += 5  # Base risk for having attachments
            indicators.append(f"{len(attachments)} attachments")

            # Risky file types
            risky_extensions = [".exe", ".zip", ".rar", ".js", ".vbs", ".html", ".htm", ".bat", ".cmd", ".scr", ".dll"]
            for att in attachments:
                file_type = att.get("FileType", "").lower()
                if file_type in [ext.replace(".", "") for ext in risky_extensions]:
                    risk_score += 20
                    indicators.append(f"Risky attachment type: {file_type}")

            # Threat intel hash lookup (if available)
            if self.threat_intel:
                for att in attachments:
                    file_hash = att.get("SHA256")
                    if file_hash:
                        hash_results = self.threat_intel.check_file_hash(file_hash)
                        verdict = self.threat_intel.aggregate_verdict(hash_results)

                        if verdict["verdict"] == "malicious":
                            risk_score += 40
                            indicators.append("Attachment hash matches known malware")
                            break

        # === SUBJECT LINE ANALYSIS ===
        subject = features.get("Subject", "").lower()

        # Urgency keywords
        urgency_keywords = [
            "urgent", "immediate", "action required", "verify", "suspended",
            "expires", "confirm", "update", "security alert", "locked",
            "unusual activity", "click here", "act now", "limited time", "final notice"
        ]
        urgency_count = sum(1 for keyword in urgency_keywords if keyword in subject)
        if urgency_count > 0:
            risk_score += 12
            indicators.append(f"Urgency keywords in subject ({urgency_count} found)")

        # Financial keywords (BEC)
        financial_keywords = [
            "invoice", "payment", "wire transfer", "bank", "account",
            "refund", "tax", "payroll", "w-2", "gift card", "bitcoin", "paypal"
        ]
        financial_count = sum(1 for keyword in financial_keywords if keyword in subject)
        if financial_count > 0:
            risk_score += 10
            indicators.append(f"Financial keywords in subject (BEC indicator)")

        # === IP REPUTATION (if threat intel available) ===
        if self.threat_intel:
            sender_ip = features.get("SenderIPv4")
            if sender_ip:
                ip_results = self.threat_intel.check_ip(sender_ip)
                verdict = self.threat_intel.aggregate_verdict(ip_results)

                if verdict["verdict"] == "malicious":
                    risk_score += 25
                    indicators.append("Sender IP flagged in threat intel")
                elif verdict["verdict"] == "suspicious":
                    risk_score += 12
                    indicators.append("Sender IP suspicious")

        # Normalize to 0-100
        risk_score = min(max(risk_score, 0), 100)

        return {
            "risk_score": risk_score,
            "indicators": indicators,
            "indicator_count": len(indicators)
        }

    def _extract_domain_from_email(self, email_addr: str) -> str:
        """Extract domain from email address"""
        import re
        match = re.search(r'@([\w\.-]+)', email_addr)
        return match.group(1) if match else ""

    def _determine_verdict(self, ensemble_score: float, ollama_confidence: float, features: Dict) -> tuple:
        """Determine verdict and action (same logic as original)"""
        if ensemble_score >= self.confidence_thresholds["malicious"]:
            verdict = "MALICIOUS"
            if ensemble_score >= self.confidence_thresholds["auto_block"] and ollama_confidence >= 0.85:
                action = "auto_block"
            else:
                action = "analyst_review"
        elif ensemble_score >= self.confidence_thresholds["suspicious"]:
            verdict = "SUSPICIOUS"
            action = "analyst_review"
        else:
            verdict = "CLEAN"
            if ensemble_score <= self.confidence_thresholds["auto_resolve_clean"]:
                action = "auto_resolve"
            else:
                action = "analyst_review"

        return verdict, action

    def _calculate_confidence(self, ensemble_score: float, ollama_confidence: float, rule_result: Dict, features: Dict) -> float:
        """Calculate overall confidence"""
        if ensemble_score >= 0.75:
            base_confidence = 0.8 + (ensemble_score - 0.75) * 0.8
        elif ensemble_score <= 0.15:
            base_confidence = 0.8 + (0.15 - ensemble_score) * 1.3
        else:
            base_confidence = 0.5

        if ollama_confidence > 0:
            ensemble_verdict_numeric = 1.0 if ensemble_score >= 0.5 else 0.0
            ollama_verdict_numeric = 1.0 if ollama_confidence >= 0.5 else 0.0
            if ensemble_verdict_numeric == ollama_verdict_numeric:
                base_confidence += 0.1

        if rule_result.get("indicator_count", 0) >= 5:
            base_confidence += 0.05

        return min(max(base_confidence, 0.0), 1.0)

    def _build_reasoning(self, verdict: str, ensemble_score: float, ollama_result: Dict, rule_result: Dict, features: Dict) -> str:
        """Build human-readable reasoning"""
        reasoning_parts = []

        reasoning_parts.append(f"Verdict: {verdict} (Ensemble Score: {ensemble_score:.2f})")

        if ollama_result.get("reasoning"):
            reasoning_parts.append(f"\nLLM Analysis: {ollama_result['reasoning']}")

        if rule_result.get("indicators"):
            top_indicators = rule_result["indicators"][:3]
            reasoning_parts.append(f"\nRule-Based Indicators: {', '.join(top_indicators)}")

        reasoning_parts.append("\n[Standalone Mode: No Defender signals available]")

        return " ".join(reasoning_parts)

    def _collect_indicators(self, ollama_result: Dict, rule_result: Dict, features: Dict) -> list:
        """Collect all primary indicators"""
        all_indicators = []

        if ollama_result.get("primary_indicators"):
            all_indicators.extend(ollama_result["primary_indicators"])

        if rule_result.get("indicators"):
            all_indicators.extend(rule_result["indicators"][:5])

        # Deduplicate
        seen = set()
        unique_indicators = []
        for ind in all_indicators:
            if ind not in seen:
                seen.add(ind)
                unique_indicators.append(ind)

        return unique_indicators[:10]
```

### Step 3: Dataset Evaluation Pipeline

**File to create:** `src/evaluation/standalone_evaluator.py`

```python
#!/usr/bin/env python3
"""
Standalone Dataset Evaluator
Tests phishing detection on public datasets with known verdicts
"""
import logging
import json
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime
import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class StandaloneEvaluator:
    """
    Evaluate standalone ensemble engine on datasets with known verdicts
    """

    def __init__(
        self,
        email_parser,
        ensemble_engine,
        metrics_calculator
    ):
        self.parser = email_parser
        self.engine = ensemble_engine
        self.metrics = metrics_calculator

    def evaluate_dataset(
        self,
        dataset_path: str,
        ground_truth_file: str,
        max_emails: int = None
    ) -> Dict[str, Any]:
        """
        Evaluate system on a dataset

        Args:
            dataset_path: Path to directory with .eml files
            ground_truth_file: CSV with columns: filename, verdict (malicious/clean)
            max_emails: Limit number of emails to process

        Returns:
            Evaluation results with metrics
        """
        logger.info(f"Evaluating dataset: {dataset_path}")

        # Load ground truth
        ground_truth = pd.read_csv(ground_truth_file)
        logger.info(f"Loaded {len(ground_truth)} ground truth labels")

        # Process each email
        results = []
        errors = []
        misclassifications = []

        email_files = list(Path(dataset_path).glob("*.eml"))
        if max_emails:
            email_files = email_files[:max_emails]

        for i, email_file in enumerate(email_files, 1):
            try:
                # Parse email
                email_metadata = self.parser.parse_file(str(email_file))

                # Generate verdict
                verdict_result = self.engine.make_verdict(email_metadata)

                # Get ground truth
                gt_row = ground_truth[ground_truth["filename"] == email_file.name]
                if gt_row.empty:
                    logger.warning(f"No ground truth for {email_file.name}")
                    continue

                ground_truth_verdict = gt_row.iloc[0]["verdict"].upper()  # "MALICIOUS" or "CLEAN"
                predicted_verdict = verdict_result["verdict"]

                # Update metrics
                self.metrics.update(predicted_verdict, ground_truth_verdict)

                # Track misclassifications
                if predicted_verdict != ground_truth_verdict:
                    misclassifications.append({
                        "filename": email_file.name,
                        "ground_truth": ground_truth_verdict,
                        "predicted": predicted_verdict,
                        "confidence": verdict_result["confidence"],
                        "ensemble_score": verdict_result["ensemble_score"],
                        "subject": email_metadata.get("Subject", "")[:50]
                    })

                results.append({
                    "filename": email_file.name,
                    "ground_truth": ground_truth_verdict,
                    "predicted": predicted_verdict,
                    "confidence": verdict_result["confidence"],
                    "ensemble_score": verdict_result["ensemble_score"]
                })

                if i % 10 == 0:
                    logger.info(f"Processed {i}/{len(email_files)} emails")

            except Exception as e:
                logger.error(f"Error processing {email_file.name}: {e}")
                errors.append({"filename": email_file.name, "error": str(e)})

        # Calculate final metrics
        final_metrics = self.metrics.calculate_metrics()
        confusion_matrix = self.metrics.confusion_matrix()

        return {
            "dataset_path": dataset_path,
            "total_emails": len(results),
            "metrics": final_metrics,
            "confusion_matrix": confusion_matrix,
            "misclassifications": misclassifications,
            "errors": errors,
            "timestamp": datetime.now().isoformat()
        }

    def generate_report(self, results: Dict, output_path: str):
        """Generate evaluation report"""
        # Save JSON
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

        # Print summary
        print("\n" + "="*60)
        print("EVALUATION RESULTS")
        print("="*60)
        print(f"Dataset: {results['dataset_path']}")
        print(f"Total Emails: {results['total_emails']}")
        print(f"\nMetrics:")
        print(f"  Precision: {results['metrics']['precision']:.2%}")
        print(f"  Recall: {results['metrics']['recall']:.2%}")
        print(f"  F1 Score: {results['metrics']['f1_score']:.2%}")
        print(f"  Accuracy: {results['metrics']['accuracy']:.2%}")
        print(f"  False Positive Rate: {results['metrics']['false_positive_rate']:.2%}")
        print(f"  False Negative Rate: {results['metrics']['false_negative_rate']:.2%}")
        print(f"\nConfusion Matrix:")
        print(f"  True Positives: {results['confusion_matrix']['true_positives']}")
        print(f"  False Positives: {results['confusion_matrix']['false_positives']}")
        print(f"  True Negatives: {results['confusion_matrix']['true_negatives']}")
        print(f"  False Negatives: {results['confusion_matrix']['false_negatives']}")
        print(f"\nMisclassifications: {len(results['misclassifications'])}")
        print(f"Errors: {len(results['errors'])}")
        print("="*60)

        logger.info(f"Report saved to {output_path}")
```

### Step 4: Complete Standalone Workflow

**File to create:** `standalone_triage.py` (main script)

```python
#!/usr/bin/env python3
"""
Standalone Phishing Triage System
Works with public datasets, no Microsoft Defender required
"""
import argparse
from src.datasets.email_parser import EmailParser
from src.core.standalone_ensemble_engine import StandaloneEnsembleEngine
from src.core.ollama_client import OllamaSecurityAnalyst
from src.evaluation.standalone_evaluator import StandaloneEvaluator
from src.evaluation.metrics_calculator import MetricsCalculator
from src.threat_intel.threat_intel_manager import ThreatIntelManager


def main():
    parser = argparse.ArgumentParser(description="Standalone Phishing Triage System")

    parser.add_argument("--dataset", required=True, help="Path to dataset directory (.eml files)")
    parser.add_argument("--ground-truth", required=True, help="Path to ground truth CSV")
    parser.add_argument("--output", default="results/standalone_evaluation.json", help="Output file")
    parser.add_argument("--max-emails", type=int, help="Max emails to process")
    parser.add_argument("--no-llm", action="store_true", help="Disable Ollama (rules-only mode)")
    parser.add_argument("--threat-intel", action="store_true", help="Enable threat intelligence APIs")

    # Threat intel API keys
    parser.add_argument("--otx-key", help="AlienVault OTX API key")
    parser.add_argument("--vt-key", help="VirusTotal API key")

    args = parser.parse_args()

    print("\n" + "="*60)
    print("STANDALONE PHISHING TRIAGE SYSTEM")
    print("="*60)
    print(f"Dataset: {args.dataset}")
    print(f"Ground Truth: {args.ground_truth}")
    print(f"LLM: {'Disabled' if args.no_llm else 'Enabled (Ollama)'}")
    print(f"Threat Intel: {'Enabled' if args.threat_intel else 'Disabled'}")
    print("="*60 + "\n")

    # Initialize components
    email_parser = EmailParser()

    # Ollama LLM (optional)
    if not args.no_llm:
        ollama = OllamaSecurityAnalyst(model="mistral")
    else:
        ollama = None  # Will use dummy client in engine

    # Threat Intelligence (optional)
    if args.threat_intel:
        threat_intel = ThreatIntelManager(
            otx_api_key=args.otx_key,
            virustotal_api_key=args.vt_key
        )
    else:
        threat_intel = None

    # Standalone Ensemble Engine
    engine = StandaloneEnsembleEngine(
        ollama_client=ollama,
        threat_intel_manager=threat_intel
    )

    # Metrics Calculator
    metrics = MetricsCalculator()

    # Evaluator
    evaluator = StandaloneEvaluator(
        email_parser=email_parser,
        ensemble_engine=engine,
        metrics_calculator=metrics
    )

    # Run evaluation
    results = evaluator.evaluate_dataset(
        dataset_path=args.dataset,
        ground_truth_file=args.ground_truth,
        max_emails=args.max_emails
    )

    # Generate report
    evaluator.generate_report(results, args.output)


if __name__ == "__main__":
    main()
```

---

## Usage Examples

### Example 1: Evaluate Nazario Phishing Dataset

```bash
# Download Nazario dataset
mkdir -p data/established_datasets/nazario_phishing/raw
wget https://monkey.org/~jose/phishing/ -r -np -nd -P data/established_datasets/nazario_phishing/raw

# Create ground truth CSV
cat > data/established_datasets/nazario_phishing/ground_truth.csv << EOF
filename,verdict
email_001.eml,malicious
email_002.eml,malicious
email_003.eml,malicious
EOF

# Run evaluation
python standalone_triage.py \
  --dataset data/established_datasets/nazario_phishing/raw \
  --ground-truth data/established_datasets/nazario_phishing/ground_truth.csv \
  --output results/nazario_evaluation.json
```

### Example 2: Rules-Only Mode (No LLM)

```bash
# Faster evaluation, no Ollama required
python standalone_triage.py \
  --dataset data/established_datasets/spamassassin \
  --ground-truth data/established_datasets/spamassassin/ground_truth.csv \
  --no-llm \
  --output results/spamassassin_rules_only.json
```

### Example 3: With Threat Intelligence

```bash
# Enhanced detection with URL/IP/hash reputation
export OTX_API_KEY="your_otx_key"
export VT_API_KEY="your_vt_key"

python standalone_triage.py \
  --dataset data/established_datasets/phishtank_corpus \
  --ground-truth data/established_datasets/phishtank_corpus/ground_truth.csv \
  --threat-intel \
  --otx-key $OTX_API_KEY \
  --vt-key $VT_API_KEY \
  --output results/phishtank_with_threat_intel.json
```

---

## Transition to Defender Integration

### When to Integrate Defender

**Tier 2: Simulated Defender** (if you get trial access)
- Create synthetic Defender fields for testing
- Test ensemble with mock threat types, delivery actions

**Tier 3: Production Defender** (real deployment)
- Connect to Microsoft Graph API
- Use real Defender threat intelligence
- Adjust ensemble weights (40% Ollama, 30% Rules, 30% Defender)

### Migration Path

```python
# Adaptive Ensemble Engine (works with or without Defender)

class AdaptiveEnsembleEngine:
    def make_verdict(self, email_features):
        has_defender = email_features.get("HasDefenderMetadata", False)

        if has_defender:
            # Use full ensemble (Ollama 40%, Rules 30%, Defender 30%)
            weights = {"ollama": 0.40, "rules": 0.30, "defender": 0.30}
        else:
            # Standalone mode (Ollama 50%, Rules 50%, Defender 0%)
            weights = {"ollama": 0.50, "rules": 0.50}

        # ... rest of verdict logic
```

---

## Federal Compliance Considerations

### FISMA (Federal Information Security Management Act)

**Requirements for federal systems:**
1. ✅ **Data minimization** - Only process metadata, never email body
2. ✅ **Audit logging** - Log all verdict decisions
3. ✅ **Access controls** - Role-based access to triage results
4. ✅ **Encryption** - TLS for API calls, encryption at rest for logs

**Implementation:**
```python
# Add to standalone engine
def make_verdict(self, email_features):
    verdict = self._generate_verdict(email_features)

    # FISMA audit log
    self.audit_logger.log({
        "timestamp": datetime.utcnow().isoformat(),
        "email_id": email_features.get("EmailId"),
        "verdict": verdict["verdict"],
        "confidence": verdict["confidence"],
        "user": get_current_user(),
        "action": verdict["action"]
    })

    return verdict
```

### FedRAMP (Federal Risk and Authorization Management Program)

**Requirements for cloud services:**
- ✅ **Baseline controls** - Implement NIST 800-53 controls
- ✅ **Continuous monitoring** - Track API usage, errors, performance
- ✅ **Incident response** - Alert on suspicious activity (API key leaks, etc.)

**For Ollama (local LLM):**
- ✅ **No cloud dependency** - Runs on-premise (FedRAMP compliant)
- ✅ **No data leakage** - Email metadata stays local

**For Threat Intel APIs:**
- ⚠️ **Third-party services** - Must be FedRAMP authorized OR use only hash/IP lookups (no PII sent)

### HIPAA (Health Insurance Portability and Accountability Act)

**Already covered in previous docs:**
- ✅ **No PHI in threat intel API calls** - Only hashes, IPs, domains
- ✅ **Local processing** - Ollama runs on-premise
- ✅ **Audit trail** - 6-year retention

---

## Next Steps

1. **Implement EmailParser** (Week 1)
   - Parse .eml files from public datasets
   - Extract headers, URLs, attachments
   - Generate MDO-compatible metadata WITHOUT Defender

2. **Implement StandaloneEnsembleEngine** (Week 1)
   - 50/50 Ollama/Rules weighting
   - Enhanced rules compensate for missing Defender

3. **Download Public Datasets** (Week 1)
   - Nazario phishing corpus
   - SpamAssassin corpus
   - Create ground truth CSVs

4. **Run Evaluation** (Week 2)
   - Test on 1000+ emails with known verdicts
   - Calculate precision, recall, F1
   - Identify gaps and tune rules

5. **Add Threat Intel** (Week 3)
   - Integrate AlienVault OTX (free)
   - Test accuracy improvement
   - Benchmark API latency

6. **Deploy Standalone System** (Week 4)
   - Production-ready without Defender
   - Federal compliance audit
   - Documentation for accreditation

---

**Document Version:** 1.0
**Status:** Implementation Plan - Ready to Build
**Dependencies:** Ollama, Python 3.9+, public datasets
**Next Action:** Implement EmailParser class
