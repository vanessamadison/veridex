#!/usr/bin/env python3
"""
Standalone Ensemble Engine - Works WITHOUT Microsoft Defender metadata
Uses only email headers, authentication results, and optional threat intelligence
"""
import logging
import re
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
        ollama_client=None,
        threat_intel_manager=None,
        weights: Dict[str, float] = None,
        confidence_thresholds: Dict[str, float] = None
    ):
        """
        Initialize standalone ensemble engine

        Args:
            ollama_client: OllamaSecurityAnalyst instance (optional)
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
        if use_ollama and self.ollama:
            try:
                ollama_result = self.ollama.analyze_email(email_features)
                ollama_score = ollama_result.get("risk_score", 50) / 100.0
                ollama_confidence = ollama_result.get("confidence", 0.5)
            except Exception as e:
                logger.error(f"Ollama analysis failed: {e}")
                ollama_result = {"verdict": "UNKNOWN", "confidence": 0.0, "risk_score": 50, "reasoning": f"LLM error: {e}"}
                ollama_score = 0.5
                ollama_confidence = 0.0
        else:
            # Skip Ollama (rules-only mode)
            ollama_result = {"verdict": "UNKNOWN", "confidence": 0.0, "risk_score": 50, "reasoning": "LLM disabled"}
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
                for url in urls[:3]:  # Check first 3 URLs to avoid rate limits
                    url_str = url.get("Url", "")
                    if url_str:
                        try:
                            # This would call threat intel APIs
                            # For now, placeholder for future implementation
                            pass
                        except Exception as e:
                            logger.debug(f"Threat intel check failed for URL: {e}")

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
                        try:
                            # This would call threat intel APIs
                            # Placeholder for future implementation
                            pass
                        except Exception as e:
                            logger.debug(f"Threat intel check failed for hash: {e}")

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
                try:
                    # This would call threat intel APIs
                    # Placeholder for future implementation
                    pass
                except Exception as e:
                    logger.debug(f"Threat intel check failed for IP: {e}")

        # Normalize to 0-100
        risk_score = min(max(risk_score, 0), 100)

        return {
            "risk_score": risk_score,
            "indicators": indicators,
            "indicator_count": len(indicators)
        }

    def _extract_domain_from_email(self, email_addr: str) -> str:
        """Extract domain from email address"""
        match = re.search(r'@([\w\.-]+)', email_addr)
        return match.group(1) if match else ""

    def _determine_verdict(self, ensemble_score: float, ollama_confidence: float, features: Dict) -> tuple:
        """Determine verdict and action"""
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

        return round(min(max(base_confidence, 0.0), 1.0), 3)

    def _build_reasoning(self, verdict: str, ensemble_score: float, ollama_result: Dict, rule_result: Dict, features: Dict) -> str:
        """Build human-readable reasoning"""
        reasoning_parts = []

        reasoning_parts.append(f"Verdict: {verdict} (Ensemble Score: {ensemble_score:.2f})")

        if ollama_result.get("reasoning"):
            reasoning_parts.append(f"\nLLM Analysis: {ollama_result['reasoning'][:150]}")

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


def test_standalone_engine():
    """Test standalone ensemble engine"""
    print("Testing StandaloneEnsembleEngine...")

    # Create test email features (phishing example)
    phishing_features = {
        "Subject": "URGENT: Your account will be suspended in 24 hours",
        "SenderFromAddress": "security@paypa1.com",
        "SenderFromDomain": "paypa1.com",
        "SenderIPv4": "185.220.101.5",
        "ReturnPath": "bounce@phishing-domain.com",
        "ReplyTo": "noreply@paypa1.com",
        "SPF": "Fail",
        "DKIM": "None",
        "DMARC": "Fail",
        "Urls": [
            {"Url": "http://bit.ly/verify123", "UrlDomain": "bit.ly"}
        ],
        "Attachments": [],
        "HasDefenderMetadata": False
    }

    # Initialize engine (without Ollama for testing)
    engine = StandaloneEnsembleEngine(ollama_client=None)

    # Generate verdict
    result = engine.make_verdict(phishing_features, use_ollama=False)

    print(f"\n{'='*60}")
    print(f"Test Email: {phishing_features['Subject']}")
    print(f"{'='*60}")
    print(f"Verdict: {result['verdict']}")
    print(f"Action: {result['action']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"\nComponent Scores:")
    print(f"  Ollama: {result['component_scores']['ollama']} (disabled)")
    print(f"  Rules: {result['component_scores']['rules']:.2f}")
    print(f"\nPrimary Indicators:")
    for i, indicator in enumerate(result['primary_indicators'][:5], 1):
        print(f"  {i}. {indicator}")
    print(f"\nProcessing Time: {result['processing_time_seconds']}s")
    print(f"{'='*60}")

    print("\n✓ StandaloneEnsembleEngine test complete!")


if __name__ == "__main__":
    test_standalone_engine()
