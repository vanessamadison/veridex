#!/usr/bin/env python3
"""
Ensemble Verdict Engine - Combines multiple threat detection approaches
Architecture: 40% Ollama + 30% Rule-Based + 30% Defender Signals
"""

import logging
from typing import Dict, Any, List
from datetime import datetime
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnsembleVerdictEngine:
    """
    Combines Ollama LLM analysis, rule-based scoring (from SOP), and Defender signals
    to produce final verdict with high confidence
    """

    def __init__(
        self,
        ollama_client,
        weights: Dict[str, float] = None,
        confidence_thresholds: Dict[str, float] = None
    ):
        """
        Initialize ensemble engine

        Args:
            ollama_client: OllamaSecurityAnalyst instance
            weights: Component weights (default: {ollama: 0.40, rules: 0.30, defender: 0.30})
            confidence_thresholds: Verdict thresholds (default: {auto_block: 0.90, analyst_review: 0.40})
        """
        self.ollama = ollama_client

        self.weights = weights or {
            "ollama": 0.40,
            "rules": 0.30,
            "defender": 0.30
        }

        # Ensure weights sum to 1.0
        total_weight = sum(self.weights.values())
        if abs(total_weight - 1.0) > 0.01:
            logger.warning(f"Weights sum to {total_weight}, normalizing...")
            self.weights = {k: v/total_weight for k, v in self.weights.items()}

        self.confidence_thresholds = confidence_thresholds or {
            "auto_block": 0.90,          # Very high confidence - auto-block
            "malicious": 0.75,           # High confidence - likely malicious
            "suspicious": 0.40,          # Medium confidence - analyst review
            "clean": 0.15,               # Low score - likely clean
            "auto_resolve_clean": 0.10   # Very low score - auto-resolve as clean
        }

    def make_verdict(
        self,
        email_features: Dict[str, Any],
        use_ollama: bool = True
    ) -> Dict[str, Any]:
        """
        Generate ensemble verdict for email

        Args:
            email_features: Extracted features from MDOFieldExtractor
            use_ollama: If False, skip Ollama (faster but less accurate)

        Returns:
            Dict with verdict, confidence, action, reasoning, etc.
        """
        start_time = datetime.now()

        # Component 1: Ollama LLM Analysis
        if use_ollama:
            ollama_result = self.ollama.analyze_email(email_features)
            ollama_score = ollama_result.get("risk_score", 50) / 100.0
            ollama_confidence = ollama_result.get("confidence", 0.5)
        else:
            # Skip Ollama for speed
            ollama_result = {"verdict": "UNKNOWN", "confidence": 0.0, "risk_score": 50}
            ollama_score = 0.5
            ollama_confidence = 0.0

        # Component 2: Rule-Based Scoring (SOP Logic)
        rule_result = self._calculate_rule_based_score(email_features)
        rule_score = rule_result["risk_score"] / 100.0

        # Component 3: Defender Signal Scoring
        defender_result = self._calculate_defender_score(email_features)
        defender_score = defender_result["risk_score"] / 100.0

        # Weighted Ensemble
        ensemble_score = (
            self.weights["ollama"] * ollama_score +
            self.weights["rules"] * rule_score +
            self.weights["defender"] * defender_score
        )

        # Determine verdict based on ensemble score
        verdict, action = self._determine_verdict(ensemble_score, ollama_confidence, email_features)

        # Calculate overall confidence
        confidence = self._calculate_confidence(
            ensemble_score,
            ollama_confidence,
            rule_result,
            defender_result,
            email_features
        )

        # Build reasoning
        reasoning = self._build_reasoning(
            verdict,
            ensemble_score,
            ollama_result,
            rule_result,
            defender_result,
            email_features
        )

        # Collect primary indicators
        indicators = self._collect_indicators(
            ollama_result,
            rule_result,
            defender_result,
            email_features
        )

        # Calculate processing time
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
                "defender": round(defender_score, 3)
            },
            "component_weights": self.weights,
            "reasoning": reasoning,
            "primary_indicators": indicators,
            "ollama_verdict": ollama_result.get("verdict", "UNKNOWN"),
            "processing_time_seconds": round(processing_time, 2),
            "timestamp": datetime.now().isoformat()
        }

    def _calculate_rule_based_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score using rule-based logic from CURRENT_SOP.md
        """
        risk_score = 0.0
        indicators = []

        # === AUTHENTICATION FAILURES (High weight) ===
        if not features.get("auth_passed", False):
            if features.get("spf_result") == "Fail":
                risk_score += 15
                indicators.append("SPF authentication failed")

            if features.get("dkim_result") in ["Fail", "None"]:
                risk_score += 10
                indicators.append("DKIM authentication failed/missing")

            if features.get("dmarc_result") in ["Fail", "None"]:
                risk_score += 10
                indicators.append("DMARC authentication failed/missing")

        # === SENDER ANALYSIS ===
        if features.get("is_external", False):
            risk_score += 5
            indicators.append("External sender")

            # Spoofing indicators
            if features.get("return_path_mismatch", False):
                risk_score += 10
                indicators.append("Return-Path mismatch (spoofing indicator)")

            if features.get("reply_to_mismatch", False):
                risk_score += 8
                indicators.append("Reply-To mismatch")

        elif features.get("sender_domain_is_safe", False):
            risk_score -= 10  # Internal/safe domain reduces risk
            indicators.append("Trusted sender domain")

        # === URL ANALYSIS ===
        if features.get("malicious_url_count", 0) > 0:
            risk_score += 25
            indicators.append(f"{features['malicious_url_count']} malicious URLs detected")

        if features.get("suspicious_url_count", 0) > 0:
            risk_score += 15
            indicators.append(f"{features['suspicious_url_count']} suspicious URLs detected")

        if features.get("has_shortened_url", False):
            risk_score += 12
            indicators.append("Shortened URLs (bit.ly, tinyurl)")

        # === ATTACHMENT ANALYSIS ===
        if features.get("malicious_attachment_count", 0) > 0:
            risk_score += 30
            indicators.append(f"{features['malicious_attachment_count']} malicious attachments")

        if features.get("has_risky_attachment", False):
            risk_score += 15
            indicators.append("Risky attachment type (exe, zip, js, html)")

        # === CONTENT ANALYSIS ===
        if features.get("has_urgency", False):
            risk_score += 10
            indicators.append(f"Urgency keywords in subject ({features.get('urgency_keyword_count', 0)} found)")

        if features.get("has_financial_terms", False):
            risk_score += 8
            indicators.append("Financial terms in subject (BEC/invoice fraud indicator)")

        # === COMPOUND INDICATORS (SOP-based) ===
        if features.get("external_with_attachment", False):
            risk_score += 10
            indicators.append("External sender with attachment")

        if features.get("external_with_urgency", False):
            risk_score += 10
            indicators.append("External sender with urgency")

        if features.get("failed_auth_with_urgency", False):
            risk_score += 15
            indicators.append("Failed authentication + urgency (high risk)")

        # === USER REPORTING ===
        if features.get("is_user_reported", False):
            risk_score += 12
            indicators.append("User reported as suspicious")

        # Normalize to 0-100
        risk_score = min(max(risk_score, 0), 100)

        return {
            "risk_score": risk_score,
            "indicators": indicators,
            "indicator_count": len(indicators)
        }

    def _calculate_defender_score(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk score based on Microsoft Defender signals
        """
        risk_score = 0.0
        indicators = []

        # Threat types detected by Defender
        threat_types = features.get("threat_types", [])

        if "Malware" in threat_types:
            risk_score = 100
            indicators.append("Defender: Malware detected")

        elif "Phish" in threat_types or "Phishing" in threat_types:
            risk_score = 90
            indicators.append("Defender: Phishing detected")

        elif "Spam" in threat_types:
            risk_score = 40
            indicators.append("Defender: Spam detected")

        elif features.get("has_threats", False):
            risk_score = 70
            indicators.append(f"Defender: Threats detected - {', '.join(threat_types)}")

        else:
            # No threats found
            risk_score = 0
            indicators.append("Defender: No threats found")

        # Detection technologies add confidence
        detection_tech = features.get("detection_tech", [])
        if detection_tech:
            indicators.append(f"Detection tech: {', '.join(detection_tech)}")

        # Delivery action
        delivery_action = features.get("delivery_action", "Delivered")
        if delivery_action == "Blocked":
            risk_score = max(risk_score, 85)
            indicators.append("Defender: Email blocked")
        elif delivery_action == "Quarantined":
            risk_score = max(risk_score, 75)
            indicators.append("Defender: Email quarantined")

        # Delivery location
        delivery_location = features.get("delivery_location", "Inbox")
        if delivery_location == "JunkFolder":
            risk_score = max(risk_score, 50)
            indicators.append("Delivered to Junk folder")
        elif delivery_location == "Quarantine":
            risk_score = max(risk_score, 75)
            indicators.append("Delivered to Quarantine")

        return {
            "risk_score": risk_score,
            "indicators": indicators,
            "indicator_count": len(indicators)
        }

    def _determine_verdict(
        self,
        ensemble_score: float,
        ollama_confidence: float,
        features: Dict[str, Any]
    ) -> tuple:
        """
        Determine verdict and recommended action based on ensemble score

        Returns:
            (verdict, action) tuple
        """
        # High risk score → MALICIOUS
        if ensemble_score >= self.confidence_thresholds["malicious"]:
            verdict = "MALICIOUS"

            # Auto-block only if very high confidence AND Ollama agrees
            if ensemble_score >= self.confidence_thresholds["auto_block"] and ollama_confidence >= 0.85:
                action = "auto_block"
            else:
                action = "analyst_review"

        # Medium risk score → SUSPICIOUS
        elif ensemble_score >= self.confidence_thresholds["suspicious"]:
            verdict = "SUSPICIOUS"
            action = "analyst_review"

        # Low risk score → CLEAN
        else:
            verdict = "CLEAN"

            # Auto-resolve only if very low score AND trusted sender
            if (
                ensemble_score <= self.confidence_thresholds["auto_resolve_clean"] and
                (features.get("sender_domain_is_safe", False) or features.get("is_internal", False))
            ):
                action = "auto_resolve"
            else:
                action = "analyst_review"  # Conservative approach

        return verdict, action

    def _calculate_confidence(
        self,
        ensemble_score: float,
        ollama_confidence: float,
        rule_result: Dict,
        defender_result: Dict,
        features: Dict[str, Any]
    ) -> float:
        """
        Calculate overall confidence in the verdict
        Higher confidence when multiple components agree
        """
        # Base confidence from ensemble score proximity to thresholds
        if ensemble_score >= 0.75:
            base_confidence = 0.8 + (ensemble_score - 0.75) * 0.8
        elif ensemble_score <= 0.15:
            base_confidence = 0.8 + (0.15 - ensemble_score) * 1.3
        else:
            # Medium scores have lower confidence (ambiguous)
            base_confidence = 0.5

        # Boost confidence when Ollama agrees with ensemble
        if ollama_confidence > 0:
            # If Ollama and ensemble agree on direction, boost confidence
            ensemble_verdict_numeric = 1.0 if ensemble_score >= 0.5 else 0.0
            ollama_verdict_numeric = 1.0 if ollama_confidence >= 0.5 else 0.0

            if ensemble_verdict_numeric == ollama_verdict_numeric:
                base_confidence += 0.1

        # Boost confidence when multiple indicators align
        total_indicators = (
            rule_result.get("indicator_count", 0) +
            defender_result.get("indicator_count", 0)
        )

        if total_indicators >= 5:
            base_confidence += 0.05

        # Reduce confidence for edge cases
        if features.get("is_user_reported", False) and ensemble_score < 0.3:
            # User reported but looks clean - needs analyst review
            base_confidence -= 0.15

        # Normalize to 0.0-1.0
        confidence = min(max(base_confidence, 0.0), 1.0)

        return round(confidence, 3)

    def _build_reasoning(
        self,
        verdict: str,
        ensemble_score: float,
        ollama_result: Dict,
        rule_result: Dict,
        defender_result: Dict,
        features: Dict[str, Any]
    ) -> str:
        """Build human-readable reasoning for the verdict"""
        reasoning_parts = []

        # Verdict summary
        reasoning_parts.append(f"Verdict: {verdict} (Ensemble Score: {ensemble_score:.2f})")

        # Top indicators from each component
        if ollama_result.get("reasoning"):
            reasoning_parts.append(f"\nOllama Analysis: {ollama_result['reasoning']}")

        if rule_result.get("indicators"):
            top_rule_indicators = rule_result["indicators"][:3]
            reasoning_parts.append(f"\nRule-Based Indicators: {', '.join(top_rule_indicators)}")

        if defender_result.get("indicators"):
            top_defender_indicators = defender_result["indicators"][:2]
            reasoning_parts.append(f"\nDefender Signals: {', '.join(top_defender_indicators)}")

        # Key features
        key_features = []
        if features.get("is_external"):
            key_features.append("External sender")
        if not features.get("auth_passed"):
            key_features.append("Failed authentication")
        if features.get("is_user_reported"):
            key_features.append("User reported")
        if features.get("has_urls"):
            key_features.append(f"{features['url_count']} URLs")
        if features.get("has_attachments"):
            key_features.append(f"{features['attachment_count']} attachments")

        if key_features:
            reasoning_parts.append(f"\nKey Features: {', '.join(key_features)}")

        return " ".join(reasoning_parts)

    def _collect_indicators(
        self,
        ollama_result: Dict,
        rule_result: Dict,
        defender_result: Dict,
        features: Dict[str, Any]
    ) -> List[str]:
        """Collect all primary indicators across components"""
        all_indicators = []

        # Ollama indicators
        if ollama_result.get("primary_indicators"):
            all_indicators.extend(ollama_result["primary_indicators"])

        # Rule-based indicators
        if rule_result.get("indicators"):
            all_indicators.extend(rule_result["indicators"][:5])  # Top 5

        # Defender indicators
        if defender_result.get("indicators"):
            all_indicators.extend(defender_result["indicators"])

        # Deduplicate while preserving order
        seen = set()
        unique_indicators = []
        for ind in all_indicators:
            if ind not in seen:
                seen.add(ind)
                unique_indicators.append(ind)

        return unique_indicators[:10]  # Return top 10


def test_ensemble_engine():
    """Test ensemble verdict engine"""
    from ollama_client import OllamaSecurityAnalyst

    print("="*60)
    print("Testing Ensemble Verdict Engine")
    print("="*60)

    # Initialize components
    ollama_client = OllamaSecurityAnalyst(model="mistral")
    engine = EnsembleVerdictEngine(ollama_client)

    # Test case: Phishing email
    phishing_features = {
        "sender": "security@paypa1.com",
        "sender_domain": "paypa1.com",
        "sender_ip": "185.220.101.5",
        "return_path": "bounce@paypa1.com",
        "reply_to": "noreply@paypa1.com",
        "subject": "URGENT: Your account will be suspended in 24 hours",
        "spf_result": "Fail",
        "dkim_result": "None",
        "dmarc_result": "Fail",
        "auth_passed": False,
        "threat_types": ["Phish"],
        "detection_tech": ["URL Reputation"],
        "delivery_action": "Delivered",
        "delivery_location": "Inbox",
        "urls": [{"url": "http://bit.ly/abc123", "threat_verdict": "Suspicious", "click_count": 0}],
        "url_count": 1,
        "has_shortened_url": True,
        "attachments": [],
        "attachment_count": 0,
        "directionality": "Inbound",
        "is_internal": False,
        "is_external": True,
        "is_user_reported": True,
        "has_urgency": True,
        "urgency_keyword_count": 2,
        "has_financial_terms": False,
        "external_with_urgency": True,
        "failed_auth_with_urgency": True,
        "sender_domain_is_safe": False
    }

    print("\nTest 1: Phishing Email")
    print("-" * 60)
    result = engine.make_verdict(phishing_features, use_ollama=True)

    print(f"Verdict: {result['verdict']}")
    print(f"Action: {result['action']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"\nComponent Scores:")
    for component, score in result['component_scores'].items():
        print(f"  - {component}: {score:.2f}")
    print(f"\nReasoning: {result['reasoning'][:200]}...")
    print(f"\nProcessing Time: {result['processing_time_seconds']}s")

    print("\n" + "="*60)
    print("✓ Test complete")
    print("="*60)


if __name__ == "__main__":
    test_ensemble_engine()
