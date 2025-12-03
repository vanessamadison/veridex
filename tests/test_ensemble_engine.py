#!/usr/bin/env python3
"""
Unit tests for Ensemble Verdict Engine
Tests the 50/50 LLM + Rules ensemble logic
"""
import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.ensemble_verdict_engine import EnsembleVerdictEngine


class TestEnsembleEngine:
    """Test ensemble verdict logic"""

    @pytest.fixture
    def engine(self):
        """Create engine instance for testing"""
        return EnsembleVerdictEngine(use_ollama=False)  # Disable LLM for unit tests

    def test_high_confidence_malicious(self, engine):
        """Test high-confidence malicious verdict"""
        email_data = {
            "email_id": "test-001",
            "subject": "Urgent: Wire Transfer Required",
            "from": "ceo@suspicious-domain.com",
            "authentication": {
                "spf": "Fail",
                "dkim": "Fail",
                "dmarc": "Fail"
            },
            "bcl": 9,
            "urls": [{"url": "http://malicious-site.com", "threat": "Phishing"}],
            "attachments": []
        }

        verdict = engine.get_verdict(email_data)

        assert verdict["verdict"] in ["MALICIOUS", "SUSPICIOUS"]
        assert verdict["confidence"] > 0.75
        assert verdict["action"] in ["Block", "Analyst Review"]

    def test_clean_internal_email(self, engine):
        """Test clean internal email verdict"""
        email_data = {
            "email_id": "test-002",
            "subject": "Team Meeting Notes",
            "from": "colleague@example.com",
            "authentication": {
                "spf": "Pass",
                "dkim": "Pass",
                "dmarc": "Pass"
            },
            "bcl": 0,
            "urls": [],
            "attachments": []
        }

        verdict = engine.get_verdict(email_data)

        assert verdict["verdict"] == "CLEAN"
        assert verdict["confidence"] > 0.5
        assert verdict["action"] in ["Allow", "Auto-Resolve"]

    def test_suspicious_email_analyst_review(self, engine):
        """Test suspicious email routed to analyst"""
        email_data = {
            "email_id": "test-003",
            "subject": "Invoice Payment",
            "from": "vendor@unknown-domain.com",
            "authentication": {
                "spf": "Pass",
                "dkim": "None",
                "dmarc": "Fail"
            },
            "bcl": 5,
            "urls": [{"url": "http://invoice-portal.com", "threat": None}],
            "attachments": [{"filename": "invoice.pdf", "threat": None}]
        }

        verdict = engine.get_verdict(email_data)

        # Should be flagged for review due to mixed signals
        assert verdict["action"] == "Analyst Review"
        assert 0.40 <= verdict["confidence"] <= 0.85

    def test_ensemble_weights(self, engine):
        """Test that ensemble weights are properly configured"""
        # Engine should have 50/50 weighting (or configured weights)
        assert hasattr(engine, "weights") or hasattr(engine, "config")
        # Confidence scores should be between 0 and 1
        assert 0.0 <= engine.thresholds.get("malicious", 0.75) <= 1.0

    def test_decision_factors_present(self, engine):
        """Test that decision factors are included in verdict"""
        email_data = {
            "email_id": "test-004",
            "subject": "Test",
            "from": "test@example.com",
            "authentication": {
                "spf": "Pass",
                "dkim": "Pass",
                "dmarc": "Pass"
            },
            "bcl": 3,
            "urls": [],
            "attachments": []
        }

        verdict = engine.get_verdict(email_data)

        # Should include decision factors for transparency
        assert "decision_factors" in verdict or "reasoning" in verdict


class TestRulesEngine:
    """Test rules-based scoring logic"""

    @pytest.fixture
    def engine(self):
        """Create engine with rules-only mode"""
        return EnsembleVerdictEngine(use_ollama=False)

    def test_authentication_failure_negative_score(self, engine):
        """Test that auth failures reduce score"""
        fail_email = {
            "email_id": "test-005",
            "subject": "Test",
            "from": "test@example.com",
            "authentication": {
                "spf": "Fail",
                "dkim": "Fail",
                "dmarc": "Fail"
            },
            "bcl": 0,
            "urls": [],
            "attachments": []
        }

        pass_email = {
            "email_id": "test-006",
            "subject": "Test",
            "from": "test@example.com",
            "authentication": {
                "spf": "Pass",
                "dkim": "Pass",
                "dmarc": "Pass"
            },
            "bcl": 0,
            "urls": [],
            "attachments": []
        }

        fail_verdict = engine.get_verdict(fail_email)
        pass_verdict = engine.get_verdict(pass_email)

        # Failed auth should have lower confidence than passed auth
        assert fail_verdict["confidence"] < pass_verdict["confidence"]

    def test_high_bcl_negative_impact(self, engine):
        """Test that high BCL reduces confidence in clean verdict"""
        high_bcl_email = {
            "email_id": "test-007",
            "subject": "Test",
            "from": "test@example.com",
            "authentication": {
                "spf": "Pass",
                "dkim": "Pass",
                "dmarc": "Pass"
            },
            "bcl": 9,
            "urls": [],
            "attachments": []
        }

        low_bcl_email = {
            "email_id": "test-008",
            "subject": "Test",
            "from": "test@example.com",
            "authentication": {
                "spf": "Pass",
                "dkim": "Pass",
                "dmarc": "Pass"
            },
            "bcl": 0,
            "urls": [],
            "attachments": []
        }

        high_verdict = engine.get_verdict(high_bcl_email)
        low_verdict = engine.get_verdict(low_bcl_email)

        # High BCL should reduce confidence or increase malicious verdict
        assert (high_verdict["verdict"] != "CLEAN") or \
               (high_verdict["confidence"] < low_verdict["confidence"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
