#!/usr/bin/env python3
"""
Unit tests for metrics calculator
Tests precision, recall, F1 score calculations
"""
import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.evaluation.metrics_calculator import MetricsCalculator


class TestMetricsCalculator:
    """Test metrics calculation"""

    @pytest.fixture
    def calculator(self):
        """Create calculator instance"""
        return MetricsCalculator()

    def test_perfect_classification(self, calculator):
        """Test metrics with perfect classification"""
        verdicts = [
            {"email_id": "1", "predicted": "MALICIOUS", "actual": "spam"},
            {"email_id": "2", "predicted": "MALICIOUS", "actual": "spam"},
            {"email_id": "3", "predicted": "CLEAN", "actual": "ham"},
            {"email_id": "4", "predicted": "CLEAN", "actual": "ham"},
        ]

        metrics = calculator.calculate_metrics(verdicts)

        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["f1_score"] == 1.0
        assert metrics["accuracy"] == 1.0

    def test_zero_false_positives(self, calculator):
        """Test precision of 1.0 with zero false positives"""
        verdicts = [
            {"email_id": "1", "predicted": "MALICIOUS", "actual": "spam"},
            {"email_id": "2", "predicted": "MALICIOUS", "actual": "spam"},
            {"email_id": "3", "predicted": "CLEAN", "actual": "ham"},
            {"email_id": "4", "predicted": "CLEAN", "actual": "spam"},  # False negative
        ]

        metrics = calculator.calculate_metrics(verdicts)

        # Precision should be 1.0 (no false positives)
        assert metrics["precision"] == 1.0
        # Recall should be less than 1.0 (missed one spam)
        assert metrics["recall"] < 1.0

    def test_false_positive_rate(self, calculator):
        """Test false positive rate calculation"""
        verdicts = [
            {"email_id": "1", "predicted": "MALICIOUS", "actual": "spam"},
            {"email_id": "2", "predicted": "MALICIOUS", "actual": "ham"},  # False positive
            {"email_id": "3", "predicted": "CLEAN", "actual": "ham"},
            {"email_id": "4", "predicted": "CLEAN", "actual": "ham"},
        ]

        metrics = calculator.calculate_metrics(verdicts)

        # Should have 1 FP out of 3 actual ham
        assert metrics["false_positive_rate"] > 0
        assert metrics["precision"] < 1.0

    def test_confusion_matrix(self, calculator):
        """Test confusion matrix generation"""
        verdicts = [
            {"email_id": "1", "predicted": "MALICIOUS", "actual": "spam"},  # TP
            {"email_id": "2", "predicted": "MALICIOUS", "actual": "ham"},   # FP
            {"email_id": "3", "predicted": "CLEAN", "actual": "spam"},      # FN
            {"email_id": "4", "predicted": "CLEAN", "actual": "ham"},       # TN
        ]

        metrics = calculator.calculate_metrics(verdicts)

        assert metrics["true_positives"] == 1
        assert metrics["false_positives"] == 1
        assert metrics["false_negatives"] == 1
        assert metrics["true_negatives"] == 1

    def test_f1_score_calculation(self, calculator):
        """Test F1 score is harmonic mean of precision and recall"""
        verdicts = [
            {"email_id": "1", "predicted": "MALICIOUS", "actual": "spam"},
            {"email_id": "2", "predicted": "MALICIOUS", "actual": "spam"},
            {"email_id": "3", "predicted": "CLEAN", "actual": "ham"},
            {"email_id": "4", "predicted": "CLEAN", "actual": "spam"},
        ]

        metrics = calculator.calculate_metrics(verdicts)

        precision = metrics["precision"]
        recall = metrics["recall"]
        expected_f1 = 2 * (precision * recall) / (precision + recall)

        assert abs(metrics["f1_score"] - expected_f1) < 0.001

    def test_automation_rate(self, calculator):
        """Test automation rate calculation"""
        verdicts = [
            {"email_id": "1", "predicted": "MALICIOUS", "action": "Block", "confidence": 0.95},
            {"email_id": "2", "predicted": "SUSPICIOUS", "action": "Analyst Review", "confidence": 0.60},
            {"email_id": "3", "predicted": "CLEAN", "action": "Allow", "confidence": 0.90},
            {"email_id": "4", "predicted": "SUSPICIOUS", "action": "Analyst Review", "confidence": 0.55},
        ]

        metrics = calculator.calculate_metrics(verdicts)

        # 2 out of 4 automated (Block + Allow)
        expected_automation = 0.50
        assert abs(metrics.get("automation_rate", 0) - expected_automation) < 0.01

    def test_empty_verdicts(self, calculator):
        """Test handling of empty verdicts list"""
        verdicts = []

        metrics = calculator.calculate_metrics(verdicts)

        # Should handle gracefully, returning 0 or None for metrics
        assert metrics is not None
        assert metrics.get("precision", 0) == 0 or metrics.get("total", 0) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
