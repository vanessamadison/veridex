#!/usr/bin/env python3
"""
Metrics Calculator - Calculate precision, recall, F1, and other efficacy metrics
"""
import logging
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MetricsCalculator:
    """
    Calculate precision, recall, F1, and other efficacy metrics
    for phishing detection evaluation
    """

    def __init__(self):
        self.tp = 0  # True Positives
        self.fp = 0  # False Positives
        self.tn = 0  # True Negatives
        self.fn = 0  # False Negatives

    def update(self, predicted_verdict: str, ground_truth: str):
        """
        Update confusion matrix

        Args:
            predicted_verdict: System verdict (MALICIOUS/SUSPICIOUS/CLEAN)
            ground_truth: Ground truth label (MALICIOUS/CLEAN)
        """
        # Treat SUSPICIOUS as requiring review (conservative approach)
        # For metrics: SUSPICIOUS counts as predicting MALICIOUS
        predicted_malicious = predicted_verdict in ["MALICIOUS", "SUSPICIOUS"]
        actual_malicious = ground_truth == "MALICIOUS"

        if predicted_malicious and actual_malicious:
            self.tp += 1  # Correctly identified threat
        elif predicted_malicious and not actual_malicious:
            self.fp += 1  # False alarm (legitimate email flagged)
        elif not predicted_malicious and not actual_malicious:
            self.tn += 1  # Correctly identified legitimate email
        else:  # not predicted_malicious and actual_malicious
            self.fn += 1  # Missed threat (dangerous!)

    def calculate_metrics(self) -> Dict[str, float]:
        """
        Calculate all metrics

        Returns:
            Dictionary with precision, recall, F1, accuracy, FPR, FNR
        """
        # Precision: Of all emails we flagged, how many were actually malicious?
        # High precision = low false alarm rate
        if (self.tp + self.fp) > 0:
            precision = self.tp / (self.tp + self.fp)
        else:
            precision = 0.0

        # Recall (Sensitivity): Of all malicious emails, how many did we catch?
        # High recall = low miss rate
        if (self.tp + self.fn) > 0:
            recall = self.tp / (self.tp + self.fn)
        else:
            recall = 0.0

        # F1 Score: Harmonic mean of precision and recall
        # Balances precision and recall
        if (precision + recall) > 0:
            f1_score = 2 * (precision * recall) / (precision + recall)
        else:
            f1_score = 0.0

        # Accuracy: Overall correct predictions
        total = self.tp + self.tn + self.fp + self.fn
        if total > 0:
            accuracy = (self.tp + self.tn) / total
        else:
            accuracy = 0.0

        # False Positive Rate: Of all legitimate emails, how many did we falsely flag?
        # Lower is better (avoid alert fatigue)
        if (self.fp + self.tn) > 0:
            false_positive_rate = self.fp / (self.fp + self.tn)
        else:
            false_positive_rate = 0.0

        # False Negative Rate: Of all malicious emails, how many did we miss?
        # Lower is better (security critical!)
        if (self.fn + self.tp) > 0:
            false_negative_rate = self.fn / (self.fn + self.tp)
        else:
            false_negative_rate = 0.0

        # Specificity: Of all legitimate emails, how many did we correctly identify?
        if (self.tn + self.fp) > 0:
            specificity = self.tn / (self.tn + self.fp)
        else:
            specificity = 0.0

        return {
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "accuracy": accuracy,
            "false_positive_rate": false_positive_rate,
            "false_negative_rate": false_negative_rate,
            "specificity": specificity,
            "total_samples": total
        }

    def confusion_matrix(self) -> Dict[str, int]:
        """
        Return confusion matrix

        Returns:
            Dictionary with TP, FP, TN, FN counts
        """
        return {
            "true_positives": self.tp,
            "false_positives": self.fp,
            "true_negatives": self.tn,
            "false_negatives": self.fn
        }

    def classification_report(self) -> str:
        """
        Generate sklearn-style classification report

        Returns:
            Formatted string with metrics
        """
        metrics = self.calculate_metrics()
        cm = self.confusion_matrix()

        report = []
        report.append("=" * 60)
        report.append("CLASSIFICATION REPORT")
        report.append("=" * 60)
        report.append("")
        report.append(f"Precision:          {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        report.append(f"Recall:             {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        report.append(f"F1 Score:           {metrics['f1_score']:.4f} ({metrics['f1_score']*100:.2f}%)")
        report.append(f"Accuracy:           {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        report.append("")
        report.append(f"False Positive Rate: {metrics['false_positive_rate']:.4f} ({metrics['false_positive_rate']*100:.2f}%)")
        report.append(f"False Negative Rate: {metrics['false_negative_rate']:.4f} ({metrics['false_negative_rate']*100:.2f}%)")
        report.append(f"Specificity:        {metrics['specificity']:.4f} ({metrics['specificity']*100:.2f}%)")
        report.append("")
        report.append("=" * 60)
        report.append("CONFUSION MATRIX")
        report.append("=" * 60)
        report.append("")
        report.append(f"True Positives (TP):   {cm['true_positives']:4d}  (Malicious correctly identified)")
        report.append(f"False Positives (FP):  {cm['false_positives']:4d}  (Legitimate incorrectly flagged)")
        report.append(f"True Negatives (TN):   {cm['true_negatives']:4d}  (Legitimate correctly identified)")
        report.append(f"False Negatives (FN):  {cm['false_negatives']:4d}  (Malicious missed - CRITICAL!)")
        report.append("")
        report.append(f"Total Samples:         {metrics['total_samples']:4d}")
        report.append("=" * 60)

        return "\n".join(report)

    def reset(self):
        """Reset all counters"""
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0


def test_metrics_calculator():
    """Test metrics calculator"""
    print("Testing MetricsCalculator...")

    calc = MetricsCalculator()

    # Simulate some predictions
    test_cases = [
        ("MALICIOUS", "MALICIOUS"),  # TP
        ("MALICIOUS", "MALICIOUS"),  # TP
        ("MALICIOUS", "CLEAN"),      # FP
        ("CLEAN", "CLEAN"),          # TN
        ("CLEAN", "CLEAN"),          # TN
        ("CLEAN", "MALICIOUS"),      # FN
        ("SUSPICIOUS", "MALICIOUS"), # TP (SUSPICIOUS counts as MALICIOUS)
        ("SUSPICIOUS", "CLEAN"),     # FP
    ]

    for predicted, actual in test_cases:
        calc.update(predicted, actual)

    # Print report
    print("\n" + calc.classification_report())

    # Verify expected values
    metrics = calc.calculate_metrics()
    cm = calc.confusion_matrix()

    print("\nExpected values:")
    print(f"  TP: 3, FP: 2, TN: 2, FN: 1")
    print(f"\nActual values:")
    print(f"  TP: {cm['true_positives']}, FP: {cm['false_positives']}, TN: {cm['true_negatives']}, FN: {cm['false_negatives']}")

    assert cm['true_positives'] == 3, "TP count mismatch"
    assert cm['false_positives'] == 2, "FP count mismatch"
    assert cm['true_negatives'] == 2, "TN count mismatch"
    assert cm['false_negatives'] == 1, "FN count mismatch"

    print("\n✓ MetricsCalculator test passed!")


if __name__ == "__main__":
    test_metrics_calculator()
