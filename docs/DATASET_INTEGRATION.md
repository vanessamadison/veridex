# Phishing Dataset Integration Architecture

**Version:** 1.0
**Last Updated:** 2025-11-19
**Purpose:** Enable external validation using established public phishing datasets

---

## Overview

To ensure the phishing analyst system's accuracy can be externally validated, this document outlines the architecture for integrating established public phishing datasets and quantifying efficacy metrics (precision, recall, F1 score).

---

## Established Phishing Datasets

### Primary Datasets for Integration

| Dataset | Type | Size | Key Features | Use Case |
|---------|------|------|--------------|----------|
| **CEAS_08** | Conference corpus | ~50K emails | Spam/ham classification, headers | Baseline testing |
| **Enron** | Legitimate business | 500K+ emails | Real corporate email patterns | False positive testing |
| **Ling Spam** | Spam/ham | ~2,900 emails | Spam vs. legitimate | Binary classification |
| **Nazario Phishing** | Phishing corpus | ~4,000 emails | Real phishing samples, complete headers | Phishing detection |
| **Nigerian_5 / Nigerian_Fraud** | 419 scams | ~1,000 emails | Advance-fee fraud patterns | BEC detection |
| **SpamAssassin** | Public corpus | 6K-9K per set | Complete headers, labeled spam/ham | Comprehensive testing |
| **TREC_05/06/07** | Evaluation datasets | ~75K emails | Standardized spam benchmarks | Comparative analysis |

### Dataset Access

**Public Repositories:**
- CEAS_08: http://ceas.cc/2008/
- Enron: https://www.cs.cmu.edu/~enron/
- Ling Spam: http://www.aueb.gr/users/ion/data/lingspam_public.tar.gz
- Nazario: https://monkey.org/~jose/phishing/
- SpamAssassin: https://spamassassin.apache.org/old/publiccorpus/
- TREC: https://trec.nist.gov/data/spam.html

---

## Integration Architecture

### Proposed Directory Structure

```
data/
├── established_datasets/
│   ├── ceas_08/
│   │   ├── raw/                    # Original dataset files
│   │   ├── normalized/             # Converted to MDO format
│   │   └── metadata.yaml           # Dataset info and labels
│   ├── enron/
│   │   ├── raw/
│   │   ├── normalized/
│   │   └── metadata.yaml
│   ├── ling_spam/
│   ├── nazario_phishing/
│   ├── nigerian_fraud/
│   ├── spamassassin/
│   └── trec_05_06_07/
├── ground_truth/
│   └── dataset_labels.csv          # Consolidated ground truth labels
└── results/
    └── dataset_evaluations/
        ├── ceas_08_results.json
        ├── enron_results.json
        └── comparative_analysis.json
```

### Dataset Normalizer

**File to create:** `src/datasets/dataset_normalizer.py`

#### Purpose
Convert various dataset formats to standardized MDO-compatible format

#### Key Functions

```python
class DatasetNormalizer:
    """
    Convert public phishing datasets to MDO email entity format
    for consistent triage evaluation
    """

    def normalize_email(self, raw_email: str, dataset_source: str) -> Dict[str, Any]:
        """
        Convert raw email to MDO format

        Args:
            raw_email: Raw email text (headers + body)
            dataset_source: Source dataset name

        Returns:
            MDO-compatible email entity dictionary
        """

    def extract_headers(self, email_text: str) -> Dict[str, str]:
        """Extract email headers using Python email library"""

    def extract_authentication(self, headers: Dict) -> Dict[str, str]:
        """
        Extract SPF, DKIM, DMARC from Authentication-Results header

        Note: Many older datasets lack auth headers - default to "None"
        """

    def infer_threat_type(self, dataset_source: str, label: str) -> str:
        """
        Map dataset label to Defender ThreatTypes

        Examples:
        - "spam" → "Spam"
        - "phishing" → "Phish"
        - "ham" / "legitimate" → "NoThreatsFound"
        - "419" → "Phish" (BEC pattern)
        """

    def extract_urls(self, email_body: str) -> List[Dict]:
        """Extract URLs from email body using regex"""

    def extract_attachments(self, email_obj) -> List[Dict]:
        """Extract attachment metadata from MIME structure"""
```

#### Example Usage

```python
normalizer = DatasetNormalizer()

# Load Nazario phishing email
with open("data/established_datasets/nazario_phishing/raw/email_001.txt") as f:
    raw_email = f.read()

# Normalize to MDO format
mdo_email = normalizer.normalize_email(raw_email, dataset_source="nazario_phishing")

# Result:
{
    "EmailId": "nazario_phishing_001",
    "Subject": "Your PayPal Account Has Been Limited",
    "SenderFromAddress": "service@paypal-security.com",
    "SenderFromDomain": "paypal-security.com",
    "ThreatTypes": ["Phish"],  # From dataset ground truth
    "SPF": "None",  # Older emails lack SPF
    "DKIM": "None",
    "DMARC": "None",
    "GroundTruth": "phishing",  # Original label
    "DatasetSource": "nazario_phishing",
    "Urls": [...],
    "Attachments": [...]
}
```

### Ground Truth Manager

**File to create:** `src/datasets/ground_truth_manager.py`

#### Purpose
Manage dataset labels and provide ground truth for evaluation

```python
class GroundTruthManager:
    """
    Manage ground truth labels for dataset evaluation
    """

    def __init__(self, ground_truth_path: str = "data/ground_truth/dataset_labels.csv"):
        """Load ground truth labels from CSV"""

    def get_label(self, email_id: str, dataset_source: str) -> str:
        """
        Get ground truth label for an email

        Returns: "malicious" | "clean" | "spam"
        """

    def map_to_system_verdict(self, dataset_label: str, dataset_source: str) -> str:
        """
        Map dataset-specific labels to system verdicts

        Examples:
        - "spam" → "SUSPICIOUS" (for datasets where spam != phishing)
        - "phishing" → "MALICIOUS"
        - "ham" / "legitimate" → "CLEAN"
        - "malware" → "MALICIOUS"
        """

    def export_ground_truth(self, output_path: str):
        """Export consolidated ground truth labels"""
```

#### Ground Truth CSV Format

```csv
email_id,dataset_source,original_label,system_verdict,notes
nazario_phishing_001,nazario_phishing,phishing,MALICIOUS,PayPal credential harvesting
enron_001,enron,ham,CLEAN,Legitimate business email
spamassassin_001,spamassassin,spam,SUSPICIOUS,Bulk advertisement
```

---

## Efficacy Quantification System

### Metrics Calculator

**File to create:** `src/evaluation/metrics_calculator.py`

#### Core Metrics

```python
class MetricsCalculator:
    """
    Calculate precision, recall, F1, and other efficacy metrics
    for dataset evaluation
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
        # Treat SUSPICIOUS as requiring review (conservative)
        predicted_malicious = predicted_verdict in ["MALICIOUS", "SUSPICIOUS"]
        actual_malicious = ground_truth == "MALICIOUS"

        if predicted_malicious and actual_malicious:
            self.tp += 1
        elif predicted_malicious and not actual_malicious:
            self.fp += 1
        elif not predicted_malicious and not actual_malicious:
            self.tn += 1
        else:  # not predicted_malicious and actual_malicious
            self.fn += 1

    def calculate_metrics(self) -> Dict[str, float]:
        """
        Calculate all metrics

        Returns:
            {
                "precision": TP / (TP + FP),
                "recall": TP / (TP + FN),
                "f1_score": 2 * (precision * recall) / (precision + recall),
                "accuracy": (TP + TN) / (TP + TN + FP + FN),
                "false_positive_rate": FP / (FP + TN),
                "false_negative_rate": FN / (FN + TP),
                "specificity": TN / (TN + FP)
            }
        """

    def confusion_matrix(self) -> Dict[str, int]:
        """Return confusion matrix"""
        return {
            "true_positives": self.tp,
            "false_positives": self.fp,
            "true_negatives": self.tn,
            "false_negatives": self.fn
        }

    def classification_report(self) -> str:
        """Generate sklearn-style classification report"""
```

#### Target Metrics (from RESEARCH_CONSIDERATIONS.md)

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| **Precision** | > 95% | Do not accept < 90% |
| **Recall** | > 85% | Do not accept < 80% |
| **F1 Score** | > 90% | Do not accept < 85% |
| **False Positive Rate** | < 5% | Do not accept > 10% |
| **False Negative Rate** | < 2% | Do not accept > 5% |
| **Accuracy** | > 90% | Do not accept < 85% |

**Rationale:**
- **False Negatives** are more costly (missed phishing) → Prioritize recall
- **False Positives** impact productivity (legitimate emails blocked) → Maintain precision
- Healthcare context requires high confidence → Conservative thresholds

### Resource Utilization Metrics

```python
class ResourceMetrics:
    """
    Track computational resources used during evaluation
    """

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.ollama_calls = 0
        self.ollama_time_total = 0.0
        self.memory_peak_mb = 0.0

    def start_tracking(self):
        """Begin tracking resources"""

    def stop_tracking(self):
        """Stop tracking and calculate totals"""

    def get_metrics(self) -> Dict[str, Any]:
        """
        Return resource metrics

        Returns:
            {
                "total_time_seconds": float,
                "avg_time_per_email": float,
                "ollama_calls": int,
                "avg_ollama_time": float,
                "memory_peak_mb": float,
                "throughput_emails_per_second": float
            }
        """
```

---

## Dataset Evaluation Pipeline

### Evaluation Runner

**File to create:** `src/evaluation/dataset_evaluator.py`

```python
class DatasetEvaluator:
    """
    Run triage system against established datasets
    and quantify efficacy
    """

    def __init__(
        self,
        ensemble_engine: EnsembleVerdictEngine,
        ground_truth_manager: GroundTruthManager,
        metrics_calculator: MetricsCalculator,
        resource_metrics: ResourceMetrics
    ):
        """Initialize evaluator with required components"""

    def evaluate_dataset(
        self,
        dataset_name: str,
        dataset_path: str,
        use_ollama: bool = True,
        batch_size: int = 100
    ) -> Dict[str, Any]:
        """
        Evaluate system against a single dataset

        Args:
            dataset_name: Name of dataset (e.g., "nazario_phishing")
            dataset_path: Path to normalized dataset
            use_ollama: Whether to use LLM component (disable for faster testing)
            batch_size: Number of emails to process in each batch

        Returns:
            {
                "dataset_name": str,
                "total_emails": int,
                "metrics": {...},  # Precision, recall, F1, etc.
                "confusion_matrix": {...},
                "resource_usage": {...},
                "errors": List[Dict],  # Emails that caused errors
                "misclassifications": List[Dict],  # FP and FN details
                "component_analysis": {
                    "ollama_only": {...},
                    "rules_only": {...},
                    "defender_only": {...},
                    "ensemble": {...}
                }
            }
        """

    def evaluate_all_datasets(self, datasets_dir: str) -> Dict[str, Any]:
        """
        Evaluate against all datasets in directory

        Returns comparative analysis across datasets
        """

    def generate_report(self, results: Dict, output_path: str):
        """
        Generate comprehensive evaluation report

        Outputs:
        - JSON results file
        - CSV with per-email verdicts
        - Markdown summary report
        - Confusion matrix visualization
        """
```

### Comparative Analysis

```python
class ComparativeAnalyzer:
    """
    Compare system performance across datasets
    """

    def compare_datasets(self, results: List[Dict]) -> Dict[str, Any]:
        """
        Compare metrics across multiple datasets

        Returns:
            {
                "aggregate_metrics": {
                    "precision": float,  # Weighted average
                    "recall": float,
                    "f1_score": float
                },
                "per_dataset_metrics": {...},
                "best_dataset": str,
                "worst_dataset": str,
                "variance_analysis": {...}
            }
        """

    def component_ablation(self, results: Dict) -> Dict[str, Any]:
        """
        Analyze contribution of each ensemble component

        Compare:
        - Ollama-only performance
        - Rules-only performance
        - Defender-only performance
        - Full ensemble performance
        """
```

---

## Usage Examples

### Example 1: Evaluate Single Dataset

```python
from src.datasets.dataset_normalizer import DatasetNormalizer
from src.datasets.ground_truth_manager import GroundTruthManager
from src.evaluation.metrics_calculator import MetricsCalculator, ResourceMetrics
from src.evaluation.dataset_evaluator import DatasetEvaluator
from src.core.ensemble_verdict_engine import EnsembleVerdictEngine
from src.core.ollama_client import OllamaSecurityAnalyst

# Initialize components
normalizer = DatasetNormalizer()
ground_truth = GroundTruthManager()
metrics = MetricsCalculator()
resources = ResourceMetrics()

ollama = OllamaSecurityAnalyst(model="mistral")
engine = EnsembleVerdictEngine(ollama)

evaluator = DatasetEvaluator(engine, ground_truth, metrics, resources)

# Evaluate Nazario phishing dataset
results = evaluator.evaluate_dataset(
    dataset_name="nazario_phishing",
    dataset_path="data/established_datasets/nazario_phishing/normalized/",
    use_ollama=True
)

# Print results
print(f"Precision: {results['metrics']['precision']:.2%}")
print(f"Recall: {results['metrics']['recall']:.2%}")
print(f"F1 Score: {results['metrics']['f1_score']:.2%}")
print(f"Processing time: {results['resource_usage']['total_time_seconds']:.2f}s")
print(f"Throughput: {results['resource_usage']['throughput_emails_per_second']:.2f} emails/sec")

# Generate report
evaluator.generate_report(results, "results/dataset_evaluations/nazario_phishing_report.json")
```

### Example 2: Comparative Analysis Across All Datasets

```python
# Evaluate all datasets
all_results = evaluator.evaluate_all_datasets("data/established_datasets/")

# Comparative analysis
analyzer = ComparativeAnalyzer()
comparison = analyzer.compare_datasets(all_results)

print("Aggregate Performance:")
print(f"  Precision: {comparison['aggregate_metrics']['precision']:.2%}")
print(f"  Recall: {comparison['aggregate_metrics']['recall']:.2%}")
print(f"  F1 Score: {comparison['aggregate_metrics']['f1_score']:.2%}")

print("\nPer-Dataset Performance:")
for dataset, metrics in comparison['per_dataset_metrics'].items():
    print(f"  {dataset}: F1={metrics['f1_score']:.2%}")

print(f"\nBest performing dataset: {comparison['best_dataset']}")
print(f"Worst performing dataset: {comparison['worst_dataset']}")
```

### Example 3: Ablation Study

```python
# Evaluate with different component configurations
configs = [
    {"ollama": 1.0, "rules": 0.0, "defender": 0.0},  # LLM only
    {"ollama": 0.0, "rules": 1.0, "defender": 0.0},  # Rules only
    {"ollama": 0.0, "rules": 0.0, "defender": 1.0},  # Defender only
    {"ollama": 0.40, "rules": 0.30, "defender": 0.30},  # Default ensemble
    {"ollama": 0.60, "rules": 0.20, "defender": 0.20},  # LLM-heavy
    {"ollama": 0.20, "rules": 0.40, "defender": 0.40},  # Rules+Defender-heavy
]

results = []
for config in configs:
    engine = EnsembleVerdictEngine(ollama, weights=config)
    evaluator = DatasetEvaluator(engine, ground_truth, MetricsCalculator(), ResourceMetrics())

    result = evaluator.evaluate_dataset("nazario_phishing", "data/established_datasets/nazario_phishing/normalized/")
    result["config"] = config
    results.append(result)

# Analyze which configuration performs best
analyzer = ComparativeAnalyzer()
ablation_analysis = analyzer.component_ablation(results)
```

---

## Implementation Roadmap

### Phase 1: Data Preparation (Week 1)

- [ ] Download public datasets (CEAS_08, Enron, Nazario, SpamAssassin)
- [ ] Create `data/established_datasets/` directory structure
- [ ] Implement `DatasetNormalizer` class
- [ ] Normalize 1-2 datasets as proof of concept
- [ ] Create ground truth CSV with labels

### Phase 2: Metrics Infrastructure (Week 1-2)

- [ ] Implement `MetricsCalculator` class
- [ ] Implement `ResourceMetrics` class
- [ ] Implement `GroundTruthManager` class
- [ ] Unit tests for metrics calculation

### Phase 3: Evaluation Pipeline (Week 2)

- [ ] Implement `DatasetEvaluator` class
- [ ] Implement `ComparativeAnalyzer` class
- [ ] Create report generation templates (JSON, CSV, Markdown)
- [ ] Integration tests with normalized datasets

### Phase 4: Validation (Week 3)

- [ ] Run evaluation on all datasets
- [ ] Analyze results and identify gaps
- [ ] Tune ensemble weights if needed
- [ ] Document findings in research paper

### Phase 5: Continuous Integration (Week 4)

- [ ] Add dataset evaluation to CI/CD pipeline
- [ ] Set up automated regression testing
- [ ] Create dataset evaluation dashboard
- [ ] Establish performance baselines

---

## Expected Outcomes

### Quantified Efficacy

After implementing this architecture, you will have:

1. **Precision, Recall, F1 Scores** for each dataset
2. **Comparative analysis** showing which datasets the system handles best/worst
3. **Resource usage metrics** (time, memory, throughput)
4. **Ablation study results** showing contribution of each ensemble component
5. **Reproducible benchmarks** for future improvements

### External Validation

Results can be compared to published research:

| Dataset | Published Baseline | Our System Target |
|---------|-------------------|-------------------|
| SpamAssassin | F1: 92-95% (Naive Bayes) | F1: > 90% |
| Nazario Phishing | Precision: 88-92% (Various ML) | Precision: > 95% |
| TREC Spam | Accuracy: 90-94% (Ensemble methods) | Accuracy: > 90% |

### Research Publication Support

This quantification enables:
- **Academic papers** with reproducible results
- **Conference presentations** with comparative benchmarks
- **Open-source credibility** via public dataset validation
- **Compliance audits** with documented accuracy metrics

---

## Maintenance and Updates

### Dataset Refresh

Public datasets should be re-evaluated:
- **Quarterly:** Check for dataset updates
- **After system changes:** Re-run evaluations to detect regressions
- **New datasets:** Integrate emerging phishing corpora

### Metric Tracking

Track performance over time:
- Maintain historical evaluation results
- Plot metric trends (precision, recall, F1)
- Alert on performance degradation

---

**Document Version:** 1.0
**Status:** Design Complete - Implementation Pending
**Dependencies:** Requires verdict transparency documentation
**Next Steps:** Implement Phase 1 (Data Preparation)
