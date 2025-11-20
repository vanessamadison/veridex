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
        """
        Initialize evaluator

        Args:
            email_parser: EmailParser instance
            ensemble_engine: StandaloneEnsembleEngine instance
            metrics_calculator: MetricsCalculator instance
        """
        self.parser = email_parser
        self.engine = ensemble_engine
        self.metrics = metrics_calculator

    def evaluate_dataset(
        self,
        dataset_path: str,
        ground_truth_file: str,
        max_emails: int = None,
        use_ollama: bool = True
    ) -> Dict[str, Any]:
        """
        Evaluate system on a dataset

        Args:
            dataset_path: Path to directory with .eml files
            ground_truth_file: CSV with columns: filename, verdict (malicious/clean)
            max_emails: Limit number of emails to process
            use_ollama: Whether to use LLM component

        Returns:
            Evaluation results with metrics
        """
        logger.info(f"Evaluating dataset: {dataset_path}")
        logger.info(f"Ground truth: {ground_truth_file}")

        # Load ground truth
        try:
            ground_truth = pd.read_csv(ground_truth_file)
            logger.info(f"Loaded {len(ground_truth)} ground truth labels")
        except Exception as e:
            logger.error(f"Failed to load ground truth file: {e}")
            raise

        # Reset metrics
        self.metrics.reset()

        # Process each email
        results = []
        errors = []
        misclassifications = []

        dataset_dir = Path(dataset_path)
        email_files = list(dataset_dir.glob("*.eml")) + list(dataset_dir.glob("*"))
        email_files = [f for f in email_files if f.is_file() and not f.name.startswith('.')]

        if max_emails:
            email_files = email_files[:max_emails]

        logger.info(f"Found {len(email_files)} email files to process")

        for i, email_file in enumerate(email_files, 1):
            try:
                # Parse email
                logger.debug(f"Parsing {email_file.name}")
                email_metadata = self.parser.parse_file(str(email_file))

                # Generate verdict
                logger.debug(f"Generating verdict for {email_file.name}")
                verdict_result = self.engine.make_verdict(email_metadata, use_ollama=use_ollama)

                # Get ground truth
                gt_row = ground_truth[ground_truth["filename"] == email_file.name]
                if gt_row.empty:
                    # Try without extension
                    base_name = email_file.stem
                    gt_row = ground_truth[ground_truth["filename"] == base_name]

                if gt_row.empty:
                    logger.warning(f"No ground truth for {email_file.name}, skipping")
                    continue

                ground_truth_verdict = gt_row.iloc[0]["verdict"].upper()  # "MALICIOUS" or "CLEAN"
                predicted_verdict = verdict_result["verdict"]

                # Update metrics
                self.metrics.update(predicted_verdict, ground_truth_verdict)

                # Track results
                result_entry = {
                    "filename": email_file.name,
                    "ground_truth": ground_truth_verdict,
                    "predicted": predicted_verdict,
                    "confidence": verdict_result["confidence"],
                    "ensemble_score": verdict_result["ensemble_score"],
                    "subject": email_metadata.get("Subject", "")[:50]
                }
                results.append(result_entry)

                # Track misclassifications
                if predicted_verdict != ground_truth_verdict:
                    misclass = result_entry.copy()
                    misclass["primary_indicators"] = verdict_result.get("primary_indicators", [])
                    misclass["reasoning"] = verdict_result.get("reasoning", "")[:200]
                    misclassifications.append(misclass)

                    logger.debug(f"Misclassification: {email_file.name} - GT: {ground_truth_verdict}, Predicted: {predicted_verdict}")

                if i % 10 == 0:
                    logger.info(f"Processed {i}/{len(email_files)} emails")

            except Exception as e:
                logger.error(f"Error processing {email_file.name}: {e}")
                errors.append({"filename": email_file.name, "error": str(e)})

        # Calculate final metrics
        final_metrics = self.metrics.calculate_metrics()
        confusion_matrix = self.metrics.confusion_matrix()

        logger.info(f"\nEvaluation complete!")
        logger.info(f"Processed: {len(results)} emails")
        logger.info(f"Errors: {len(errors)}")
        logger.info(f"Misclassifications: {len(misclassifications)}")

        return {
            "dataset_path": dataset_path,
            "ground_truth_file": ground_truth_file,
            "total_emails": len(results),
            "metrics": final_metrics,
            "confusion_matrix": confusion_matrix,
            "results": results,
            "misclassifications": misclassifications,
            "errors": errors,
            "timestamp": datetime.now().isoformat(),
            "config": {
                "use_ollama": use_ollama,
                "weights": self.engine.weights if hasattr(self.engine, 'weights') else {}
            }
        }

    def generate_report(self, results: Dict, output_path: str):
        """
        Generate evaluation report

        Args:
            results: Results dictionary from evaluate_dataset
            output_path: Path to save JSON report
        """
        # Save JSON
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

        # Print summary
        print("\n" + "="*60)
        print("EVALUATION RESULTS")
        print("="*60)
        print(f"Dataset: {results['dataset_path']}")
        print(f"Total Emails: {results['total_emails']}")
        print(f"\nMetrics:")
        print(f"  Precision:          {results['metrics']['precision']:.2%}")
        print(f"  Recall:             {results['metrics']['recall']:.2%}")
        print(f"  F1 Score:           {results['metrics']['f1_score']:.2%}")
        print(f"  Accuracy:           {results['metrics']['accuracy']:.2%}")
        print(f"  False Positive Rate: {results['metrics']['false_positive_rate']:.2%}")
        print(f"  False Negative Rate: {results['metrics']['false_negative_rate']:.2%}")
        print(f"\nConfusion Matrix:")
        print(f"  True Positives:  {results['confusion_matrix']['true_positives']:4d}")
        print(f"  False Positives: {results['confusion_matrix']['false_positives']:4d}")
        print(f"  True Negatives:  {results['confusion_matrix']['true_negatives']:4d}")
        print(f"  False Negatives: {results['confusion_matrix']['false_negatives']:4d}")
        print(f"\nMisclassifications: {len(results['misclassifications'])}")
        if results['misclassifications']:
            print("\nTop 5 Misclassifications:")
            for i, misclass in enumerate(results['misclassifications'][:5], 1):
                print(f"  {i}. {misclass['filename']}")
                print(f"     GT: {misclass['ground_truth']}, Predicted: {misclass['predicted']}")
                print(f"     Subject: {misclass['subject']}")
        print(f"\nErrors: {len(results['errors'])}")
        print("="*60)
        print(f"\nReport saved to: {output_path}")

        logger.info(f"Report saved to {output_path}")

    def generate_csv_report(self, results: Dict, output_path: str):
        """Generate CSV report of all verdicts"""
        csv_data = []
        for result in results['results']:
            csv_data.append({
                'filename': result['filename'],
                'ground_truth': result['ground_truth'],
                'predicted': result['predicted'],
                'match': result['predicted'] == result['ground_truth'],
                'confidence': result['confidence'],
                'ensemble_score': result['ensemble_score'],
                'subject': result['subject']
            })

        df = pd.DataFrame(csv_data)
        csv_output = output_path.replace('.json', '.csv')
        df.to_csv(csv_output, index=False)
        logger.info(f"CSV report saved to {csv_output}")


def test_evaluator():
    """Test standalone evaluator"""
    print("Testing StandaloneEvaluator...")
    print("(This is a unit test, not a full dataset evaluation)")

    from src.datasets.email_parser import EmailParser
    from src.core.standalone_ensemble_engine import StandaloneEnsembleEngine
    from src.evaluation.metrics_calculator import MetricsCalculator

    # Initialize components
    parser = EmailParser()
    engine = StandaloneEnsembleEngine(ollama_client=None)
    metrics = MetricsCalculator()

    evaluator = StandaloneEvaluator(parser, engine, metrics)

    print("\n✓ StandaloneEvaluator initialized successfully")
    print("  - EmailParser: Ready")
    print("  - EnsembleEngine: Ready (Ollama disabled for test)")
    print("  - MetricsCalculator: Ready")
    print("\nTo run full evaluation, use standalone_triage.py with a dataset")


if __name__ == "__main__":
    test_evaluator()
