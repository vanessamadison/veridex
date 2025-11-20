#!/usr/bin/env python3
"""
Standalone Phishing Triage System
Works with public datasets, no Microsoft Defender required

Usage:
    python standalone_triage.py --dataset data/spam --ground-truth data/spam/ground_truth.csv

Examples:
    # Basic evaluation
    python standalone_triage.py \
        --dataset data/spamassassin/spam \
        --ground-truth data/spamassassin/ground_truth.csv

    # Rules-only mode (faster, no LLM)
    python standalone_triage.py \
        --dataset data/spamassassin/spam \
        --ground-truth data/spamassassin/ground_truth.csv \
        --no-llm

    # With threat intelligence
    python standalone_triage.py \
        --dataset data/nazario_phishing \
        --ground-truth data/nazario_phishing/ground_truth.csv \
        --threat-intel \
        --otx-key YOUR_KEY
"""
import argparse
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.datasets.email_parser import EmailParser
from src.core.standalone_ensemble_engine import StandaloneEnsembleEngine
from src.evaluation.standalone_evaluator import StandaloneEvaluator
from src.evaluation.metrics_calculator import MetricsCalculator


def main():
    parser = argparse.ArgumentParser(
        description="Standalone Phishing Triage System - No Defender Required",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Evaluate with LLM (default)
  python standalone_triage.py --dataset data/spam --ground-truth data/spam/labels.csv

  # Rules-only mode (faster)
  python standalone_triage.py --dataset data/spam --ground-truth data/spam/labels.csv --no-llm

  # Limit number of emails
  python standalone_triage.py --dataset data/spam --ground-truth data/spam/labels.csv --max-emails 50

  # Custom output location
  python standalone_triage.py --dataset data/spam --ground-truth data/spam/labels.csv --output results/my_test.json
        """
    )

    parser.add_argument("--dataset", required=True, help="Path to dataset directory (.eml files)")
    parser.add_argument("--ground-truth", required=True, help="Path to ground truth CSV")
    parser.add_argument("--output", default="results/standalone_evaluation.json", help="Output file path")
    parser.add_argument("--max-emails", type=int, help="Max emails to process (for testing)")
    parser.add_argument("--no-llm", action="store_true", help="Disable Ollama (rules-only mode)")
    parser.add_argument("--threat-intel", action="store_true", help="Enable threat intelligence APIs (future)")

    # Threat intel API keys (for future use)
    parser.add_argument("--otx-key", help="AlienVault OTX API key")
    parser.add_argument("--vt-key", help="VirusTotal API key")

    # Model selection
    parser.add_argument("--model", default="mistral", help="Ollama model to use (default: mistral)")

    args = parser.parse_args()

    # Print header
    print("\n" + "="*60)
    print("STANDALONE PHISHING TRIAGE SYSTEM")
    print("="*60)
    print(f"Dataset:       {args.dataset}")
    print(f"Ground Truth:  {args.ground_truth}")
    print(f"LLM:           {'Disabled (Rules-Only)' if args.no_llm else f'Enabled (Ollama {args.model})'}")
    print(f"Threat Intel:  {'Enabled' if args.threat_intel else 'Disabled'}")
    if args.max_emails:
        print(f"Max Emails:    {args.max_emails}")
    print("="*60 + "\n")

    # Validate inputs
    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"❌ Error: Dataset path does not exist: {args.dataset}")
        sys.exit(1)

    ground_truth_path = Path(args.ground_truth)
    if not ground_truth_path.exists():
        print(f"❌ Error: Ground truth file does not exist: {args.ground_truth}")
        sys.exit(1)

    # Initialize components
    print("Initializing components...")

    # 1. Email Parser
    email_parser = EmailParser()
    print("  ✓ EmailParser initialized")

    # 2. Ollama LLM (optional)
    ollama_client = None
    if not args.no_llm:
        try:
            from src.core.ollama_client import OllamaSecurityAnalyst
            ollama_client = OllamaSecurityAnalyst(model=args.model)
            print(f"  ✓ Ollama initialized (model: {args.model})")
        except Exception as e:
            print(f"  ⚠ Ollama initialization failed: {e}")
            print(f"  → Falling back to rules-only mode")
            ollama_client = None
    else:
        print("  ✓ Ollama disabled (rules-only mode)")

    # 3. Threat Intelligence (optional, future feature)
    threat_intel = None
    if args.threat_intel:
        print("  ⚠ Threat intelligence integration not yet implemented")
        print("  → This will be added in a future update")
        # Future: Initialize ThreatIntelManager here
        # threat_intel = ThreatIntelManager(otx_api_key=args.otx_key, vt_api_key=args.vt_key)

    # 4. Standalone Ensemble Engine
    engine = StandaloneEnsembleEngine(
        ollama_client=ollama_client,
        threat_intel_manager=threat_intel
    )
    print("  ✓ StandaloneEnsembleEngine initialized")

    # 5. Metrics Calculator
    metrics = MetricsCalculator()
    print("  ✓ MetricsCalculator initialized")

    # 6. Evaluator
    evaluator = StandaloneEvaluator(
        email_parser=email_parser,
        ensemble_engine=engine,
        metrics_calculator=metrics
    )
    print("  ✓ StandaloneEvaluator initialized")

    print("\n" + "="*60)
    print("STARTING EVALUATION")
    print("="*60 + "\n")

    # Run evaluation
    try:
        results = evaluator.evaluate_dataset(
            dataset_path=str(dataset_path),
            ground_truth_file=str(ground_truth_path),
            max_emails=args.max_emails,
            use_ollama=(ollama_client is not None)
        )

        # Generate reports
        print("\nGenerating reports...")
        evaluator.generate_report(results, args.output)
        evaluator.generate_csv_report(results, args.output)

        print("\n" + "="*60)
        print("EVALUATION COMPLETE")
        print("="*60)
        print(f"\nResults saved to:")
        print(f"  - JSON: {args.output}")
        print(f"  - CSV:  {args.output.replace('.json', '.csv')}")

        # Print key metrics
        metrics_data = results['metrics']
        print(f"\n🎯 Key Metrics:")
        print(f"  F1 Score:  {metrics_data['f1_score']:.2%}")
        print(f"  Precision: {metrics_data['precision']:.2%}")
        print(f"  Recall:    {metrics_data['recall']:.2%}")

        # Exit with success
        sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n⚠ Evaluation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Evaluation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
