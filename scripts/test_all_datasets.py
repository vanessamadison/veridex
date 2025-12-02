#!/usr/bin/env python3
"""
Comprehensive dataset testing script.

Tests the phishing triage tool across multiple public datasets:
- SpamAssassin (spam_2, easy_ham, hard_ham)
- Ling-Spam
- Nazario
- Combined test dataset
- CEAS_08
- Enron
- TREC datasets

Generates comprehensive results for paper publication.
"""

import subprocess
import sys
import json
import csv
from pathlib import Path
from datetime import datetime
import pandas as pd

# Base directories
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

# Dataset configurations
DATASETS = {
    "spamassassin_spam2": {
        "name": "SpamAssassin Spam Corpus 2",
        "data_dir": DATA_DIR / "spamassassin" / "spam_2",
        "ground_truth": DATA_DIR / "spamassassin" / "ground_truth.csv",
        "expected_label": "spam",
        "size": 1397
    },
    "spamassassin_easy_ham": {
        "name": "SpamAssassin Easy Ham",
        "data_dir": DATA_DIR / "spamassassin" / "easy_ham",
        "ground_truth": DATA_DIR / "spamassassin" / "easy_ham_ground_truth.csv",
        "expected_label": "ham",
        "size": None
    },
    "spamassassin_hard_ham": {
        "name": "SpamAssassin Hard Ham",
        "data_dir": DATA_DIR / "spamassassin" / "hard_ham",
        "ground_truth": DATA_DIR / "spamassassin" / "hard_ham_ground_truth.csv",
        "expected_label": "ham",
        "size": None
    },
    "ling_spam": {
        "name": "Ling-Spam Corpus",
        "data_dir": DATA_DIR / "ling_spam" / "lingspam_public",
        "ground_truth": DATA_DIR / "ling_spam" / "ground_truth.csv",
        "expected_label": "mixed",
        "size": 11573
    },
    "combined_test": {
        "name": "Combined Test Dataset",
        "data_dir": DATA_DIR / "combined_test",
        "ground_truth": DATA_DIR / "combined_test" / "ground_truth.csv",
        "expected_label": "mixed",
        "size": 4383
    },
    "nazario": {
        "name": "Nazario Phishing Corpus",
        "data_dir": DATA_DIR / "nazario",
        "ground_truth": DATA_DIR / "nazario" / "ground_truth.csv",
        "expected_label": "phishing",
        "size": None
    }
}


def check_dataset_exists(dataset_config):
    """Check if dataset exists and has valid ground truth"""
    data_dir = dataset_config["data_dir"]
    ground_truth = dataset_config["ground_truth"]

    if not data_dir.exists():
        return False, f"Data directory not found: {data_dir}"

    if not ground_truth.exists():
        return False, f"Ground truth file not found: {ground_truth}"

    # Check if ground truth has content
    try:
        df = pd.read_csv(ground_truth)
        if len(df) == 0:
            return False, "Ground truth file is empty"
        return True, f"Dataset ready ({len(df)} emails)"
    except Exception as e:
        return False, f"Error reading ground truth: {e}"


def run_triage_test(dataset_key, dataset_config, use_ollama=True):
    """Run triage test on a dataset"""
    print(f"\n{'='*70}")
    print(f"Testing: {dataset_config['name']}")
    print(f"{'='*70}")

    # Check dataset exists
    exists, message = check_dataset_exists(dataset_config)
    if not exists:
        print(f"⚠ SKIPPED: {message}")
        return None

    print(f"✓ {message}")

    # Prepare output paths
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_prefix = RESULTS_DIR / f"{dataset_key}_{timestamp}"
    results_file = f"{output_prefix}_results.json"
    metrics_file = f"{output_prefix}_metrics.csv"

    # Build command
    cmd = [
        sys.executable,
        str(BASE_DIR / "standalone_triage.py"),
        "--dataset", str(dataset_config["data_dir"]),
        "--ground-truth", str(dataset_config["ground_truth"]),
        "--output", results_file,
        "--metrics", metrics_file
    ]

    if use_ollama:
        cmd.append("--use-ollama")

    print(f"\nRunning triage test...")
    print(f"Command: {' '.join(cmd)}")

    try:
        # Run the test
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour timeout
        )

        if result.returncode == 0:
            print("✓ Test completed successfully")

            # Load and display results
            if Path(results_file).exists():
                with open(results_file, 'r') as f:
                    results = json.load(f)

                print("\n" + "="*70)
                print("RESULTS SUMMARY")
                print("="*70)
                print(f"Total Emails: {results.get('total_emails', 'N/A')}")
                print(f"Accuracy: {results.get('accuracy', 'N/A'):.2%}")
                print(f"Precision: {results.get('precision', 'N/A'):.2%}")
                print(f"Recall: {results.get('recall', 'N/A'):.2%}")
                print(f"F1 Score: {results.get('f1_score', 'N/A'):.2%}")
                print(f"Automation Rate: {results.get('automation_rate', 'N/A'):.2%}")
                print(f"Avg Processing Time: {results.get('avg_processing_time', 'N/A'):.3f}s")

                return {
                    "dataset": dataset_key,
                    "name": dataset_config["name"],
                    "results": results,
                    "results_file": results_file,
                    "metrics_file": metrics_file
                }
            else:
                print(f"⚠ Results file not found: {results_file}")
                return None
        else:
            print(f"✗ Test failed with return code {result.returncode}")
            print(f"\nSTDOUT:\n{result.stdout}")
            print(f"\nSTDERR:\n{result.stderr}")
            return None

    except subprocess.TimeoutExpired:
        print("✗ Test timed out after 1 hour")
        return None
    except Exception as e:
        print(f"✗ Test failed with error: {e}")
        return None


def generate_comparison_table(all_results):
    """Generate comparison table across all datasets"""
    if not all_results:
        print("\nNo results to compare")
        return

    print("\n" + "="*70)
    print("COMPREHENSIVE RESULTS COMPARISON")
    print("="*70)

    # Create comparison DataFrame
    comparison_data = []
    for result in all_results:
        r = result["results"]
        comparison_data.append({
            "Dataset": result["name"],
            "Total Emails": r.get("total_emails", 0),
            "Accuracy": f"{r.get('accuracy', 0):.2%}",
            "Precision": f"{r.get('precision', 0):.2%}",
            "Recall": f"{r.get('recall', 0):.2%}",
            "F1 Score": f"{r.get('f1_score', 0):.2%}",
            "Automation Rate": f"{r.get('automation_rate', 0):.2%}",
            "Avg Time (s)": f"{r.get('avg_processing_time', 0):.3f}"
        })

    df = pd.DataFrame(comparison_data)
    print("\n" + df.to_string(index=False))

    # Save to CSV
    comparison_file = RESULTS_DIR / f"dataset_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(comparison_file, index=False)
    print(f"\n✓ Comparison saved to: {comparison_file}")

    # Generate summary statistics
    print("\n" + "="*70)
    print("AGGREGATE STATISTICS")
    print("="*70)
    total_emails = sum(r["results"].get("total_emails", 0) for r in all_results)
    avg_accuracy = sum(r["results"].get("accuracy", 0) for r in all_results) / len(all_results)
    avg_precision = sum(r["results"].get("precision", 0) for r in all_results) / len(all_results)
    avg_recall = sum(r["results"].get("recall", 0) for r in all_results) / len(all_results)
    avg_f1 = sum(r["results"].get("f1_score", 0) for r in all_results) / len(all_results)

    print(f"Total Datasets Tested: {len(all_results)}")
    print(f"Total Emails Processed: {total_emails:,}")
    print(f"Average Accuracy: {avg_accuracy:.2%}")
    print(f"Average Precision: {avg_precision:.2%}")
    print(f"Average Recall: {avg_recall:.2%}")
    print(f"Average F1 Score: {avg_f1:.2%}")


def main():
    """Main testing orchestrator"""
    print("\n" + "="*70)
    print(" COMPREHENSIVE DATASET TESTING")
    print("="*70)
    print(f"\nTesting phishing triage tool across {len(DATASETS)} datasets")
    print(f"Results will be saved to: {RESULTS_DIR}")

    # Check which datasets are available
    print("\n" + "="*70)
    print("DATASET AVAILABILITY CHECK")
    print("="*70)

    available_datasets = []
    for key, config in DATASETS.items():
        exists, message = check_dataset_exists(config)
        status = "✓ READY" if exists else "✗ MISSING"
        print(f"{status:12} {config['name']:40} {message}")
        if exists:
            available_datasets.append(key)

    if not available_datasets:
        print("\n✗ No datasets available for testing")
        print("Run: python scripts/download_datasets.py")
        return 1

    print(f"\n{len(available_datasets)} of {len(DATASETS)} datasets available")

    # Ask user which datasets to test
    print("\nOptions:")
    print("  1. Test all available datasets")
    print("  2. Select specific datasets")
    print("  0. Exit")

    choice = input("\nSelect option (0-2): ").strip()

    datasets_to_test = []

    if choice == '1':
        datasets_to_test = available_datasets
    elif choice == '2':
        print("\nAvailable datasets:")
        for i, key in enumerate(available_datasets, 1):
            print(f"  {i}. {DATASETS[key]['name']}")

        indices = input("\nEnter dataset numbers (comma-separated, e.g., 1,3,5): ").strip()
        try:
            for idx in indices.split(','):
                idx_int = int(idx.strip()) - 1
                if 0 <= idx_int < len(available_datasets):
                    datasets_to_test.append(available_datasets[idx_int])
        except ValueError:
            print("Invalid input")
            return 1
    elif choice == '0':
        print("Exiting...")
        return 0
    else:
        print("Invalid choice")
        return 1

    if not datasets_to_test:
        print("No datasets selected")
        return 1

    # Ask about Ollama
    use_ollama = input("\nUse Ollama LLM for analysis? (y/N): ").strip().lower() == 'y'

    # Run tests
    all_results = []
    for dataset_key in datasets_to_test:
        config = DATASETS[dataset_key]
        result = run_triage_test(dataset_key, config, use_ollama=use_ollama)
        if result:
            all_results.append(result)

    # Generate comparison table
    if all_results:
        generate_comparison_table(all_results)

        print("\n" + "="*70)
        print("TESTING COMPLETE")
        print("="*70)
        print(f"Successfully tested {len(all_results)} datasets")
        print(f"Results saved to: {RESULTS_DIR}")

        return 0
    else:
        print("\n✗ No successful test results")
        return 1


if __name__ == "__main__":
    sys.exit(main())
