#!/usr/bin/env python3
"""
Summarize test results from multiple datasets.
"""
import json
import sys
from pathlib import Path
import pandas as pd

def load_results(results_dir):
    """Load all JSON result files"""
    results = []
    for json_file in Path(results_dir).glob("*.json"):
        try:
            with open(json_file) as f:
                data = json.load(f)
                data['source_file'] = json_file.name
                results.append(data)
        except Exception as e:
            print(f"Error loading {json_file}: {e}")
    return results

def print_summary(results):
    """Print formatted summary table"""
    if not results:
        print("No results found")
        return

    print("\n" + "="*100)
    print(" COMPREHENSIVE DATASET VALIDATION RESULTS")
    print("="*100)

    # Create summary table
    data = []
    for r in results:
        data.append({
            'Dataset': r.get('dataset_name', r.get('source_file', 'Unknown')),
            'Total': r.get('total_emails', 0),
            'Accuracy': f"{r.get('accuracy', 0):.2%}",
            'Precision': f"{r.get('precision', 0):.2%}",
            'Recall': f"{r.get('recall', 0):.2%}",
            'F1 Score': f"{r.get('f1_score', 0):.2%}",
            'Auto %': f"{r.get('automation_rate', 0):.1%}",
            'Avg Time': f"{r.get('avg_processing_time', 0):.3f}s"
        })

    df = pd.DataFrame(data)
    print("\n" + df.to_string(index=False))

    # Print aggregates
    print("\n" + "="*100)
    print(" AGGREGATE STATISTICS")
    print("="*100)

    total_emails = sum(r.get('total_emails', 0) for r in results)
    avg_accuracy = sum(r.get('accuracy', 0) for r in results) / len(results)
    avg_precision = sum(r.get('precision', 0) for r in results) / len(results)
    avg_recall = sum(r.get('recall', 0) for r in results) / len(results)
    avg_f1 = sum(r.get('f1_score', 0) for r in results) / len(results)

    print(f"\nDatasets Tested: {len(results)}")
    print(f"Total Emails: {total_emails:,}")
    print(f"Average Accuracy: {avg_accuracy:.2%}")
    print(f"Average Precision: {avg_precision:.2%}")
    print(f"Average Recall: {avg_recall:.2%}")
    print(f"Average F1 Score: {avg_f1:.2%}")
    print("="*100 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python summarize_results.py <results_directory>")
        sys.exit(1)

    results_dir = sys.argv[1]
    if not Path(results_dir).exists():
        print(f"Error: Directory not found: {results_dir}")
        sys.exit(1)

    results = load_results(results_dir)
    print_summary(results)
