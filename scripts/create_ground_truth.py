#!/usr/bin/env python3
"""
Ground Truth Generator
Creates ground truth CSV files from directory structure

Usage:
    # For datasets with spam/ham folders
    python scripts/create_ground_truth.py \
        --spam-dir data/spam \
        --ham-dir data/ham \
        --output data/ground_truth.csv

    # For single folder with manual labels
    python scripts/create_ground_truth.py \
        --input-csv data/manual_labels.csv \
        --output data/ground_truth.csv
"""
import argparse
import csv
from pathlib import Path


def create_from_directories(spam_dir: str, ham_dir: str, output_file: str):
    """
    Create ground truth from spam/ham directory structure

    Args:
        spam_dir: Directory containing malicious emails
        ham_dir: Directory containing legitimate emails
        output_file: Output CSV path
    """
    ground_truth = []

    # Process spam emails
    if spam_dir:
        spam_path = Path(spam_dir)
        if spam_path.exists():
            spam_files = list(spam_path.glob("*"))
            spam_files = [f for f in spam_files if f.is_file() and not f.name.startswith('.')]
            print(f"Found {len(spam_files)} spam emails in {spam_dir}")

            for email_file in spam_files:
                ground_truth.append({
                    "filename": email_file.name,
                    "verdict": "malicious"
                })

    # Process ham emails
    if ham_dir:
        ham_path = Path(ham_dir)
        if ham_path.exists():
            ham_files = list(ham_path.glob("*"))
            ham_files = [f for f in ham_files if f.is_file() and not f.name.startswith('.')]
            print(f"Found {len(ham_files)} ham emails in {ham_dir}")

            for email_file in ham_files:
                ground_truth.append({
                    "filename": email_file.name,
                    "verdict": "clean"
                })

    # Write CSV
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["filename", "verdict"])
        writer.writeheader()
        writer.writerows(ground_truth)

    print(f"\n✓ Ground truth created: {output_file}")
    print(f"  Total entries: {len(ground_truth)}")
    print(f"  Malicious: {sum(1 for item in ground_truth if item['verdict'] == 'malicious')}")
    print(f"  Clean: {sum(1 for item in ground_truth if item['verdict'] == 'clean')}")


def create_from_csv(input_csv: str, output_file: str):
    """
    Convert existing CSV to ground truth format

    Expected input format:
        - filename, label (where label is "spam"/"phishing"/"malicious" or "ham"/"legitimate"/"clean")
    """
    import pandas as pd

    df = pd.read_csv(input_csv)

    # Normalize labels
    def normalize_label(label: str) -> str:
        label_lower = str(label).lower()
        if label_lower in ["spam", "phishing", "malicious", "phish", "malware"]:
            return "malicious"
        elif label_lower in ["ham", "legitimate", "clean", "normal"]:
            return "clean"
        else:
            return "unknown"

    # Detect label column
    possible_label_cols = ["label", "verdict", "class", "category", "type"]
    label_col = None
    for col in possible_label_cols:
        if col in df.columns:
            label_col = col
            break

    if not label_col:
        print(f"❌ Error: Could not find label column in CSV")
        print(f"Expected one of: {possible_label_cols}")
        print(f"Found columns: {list(df.columns)}")
        return

    # Detect filename column
    possible_filename_cols = ["filename", "file", "name", "email_id"]
    filename_col = None
    for col in possible_filename_cols:
        if col in df.columns:
            filename_col = col
            break

    if not filename_col:
        print(f"❌ Error: Could not find filename column in CSV")
        print(f"Expected one of: {possible_filename_cols}")
        print(f"Found columns: {list(df.columns)}")
        return

    # Create ground truth
    ground_truth = []
    for _, row in df.iterrows():
        verdict = normalize_label(row[label_col])
        if verdict != "unknown":
            ground_truth.append({
                "filename": row[filename_col],
                "verdict": verdict
            })

    # Write output
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["filename", "verdict"])
        writer.writeheader()
        writer.writerows(ground_truth)

    print(f"\n✓ Ground truth created: {output_file}")
    print(f"  Total entries: {len(ground_truth)}")
    print(f"  Malicious: {sum(1 for item in ground_truth if item['verdict'] == 'malicious')}")
    print(f"  Clean: {sum(1 for item in ground_truth if item['verdict'] == 'clean')}")


def main():
    parser = argparse.ArgumentParser(description="Generate ground truth CSV for dataset evaluation")

    # Option 1: From directories
    parser.add_argument("--spam-dir", help="Directory containing spam/malicious emails")
    parser.add_argument("--ham-dir", help="Directory containing ham/legitimate emails")

    # Option 2: From existing CSV
    parser.add_argument("--input-csv", help="Existing CSV with labels to convert")

    # Output
    parser.add_argument("--output", required=True, help="Output ground truth CSV path")

    args = parser.parse_args()

    if args.spam_dir or args.ham_dir:
        # Create from directories
        if not args.spam_dir and not args.ham_dir:
            print("❌ Error: Specify at least --spam-dir or --ham-dir")
            return
        create_from_directories(args.spam_dir, args.ham_dir, args.output)

    elif args.input_csv:
        # Create from existing CSV
        create_from_csv(args.input_csv, args.output)

    else:
        print("❌ Error: Specify either --spam-dir/--ham-dir OR --input-csv")
        parser.print_help()


if __name__ == "__main__":
    main()
