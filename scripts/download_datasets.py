#!/usr/bin/env python3
"""
Download and prepare additional phishing email datasets for validation.

Datasets:
- CEAS_08: Conference email corpus
- Enron: Legitimate business emails
- Ling: Spam/ham collection
- Nazario: Phishing corpus
- Nigerian Fraud: 419 scam emails
- TREC: Standardized spam evaluation datasets (2005, 2006, 2007)
"""

import os
import urllib.request
import tarfile
import zipfile
import gzip
import shutil
from pathlib import Path
import subprocess
import sys

# Base data directory
BASE_DIR = Path(__file__).parent.parent / "data"
BASE_DIR.mkdir(exist_ok=True)

# Dataset URLs and information
DATASETS = {
    "enron": {
        "name": "Enron Email Dataset",
        "url": "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz",
        "type": "tar.gz",
        "dir": "enron",
        "description": "500K+ legitimate business emails from Enron Corporation"
    },
    "nazario": {
        "name": "Nazario Phishing Corpus",
        "urls": [
            "https://monkey.org/~jose/phishing/phishing1.mbox.gz",
            "https://monkey.org/~jose/phishing/phishing2.mbox.gz",
            "https://monkey.org/~jose/phishing/phishing3.mbox.gz"
        ],
        "type": "mbox.gz",
        "dir": "nazario",
        "description": "Curated phishing emails from Jose Nazario"
    },
    "trec05": {
        "name": "TREC 2005 Spam Corpus",
        "url": "https://plg.uwaterloo.ca/~gvcormac/treccorpus/",
        "type": "manual",
        "dir": "trec05",
        "description": "TREC 2005 spam evaluation dataset - Requires manual download"
    },
    "trec06": {
        "name": "TREC 2006 Spam Corpus",
        "url": "https://plg.uwaterloo.ca/~gvcormac/treccorpus06/",
        "type": "manual",
        "dir": "trec06",
        "description": "TREC 2006 spam evaluation dataset - Requires manual download"
    },
    "trec07": {
        "name": "TREC 2007 Spam Corpus",
        "url": "https://plg.uwaterloo.ca/~gvcormac/treccorpus07/",
        "type": "manual",
        "dir": "trec07",
        "description": "TREC 2007 spam evaluation dataset - Requires manual download"
    },
    "spamassassin_easy_ham": {
        "name": "SpamAssassin Easy Ham",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "type": "tar.bz2",
        "dir": "spamassassin/easy_ham",
        "description": "SpamAssassin easy ham (legitimate emails)"
    },
    "spamassassin_hard_ham": {
        "name": "SpamAssassin Hard Ham",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
        "type": "tar.bz2",
        "dir": "spamassassin/hard_ham",
        "description": "SpamAssassin hard ham (difficult legitimate emails)"
    },
    "spamassassin_easy_ham_2": {
        "name": "SpamAssassin Easy Ham 2",
        "url": "https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2",
        "type": "tar.bz2",
        "dir": "spamassassin/spam_2",
        "description": "SpamAssassin spam corpus 2 (already downloaded)"
    },
    "ling_spam": {
        "name": "Ling-Spam Corpus",
        "url": "http://www.aueb.gr/users/ion/data/lingspam_public.tar.gz",
        "type": "tar.gz",
        "dir": "ling_spam",
        "description": "Spam/ham emails from linguistics mailing list"
    },
    "nigerian_fraud": {
        "name": "Nigerian Fraud Emails",
        "manual_instructions": """
Nigerian fraud datasets can be found at:
- https://github.com/topics/nigerian-scam
- http://www.aa419.org/fakebanks/
- Manual collection from spam traps

These typically require manual collection or ethical sourcing.
""",
        "type": "manual",
        "dir": "nigerian_fraud",
        "description": "419 scam emails - Requires manual collection"
    }
}


def download_file(url, dest_path, dataset_name):
    """Download a file with progress indicator"""
    print(f"  Downloading {dataset_name}...")
    print(f"  URL: {url}")

    try:
        # Try using curl first (better SSL handling)
        result = subprocess.run(
            ['curl', '-L', '-o', str(dest_path), '--progress-bar', url],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("  ✓ Download complete")
            return True
        else:
            # Fallback to wget
            result = subprocess.run(
                ['wget', '-O', str(dest_path), url],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                print("  ✓ Download complete")
                return True
            else:
                print(f"  ✗ Download failed")
                print(f"  Try manually downloading from: {url}")
                print(f"  Save to: {dest_path}")
                return False

    except Exception as e:
        print(f"  ✗ Download failed: {e}")
        return False


def extract_archive(archive_path, extract_dir, archive_type):
    """Extract tar.gz, tar.bz2, or zip archives"""
    print(f"  Extracting to {extract_dir}...")
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        if archive_type == "tar.gz":
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(extract_dir)
        elif archive_type == "tar.bz2":
            with tarfile.open(archive_path, "r:bz2") as tar:
                tar.extractall(extract_dir)
        elif archive_type == "zip":
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif archive_type == "mbox.gz":
            mbox_path = extract_dir / archive_path.stem
            with gzip.open(archive_path, 'rb') as f_in:
                with open(mbox_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

        print("  ✓ Extraction complete")
        return True
    except Exception as e:
        print(f"  ✗ Extraction failed: {e}")
        return False


def download_dataset(dataset_key, config):
    """Download and prepare a single dataset"""
    print(f"\n{'='*70}")
    print(f"{config['name']}")
    print(f"{'='*70}")
    print(f"Description: {config['description']}")

    dataset_dir = BASE_DIR / config['dir']

    # Check if already exists
    if dataset_dir.exists() and any(dataset_dir.iterdir()):
        print(f"  ⚠ Dataset already exists at {dataset_dir}")
        response = input("  Download anyway? (y/N): ")
        if response.lower() != 'y':
            print("  Skipping...")
            return False

    # Handle manual downloads
    if config['type'] == 'manual':
        print(f"\n  ⚠ Manual download required:")
        print(f"  URL: {config['url']}")
        if 'manual_instructions' in config:
            print(config['manual_instructions'])
        print(f"  Please download manually to: {dataset_dir}")
        return False

    dataset_dir.mkdir(parents=True, exist_ok=True)

    # Handle single URL datasets
    if 'url' in config:
        archive_name = config['url'].split('/')[-1]
        archive_path = dataset_dir / archive_name

        if download_file(config['url'], archive_path, config['name']):
            if config['type'] in ['tar.gz', 'tar.bz2', 'zip']:
                extract_archive(archive_path, dataset_dir, config['type'])
                # Clean up archive after extraction
                archive_path.unlink()
            return True

    # Handle multiple URLs (like Nazario)
    elif 'urls' in config:
        for i, url in enumerate(config['urls'], 1):
            archive_name = url.split('/')[-1]
            archive_path = dataset_dir / archive_name

            print(f"\n  Part {i}/{len(config['urls'])}:")
            if download_file(url, archive_path, config['name']):
                extract_archive(archive_path, dataset_dir, config['type'])
                archive_path.unlink()
        return True

    return False


def count_emails(directory):
    """Count email files in a directory"""
    email_extensions = ['.eml', '.txt', '.msg', '']
    count = 0

    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in email_extensions):
                # Skip hidden files and metadata
                if not file.startswith('.'):
                    count += 1

    return count


def main():
    """Main dataset download orchestrator"""
    print("\n" + "="*70)
    print(" Phishing Dataset Downloader")
    print("="*70)
    print("\nThis script will download public phishing and spam email datasets")
    print("for validation testing.\n")

    print("Available datasets:")
    for i, (key, config) in enumerate(DATASETS.items(), 1):
        dataset_dir = BASE_DIR / config['dir']
        exists = "✓ EXISTS" if dataset_dir.exists() and any(dataset_dir.iterdir()) else "✗ NOT DOWNLOADED"
        print(f"  {i}. {config['name']} - {exists}")

    print("\nOptions:")
    print("  1. Download all datasets")
    print("  2. Download specific datasets")
    print("  3. View dataset details")
    print("  4. Count emails in existing datasets")
    print("  0. Exit")

    choice = input("\nSelect option (0-4): ").strip()

    if choice == '1':
        # Download all
        print("\n⚠ WARNING: This will download several GB of data.")
        confirm = input("Continue? (y/N): ")
        if confirm.lower() == 'y':
            for key, config in DATASETS.items():
                download_dataset(key, config)

    elif choice == '2':
        # Download specific
        print("\nEnter dataset numbers to download (comma-separated, e.g., 1,3,5):")
        indices = input("> ").strip().split(',')
        dataset_keys = list(DATASETS.keys())

        for idx in indices:
            try:
                idx_int = int(idx.strip()) - 1
                if 0 <= idx_int < len(dataset_keys):
                    key = dataset_keys[idx_int]
                    download_dataset(key, DATASETS[key])
            except ValueError:
                print(f"Invalid input: {idx}")

    elif choice == '3':
        # View details
        for key, config in DATASETS.items():
            print(f"\n{config['name']}:")
            print(f"  Description: {config['description']}")
            print(f"  Type: {config['type']}")
            if 'url' in config:
                print(f"  URL: {config['url']}")
            elif 'urls' in config:
                print(f"  URLs: {len(config['urls'])} files")

    elif choice == '4':
        # Count emails
        print("\nCounting emails in existing datasets...\n")
        total = 0
        for key, config in DATASETS.items():
            dataset_dir = BASE_DIR / config['dir']
            if dataset_dir.exists():
                count = count_emails(dataset_dir)
                total += count
                print(f"  {config['name']}: {count:,} emails")
        print(f"\n  TOTAL: {total:,} emails across all datasets")

    elif choice == '0':
        print("Exiting...")
        return

    else:
        print("Invalid choice")

    print("\n" + "="*70)
    print("Dataset download complete!")
    print("="*70)
    print(f"\nDatasets saved to: {BASE_DIR}")
    print("\nNext steps:")
    print("  1. Run: python scripts/create_ground_truth.py for each dataset")
    print("  2. Run: python standalone_triage.py --dataset <dataset_dir> --ground-truth <gt.csv>")
    print("  3. Compare results across datasets for comprehensive validation")


if __name__ == "__main__":
    main()
