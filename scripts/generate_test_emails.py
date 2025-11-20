#!/usr/bin/env python3
"""
Generate Test Emails
Creates sample .eml files for testing the standalone system

Usage:
    python scripts/generate_test_emails.py --output data/test_dataset --count 10
"""
import argparse
from pathlib import Path
from datetime import datetime, timedelta
import random


def generate_phishing_email(filename: str) -> str:
    """Generate a realistic phishing email"""
    subjects = [
        "URGENT: Your account will be suspended in 24 hours",
        "Action Required: Verify your payment information",
        "Security Alert: Unusual activity detected",
        "Your PayPal account has been limited",
        "Invoice #INV-{} - Payment Due",
        "Wire Transfer Request - CONFIDENTIAL"
    ]

    senders = [
        ("security@paypa1.com", "PayPal Security Team"),
        ("noreply@micros0ft.com", "Microsoft Account Team"),
        ("support@secure-login.net", "Security Alert"),
        ("admin@account-verify.com", "Account Services"),
        ("billing@invoice-dept.biz", "Billing Department")
    ]

    sender_email, sender_name = random.choice(senders)
    subject = random.choice(subjects).format(random.randint(10000, 99999))

    # Generate email
    email = f"""From: "{sender_name}" <{sender_email}>
To: user@example.com
Subject: {subject}
Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')}
Message-ID: <{random.randint(10000000, 99999999)}@{sender_email.split('@')[1]}>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Return-Path: <bounce@different-domain.com>
Received-SPF: fail

Dear Customer,

We have detected suspicious activity on your account.

Please verify your account immediately by clicking the link below:
http://bit.ly/verify{random.randint(1000, 9999)}

If you do not verify within 24 hours, your account will be suspended.

Thank you,
Security Team

This is an automated message, please do not reply.
"""

    return email


def generate_legitimate_email(filename: str) -> str:
    """Generate a realistic legitimate email"""
    subjects = [
        "Team Meeting Notes - {}",
        "Weekly Project Update",
        "Quarterly Budget Review",
        "Training Session Reminder",
        "Department Announcement"
    ]

    senders = [
        ("john.smith@example.com", "John Smith"),
        ("hr@example.com", "Human Resources"),
        ("noreply@internal-systems.com", "IT Department"),
        ("notifications@workday.com", "Workday Notifications")
    ]

    sender_email, sender_name = random.choice(senders)
    subject = random.choice(subjects).format(datetime.now().strftime('%Y-%m-%d'))

    email = f"""From: "{sender_name}" <{sender_email}>
To: user@example.com
Subject: {subject}
Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')}
Message-ID: <{random.randint(10000000, 99999999)}@{sender_email.split('@')[1]}>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Received-SPF: pass
Authentication-Results: example.com; spf=pass; dkim=pass; dmarc=pass

Hi Team,

Here are the notes from today's meeting:

1. Project timeline updated
2. Budget approved for Q2
3. New team member starting next week

Please review and let me know if you have any questions.

Best regards,
{sender_name}
"""

    return email


def main():
    parser = argparse.ArgumentParser(description="Generate test emails for evaluation")
    parser.add_argument("--output", required=True, help="Output directory for test emails")
    parser.add_argument("--count", type=int, default=20, help="Total number of emails to generate")
    parser.add_argument("--phishing-ratio", type=float, default=0.3, help="Ratio of phishing emails (0.0-1.0)")

    args = parser.parse_args()

    # Create output directories
    output_dir = Path(args.output)
    phishing_dir = output_dir / "phishing"
    legitimate_dir = output_dir / "legitimate"

    phishing_dir.mkdir(parents=True, exist_ok=True)
    legitimate_dir.mkdir(parents=True, exist_ok=True)

    # Calculate counts
    phishing_count = int(args.count * args.phishing_ratio)
    legitimate_count = args.count - phishing_count

    print(f"Generating {args.count} test emails:")
    print(f"  Phishing: {phishing_count}")
    print(f"  Legitimate: {legitimate_count}")
    print(f"  Output: {output_dir}\n")

    # Generate phishing emails
    for i in range(phishing_count):
        filename = f"phishing_{i+1:03d}.eml"
        filepath = phishing_dir / filename
        email_content = generate_phishing_email(filename)

        with open(filepath, 'w') as f:
            f.write(email_content)

        print(f"  ✓ Generated {filename}")

    # Generate legitimate emails
    for i in range(legitimate_count):
        filename = f"legitimate_{i+1:03d}.eml"
        filepath = legitimate_dir / filename
        email_content = generate_legitimate_email(filename)

        with open(filepath, 'w') as f:
            f.write(email_content)

        print(f"  ✓ Generated {filename}")

    # Create ground truth CSV
    import csv
    ground_truth_path = output_dir / "ground_truth.csv"

    with open(ground_truth_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["filename", "verdict"])
        writer.writeheader()

        # Phishing emails
        for i in range(phishing_count):
            writer.writerow({
                "filename": f"phishing_{i+1:03d}.eml",
                "verdict": "malicious"
            })

        # Legitimate emails
        for i in range(legitimate_count):
            writer.writerow({
                "filename": f"legitimate_{i+1:03d}.eml",
                "verdict": "clean"
            })

    print(f"\n✓ Ground truth created: {ground_truth_path}")
    print(f"\nTest dataset ready in: {output_dir}")
    print(f"\nTo evaluate:")
    print(f"  python standalone_triage.py \\")
    print(f"    --dataset {output_dir} \\")
    print(f"    --ground-truth {ground_truth_path} \\")
    print(f"    --output results/test_evaluation.json")


if __name__ == "__main__":
    main()
