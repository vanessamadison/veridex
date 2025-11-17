#!/usr/bin/env python3
"""
Ollama-Powered Email Generator & Augmenter

Generates realistic email metadata (NOT body content) for:
- Synthetic phishing emails with Defender-style metadata
- Clean business emails
- Augmentation of existing sanitized datasets
- HIPAA-compliant (metadata only, no PHI)

Simulates Microsoft Defender for Office 365 email entity fields.
"""
import json
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import httpx
import yaml


class OllamaEmailGenerator:
    """Generate and augment email metadata using local Ollama LLM"""

    def __init__(
        self,
        model: str = "mistral:latest",
        base_url: str = "http://localhost:11434"
    ):
        self.model = model
        self.base_url = base_url
        self.api_endpoint = f"{base_url}/api/generate"

        # Defender email entity templates
        self.threat_types = ["NoThreatsFound", "Phish", "Malware", "Spam", "HighConfPhish"]
        self.delivery_actions = ["Delivered", "Blocked", "Quarantined", "Replaced", "Redirected"]
        self.delivery_locations = ["Inbox", "JunkFolder", "Quarantine", "DeletedFolder", "Dropped"]
        self.detection_techs = ["URL detonation", "File detonation", "Fingerprint matching",
                                 "Anti-spam engines", "URL reputation", "Advanced filter", "General filter",
                                 "Campaign", "Domain reputation", "Impersonation brand", "Mixed analysis detection"]
        self.auth_results = ["Pass", "Fail", "None", "SoftFail", "Neutral", "TempError", "PermError"]

        # Realistic sender domains (safe for simulation)
        self.phishing_domains = [
            "secure-login.net", "account-verify.com", "paypa1.com", "micr0soft.com",
            "supprt-desk.net", "it-helpdesk.org", "urgent-action.com", "verify-now.net",
            "security-alert.info", "password-reset.biz"
        ]
        self.legitimate_domains = [
            "example-healthcare.org", "campus-university.edu", "internal-corp.com",
            "trusted-vendor.com", "hr-services.net", "finance-dept.org"
        ]

        # Subject line patterns
        self.phishing_subjects = [
            "Action Required: Verify Your Account Immediately",
            "Urgent: Password Expires in 24 Hours",
            "Invoice #{} Attached - Payment Due",
            "Security Alert: Suspicious Login Detected",
            "Your Account Has Been Compromised",
            "Important: Update Your Payment Information",
            "Wire Transfer Request - Confidential",
            "IT Support: System Update Required",
            "HR: Review and Sign Your Benefits Form",
            "Final Notice: Account Suspension Warning"
        ]
        self.legitimate_subjects = [
            "Weekly Team Meeting Agenda",
            "Q{} Budget Review",
            "Training Session Reminder",
            "Project Update: Phase {} Complete",
            "Monthly Newsletter - {}",
            "Department Announcement",
            "Conference Room Booking Confirmed",
            "PTO Request Approved",
            "System Maintenance Notice - Planned",
            "New Policy Update - Please Review"
        ]

    def _check_ollama_health(self) -> bool:
        """Verify Ollama service is running"""
        try:
            with httpx.Client(timeout=5) as client:
                response = client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False

    def _call_ollama(self, prompt: str) -> str:
        """Call Ollama API for generation"""
        if not self._check_ollama_health():
            raise ConnectionError("Ollama service not available")

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "num_predict": 1000
            }
        }

        try:
            with httpx.Client(timeout=60) as client:
                response = client.post(self.api_endpoint, json=payload)
                response.raise_for_status()
                return response.json().get("response", "")
        except Exception as e:
            raise RuntimeError(f"Ollama generation failed: {str(e)}")

    def generate_defender_metadata(self, email_type: str = "random") -> Dict:
        """
        Generate realistic Microsoft Defender email metadata.

        Args:
            email_type: "phishing", "clean", or "random"

        Returns:
            Dictionary mimicking Defender email entity fields
        """
        if email_type == "random":
            email_type = random.choice(["phishing", "clean"])

        # Determine threat profile
        if email_type == "phishing":
            threat_type = random.choice(["Phish", "HighConfPhish", "Malware", "Spam"])
            delivery_action = random.choice(["Blocked", "Quarantined", "Delivered"])
            sender_domain = random.choice(self.phishing_domains)
            subject = random.choice(self.phishing_subjects).format(random.randint(1000, 9999))
            spf_result = random.choice(["Fail", "SoftFail", "None"])
            dkim_result = random.choice(["Fail", "None"])
            dmarc_result = random.choice(["Fail", "None"])
            url_count = random.randint(1, 5)
            has_malicious_url = random.choice([True, False])
            attachment_count = random.randint(0, 2)
        else:  # clean
            threat_type = "NoThreatsFound"
            delivery_action = "Delivered"
            sender_domain = random.choice(self.legitimate_domains)
            subject = random.choice(self.legitimate_subjects).format(
                random.randint(1, 4),
                random.choice(["January", "February", "March", "April"])
            )
            spf_result = "Pass"
            dkim_result = "Pass"
            dmarc_result = "Pass"
            url_count = random.randint(0, 3)
            has_malicious_url = False
            attachment_count = random.randint(0, 1)

        # Generate timestamp
        days_ago = random.randint(0, 30)
        hours_ago = random.randint(0, 23)
        email_date = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)

        # Construct Defender metadata (mimics real export)
        metadata = {
            "EmailId": f"email_{random.randint(10000, 99999)}_{int(email_date.timestamp())}",
            "NetworkMessageId": f"{random.randbytes(16).hex()}",
            "Subject": subject,
            "SenderAddress": f"{random.choice(['info', 'support', 'admin', 'noreply', 'service'])}@{sender_domain}",
            "SenderDisplayName": self._generate_display_name(email_type),
            "SenderDomain": sender_domain,
            "RecipientAddress": "user@example-healthcare.org",
            "ReceivedDateTime": email_date.isoformat(),
            "DeliveryAction": delivery_action,
            "DeliveryLocation": self._get_delivery_location(delivery_action),
            "ThreatTypes": threat_type,
            "DetectionTechnologies": self._get_detection_tech(threat_type),
            "UrlCount": url_count,
            "AttachmentCount": attachment_count,
            "SPFResult": spf_result,
            "DKIMResult": dkim_result,
            "DMARCResult": dmarc_result,
            "AuthenticationDetails": f"spf={spf_result.lower()};dkim={dkim_result.lower()};dmarc={dmarc_result.lower()}",
            "Directionality": "Inbound",
            "IsUserReported": random.choice([True, False]),
            "UserReportedReason": self._get_report_reason(email_type) if random.random() > 0.5 else None,
            "ReturnPath": self._generate_return_path(sender_domain, email_type),
            "ReplyTo": self._generate_reply_to(sender_domain, email_type),
            "SenderIP": self._generate_ip(),
            "Urls": self._generate_urls(url_count, has_malicious_url),
            "Attachments": self._generate_attachments(attachment_count, email_type),
            "ThreatConfidenceLevel": self._get_confidence_level(threat_type),
            "EmailActionPolicy": self._get_action_policy(threat_type),
            "Tags": self._generate_tags(email_type, threat_type),
            "SimulationSource": "OllamaGenerator",
            "GeneratedAt": datetime.utcnow().isoformat()
        }

        return metadata

    def _generate_display_name(self, email_type: str) -> str:
        """Generate realistic display name"""
        if email_type == "phishing":
            return random.choice([
                "IT Support Team",
                "Security Department",
                "Account Services",
                "Human Resources",
                "Microsoft Support",
                "PayPal Customer Service",
                "System Administrator"
            ])
        else:
            return random.choice([
                "John Smith",
                "Sarah Johnson",
                "HR Department",
                "Finance Team",
                "Project Coordinator",
                "Department Manager"
            ])

    def _get_delivery_location(self, action: str) -> str:
        """Map delivery action to location"""
        mapping = {
            "Delivered": random.choice(["Inbox", "JunkFolder"]),
            "Blocked": "Dropped",
            "Quarantined": "Quarantine",
            "Replaced": "Inbox",
            "Redirected": "JunkFolder"
        }
        return mapping.get(action, "Inbox")

    def _get_detection_tech(self, threat_type: str) -> str:
        """Get relevant detection technologies"""
        if threat_type in ["Phish", "HighConfPhish"]:
            return random.choice(["URL detonation", "URL reputation", "Impersonation brand", "Anti-spam engines"])
        elif threat_type == "Malware":
            return random.choice(["File detonation", "Fingerprint matching", "Campaign"])
        elif threat_type == "Spam":
            return random.choice(["Anti-spam engines", "General filter", "Domain reputation"])
        else:
            return "Advanced filter"

    def _get_report_reason(self, email_type: str) -> str:
        """Generate user report reason"""
        if email_type == "phishing":
            return random.choice(["Phish", "Spam", "Junk", "Not junk"])
        else:
            return random.choice(["Not junk", "Spam", "Junk"])

    def _generate_return_path(self, domain: str, email_type: str) -> str:
        """Generate Return-Path header"""
        if email_type == "phishing" and random.random() > 0.5:
            # Spoofing indicator: mismatched return path
            return f"bounce@{random.choice(self.phishing_domains)}"
        return f"bounce@{domain}"

    def _generate_reply_to(self, domain: str, email_type: str) -> str:
        """Generate Reply-To header"""
        if email_type == "phishing" and random.random() > 0.6:
            # Spoofing indicator: different reply-to
            return f"reply@{random.choice(self.phishing_domains)}"
        return f"noreply@{domain}"

    def _generate_ip(self) -> str:
        """Generate realistic IP address"""
        return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

    def _generate_urls(self, count: int, has_malicious: bool) -> List[Dict]:
        """Generate URL metadata (not actual URLs)"""
        urls = []
        for i in range(count):
            is_malicious = has_malicious and i == 0
            url = {
                "UrlId": f"url_{random.randint(1000, 9999)}",
                "UrlDomain": random.choice(self.phishing_domains if is_malicious else self.legitimate_domains),
                "ThreatVerdict": "Malicious" if is_malicious else "Clean",
                "ClickCount": random.randint(0, 5) if not is_malicious else 0,
                "IsShortened": random.choice([True, False]) if is_malicious else False
            }
            urls.append(url)
        return urls

    def _generate_attachments(self, count: int, email_type: str) -> List[Dict]:
        """Generate attachment metadata"""
        attachments = []
        risky_extensions = [".exe", ".zip", ".rar", ".js", ".vbs", ".html"]
        safe_extensions = [".pdf", ".docx", ".xlsx", ".png", ".jpg"]

        for _ in range(count):
            if email_type == "phishing":
                ext = random.choice(risky_extensions + safe_extensions)
            else:
                ext = random.choice(safe_extensions)

            attachment = {
                "AttachmentId": f"att_{random.randint(1000, 9999)}",
                "FileName": f"document_{random.randint(100, 999)}{ext}",
                "FileType": ext.replace(".", ""),
                "SHA256": random.randbytes(32).hex(),
                "ThreatVerdict": "Malicious" if ext in risky_extensions and email_type == "phishing" else "Clean"
            }
            attachments.append(attachment)
        return attachments

    def _get_confidence_level(self, threat_type: str) -> str:
        """Get threat confidence level"""
        if threat_type == "HighConfPhish":
            return "High"
        elif threat_type in ["Phish", "Malware"]:
            return random.choice(["High", "Medium"])
        elif threat_type == "Spam":
            return "Medium"
        else:
            return "Low"

    def _get_action_policy(self, threat_type: str) -> str:
        """Get email action policy"""
        if threat_type in ["HighConfPhish", "Malware"]:
            return "BlockSender"
        elif threat_type == "Phish":
            return "Quarantine"
        elif threat_type == "Spam":
            return "MoveToJunk"
        else:
            return "Allow"

    def _generate_tags(self, email_type: str, threat_type: str) -> List[str]:
        """Generate relevant tags"""
        tags = []
        if email_type == "phishing":
            tags.extend(["ExternalSender", "SuspiciousContent"])
            if threat_type == "HighConfPhish":
                tags.append("HighConfidence")
        else:
            tags.append("InternalSender" if random.random() > 0.5 else "TrustedSender")
        return tags

    def augment_existing_email(self, email_data: Dict) -> Dict:
        """
        Augment existing email metadata with variations.

        Creates realistic variations while preserving core characteristics.
        """
        augmented = email_data.copy()

        # Vary timestamp
        original_date = datetime.fromisoformat(email_data.get("ReceivedDateTime", datetime.utcnow().isoformat()))
        time_shift = timedelta(hours=random.randint(-48, 48), minutes=random.randint(0, 59))
        augmented["ReceivedDateTime"] = (original_date + time_shift).isoformat()

        # Vary subject slightly
        if "Subject" in augmented:
            subject_variations = [
                lambda s: s.replace(":", " -"),
                lambda s: s.upper() if random.random() > 0.7 else s,
                lambda s: f"FW: {s}" if random.random() > 0.8 else s,
                lambda s: f"RE: {s}" if random.random() > 0.8 else s,
            ]
            augmented["Subject"] = random.choice(subject_variations)(augmented["Subject"])

        # Vary IP
        augmented["SenderIP"] = self._generate_ip()

        # Vary network message ID
        augmented["NetworkMessageId"] = f"{random.randbytes(16).hex()}"

        # Mark as augmented
        augmented["IsAugmented"] = True
        augmented["OriginalEmailId"] = email_data.get("EmailId", "unknown")
        augmented["AugmentedAt"] = datetime.utcnow().isoformat()

        return augmented

    def generate_campaign(self, campaign_type: str = "phishing", count: int = 10) -> List[Dict]:
        """
        Generate a coordinated email campaign.

        Args:
            campaign_type: "phishing" or "legitimate"
            count: Number of emails in campaign

        Returns:
            List of related email metadata
        """
        campaign_id = f"campaign_{random.randint(10000, 99999)}"

        # Campaign characteristics (same across all emails)
        sender_domain = random.choice(
            self.phishing_domains if campaign_type == "phishing" else self.legitimate_domains
        )
        base_subject = random.choice(
            self.phishing_subjects if campaign_type == "phishing" else self.legitimate_subjects
        )

        emails = []
        for i in range(count):
            email = self.generate_defender_metadata(campaign_type)
            email["CampaignId"] = campaign_id
            email["SenderDomain"] = sender_domain
            email["Subject"] = base_subject.format(random.randint(1000, 9999))
            email["Tags"].append("Campaign")

            # Stagger timing (coordinated attack)
            email["ReceivedDateTime"] = (
                datetime.utcnow() - timedelta(hours=random.randint(0, 24), minutes=i * 2)
            ).isoformat()

            emails.append(email)

        return emails

    def generate_batch(
        self,
        phishing_count: int = 10,
        clean_count: int = 40,
        campaign_count: int = 0
    ) -> List[Dict]:
        """
        Generate a batch of mixed emails for testing.

        Args:
            phishing_count: Number of phishing emails
            clean_count: Number of clean emails
            campaign_count: Number of campaign emails (optional)

        Returns:
            List of email metadata dictionaries
        """
        emails = []

        # Generate phishing emails
        for _ in range(phishing_count):
            emails.append(self.generate_defender_metadata("phishing"))

        # Generate clean emails
        for _ in range(clean_count):
            emails.append(self.generate_defender_metadata("clean"))

        # Generate campaign emails
        if campaign_count > 0:
            emails.extend(self.generate_campaign("phishing", campaign_count))

        # Shuffle
        random.shuffle(emails)

        return emails


def test_generator():
    """Test email generation"""
    generator = OllamaEmailGenerator()

    print("Testing Ollama Email Generator")
    print("=" * 60)

    # Generate single phishing email
    print("\n1. Phishing Email Metadata:")
    phishing = generator.generate_defender_metadata("phishing")
    print(json.dumps(phishing, indent=2, default=str)[:500] + "...")

    # Generate clean email
    print("\n2. Clean Email Metadata:")
    clean = generator.generate_defender_metadata("clean")
    print(json.dumps(clean, indent=2, default=str)[:500] + "...")

    # Generate batch
    print("\n3. Batch Generation (5 phishing, 10 clean):")
    batch = generator.generate_batch(5, 10)
    print(f"   Generated {len(batch)} emails")
    phish_count = sum(1 for e in batch if e["ThreatTypes"] != "NoThreatsFound")
    print(f"   Phishing: {phish_count}, Clean: {len(batch) - phish_count}")

    print("\nGenerator test complete!")


if __name__ == "__main__":
    test_generator()
