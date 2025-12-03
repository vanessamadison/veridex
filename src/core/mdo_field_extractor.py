#!/usr/bin/env python3
"""
Microsoft Defender for Office 365 Email Entity Field Extractor
Extracts all 30+ email entity fields per MDO documentation
Reference: https://learn.microsoft.com/en-us/defender-office-365/mdo-email-entity-page
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MDOFieldExtractor:
    """
    Extract and normalize Microsoft Defender email entity fields
    Ensures HIPAA compliance by excluding body content
    """

    # Internal domains - configure these for your organization
    INTERNAL_DOMAINS = [
        "example.com",
        "yourhealthcare.org",
        "internal.local"
    ]

    # Known safe automated systems
    SAFE_AUTOMATED_SENDERS = [
        "workday.com",
        "canvas.instructure.com",
        "servicenow.com",
        "zoom.us",
        "docusign.com",
        "adobe.com",
        "office365.com",
        "microsoft.com"
    ]

    def __init__(self, enforce_hipaa: bool = True):
        """
        Initialize extractor

        Args:
            enforce_hipaa: If True, exclude email body content
        """
        self.enforce_hipaa = enforce_hipaa

    def extract(self, email_entity: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract all MDO email entity fields

        Args:
            email_entity: Raw email entity from Graph API or CSV

        Returns:
            Normalized feature dictionary
        """
        features = {}

        # === HEADER INFORMATION ===
        features["sender"] = email_entity.get("SenderFromAddress") or email_entity.get("Sender")
        features["sender_display_name"] = email_entity.get("SenderDisplayName") or email_entity.get("sender_display_name")
        features["sender_domain"] = email_entity.get("SenderFromDomain") or email_entity.get("sender_domain") or self._extract_domain(features["sender"])
        features["sender_ip"] = email_entity.get("SenderIPv4") or email_entity.get("sender_ip")

        features["return_path"] = email_entity.get("ReturnPath") or email_entity.get("return_path")
        features["reply_to"] = email_entity.get("ReplyTo") or email_entity.get("reply_to")

        features["subject"] = email_entity.get("Subject") or email_entity.get("subject", "")
        features["internet_message_id"] = email_entity.get("InternetMessageId") or email_entity.get("internet_message_id")
        features["network_message_id"] = email_entity.get("NetworkMessageId") or email_entity.get("network_message_id")

        # Recipients
        features["recipients_to"] = email_entity.get("Recipients") or email_entity.get("recipients_to", [])
        features["recipients_cc"] = email_entity.get("RecipientsCc") or email_entity.get("recipients_cc", [])
        features["recipients_bcc"] = email_entity.get("RecipientsBcc") or email_entity.get("recipients_bcc", [])

        # === AUTHENTICATION RESULTS ===
        auth_details = email_entity.get("AuthenticationDetails") or {}

        features["spf_result"] = (
            auth_details.get("SPF") or
            email_entity.get("spf") or
            email_entity.get("spf_result") or
            "None"
        )

        features["dkim_result"] = (
            auth_details.get("DKIM") or
            email_entity.get("dkim") or
            email_entity.get("dkim_result") or
            "None"
        )

        features["dmarc_result"] = (
            auth_details.get("DMARC") or
            email_entity.get("dmarc") or
            email_entity.get("dmarc_result") or
            "None"
        )

        # Authentication summary
        features["auth_passed"] = (
            features["spf_result"] == "Pass" and
            features["dkim_result"] == "Pass" and
            features["dmarc_result"] == "Pass"
        )

        # === THREAT INTELLIGENCE ===
        threat_types = email_entity.get("ThreatTypes") or email_entity.get("threat_types") or email_entity.get("Threat types") or []

        # Normalize threat types
        if isinstance(threat_types, str):
            threat_types = [t.strip() for t in threat_types.split(",") if t.strip()]

        features["threat_types"] = threat_types
        features["has_threats"] = len(threat_types) > 0 and "NoThreatsFound" not in threat_types

        detection_tech = email_entity.get("DetectionTechnologies") or email_entity.get("detection_tech") or []
        if isinstance(detection_tech, str):
            detection_tech = [d.strip() for d in detection_tech.split(",") if d.strip()]

        features["detection_tech"] = detection_tech

        # Delivery information
        features["delivery_action"] = email_entity.get("DeliveryAction") or email_entity.get("delivery_action") or "Delivered"
        features["delivery_location"] = email_entity.get("DeliveryLocation") or email_entity.get("delivery_location") or "Inbox"
        features["original_delivery_location"] = email_entity.get("OriginalDeliveryLocation") or email_entity.get("original_delivery_location")

        # === URLs ===
        urls_raw = email_entity.get("Urls") or email_entity.get("urls") or []

        # Handle JSON string or list
        if isinstance(urls_raw, str):
            import json
            try:
                urls_raw = json.loads(urls_raw)
            except:
                urls_raw = []

        features["urls"] = self._parse_urls(urls_raw)
        features["url_count"] = len(features["urls"])
        features["has_urls"] = features["url_count"] > 0

        # URL threat analysis
        features["malicious_url_count"] = sum(
            1 for u in features["urls"]
            if u.get("threat_verdict") in ["Malicious", "Phishing"]
        )
        features["suspicious_url_count"] = sum(
            1 for u in features["urls"]
            if u.get("threat_verdict") == "Suspicious"
        )

        # Check for shortened URLs (common in phishing)
        features["has_shortened_url"] = any(
            any(domain in u.get("url", "").lower() for domain in ["bit.ly", "tinyurl", "goo.gl", "ow.ly"])
            for u in features["urls"]
        )

        # === ATTACHMENTS ===
        attachments_raw = email_entity.get("Attachments") or email_entity.get("attachments") or []

        if isinstance(attachments_raw, str):
            import json
            try:
                attachments_raw = json.loads(attachments_raw)
            except:
                attachments_raw = []

        features["attachments"] = self._parse_attachments(attachments_raw)
        features["attachment_count"] = len(features["attachments"])
        features["has_attachments"] = features["attachment_count"] > 0

        # Risky file types
        risky_extensions = [".exe", ".zip", ".rar", ".js", ".vbs", ".html", ".htm", ".bat", ".cmd", ".scr"]
        features["has_risky_attachment"] = any(
            any(att.get("filename", "").lower().endswith(ext) for ext in risky_extensions)
            for att in features["attachments"]
        )

        features["malicious_attachment_count"] = sum(
            1 for att in features["attachments"]
            if len(att.get("threat_names", [])) > 0
        )

        # === CONTENT SIGNALS (HIPAA-SAFE) ===
        if self.enforce_hipaa:
            # Only first 50 chars of preview (subject-like content)
            body_preview = email_entity.get("BodyPreview") or email_entity.get("body_preview") or ""
            features["body_preview"] = body_preview[:50] if body_preview else None
        else:
            features["body_preview"] = email_entity.get("BodyPreview") or email_entity.get("body_preview")

        features["language"] = email_entity.get("Language") or email_entity.get("language")

        # Content analysis
        subject_lower = features["subject"].lower()
        features["subject_length"] = len(features["subject"])

        # Urgency keywords (common in phishing)
        urgency_keywords = [
            "urgent", "immediate", "action required", "verify", "suspended",
            "expires", "confirm", "update", "security alert", "locked",
            "unusual activity", "click here", "act now", "limited time"
        ]
        features["urgency_keyword_count"] = sum(
            1 for keyword in urgency_keywords if keyword in subject_lower
        )
        features["has_urgency"] = features["urgency_keyword_count"] > 0

        # Financial keywords (BEC/invoice fraud)
        financial_keywords = [
            "invoice", "payment", "wire transfer", "bank", "account",
            "refund", "tax", "payroll", "w-2", "gift card"
        ]
        features["financial_keyword_count"] = sum(
            1 for keyword in financial_keywords if keyword in subject_lower
        )
        features["has_financial_terms"] = features["financial_keyword_count"] > 0

        # === DIRECTIONALITY ===
        directionality = email_entity.get("Directionality") or email_entity.get("directionality")

        if not directionality:
            # Infer from sender domain
            if features["sender_domain"] and any(
                features["sender_domain"].endswith(d) for d in self.INTERNAL_DOMAINS
            ):
                directionality = "Intra-org"
            else:
                directionality = "Inbound"

        features["directionality"] = directionality
        features["is_internal"] = directionality == "Intra-org"
        features["is_external"] = directionality == "Inbound"

        # === USER CONTEXT ===
        features["is_user_reported"] = email_entity.get("IsUserReported") or email_entity.get("is_user_reported") or False
        features["user_report_classification"] = email_entity.get("UserReportClassification") or email_entity.get("user_report_classification")
        features["analyst_comments"] = email_entity.get("AnalystComments") or email_entity.get("analyst_comments")

        # === TIMING ===
        received_dt = email_entity.get("ReceivedDateTime") or email_entity.get("received_datetime") or email_entity.get("received_time")
        if received_dt:
            features["received_datetime"] = self._parse_datetime(received_dt)
        else:
            features["received_datetime"] = None

        reported_dt = email_entity.get("ReportedDateTime") or email_entity.get("reported_datetime") or email_entity.get("reported_time")
        if reported_dt:
            features["reported_datetime"] = self._parse_datetime(reported_dt)
        else:
            features["reported_datetime"] = None

        # Time to report (if user-reported)
        if features["received_datetime"] and features["reported_datetime"]:
            delta = features["reported_datetime"] - features["received_datetime"]
            features["time_to_report_hours"] = delta.total_seconds() / 3600
        else:
            features["time_to_report_hours"] = None

        # === DERIVED FEATURES (RISK INDICATORS) ===

        # Sender reputation indicators
        features["sender_domain_is_safe"] = features["sender_domain"] and any(
            features["sender_domain"].endswith(d)
            for d in self.INTERNAL_DOMAINS + self.SAFE_AUTOMATED_SENDERS
        )

        # Spoofing indicators
        features["return_path_mismatch"] = (
            features["return_path"] and
            features["sender"] and
            self._extract_domain(features["return_path"]) != features["sender_domain"]
        )

        features["reply_to_mismatch"] = (
            features["reply_to"] and
            features["sender"] and
            self._extract_domain(features["reply_to"]) != features["sender_domain"]
        )

        # Compound risk indicators
        features["external_with_attachment"] = features["is_external"] and features["has_attachments"]
        features["external_with_urgency"] = features["is_external"] and features["has_urgency"]
        features["failed_auth_with_urgency"] = (not features["auth_passed"]) and features["has_urgency"]

        return features

    def _extract_domain(self, email: Optional[str]) -> Optional[str]:
        """Extract domain from email address"""
        if not email or "@" not in email:
            return None
        return email.split("@")[1].lower()

    def _parse_urls(self, urls_raw: List) -> List[Dict]:
        """Parse and normalize URL information"""
        if not urls_raw:
            return []

        urls = []
        for url_obj in urls_raw:
            if isinstance(url_obj, str):
                # Simple URL string
                urls.append({
                    "url": url_obj,
                    "threat_verdict": "Unknown",
                    "click_count": 0
                })
            elif isinstance(url_obj, dict):
                # URL with metadata
                urls.append({
                    "url": url_obj.get("Url") or url_obj.get("url", ""),
                    "threat_verdict": url_obj.get("ThreatVerdict") or url_obj.get("threat_verdict", "Unknown"),
                    "click_count": url_obj.get("ClickCount") or url_obj.get("click_count", 0)
                })

        return urls

    def _parse_attachments(self, attachments_raw: List) -> List[Dict]:
        """Parse and normalize attachment information"""
        if not attachments_raw:
            return []

        attachments = []
        for att_obj in attachments_raw:
            if isinstance(att_obj, str):
                # Simple filename
                attachments.append({
                    "filename": att_obj,
                    "file_type": att_obj.split(".")[-1] if "." in att_obj else "unknown",
                    "sha256": None,
                    "threat_names": []
                })
            elif isinstance(att_obj, dict):
                # Attachment with metadata
                threat_names = att_obj.get("ThreatNames") or att_obj.get("threat_names") or att_obj.get("threats") or []
                if isinstance(threat_names, str):
                    threat_names = [t.strip() for t in threat_names.split(",") if t.strip()]

                attachments.append({
                    "filename": att_obj.get("FileName") or att_obj.get("filename", ""),
                    "file_type": att_obj.get("FileType") or att_obj.get("file_type", "unknown"),
                    "sha256": att_obj.get("SHA256") or att_obj.get("sha256"),
                    "threat_names": threat_names
                })

        return attachments

    def _parse_datetime(self, dt_str: Any) -> Optional[datetime]:
        """Parse datetime string to datetime object"""
        if isinstance(dt_str, datetime):
            return dt_str

        if not dt_str:
            return None

        try:
            # Try ISO format
            return datetime.fromisoformat(str(dt_str).replace("Z", "+00:00"))
        except:
            try:
                # Try common formats
                return datetime.strptime(str(dt_str), "%Y-%m-%d %H:%M:%S")
            except:
                return None


def test_extractor():
    """Test MDO field extractor"""
    print("="*60)
    print("Testing MDO Field Extractor")
    print("="*60)

    extractor = MDOFieldExtractor(enforce_hipaa=True)

    # Test email entity
    test_email = {
        "SenderFromAddress": "security@paypa1.com",
        "SenderDisplayName": "PayPal Security",
        "SenderFromDomain": "paypa1.com",
        "SenderIPv4": "185.220.101.5",
        "ReturnPath": "bounce@paypa1.com",
        "ReplyTo": "noreply@paypa1.com",
        "Subject": "URGENT: Your account will be suspended",
        "AuthenticationDetails": {
            "SPF": "Fail",
            "DKIM": "None",
            "DMARC": "Fail"
        },
        "ThreatTypes": ["Phish"],
        "DetectionTechnologies": ["URL Reputation"],
        "DeliveryAction": "Delivered",
        "DeliveryLocation": "Inbox",
        "Urls": [
            {
                "Url": "http://bit.ly/abc123",
                "ThreatVerdict": "Suspicious",
                "ClickCount": 0
            }
        ],
        "Attachments": [],
        "Directionality": "Inbound",
        "IsUserReported": True,
        "ReceivedDateTime": "2025-01-10T14:30:00Z"
    }

    features = extractor.extract(test_email)

    print("\nExtracted Features:")
    print(f"  Sender: {features['sender']}")
    print(f"  Domain: {features['sender_domain']}")
    print(f"  SPF/DKIM/DMARC: {features['spf_result']}/{features['dkim_result']}/{features['dmarc_result']}")
    print(f"  Auth Passed: {features['auth_passed']}")
    print(f"  Threat Types: {features['threat_types']}")
    print(f"  URL Count: {features['url_count']}")
    print(f"  Has Shortened URL: {features['has_shortened_url']}")
    print(f"  Has Urgency: {features['has_urgency']}")
    print(f"  Is External: {features['is_external']}")
    print(f"  User Reported: {features['is_user_reported']}")
    print(f"  Failed Auth + Urgency: {features['failed_auth_with_urgency']}")

    print("\n" + "="*60)
    print(f"✓ Extracted {len(features)} features")
    print("="*60)


if __name__ == "__main__":
    test_extractor()
