#!/usr/bin/env python3
"""
Email Parser - Extract metadata from raw .eml files
Works with public phishing datasets (no Defender required)
"""
import email
import re
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Optional
from datetime import datetime
import hashlib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailParser:
    """
    Parse raw email files (.eml, .msg, raw RFC822)
    Extract metadata for phishing detection without Defender
    """

    def __init__(self):
        self.parser = BytesParser(policy=policy.default)

    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse .eml file and extract all metadata

        Args:
            file_path: Path to .eml file

        Returns:
            Dictionary with email metadata (MDO-compatible format)
        """
        try:
            with open(file_path, 'rb') as f:
                msg = self.parser.parse(f)
            return self._extract_metadata(msg, file_path)
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            raise

    def parse_string(self, email_content: str) -> Dict[str, Any]:
        """Parse email from string (for dataset text files)"""
        try:
            msg = email.message_from_string(email_content, policy=policy.default)
            return self._extract_metadata(msg, source="string")
        except Exception as e:
            logger.error(f"Error parsing email string: {e}")
            raise

    def _extract_metadata(self, msg, source: str) -> Dict[str, Any]:
        """
        Extract all metadata from email message object

        Returns MDO-compatible dictionary WITHOUT Defender fields
        """
        metadata = {}

        # === IDENTIFIERS ===
        metadata["EmailId"] = self._generate_email_id(msg, source)
        metadata["InternetMessageId"] = msg.get("Message-ID", "")
        metadata["NetworkMessageId"] = hashlib.sha256(
            (metadata["InternetMessageId"] + str(datetime.now())).encode()
        ).hexdigest()[:32]

        # === HEADERS ===
        metadata["Subject"] = msg.get("Subject", "")
        metadata["SenderFromAddress"] = msg.get("From", "")
        metadata["SenderDisplayName"] = self._extract_display_name(msg.get("From", ""))
        metadata["SenderFromDomain"] = self._extract_domain(metadata["SenderFromAddress"])

        # Recipients
        metadata["RecipientAddress"] = msg.get("To", "")
        metadata["RecipientsCc"] = msg.get("Cc", "")
        metadata["RecipientsBcc"] = msg.get("Bcc", "")

        # Return-Path and Reply-To
        metadata["ReturnPath"] = msg.get("Return-Path", "")
        metadata["ReplyTo"] = msg.get("Reply-To", "")

        # === AUTHENTICATION RESULTS ===
        # Parse Authentication-Results header (if present)
        auth_results = msg.get("Authentication-Results", "")
        metadata["SPF"] = self._extract_spf_result(auth_results, msg)
        metadata["DKIM"] = self._extract_dkim_result(auth_results, msg)
        metadata["DMARC"] = self._extract_dmarc_result(auth_results, msg)

        # === RECEIVED HEADERS (IP extraction) ===
        metadata["SenderIPv4"] = self._extract_sender_ip(msg.get_all("Received", []))

        # === TIMESTAMPS ===
        metadata["ReceivedDateTime"] = self._parse_date(msg.get("Date", ""))

        # === URLS ===
        body_text = self._get_body_text(msg)
        metadata["Urls"] = self._extract_urls(body_text)
        metadata["UrlCount"] = len(metadata["Urls"])

        # === ATTACHMENTS ===
        metadata["Attachments"] = self._extract_attachments(msg)
        metadata["AttachmentCount"] = len(metadata["Attachments"])

        # === BODY PREVIEW (HIPAA-SAFE: first 50 chars only) ===
        metadata["BodyPreview"] = body_text[:50] if body_text else ""

        # === DIRECTIONALITY ===
        # Infer from sender domain (no Defender signal available)
        metadata["Directionality"] = "Inbound"  # Assume external for public datasets

        # === METADATA FLAGS ===
        metadata["DatasetSource"] = "public_dataset"
        metadata["HasDefenderMetadata"] = False  # Critical flag
        metadata["ParsedAt"] = datetime.utcnow().isoformat()

        return metadata

    def _extract_display_name(self, from_header: str) -> str:
        """Extract display name from 'From' header"""
        # Example: "John Smith <john@example.com>" -> "John Smith"
        match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
        if match:
            return match.group(1).strip()
        return ""

    def _extract_domain(self, email_addr: str) -> str:
        """Extract domain from email address"""
        match = re.search(r'@([\w\.-]+)', email_addr)
        return match.group(1) if match else ""

    def _extract_spf_result(self, auth_results: str, msg) -> str:
        """
        Extract SPF result from Authentication-Results header

        Examples:
        - "spf=pass" -> "Pass"
        - "spf=fail" -> "Fail"
        - "spf=softfail" -> "SoftFail"
        - No SPF -> "None"
        """
        if not auth_results:
            # Check for separate Received-SPF header
            spf_header = msg.get("Received-SPF", "")
            if "pass" in spf_header.lower():
                return "Pass"
            elif "fail" in spf_header.lower():
                return "Fail"
            elif "softfail" in spf_header.lower():
                return "SoftFail"
            return "None"

        # Parse Authentication-Results
        if "spf=pass" in auth_results.lower():
            return "Pass"
        elif "spf=fail" in auth_results.lower():
            return "Fail"
        elif "spf=softfail" in auth_results.lower():
            return "SoftFail"
        elif "spf=neutral" in auth_results.lower():
            return "Neutral"
        else:
            return "None"

    def _extract_dkim_result(self, auth_results: str, msg) -> str:
        """Extract DKIM result"""
        if not auth_results:
            return "None"

        if "dkim=pass" in auth_results.lower():
            return "Pass"
        elif "dkim=fail" in auth_results.lower():
            return "Fail"
        else:
            return "None"

    def _extract_dmarc_result(self, auth_results: str, msg) -> str:
        """Extract DMARC result"""
        if not auth_results:
            return "None"

        if "dmarc=pass" in auth_results.lower():
            return "Pass"
        elif "dmarc=fail" in auth_results.lower():
            return "Fail"
        else:
            return "None"

    def _extract_sender_ip(self, received_headers: List[str]) -> str:
        """
        Extract sender IP from Received headers

        Example Received header:
        "Received: from mail.example.com (mail.example.com [192.168.1.1]) ..."
        """
        if not received_headers:
            return ""

        # Get the LAST Received header (closest to sender)
        last_received = received_headers[-1] if received_headers else ""

        # Extract IP address (IPv4)
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', last_received)
        if ip_match:
            return ip_match.group(1)

        return ""

    def _parse_date(self, date_header: str) -> str:
        """Parse Date header to ISO format"""
        if not date_header:
            return datetime.utcnow().isoformat()

        try:
            # email.utils.parsedate_to_datetime handles RFC 2822 dates
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_header)
            return dt.isoformat()
        except:
            return datetime.utcnow().isoformat()

    def _get_body_text(self, msg) -> str:
        """Extract plain text body (prefer text/plain over text/html)"""
        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        body = part.get_content()
                        break
                    except:
                        pass
        else:
            try:
                body = msg.get_content()
            except:
                pass

        return body if isinstance(body, str) else ""

    def _extract_urls(self, body_text: str) -> List[Dict[str, Any]]:
        """
        Extract URLs from email body

        Returns list of URL dictionaries (without Defender threat verdicts)
        """
        # URL regex pattern
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )

        urls = []
        for match in url_pattern.finditer(body_text):
            url = match.group(0)
            urls.append({
                "Url": url,
                "UrlDomain": self._extract_domain_from_url(url),
                # Note: No ThreatVerdict from Defender
                # Will be enriched by threat intel APIs later
            })

        return urls

    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        match = re.search(r'://([^/]+)', url)
        return match.group(1) if match else ""

    def _extract_attachments(self, msg) -> List[Dict[str, Any]]:
        """
        Extract attachment metadata

        Returns list of attachment dictionaries (without Defender verdicts)
        """
        attachments = []

        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename() or "unknown"

                try:
                    file_data = part.get_content()

                    # Handle both bytes and string data
                    if isinstance(file_data, bytes):
                        file_bytes = file_data
                    elif isinstance(file_data, str):
                        file_bytes = file_data.encode()
                    else:
                        file_bytes = b""

                    # Calculate SHA256 hash
                    file_hash = hashlib.sha256(file_bytes).hexdigest()

                    attachments.append({
                        "FileName": filename,
                        "FileType": filename.split('.')[-1] if '.' in filename else "unknown",
                        "SHA256": file_hash,
                        "SizeBytes": len(file_bytes),
                        # Note: No ThreatNames from Defender
                        # Will be enriched by hash reputation APIs later
                    })
                except Exception as e:
                    logger.warning(f"Could not extract attachment {filename}: {e}")

        return attachments

    def _generate_email_id(self, msg, source: str) -> str:
        """Generate unique email ID"""
        message_id = msg.get("Message-ID", "")
        timestamp = datetime.utcnow().timestamp()
        return hashlib.sha256(f"{message_id}{source}{timestamp}".encode()).hexdigest()[:16]


def test_parser():
    """Test email parser"""
    print("Testing EmailParser...")

    # Create test email
    test_email = """From: test@example.com
To: user@test.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000
Message-ID: <test123@example.com>
Received-SPF: pass

This is a test email body with a URL: http://example.com/test
"""

    parser = EmailParser()
    result = parser.parse_string(test_email)

    print(f"\nParsed metadata:")
    print(f"  Subject: {result['Subject']}")
    print(f"  Sender: {result['SenderFromAddress']}")
    print(f"  Domain: {result['SenderFromDomain']}")
    print(f"  SPF: {result['SPF']}")
    print(f"  URLs: {len(result['Urls'])}")
    print(f"  Has Defender: {result['HasDefenderMetadata']}")
    print("\n✓ EmailParser test complete!")


if __name__ == "__main__":
    test_parser()
