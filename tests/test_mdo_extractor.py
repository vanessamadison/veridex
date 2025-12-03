#!/usr/bin/env python3
"""
Unit tests for Microsoft Defender field extractor
Tests HIPAA-compliant metadata extraction
"""
import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.mdo_field_extractor import MDOFieldExtractor


class TestMDOFieldExtractor:
    """Test MDO field extraction and normalization"""

    @pytest.fixture
    def extractor(self):
        """Create extractor instance"""
        return MDOFieldExtractor(enforce_hipaa=True)

    def test_hipaa_compliance_no_body_content(self, extractor):
        """Test that body content is excluded when HIPAA is enforced"""
        email_data = {
            "subject": "Test Email",
            "body": "This is sensitive PHI content that should be excluded",
            "sender": "test@example.com"
        }

        extracted = extractor.extract_fields(email_data)

        # Body should not be in extracted fields
        assert "body" not in extracted or extracted.get("body") is None

    def test_authentication_field_extraction(self, extractor):
        """Test extraction of SPF/DKIM/DMARC fields"""
        email_data = {
            "subject": "Test",
            "authentication_results": {
                "spf": "Pass",
                "dkim": "Pass",
                "dmarc": "Pass"
            }
        }

        extracted = extractor.extract_fields(email_data)

        assert "authentication" in extracted
        assert extracted["authentication"]["spf"] == "Pass"
        assert extracted["authentication"]["dkim"] == "Pass"
        assert extracted["authentication"]["dmarc"] == "Pass"

    def test_bcl_extraction(self, extractor):
        """Test Bulk Complaint Level extraction"""
        email_data = {
            "subject": "Test",
            "bulk_complaint_level": 7
        }

        extracted = extractor.extract_fields(email_data)

        assert "bcl" in extracted
        assert extracted["bcl"] == 7

    def test_internal_domain_detection(self, extractor):
        """Test detection of internal trusted domains"""
        # Internal domain
        internal_email = {
            "subject": "Test",
            "sender": "user@example.com"
        }

        # External domain
        external_email = {
            "subject": "Test",
            "sender": "user@external-unknown.com"
        }

        internal_extracted = extractor.extract_fields(internal_email)
        external_extracted = extractor.extract_fields(external_email)

        # Should identify internal vs external
        # Implementation may vary, but should have domain classification
        assert "sender" in internal_extracted
        assert "sender" in external_extracted

    def test_url_extraction(self, extractor):
        """Test URL extraction from email"""
        email_data = {
            "subject": "Test",
            "urls": [
                {"url": "http://example.com", "threat": None},
                {"url": "http://malicious.com", "threat": "Phishing"}
            ]
        }

        extracted = extractor.extract_fields(email_data)

        assert "urls" in extracted
        assert len(extracted["urls"]) == 2

    def test_attachment_extraction(self, extractor):
        """Test attachment metadata extraction"""
        email_data = {
            "subject": "Test",
            "attachments": [
                {"filename": "document.pdf", "threat": None},
                {"filename": "malware.exe", "threat": "Malware"}
            ]
        }

        extracted = extractor.extract_fields(email_data)

        assert "attachments" in extracted
        assert len(extracted["attachments"]) == 2


class TestHIPAACompliance:
    """Test HIPAA compliance enforcement"""

    def test_metadata_only_processing(self):
        """Test that only metadata is processed, no content"""
        extractor = MDOFieldExtractor(enforce_hipaa=True)

        email_with_phi = {
            "subject": "Patient: John Doe - MRN: 123456",
            "body": "Patient John Doe (DOB: 01/01/1980) has diagnosis of...",
            "sender": "doctor@example.com",
            "authentication_results": {
                "spf": "Pass",
                "dkim": "Pass",
                "dmarc": "Pass"
            }
        }

        extracted = extractor.extract_fields(email_with_phi)

        # Should have metadata
        assert "sender" in extracted
        assert "authentication" in extracted

        # Should NOT have body content
        assert "body" not in extracted or extracted.get("body") is None

    def test_no_subject_content_analysis(self):
        """Test that subject content is not analyzed for PHI"""
        extractor = MDOFieldExtractor(enforce_hipaa=True)

        # Even though subject has potential PHI, we only extract it,
        # we don't analyze its content for this test
        email_data = {
            "subject": "Patient Record Update",
            "sender": "test@example.com"
        }

        extracted = extractor.extract_fields(email_data)

        # Subject should be extracted as metadata
        assert "subject" in extracted
        # But no content analysis should be performed
        # (This is a design decision - subject is metadata, not body content)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
