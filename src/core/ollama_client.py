#!/usr/bin/env python3
"""
Ollama Security Analyst Client - HIPAA-Compliant Local LLM Interface
Handles all communication with local Ollama instance for threat analysis
"""
import requests
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OllamaSecurityAnalyst:
    """
    Local LLM-powered security analyst using Ollama
    All processing stays on-premise for HIPAA compliance
    """

    def __init__(
        self,
        model: str = "mistral",
        base_url: str = "http://localhost:11434",
        system_prompt_path: Optional[str] = None
    ):
        """
        Initialize Ollama client

        Args:
            model: Ollama model name (mistral, llama3, etc.)
            base_url: Ollama API endpoint
            system_prompt_path: Path to system prompt file
        """
        self.model = model
        self.base_url = base_url
        self.system_prompt = self._load_system_prompt(system_prompt_path)

        # Verify Ollama is running
        self._health_check()

    def _health_check(self) -> bool:
        """Verify Ollama service is accessible"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            response.raise_for_status()
            models = [m["name"] for m in response.json().get("models", [])]

            if self.model not in models:
                logger.warning(f"Model '{self.model}' not found. Available: {models}")
                logger.info(f"Pull with: ollama pull {self.model}")

            logger.info(f"✓ Ollama connected ({len(models)} models available)")
            return True

        except requests.exceptions.ConnectionError:
            logger.error("✗ Ollama not running. Start with: ollama serve")
            raise
        except Exception as e:
            logger.error(f"✗ Ollama health check failed: {e}")
            raise

    def _load_system_prompt(self, path: Optional[str]) -> str:
        """Load system prompt from file or use default"""
        if path:
            try:
                with open(path, 'r') as f:
                    return f.read()
            except FileNotFoundError:
                logger.warning(f"System prompt file not found: {path}, using default")

        return self._default_system_prompt()

    def _default_system_prompt(self) -> str:
        """Default SOC analyst system prompt based on CURRENT_SOP.md"""
        return """You are an expert SOC analyst specializing in email security for a healthcare organization (HIPAA-compliant).

Your role: Analyze emails and determine if they are MALICIOUS, SUSPICIOUS, or CLEAN.

Decision Criteria (follow this SOP):

MALICIOUS indicators (high confidence):
- Failed SPF/DKIM/DMARC + external sender + urgency keywords
- Known malicious URL (VirusTotal hits > 3)
- Known malicious file hash
- Spoofed internal domain from external IP
- Credential harvesting page (login form + urgency)
- BEC pattern (executive impersonation + wire transfer request)
- Malware attachment confirmed by Defender

SUSPICIOUS indicators (requires analyst review):
- External sender + attachment + urgency keywords
- Shortened URLs (bit.ly, tinyurl) + urgency
- New domain (<30 days) + financial request
- Reply-To ≠ Sender
- HTML attachment from unknown sender
- User reported + Microsoft verdict: Unknown
- Mixed authentication results (SPF pass, DKIM fail)

CLEAN indicators (high confidence):
- Internal sender from trusted domains (configured in system)
- Known partner/vendor with good reputation
- No URLs/attachments + conversational tone
- Microsoft verdict: No threats found + no user report
- Legitimate automated system (Workday, Canvas, ServiceNow, SharePoint)
- All authentication checks pass (SPF, DKIM, DMARC)

Output format (JSON only, no additional text):
{
  "verdict": "MALICIOUS|SUSPICIOUS|CLEAN",
  "confidence": 0.85,
  "primary_indicators": ["indicator1", "indicator2"],
  "risk_score": 75,
  "recommended_action": "auto_block|analyst_review|auto_resolve",
  "reasoning": "Brief explanation of decision based on SOP"
}

CRITICAL: Err on the side of caution. When in doubt, mark SUSPICIOUS for analyst review.
Healthcare data protection is paramount - false negatives are more costly than false positives."""

    def _build_analysis_prompt(self, email_features: Dict[str, Any]) -> str:
        """
        Build detailed analysis prompt from email features

        Args:
            email_features: Extracted MDO email entity fields

        Returns:
            Formatted prompt string
        """
        # HIPAA-safe: Only use metadata, no email body content
        prompt_parts = [
            "Analyze this email for security threats:",
            "",
            "=== HEADER INFORMATION ===",
            f"Sender: {email_features.get('sender', 'N/A')}",
            f"Sender Domain: {email_features.get('sender_domain', 'N/A')}",
            f"Sender IP: {email_features.get('sender_ip', 'N/A')}",
            f"Return-Path: {email_features.get('return_path', 'N/A')}",
            f"Reply-To: {email_features.get('reply_to', 'N/A')}",
            f"Subject: {email_features.get('subject', 'N/A')}",
            "",
            "=== AUTHENTICATION RESULTS ===",
            f"SPF: {email_features.get('spf_result', 'N/A')}",
            f"DKIM: {email_features.get('dkim_result', 'N/A')}",
            f"DMARC: {email_features.get('dmarc_result', 'N/A')}",
            "",
            "=== MICROSOFT DEFENDER SIGNALS ===",
            f"Threat Types: {', '.join(email_features.get('threat_types', [])) or 'None'}",
            f"Detection Technologies: {', '.join(email_features.get('detection_tech', [])) or 'None'}",
            f"Delivery Action: {email_features.get('delivery_action', 'N/A')}",
            f"Delivery Location: {email_features.get('delivery_location', 'N/A')}",
            f"Directionality: {email_features.get('directionality', 'N/A')}",
            ""
        ]

        # URL analysis
        urls = email_features.get('urls', [])
        if urls:
            prompt_parts.append("=== URL ANALYSIS ===")
            prompt_parts.append(f"Total URLs: {len(urls)}")
            for i, url_obj in enumerate(urls[:5], 1):  # Limit to first 5
                prompt_parts.append(
                    f"  {i}. {url_obj.get('url', 'N/A')} "
                    f"(Verdict: {url_obj.get('threat_verdict', 'Unknown')}, "
                    f"Clicks: {url_obj.get('click_count', 0)})"
                )
            prompt_parts.append("")

        # Attachment analysis
        attachments = email_features.get('attachments', [])
        if attachments:
            prompt_parts.append("=== ATTACHMENT ANALYSIS ===")
            prompt_parts.append(f"Total Attachments: {len(attachments)}")
            for i, att in enumerate(attachments, 1):
                prompt_parts.append(
                    f"  {i}. {att.get('filename', 'N/A')} "
                    f"(Type: {att.get('file_type', 'N/A')}, "
                    f"Threats: {', '.join(att.get('threat_names', [])) or 'None'})"
                )
            prompt_parts.append("")

        # User reporting context
        if email_features.get('is_user_reported'):
            prompt_parts.append("=== USER CONTEXT ===")
            prompt_parts.append("⚠ This email was reported by a user as suspicious")
            prompt_parts.append("")

        prompt_parts.append("=== YOUR ANALYSIS ===")
        prompt_parts.append("Provide your verdict in JSON format:")

        return "\n".join(prompt_parts)

    def analyze_email(
        self,
        email_features: Dict[str, Any],
        temperature: float = 0.1,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Analyze email for threats using Ollama

        Args:
            email_features: Extracted MDO email entity fields
            temperature: LLM temperature (0.1 = more deterministic)
            timeout: Request timeout in seconds

        Returns:
            Dict with verdict, confidence, risk_score, etc.

        Raises:
            requests.exceptions.RequestException: If Ollama API fails
            json.JSONDecodeError: If response not valid JSON
        """
        try:
            # Build prompt
            analysis_prompt = self._build_analysis_prompt(email_features)
            full_prompt = f"{self.system_prompt}\n\n{analysis_prompt}"

            # Call Ollama API
            logger.debug(f"Analyzing email: {email_features.get('subject', 'N/A')[:50]}")
            start_time = datetime.now()

            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "format": "json",
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "top_p": 0.9,
                        "num_predict": 500  # Limit response length
                    }
                },
                timeout=timeout
            )
            response.raise_for_status()

            # Parse response
            ollama_response = response.json()
            analysis_result = json.loads(ollama_response["response"])

            # Calculate inference time
            inference_time = (datetime.now() - start_time).total_seconds()
            analysis_result["inference_time_seconds"] = inference_time

            # Validate response structure
            required_fields = ["verdict", "confidence", "risk_score", "recommended_action"]
            missing_fields = [f for f in required_fields if f not in analysis_result]

            if missing_fields:
                logger.warning(f"Ollama response missing fields: {missing_fields}")
                return self._fallback_analysis(email_features, "incomplete_response")

            # Normalize values
            analysis_result["verdict"] = analysis_result["verdict"].upper()
            analysis_result["confidence"] = float(analysis_result["confidence"])
            analysis_result["risk_score"] = int(analysis_result["risk_score"])

            logger.info(
                f"✓ Analysis complete: {analysis_result['verdict']} "
                f"(confidence: {analysis_result['confidence']:.2f}, "
                f"time: {inference_time:.2f}s)"
            )

            return analysis_result

        except requests.exceptions.Timeout:
            logger.error(f"Ollama request timeout ({timeout}s)")
            return self._fallback_analysis(email_features, "timeout")

        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama API error: {e}")
            return self._fallback_analysis(email_features, "api_error")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response from Ollama: {e}")
            return self._fallback_analysis(email_features, "invalid_json")

        except Exception as e:
            logger.error(f"Unexpected error during analysis: {e}")
            return self._fallback_analysis(email_features, "unknown_error")

    def _fallback_analysis(self, email_features: Dict[str, Any], error_reason: str) -> Dict[str, Any]:
        """
        Provide safe fallback analysis when Ollama fails
        Always requires analyst review to ensure safety
        """
        logger.warning(f"Using fallback analysis due to: {error_reason}")

        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.0,
            "risk_score": 50,
            "recommended_action": "analyst_review",
            "reasoning": f"Ollama analysis failed ({error_reason}), requires manual review for safety",
            "primary_indicators": ["ollama_failure"],
            "error": error_reason,
            "inference_time_seconds": 0
        }

    def batch_analyze(self, email_list: list, max_workers: int = 5) -> list:
        """
        Analyze multiple emails in parallel

        Args:
            email_list: List of email feature dictionaries
            max_workers: Maximum concurrent Ollama requests

        Returns:
            List of analysis results
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = []
        total = len(email_list)

        logger.info(f"Starting batch analysis of {total} emails (workers: {max_workers})")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_email = {
                executor.submit(self.analyze_email, email): email
                for email in email_list
            }

            # Collect results as they complete
            for i, future in enumerate(as_completed(future_to_email), 1):
                email = future_to_email[future]
                try:
                    result = future.result()
                    result["email_id"] = email.get("id", i)
                    results.append(result)
                    logger.info(f"Progress: {i}/{total} - {result['verdict']}")
                except Exception as e:
                    logger.error(f"Batch analysis failed for email {i}: {e}")
                    results.append(self._fallback_analysis(email, "batch_error"))

        logger.info(f"✓ Batch analysis complete: {len(results)}/{total} processed")
        return results


def test_ollama_client():
    """Test function to verify Ollama client works"""
    print("="*60)
    print("Testing Ollama Security Analyst Client")
    print("="*60)

    # Initialize client
    analyst = OllamaSecurityAnalyst(model="mistral")

    # Test case 1: Obvious phishing
    phishing_email = {
        "sender": "security@paypa1.com",
        "sender_domain": "paypa1.com",
        "sender_ip": "185.220.101.5",
        "return_path": "bounce@paypa1.com",
        "reply_to": "security@paypa1.com",
        "subject": "URGENT: Your account will be suspended in 24 hours - Verify now",
        "spf_result": "Fail",
        "dkim_result": "None",
        "dmarc_result": "Fail",
        "threat_types": [],
        "detection_tech": [],
        "delivery_action": "Delivered",
        "delivery_location": "Inbox",
        "directionality": "Inbound",
        "urls": [
            {
                "url": "http://paypa1.com/verify",
                "threat_verdict": "Unknown",
                "click_count": 0
            }
        ],
        "attachments": [],
        "is_user_reported": True
    }

    print("\n1. Testing phishing email...")
    result = analyst.analyze_email(phishing_email)
    print(f"   Verdict: {result['verdict']}")
    print(f"   Confidence: {result['confidence']:.2f}")
    print(f"   Risk Score: {result['risk_score']}")
    print(f"   Action: {result['recommended_action']}")
    print(f"   Reasoning: {result['reasoning']}")

    # Test case 2: Clean internal email
    clean_email = {
        "sender": "helpdesk@example.com",
        "sender_domain": "example.com",
        "sender_ip": "10.0.0.50",
        "return_path": "helpdesk@example.com",
        "reply_to": "helpdesk@example.com",
        "subject": "IT Department Weekly Update",
        "spf_result": "Pass",
        "dkim_result": "Pass",
        "dmarc_result": "Pass",
        "threat_types": [],
        "detection_tech": [],
        "delivery_action": "Delivered",
        "delivery_location": "Inbox",
        "directionality": "Intra-org",
        "urls": [],
        "attachments": [],
        "is_user_reported": False
    }

    print("\n2. Testing clean internal email...")
    result = analyst.analyze_email(clean_email)
    print(f"   Verdict: {result['verdict']}")
    print(f"   Confidence: {result['confidence']:.2f}")
    print(f"   Risk Score: {result['risk_score']}")
    print(f"   Action: {result['recommended_action']}")

    print("\n" + "="*60)
    print("✓ Test complete")
    print("="*60)


if __name__ == "__main__":
    test_ollama_client()
