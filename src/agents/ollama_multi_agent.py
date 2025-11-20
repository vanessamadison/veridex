#!/usr/bin/env python3
"""
Multi-Agent Phishing Analyzer
Powered by Ollama local LLMs

Architecture: 6 specialized agents working in concert
- Agent 1: Email Parser (deterministic, no LLM)
- Agent 2: Reputation Checker (Ollama-powered analysis)
- Agent 3: Attachment Analyzer (Ollama-powered malware detection)
- Agent 4: Content Analyzer (Ollama-powered social engineering detection)
- Agent 5: Behavioral Analyst (Ollama-powered anomaly detection)
- Agent 6: Verdict Synthesizer (Ollama-powered final verdict)

Usage:
    python -m src.agents.ollama_multi_agent --email data/test.eml
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import logging

try:
    from ollama import Client
except ImportError:
    print("ERROR: ollama package not installed")
    print("Install with: pip install ollama")
    exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AgentResult:
    """Standard result format for all agents"""
    agent_name: str
    risk_score: float  # 0.0 - 1.0
    confidence: float  # 0.0 - 1.0
    findings: List[str]
    details: Dict
    timestamp: str


class OllamaMultiAgentAnalyzer:
    """
    Multi-agent phishing analyzer using Ollama

    Each agent is a specialized Ollama instance with custom prompts
    """

    def __init__(self, ollama_host: str = "http://localhost:11434"):
        """
        Initialize multi-agent system

        Args:
            ollama_host: Ollama API endpoint
        """
        self.client = Client(host=ollama_host)

        # Agent configurations
        self.agents = {
            'reputation': {
                'model': 'mistral:latest',  # Use available model
                'temperature': 0.1,
                'description': 'Analyzes IP/URL/domain reputation'
            },
            'attachment': {
                'model': 'mistral:latest',
                'temperature': 0.1,
                'description': 'Detects malware and malicious files'
            },
            'content': {
                'model': 'mistral:latest',
                'temperature': 0.2,
                'description': 'Analyzes social engineering tactics'
            },
            'behavioral': {
                'model': 'mistral:latest',
                'temperature': 0.1,
                'description': 'Detects anomalous sender behavior'
            },
            'synthesizer': {
                'model': 'mistral:latest',
                'temperature': 0.0,  # Deterministic for final verdict
                'description': 'Combines all evidence into final verdict'
            }
        }

        logger.info("Multi-agent system initialized")
        logger.info(f"Agents: {list(self.agents.keys())}")

    def _run_ollama_agent(
        self,
        agent_name: str,
        prompt: str,
        context: Dict,
        format_json: bool = True
    ) -> Dict:
        """
        Run specialized Ollama agent

        Args:
            agent_name: Name of agent (reputation, attachment, etc.)
            prompt: System prompt for agent
            context: Context data for analysis
            format_json: Request JSON output

        Returns:
            Agent response as dictionary
        """
        config = self.agents[agent_name]

        # Build full prompt with context
        full_prompt = f"""{prompt}

=== CONTEXT DATA ===
{json.dumps(context, indent=2)}

=== INSTRUCTIONS ===
Analyze the context data and provide your assessment.
Return your response as valid JSON with the following structure:
{{
    "risk_score": <float 0.0-1.0>,
    "confidence": <float 0.0-1.0>,
    "findings": [<list of findings>],
    "details": {{<additional details>}}
}}

Be objective and evidence-based.
"""

        logger.info(f"Running {agent_name} agent...")

        try:
            response = self.client.generate(
                model=config['model'],
                prompt=full_prompt,
                format='json' if format_json else None,
                options={
                    'temperature': config['temperature'],
                    'top_p': 0.9,
                    'num_predict': 500
                }
            )

            result = json.loads(response['response']) if format_json else response['response']
            logger.info(f"{agent_name} agent complete: risk={result.get('risk_score', 'N/A')}")
            return result

        except Exception as e:
            logger.error(f"Error running {agent_name} agent: {e}")
            return {
                "risk_score": 0.5,
                "confidence": 0.0,
                "findings": [f"Error: {str(e)}"],
                "details": {"error": str(e)}
            }

    def run_reputation_agent(self, email_data: Dict) -> AgentResult:
        """
        Agent 2: Reputation Checker

        Analyzes IP, URL, domain reputation from external threat feeds

        Args:
            email_data: Parsed email with sender IP, URLs, domains

        Returns:
            AgentResult with reputation assessment
        """
        prompt = """You are a REPUTATION CHECKER AGENT specializing in threat intelligence.

Your role is to analyze sender IP addresses, URLs, and domains for malicious indicators.

ANALYZE FOR:
1. Sender IP reputation
   - Known spam/malware sources
   - Geographic location vs claimed organization
   - VPN/Tor/proxy usage
   - Abuse confidence score

2. URL reputation
   - Phishing database matches
   - Domain age (<30 days = suspicious)
   - SSL certificate validity
   - URL shorteners (bit.ly, tinyurl)

3. Domain reputation
   - WHOIS registration age
   - Privacy protection enabled
   - Registrar reputation
   - DNS records (SPF, DMARC configured?)

RISK SCORING:
- 0.9-1.0: CRITICAL (confirmed malicious IP/URL)
- 0.7-0.9: HIGH (multiple red flags)
- 0.4-0.7: MEDIUM (some indicators)
- 0.0-0.4: LOW (mostly clean)

Provide evidence-based assessment with specific indicators.
"""

        context = {
            'sender_ip': email_data.get('sender_ip', 'unknown'),
            'sender_domain': email_data.get('sender_domain', 'unknown'),
            'urls': email_data.get('urls', []),
            'spf_result': email_data.get('spf_result', 'None'),
            'dkim_result': email_data.get('dkim_result', 'None'),
            'dmarc_result': email_data.get('dmarc_result', 'None')
        }

        result = self._run_ollama_agent('reputation', prompt, context)

        return AgentResult(
            agent_name='reputation',
            risk_score=result.get('risk_score', 0.5),
            confidence=result.get('confidence', 0.5),
            findings=result.get('findings', []),
            details=result.get('details', {}),
            timestamp=self._get_timestamp()
        )

    def run_attachment_agent(self, email_data: Dict) -> AgentResult:
        """
        Agent 3: Attachment Analyzer

        Detects malware and malicious files

        Args:
            email_data: Parsed email with attachment metadata

        Returns:
            AgentResult with malware assessment
        """
        prompt = """You are an ATTACHMENT ANALYZER AGENT specializing in malware detection.

Your role is to assess email attachments for malicious content.

ANALYZE FOR:
1. File type mismatches
   - Declared type vs actual type
   - Double extensions (invoice.pdf.exe)
   - Executable files disguised as documents

2. Dangerous file types
   - Executables: .exe, .scr, .com, .bat
   - Scripts: .js, .vbs, .ps1, .sh
   - Office macros: .docm, .xlsm
   - Compressed: .zip, .rar (may contain malware)

3. Suspicious filenames
   - Generic names (invoice.pdf, urgent.doc)
   - Typos or odd characters
   - Urgency indicators (URGENT_payment.exe)

4. File hash reputation (if available)
   - VirusTotal detections
   - Known malware families

RISK SCORING:
- 0.9-1.0: CRITICAL (malware confirmed)
- 0.7-0.9: HIGH (executable file or suspicious type)
- 0.4-0.7: MEDIUM (macro-enabled document)
- 0.0-0.4: LOW (safe file type)

Provide detailed reasoning for your assessment.
"""

        context = {
            'attachments': email_data.get('attachments', []),
            'attachment_count': len(email_data.get('attachments', []))
        }

        result = self._run_ollama_agent('attachment', prompt, context)

        return AgentResult(
            agent_name='attachment',
            risk_score=result.get('risk_score', 0.0),
            confidence=result.get('confidence', 0.5),
            findings=result.get('findings', []),
            details=result.get('details', {}),
            timestamp=self._get_timestamp()
        )

    def run_content_agent(self, email_data: Dict) -> AgentResult:
        """
        Agent 4: Content Analyzer

        Detects social engineering tactics in email body

        Args:
            email_data: Parsed email with subject and body

        Returns:
            AgentResult with social engineering assessment
        """
        prompt = """You are a CONTENT ANALYZER AGENT specializing in social engineering detection.

Your role is to identify manipulation tactics in email content.

ANALYZE FOR:
1. Urgency/Fear tactics
   - "Account suspended", "Expires in 24 hours"
   - Threats of consequences
   - Time-sensitive offers
   - "Verify immediately or lose access"

2. Authority impersonation
   - Claims from CEO, IT, HR, finance
   - Official-sounding language
   - Requests for sensitive information
   - Brand impersonation (PayPal, Microsoft, IRS)

3. Trust exploitation
   - "You won a prize"
   - "Package delivery failed"
   - "Password reset request"
   - "Invoice attached"

4. Grammar/formatting
   - Poor English (non-native speaker)
   - Inconsistent capitalization
   - Generic greetings ("Dear Customer")
   - Spelling errors

5. Suspicious requests
   - Password/credential requests via email
   - Payment/wire transfer urgency
   - Download attachment to resolve issue
   - Click link to verify account

RISK SCORING:
- 0.9-1.0: CRITICAL (multiple high-impact tactics)
- 0.7-0.9: HIGH (strong social engineering)
- 0.4-0.7: MEDIUM (some manipulation)
- 0.0-0.4: LOW (normal business email)

Rate each category and provide overall social engineering score.
"""

        context = {
            'subject': email_data.get('subject', ''),
            'body_preview': email_data.get('body_preview', '')[:500],  # First 500 chars
            'sender_display_name': email_data.get('sender_display_name', ''),
            'has_urls': len(email_data.get('urls', [])) > 0,
            'has_attachments': len(email_data.get('attachments', [])) > 0
        }

        result = self._run_ollama_agent('content', prompt, context)

        return AgentResult(
            agent_name='content',
            risk_score=result.get('risk_score', 0.5),
            confidence=result.get('confidence', 0.5),
            findings=result.get('findings', []),
            details=result.get('details', {}),
            timestamp=self._get_timestamp()
        )

    def run_behavioral_agent(self, email_data: Dict) -> AgentResult:
        """
        Agent 5: Behavioral Analyst

        Detects anomalies in sender behavior

        Args:
            email_data: Parsed email with sender metadata

        Returns:
            AgentResult with behavioral anomaly assessment
        """
        prompt = """You are a BEHAVIORAL ANALYST AGENT detecting sender anomalies.

Your role is to identify unusual patterns that indicate compromised accounts or spoofing.

ANALYZE FOR:
1. Domain age
   - Newly registered (<30 days) = HIGH RISK
   - No WHOIS data = suspicious
   - Privacy protection enabled

2. Authentication failures
   - SPF Fail = sender IP not authorized
   - DKIM None/Fail = not signed by domain
   - DMARC Fail = policy not met

3. Geographic anomalies
   - Sender IP country vs claimed organization
   - PayPal email from Russia
   - US bank email from Nigeria

4. First-time sender
   - No previous email history
   - Sudden change in behavior
   - Unusual send time (3am)

5. Volume anomalies
   - Spam burst (100+ in 1 hour)
   - First email requests money

RISK SCORING:
- 0.9-1.0: CRITICAL (new domain + auth failures)
- 0.7-0.9: HIGH (multiple anomalies)
- 0.4-0.7: MEDIUM (some red flags)
- 0.0-0.4: LOW (known sender, passes auth)

Provide behavioral risk assessment with evidence.
"""

        context = {
            'sender_domain': email_data.get('sender_domain', ''),
            'sender_ip': email_data.get('sender_ip', ''),
            'spf_result': email_data.get('spf_result', 'None'),
            'dkim_result': email_data.get('dkim_result', 'None'),
            'dmarc_result': email_data.get('dmarc_result', 'None'),
            'is_reply': email_data.get('in_reply_to') is not None
        }

        result = self._run_ollama_agent('behavioral', prompt, context)

        return AgentResult(
            agent_name='behavioral',
            risk_score=result.get('risk_score', 0.5),
            confidence=result.get('confidence', 0.5),
            findings=result.get('findings', []),
            details=result.get('details', {}),
            timestamp=self._get_timestamp()
        )

    def run_synthesizer_agent(self, agent_results: Dict[str, AgentResult]) -> Dict:
        """
        Agent 6: Verdict Synthesizer

        Combines all agent outputs into final verdict

        Args:
            agent_results: Dict of AgentResult from all agents

        Returns:
            Final verdict dictionary
        """
        prompt = """You are the VERDICT SYNTHESIZER AGENT making final phishing determinations.

Your role is to combine evidence from all specialized agents into a final verdict.

AGENTS REPORTING:
1. Reputation Checker: IP/URL/domain reputation scores
2. Attachment Analyzer: Malware detection results
3. Content Analyzer: Social engineering tactics detected
4. Behavioral Analyst: Sender behavior anomalies

VERDICT RULES:
1. MALICIOUS (score >= 0.75):
   - Malware detected in attachment (critical)
   - High IP reputation risk (>0.8) + auth failures
   - Confirmed phishing URL + social engineering
   - New domain (<30 days) + urgency tactics + auth fail

2. SUSPICIOUS (0.40 <= score < 0.75):
   - Multiple moderate risks (3+ red flags)
   - Social engineering (>0.7) without other confirmation
   - Auth failures + generic phishing indicators
   - First-time sender with suspicious content

3. CLEAN (score < 0.40):
   - Authentication passes (SPF/DKIM/DMARC)
   - Known sender with no red flags
   - No malicious indicators
   - Normal business communication

WEIGHTING:
- Attachment malware: 40% (highest priority)
- Reputation (IP/URL): 25%
- Content (social engineering): 20%
- Behavioral (anomalies): 15%

CONSERVATIVE APPROACH:
- When in doubt, flag as SUSPICIOUS for analyst review
- Better false positive than missed phishing

Provide:
1. Final verdict: MALICIOUS / SUSPICIOUS / CLEAN
2. Confidence: 0.0 - 1.0
3. Ensemble score: 0.0 - 1.0 (weighted average)
4. Top 3 risk factors
5. Detailed reasoning (2-3 sentences)
6. Recommended action
"""

        context = {
            'reputation_risk': agent_results['reputation'].risk_score,
            'reputation_findings': agent_results['reputation'].findings,
            'attachment_risk': agent_results['attachment'].risk_score,
            'attachment_findings': agent_results['attachment'].findings,
            'content_risk': agent_results['content'].risk_score,
            'content_findings': agent_results['content'].findings,
            'behavioral_risk': agent_results['behavioral'].risk_score,
            'behavioral_findings': agent_results['behavioral'].findings
        }

        result = self._run_ollama_agent('synthesizer', prompt, context)

        # Calculate weighted ensemble score
        ensemble_score = (
            0.40 * agent_results['attachment'].risk_score +
            0.25 * agent_results['reputation'].risk_score +
            0.20 * agent_results['content'].risk_score +
            0.15 * agent_results['behavioral'].risk_score
        )

        # Determine verdict based on thresholds
        if ensemble_score >= 0.75:
            verdict = "MALICIOUS"
        elif ensemble_score >= 0.40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "verdict": result.get('verdict', verdict),
            "confidence": result.get('confidence', 0.8),
            "ensemble_score": ensemble_score,
            "risk_factors": result.get('findings', [])[:3],
            "reasoning": result.get('details', {}).get('reasoning', ''),
            "recommended_action": result.get('details', {}).get('action', 'review'),
            "agent_scores": {
                'reputation': agent_results['reputation'].risk_score,
                'attachment': agent_results['attachment'].risk_score,
                'content': agent_results['content'].risk_score,
                'behavioral': agent_results['behavioral'].risk_score
            }
        }

    def analyze_email(self, email_data: Dict) -> Dict:
        """
        Run full multi-agent analysis on email

        Args:
            email_data: Parsed email metadata from EmailParser

        Returns:
            Complete analysis with verdict
        """
        logger.info("Starting multi-agent analysis...")

        # Run all agents (could be parallelized)
        results = {}

        results['reputation'] = self.run_reputation_agent(email_data)
        results['attachment'] = self.run_attachment_agent(email_data)
        results['content'] = self.run_content_agent(email_data)
        results['behavioral'] = self.run_behavioral_agent(email_data)

        # Synthesize final verdict
        verdict = self.run_synthesizer_agent(results)

        logger.info(f"Analysis complete: {verdict['verdict']} (score: {verdict['ensemble_score']:.2f})")

        return {
            'verdict': verdict,
            'agent_results': {k: asdict(v) for k, v in results.items()},
            'timestamp': self._get_timestamp()
        }

    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()


def main():
    """Demo the multi-agent system"""
    import argparse

    parser = argparse.ArgumentParser(description='Multi-Agent Phishing Analyzer')
    parser.add_argument('--email', type=str, help='Path to .eml file')
    parser.add_argument('--demo', action='store_true', help='Run demo with sample data')
    args = parser.parse_args()

    if args.demo:
        # Demo with sample phishing email
        sample_email = {
            'subject': 'URGENT: Your PayPal account has been suspended',
            'sender_display_name': 'PayPal Support',
            'sender_domain': 'paypal-verify.xyz',
            'sender_ip': '185.220.101.42',
            'spf_result': 'Fail',
            'dkim_result': 'None',
            'dmarc_result': 'None',
            'urls': [
                {
                    'url': 'http://paypal-verify.xyz/login',
                    'is_shortened': False
                }
            ],
            'attachments': [
                {
                    'filename': 'invoice.pdf.exe',
                    'declared_type': 'application/pdf',
                    'size': 245760
                }
            ],
            'body_preview': 'Your PayPal account has been suspended due to suspicious activity. Click here to verify your identity immediately or your account will be permanently closed within 24 hours.'
        }

        print("=" * 60)
        print("MULTI-AGENT PHISHING ANALYZER - DEMO")
        print("=" * 60)
        print()

        analyzer = OllamaMultiAgentAnalyzer()
        result = analyzer.analyze_email(sample_email)

        print("\n=== VERDICT ===")
        print(f"Final Verdict: {result['verdict']['verdict']}")
        print(f"Confidence: {result['verdict']['confidence']:.2f}")
        print(f"Ensemble Score: {result['verdict']['ensemble_score']:.2f}")
        print()

        print("=== RISK FACTORS ===")
        for i, factor in enumerate(result['verdict']['risk_factors'], 1):
            print(f"{i}. {factor}")
        print()

        print("=== AGENT SCORES ===")
        for agent, score in result['verdict']['agent_scores'].items():
            print(f"{agent:15} {score:.2f} {'█' * int(score * 20)}")
        print()

        print("=== RECOMMENDATION ===")
        print(result['verdict']['recommended_action'])
        print()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
