#!/usr/bin/env python3
"""
Phishing Triage Orchestrator - Master script for end-to-end email analysis
Integrates: Ollama + MDO Field Extraction + Ensemble Verdict + HIPAA Compliance
"""
import argparse
import csv
import json
import logging
import yaml
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

# Import our modules
from ollama_client import OllamaSecurityAnalyst
from mdo_field_extractor import MDOFieldExtractor
from ensemble_verdict_engine import EnsembleVerdictEngine

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"✓ Loaded configuration from {config_path}")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        logger.info("Using default configuration")
        return {}
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        logger.info("Using default configuration")
        return {}


class TriageOrchestrator:
    """
    Orchestrates the complete email triage workflow:
    1. Load emails from CSV/API
    2. Extract MDO fields
    3. Run ensemble analysis (Ollama + Rules + Defender)
    4. Generate verdicts with HIPAA-compliant audit logs
    5. Create analyst review queue
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        ollama_model: Optional[str] = None,
        output_dir: Optional[str] = None,
        enforce_hipaa: Optional[bool] = None
    ):
        """
        Initialize orchestrator

        Args:
            config: Configuration dictionary (from YAML)
            ollama_model: Ollama model to use (overrides config)
            output_dir: Directory for outputs (overrides config)
            enforce_hipaa: Enforce HIPAA data minimization (overrides config)
        """
        # Use config or defaults
        self.config = config or {}

        # Apply overrides or use config/defaults
        model = ollama_model or self.config.get('ollama', {}).get('model', 'mistral')
        output = output_dir or "results/triage_run"
        hipaa = enforce_hipaa if enforce_hipaa is not None else self.config.get('hipaa', {}).get('enforce', True)

        self.output_dir = Path(output)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Initialize components
        logger.info("Initializing Ollama Security Analyst...")
        ollama_config = self.config.get('ollama', {})
        self.ollama_client = OllamaSecurityAnalyst(
            model=model,
            base_url=ollama_config.get('base_url', 'http://localhost:11434')
        )

        logger.info("Initializing MDO Field Extractor...")
        self.field_extractor = MDOFieldExtractor(enforce_hipaa=hipaa)

        logger.info("Initializing Ensemble Verdict Engine...")
        ensemble_config = self.config.get('ensemble', {})
        self.verdict_engine = EnsembleVerdictEngine(
            self.ollama_client,
            weights=ensemble_config.get('weights'),
            confidence_thresholds=ensemble_config.get('thresholds')
        )

        self.enforce_hipaa = hipaa

        logger.info(f"✓ Configuration loaded:")
        logger.info(f"  - Model: {model}")
        logger.info(f"  - HIPAA: {'ENABLED' if hipaa else 'DISABLED'}")
        logger.info(f"  - Output: {self.output_dir}")

    def load_emails_from_csv(self, csv_path: str) -> List[Dict]:
        """Load emails from CSV file"""
        logger.info(f"Loading emails from {csv_path}...")

        emails = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                emails.append(row)

        logger.info(f"✓ Loaded {len(emails)} emails")
        return emails

    def process_email(
        self,
        email_entity: Dict[str, Any],
        use_ollama: bool = True
    ) -> Dict[str, Any]:
        """
        Process a single email through the full pipeline

        Args:
            email_entity: Raw email entity (CSV row or API response)
            use_ollama: Whether to use Ollama (set False for faster processing)

        Returns:
            Dict with verdict, features, and audit information
        """
        # Extract MDO fields
        features = self.field_extractor.extract(email_entity)

        # Generate ensemble verdict
        verdict = self.verdict_engine.make_verdict(features, use_ollama=use_ollama)

        # Combine results
        result = {
            "email_id": email_entity.get("id") or email_entity.get("InternetMessageId") or f"email_{self.run_id}",
            "subject": features.get("subject", "")[:100],  # Truncate for display
            "sender": features.get("sender", ""),
            "received_datetime": features.get("received_datetime"),
            **verdict,
            "features": features  # Full feature set for audit
        }

        return result

    def process_batch(
        self,
        emails: List[Dict],
        use_ollama: bool = True,
        max_emails: int = None,
        parallel: bool = False
    ) -> List[Dict]:
        """
        Process batch of emails

        Args:
            emails: List of email entities
            use_ollama: Whether to use Ollama
            max_emails: Limit number of emails (for testing)
            parallel: Use parallel processing (experimental)

        Returns:
            List of results
        """
        if max_emails:
            emails = emails[:max_emails]

        logger.info(f"Processing {len(emails)} emails (Ollama: {use_ollama}, Parallel: {parallel})...")

        results = []

        if parallel:
            # Parallel processing (faster but uses more resources)
            from concurrent.futures import ThreadPoolExecutor, as_completed

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {
                    executor.submit(self.process_email, email, use_ollama): email
                    for email in emails
                }

                for i, future in enumerate(as_completed(futures), 1):
                    try:
                        result = future.result()
                        results.append(result)
                        logger.info(
                            f"Progress: {i}/{len(emails)} - "
                            f"{result['verdict']} (confidence: {result['confidence']:.2f})"
                        )
                    except Exception as e:
                        logger.error(f"Failed to process email {i}: {e}")

        else:
            # Sequential processing (safer)
            for i, email in enumerate(emails, 1):
                try:
                    result = self.process_email(email, use_ollama=use_ollama)
                    results.append(result)

                    logger.info(
                        f"Progress: {i}/{len(emails)} - "
                        f"{result['subject'][:40]}... → {result['verdict']} "
                        f"(confidence: {result['confidence']:.2f}, "
                        f"action: {result['action']})"
                    )

                except Exception as e:
                    logger.error(f"Failed to process email {i}: {e}")
                    continue

        logger.info(f"✓ Processed {len(results)}/{len(emails)} emails")
        return results

    def generate_outputs(self, results: List[Dict]):
        """
        Generate all output files: verdicts, audit logs, analyst queue, dashboard

        Args:
            results: List of verdict results
        """
        logger.info("Generating output files...")

        # 1. Verdicts CSV (main results)
        verdicts_path = self.output_dir / f"verdicts_{self.run_id}.csv"
        self._write_verdicts_csv(results, verdicts_path)

        # 2. Analyst Review Queue (only emails needing review)
        analyst_queue = [r for r in results if r["action"] == "analyst_review"]
        analyst_queue_path = self.output_dir / f"analyst_queue_{self.run_id}.csv"
        self._write_analyst_queue(analyst_queue, analyst_queue_path)

        # 3. HIPAA-Compliant Audit Log (JSON)
        audit_log_path = self.output_dir / f"audit_log_{self.run_id}.json"
        self._write_audit_log(results, audit_log_path)

        # 4. Summary Statistics (JSON)
        summary_path = self.output_dir / f"summary_{self.run_id}.json"
        self._write_summary(results, summary_path)

        logger.info(f"✓ All outputs saved to {self.output_dir}/")

    def _write_verdicts_csv(self, results: List[Dict], output_path: Path):
        """Write main verdicts CSV"""
        if not results:
            logger.warning("No results to write")
            return

        fieldnames = [
            "email_id",
            "subject",
            "sender",
            "received_datetime",
            "verdict",
            "action",
            "confidence",
            "risk_score",
            "ensemble_score",
            "ollama_verdict",
            "reasoning",
            "processing_time_seconds"
        ]

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(results)

        logger.info(f"  ✓ Verdicts: {output_path} ({len(results)} rows)")

    def _write_analyst_queue(self, analyst_queue: List[Dict], output_path: Path):
        """Write analyst review queue CSV"""
        if not analyst_queue:
            logger.info("  ✓ No emails require analyst review")
            return

        # Sort by risk score (highest first)
        analyst_queue_sorted = sorted(
            analyst_queue,
            key=lambda x: x["risk_score"],
            reverse=True
        )

        fieldnames = [
            "priority",
            "email_id",
            "subject",
            "sender",
            "verdict",
            "risk_score",
            "confidence",
            "primary_indicators",
            "reasoning"
        ]

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()

            for i, email in enumerate(analyst_queue_sorted, 1):
                email["priority"] = i
                # Convert list to string for CSV
                email["primary_indicators"] = "; ".join(email.get("primary_indicators", [])[:5])
                writer.writerow(email)

        logger.info(f"  ✓ Analyst Queue: {output_path} ({len(analyst_queue)} emails)")

    def _write_audit_log(self, results: List[Dict], output_path: Path):
        """Write HIPAA-compliant audit log (JSON)"""
        audit_entries = []

        for result in results:
            # HIPAA-safe: Exclude email body, only metadata
            audit_entry = {
                "timestamp": result.get("timestamp"),
                "email_id": result.get("email_id"),
                "verdict": result.get("verdict"),
                "action": result.get("action"),
                "confidence": result.get("confidence"),
                "risk_score": result.get("risk_score"),
                "component_scores": result.get("component_scores"),
                "component_weights": result.get("component_weights"),
                "processing_time_seconds": result.get("processing_time_seconds"),
                "system_version": "phishing-analyst-v1.0",
                "ollama_model": self.ollama_client.model
            }

            # Include non-PHI features for audit trail
            features = result.get("features", {})
            audit_entry["audit_features"] = {
                "sender_domain": features.get("sender_domain"),
                "spf_result": features.get("spf_result"),
                "dkim_result": features.get("dkim_result"),
                "dmarc_result": features.get("dmarc_result"),
                "threat_types": features.get("threat_types"),
                "url_count": features.get("url_count"),
                "attachment_count": features.get("attachment_count"),
                "is_user_reported": features.get("is_user_reported"),
                "directionality": features.get("directionality")
            }

            audit_entries.append(audit_entry)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({
                "run_id": self.run_id,
                "run_timestamp": datetime.now().isoformat(),
                "total_emails": len(results),
                "hipaa_compliant": self.enforce_hipaa,
                "audit_entries": audit_entries
            }, f, indent=2)

        logger.info(f"  ✓ Audit Log: {output_path} (HIPAA-compliant)")

    def _write_summary(self, results: List[Dict], output_path: Path):
        """Write summary statistics"""
        if not results:
            return

        # Calculate statistics
        total = len(results)
        verdicts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0}
        actions = {"auto_block": 0, "analyst_review": 0, "auto_resolve": 0}

        total_confidence = 0
        total_risk_score = 0
        total_processing_time = 0

        for result in results:
            verdicts[result["verdict"]] = verdicts.get(result["verdict"], 0) + 1
            actions[result["action"]] = actions.get(result["action"], 0) + 1
            total_confidence += result["confidence"]
            total_risk_score += result["risk_score"]
            total_processing_time += result.get("processing_time_seconds", 0)

        # Automation rate
        automated = actions["auto_block"] + actions["auto_resolve"]
        automation_rate = automated / total if total > 0 else 0

        summary = {
            "run_id": self.run_id,
            "timestamp": datetime.now().isoformat(),
            "total_emails": total,
            "verdicts": verdicts,
            "actions": actions,
            "automation_rate": round(automation_rate, 3),
            "average_confidence": round(total_confidence / total, 3) if total > 0 else 0,
            "average_risk_score": round(total_risk_score / total, 1) if total > 0 else 0,
            "total_processing_time_seconds": round(total_processing_time, 2),
            "average_processing_time_seconds": round(total_processing_time / total, 2) if total > 0 else 0,
            "analyst_queue_size": actions["analyst_review"],
            "analyst_queue_percentage": round(actions["analyst_review"] / total * 100, 1) if total > 0 else 0
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        logger.info(f"  ✓ Summary: {output_path}")
        logger.info(f"\n{'='*60}")
        logger.info("TRIAGE SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Total Emails: {total}")
        logger.info(f"Verdicts: Malicious={verdicts['MALICIOUS']}, Suspicious={verdicts['SUSPICIOUS']}, Clean={verdicts['CLEAN']}")
        logger.info(f"Actions: Auto-Block={actions['auto_block']}, Analyst Review={actions['analyst_review']}, Auto-Resolve={actions['auto_resolve']}")
        logger.info(f"Automation Rate: {automation_rate:.1%}")
        logger.info(f"Average Confidence: {summary['average_confidence']:.2f}")
        logger.info(f"Average Risk Score: {summary['average_risk_score']:.1f}")
        logger.info(f"Avg Processing Time: {summary['average_processing_time_seconds']:.2f}s")
        logger.info(f"{'='*60}\n")


def main():
    """CLI interface for triage orchestrator"""
    parser = argparse.ArgumentParser(
        description="Phishing Triage Orchestrator - Ollama-powered email analysis"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Input CSV file with emails"
    )

    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Configuration file (default: config/config.yaml)"
    )

    parser.add_argument(
        "--output",
        help="Output directory (overrides config)"
    )

    parser.add_argument(
        "--model",
        help="Ollama model to use (overrides config)"
    )

    parser.add_argument(
        "--max-emails",
        type=int,
        help="Limit number of emails to process (for testing)"
    )

    parser.add_argument(
        "--no-ollama",
        action="store_true",
        help="Skip Ollama analysis (faster but less accurate)"
    )

    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Use parallel processing (experimental)"
    )

    parser.add_argument(
        "--no-hipaa",
        action="store_true",
        help="Disable HIPAA data minimization (use with caution)"
    )

    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Initialize orchestrator
    orchestrator = TriageOrchestrator(
        config=config,
        ollama_model=args.model,
        output_dir=args.output,
        enforce_hipaa=None if not args.no_hipaa else False
    )

    # Load emails
    emails = orchestrator.load_emails_from_csv(args.input)

    # Process emails
    results = orchestrator.process_batch(
        emails,
        use_ollama=not args.no_ollama,
        max_emails=args.max_emails,
        parallel=args.parallel
    )

    # Generate outputs
    orchestrator.generate_outputs(results)

    logger.info("✓ Triage complete!")


if __name__ == "__main__":
    main()
