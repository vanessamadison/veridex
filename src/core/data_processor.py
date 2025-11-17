#!/usr/bin/env python3
"""
Real Data Processor for Email Triage System

Handles actual Microsoft Defender data exports:
- User-reported submissions (24hr sample)
- Incidents (unworked queue)
- Explorer emails (30min sample of 1.2M daily)
- Analyst-reported (already triaged)

Maps real column names to triage system features.
"""
import pandas as pd
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import json


class RealDataProcessor:
    """Process actual Defender CSV exports"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.user_reports = None
        self.incidents = None
        self.explorer = None
        self.analyst_reports = None

    def load_all_data(self) -> Dict[str, int]:
        """Load all datasets and return counts"""
        counts = {}

        # User-reported emails (24hr sample)
        user_path = os.path.join(self.data_dir, "user-reported-anonymized.csv")
        if os.path.exists(user_path):
            self.user_reports = pd.read_csv(user_path)
            counts["user_reports"] = len(self.user_reports)

        # Incidents (unworked)
        incident_path = os.path.join(self.data_dir, "incidents-anonymized.csv")
        if os.path.exists(incident_path):
            self.incidents = pd.read_csv(incident_path)
            counts["incidents"] = len(self.incidents)

        # Explorer emails (30min sample)
        explorer_path = os.path.join(self.data_dir, "explorer-anonymized.csv")
        if os.path.exists(explorer_path):
            self.explorer = pd.read_csv(explorer_path)
            counts["explorer"] = len(self.explorer)

        # Analyst-reported (already triaged)
        analyst_path = os.path.join(self.data_dir, "analyst-reported-anonymized.csv")
        if os.path.exists(analyst_path):
            self.analyst_reports = pd.read_csv(analyst_path)
            counts["analyst_reports"] = len(self.analyst_reports)

        return counts

    def get_user_report_queue(self) -> List[Dict]:
        """
        Get user-reported emails formatted for triage queue.
        Uses "Submission name" as subject (not the anonymized "Subject" column).
        """
        if self.user_reports is None:
            self.load_all_data()

        queue = []
        for idx, row in self.user_reports.iterrows():
            # Map real columns to triage format
            item = {
                "id": f"UR-{idx+1:04d}",
                "submission_name": row.get("Submission name", "Unknown"),
                "sender": row.get("Sender", "Unknown"),
                "submitted_by": row.get("Submitted by", "Unknown"),
                "date_submitted": row.get("Date submitted (UTC-07:00)", ""),
                "reason": row.get("Reason for submitting", "Unknown"),
                "status": row.get("Status", "Pending"),
                "result": row.get("Result", ""),
                "tags": row.get("Tags", ""),
                # Derive verdict from existing data
                "verdict": self._derive_verdict_from_result(row),
                "risk_score": self._calculate_risk_score(row),
                "confidence": self._calculate_confidence(row),
                "action": self._determine_action(row),
                "source": "user_report"
            }
            queue.append(item)

        # Sort by risk score descending
        queue.sort(key=lambda x: x["risk_score"], reverse=True)
        return queue

    def get_incident_queue(self) -> List[Dict]:
        """
        Get incidents formatted for triage queue.
        These are unworked incidents that need analyst review.
        """
        if self.incidents is None:
            self.load_all_data()

        queue = []
        for idx, row in self.incidents.iterrows():
            item = {
                "incident_id": str(row.get("Incident Id", f"INC-{idx}")),
                "incident_name": row.get("Incident name", "Unknown"),
                "severity": row.get("Severity", "low"),
                "investigation_state": row.get("Investigation state", "Pending"),
                "categories": row.get("Categories", ""),
                "tags": row.get("Tags", ""),
                "impacted_assets": row.get("Impacted assets", ""),
                "active_alerts": row.get("Active alerts", 0),
                "status": row.get("Status", "New"),
                "assigned_to": row.get("Assigned to", "Unassigned"),
                "classification": row.get("Classification", "Not set"),
                "determination": row.get("Determination", "Not set"),
                "creation_time": row.get("Creation time", ""),
                "last_activity": row.get("Last activity", ""),
                # Derive verdict and scores
                "verdict": self._derive_incident_verdict(row),
                "risk_score": self._calculate_incident_risk(row),
                "confidence": self._calculate_incident_confidence(row),
                "action": "analyst_review" if row.get("Assigned to") == "Unassigned" else "assigned",
                "source": "incident"
            }
            queue.append(item)

        # Sort by severity and risk
        severity_map = {"high": 3, "medium": 2, "low": 1, "informational": 0}
        queue.sort(key=lambda x: (severity_map.get(x["severity"], 0), x["risk_score"]), reverse=True)
        return queue

    def get_explorer_emails(self) -> List[Dict]:
        """
        Get explorer emails (30min sample of email flow).
        These show the actual email metadata from Defender.
        """
        if self.explorer is None:
            self.load_all_data()

        emails = []
        for idx, row in self.explorer.iterrows():
            # Parse threats and detection
            threats = str(row.get("Threats", ""))
            has_threat = bool(threats.strip() and threats.strip() != "nan")

            item = {
                "id": f"EXP-{idx+1:05d}",
                "email_date": row.get("Email date (UTC)", ""),
                "recipients": row.get("Recipients", ""),
                "subject": row.get("Subject", "Unknown"),
                "sender_address": row.get("Sender address", ""),
                "sender_display_name": row.get("Sender display name", ""),
                "sender_domain": row.get("Sender domain", ""),
                "sender_ip": row.get("Sender IP", ""),
                "sender_mail_from": row.get("Sender mail from address", ""),
                "sender_mail_from_domain": row.get("Sender mail from domain", ""),
                "delivery_action": row.get("Delivery action", ""),
                "delivery_location": row.get("Latest delivery location", ""),
                "original_location": row.get("Original delivery location", ""),
                "threats": threats,
                "file_threats": row.get("File threats", ""),
                "detection_technologies": row.get("Detection technologies", ""),
                "directionality": row.get("Directionality", ""),
                "attachment_count": int(row.get("Attachment Count", 0) or 0),
                "url_count": int(row.get("Url Count", 0) or 0),
                "size": int(row.get("Size", 0) or 0),
                # SPF/DKIM check via mail from vs sender domain match
                "spf_aligned": row.get("Sender domain", "") == row.get("Sender mail from domain", ""),
                # Derive verdict
                "verdict": "CLEAN" if not has_threat else "MALICIOUS",
                "risk_score": 85 if has_threat else 15,
                "confidence": 0.90 if not has_threat else 0.85,
                "action": "delivered" if row.get("Delivery action") == "Delivered" else "blocked",
                "source": "explorer"
            }
            emails.append(item)

        return emails

    def _derive_verdict_from_result(self, row) -> str:
        """Derive verdict from user report result"""
        result = str(row.get("Result", "")).lower()
        reason = str(row.get("Reason for submitting", "")).lower()

        if "threats found" in result:
            if "phish" in reason:
                return "MALICIOUS"
            else:
                return "SUSPICIOUS"
        elif "bulk" in result:
            return "SUSPICIOUS"
        elif "not junk" in reason:
            return "CLEAN"
        else:
            return "SUSPICIOUS"

    def _calculate_risk_score(self, row) -> int:
        """Calculate risk score for user-reported email"""
        score = 50  # Base score

        result = str(row.get("Result", "")).lower()
        reason = str(row.get("Reason for submitting", "")).lower()
        status = str(row.get("Status", "")).lower()

        # Adjust based on result
        if "threats found" in result:
            score += 30
        elif "bulk" in result:
            score += 10

        # Adjust based on reason
        if "phish" in reason:
            score += 20
        elif "spam" in reason:
            score += 10
        elif "not junk" in reason:
            score -= 30

        # Adjust based on status
        if "completed" in status:
            score -= 10  # Already reviewed

        return max(0, min(100, score))

    def _calculate_confidence(self, row) -> float:
        """Calculate confidence score"""
        status = str(row.get("Status", "")).lower()
        result = str(row.get("Result", "")).lower()

        if "completed" in status:
            if "threats found" in result or "bulk" in result:
                return 0.85
            else:
                return 0.75
        else:
            return 0.60

    def _determine_action(self, row) -> str:
        """Determine action for user report"""
        result = str(row.get("Result", "")).lower()
        status = str(row.get("Status", "")).lower()

        if "completed" in status:
            if "threats found" in result:
                return "auto_block"
            elif "bulk" in result:
                return "analyst_review"
            else:
                return "auto_resolve"
        else:
            return "analyst_review"

    def _derive_incident_verdict(self, row) -> str:
        """Derive verdict from incident data"""
        state = str(row.get("Investigation state", "")).lower()
        tags = str(row.get("Tags", "")).lower()

        if "no threats found" in state:
            return "CLEAN"
        elif "phish" in tags or "credential" in tags:
            return "MALICIOUS"
        else:
            return "SUSPICIOUS"

    def _calculate_incident_risk(self, row) -> int:
        """Calculate risk score for incident"""
        score = 50

        severity = str(row.get("Severity", "")).lower()
        tags = str(row.get("Tags", "")).lower()

        # Severity adjustments
        if severity == "high":
            score += 40
        elif severity == "medium":
            score += 20
        elif severity == "low":
            score += 10

        # Tag adjustments
        if "phish" in tags:
            score += 15
        if "credential" in tags:
            score += 10

        return max(0, min(100, score))

    def _calculate_incident_confidence(self, row) -> float:
        """Calculate confidence for incident"""
        state = str(row.get("Investigation state", "")).lower()

        if "no threats found" in state:
            return 0.80
        elif "pending" in state:
            return 0.50
        else:
            return 0.65

    def get_triage_statistics(self) -> Dict:
        """Get overall triage statistics"""
        stats = {
            "user_reports": {
                "total": 0,
                "threats_found": 0,
                "bulk": 0,
                "clean": 0,
                "pending": 0
            },
            "incidents": {
                "total": 0,
                "unassigned": 0,
                "high_severity": 0,
                "medium_severity": 0,
                "low_severity": 0
            },
            "explorer": {
                "total": 0,
                "with_threats": 0,
                "delivered": 0,
                "blocked": 0,
                "inbound": 0,
                "outbound": 0
            },
            "automation": {
                "auto_blocked": 0,
                "auto_resolved": 0,
                "analyst_review": 0,
                "automation_rate": 0.0
            }
        }

        if self.user_reports is not None:
            stats["user_reports"]["total"] = len(self.user_reports)
            stats["user_reports"]["threats_found"] = len(
                self.user_reports[self.user_reports["Result"].str.contains("Threats found", na=False)]
            )
            stats["user_reports"]["bulk"] = len(
                self.user_reports[self.user_reports["Result"].str.contains("Bulk", na=False)]
            )
            pending = len(self.user_reports[self.user_reports["Status"] != "Completed"])
            stats["user_reports"]["pending"] = pending

            # Calculate automation based on results
            queue = self.get_user_report_queue()
            auto_blocked = sum(1 for q in queue if q["action"] == "auto_block")
            auto_resolved = sum(1 for q in queue if q["action"] == "auto_resolve")
            analyst_review = sum(1 for q in queue if q["action"] == "analyst_review")

            stats["automation"]["auto_blocked"] = auto_blocked
            stats["automation"]["auto_resolved"] = auto_resolved
            stats["automation"]["analyst_review"] = analyst_review

            total_actions = auto_blocked + auto_resolved + analyst_review
            if total_actions > 0:
                stats["automation"]["automation_rate"] = (auto_blocked + auto_resolved) / total_actions

        if self.incidents is not None:
            stats["incidents"]["total"] = len(self.incidents)
            stats["incidents"]["unassigned"] = len(
                self.incidents[self.incidents["Assigned to"] == "Unassigned"]
            )
            for sev in ["high", "medium", "low"]:
                stats["incidents"][f"{sev}_severity"] = len(
                    self.incidents[self.incidents["Severity"].str.lower() == sev]
                )

        if self.explorer is not None:
            stats["explorer"]["total"] = len(self.explorer)
            # Count threats (non-empty threat column)
            threats = self.explorer["Threats"].fillna("").astype(str).str.strip()
            stats["explorer"]["with_threats"] = len(threats[threats != ""])
            stats["explorer"]["delivered"] = len(
                self.explorer[self.explorer["Delivery action"] == "Delivered"]
            )
            stats["explorer"]["inbound"] = len(
                self.explorer[self.explorer["Directionality"] == "Inbound"]
            )
            stats["explorer"]["outbound"] = len(
                self.explorer[self.explorer["Directionality"] == "Outbound"]
            )

        return stats

    def get_combined_queue(self, limit: int = 50) -> List[Dict]:
        """Get combined queue from all sources, prioritized"""
        all_items = []

        # Add user reports
        all_items.extend(self.get_user_report_queue())

        # Add incidents
        all_items.extend(self.get_incident_queue())

        # Sort by risk score and return limited
        all_items.sort(key=lambda x: x["risk_score"], reverse=True)

        return all_items[:limit]


def test_processor():
    """Test the data processor"""
    processor = RealDataProcessor(data_dir="data")
    counts = processor.load_all_data()

    print("=" * 60)
    print("  Real Data Processor Test")
    print("=" * 60)

    print(f"\nData loaded:")
    for key, count in counts.items():
        print(f"  - {key}: {count} records")

    print("\nUser Report Queue (top 5):")
    queue = processor.get_user_report_queue()[:5]
    for item in queue:
        print(f"  [{item['id']}] {item['submission_name'][:40]}")
        print(f"    Verdict: {item['verdict']}, Risk: {item['risk_score']}, Action: {item['action']}")

    print("\nIncident Queue (top 5):")
    incidents = processor.get_incident_queue()[:5]
    for item in incidents:
        print(f"  [INC-{item['incident_id']}] {item['incident_name'][:40]}")
        print(f"    Severity: {item['severity']}, Status: {item['status']}")

    print("\nStatistics:")
    stats = processor.get_triage_statistics()
    print(json.dumps(stats, indent=2))

    print("=" * 60)


if __name__ == "__main__":
    test_processor()
