#!/usr/bin/env python3
"""
System Integration Test
Tests all major components of the Email Triage Automation System
"""
import sys
import os

# Add to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test all core imports"""
    print("Testing imports...")
    try:
        from src.core.mdo_field_extractor import MDOFieldExtractor
        from src.core.ensemble_verdict_engine import EnsembleVerdictEngine
        from src.core.ollama_client import OllamaSecurityAnalyst
        from src.generators.ollama_email_generator import OllamaEmailGenerator
        from src.auth.security import user_store, audit_logger
        print("  ✓ Core modules imported")
        return True
    except ImportError as e:
        print(f"  ✗ Import error: {e}")
        return False


def test_email_generator():
    """Test Ollama email generator"""
    print("Testing email generator...")
    try:
        from src.generators.ollama_email_generator import OllamaEmailGenerator
        gen = OllamaEmailGenerator()

        # Generate phishing email
        phishing = gen.generate_defender_metadata("phishing")
        assert "EmailId" in phishing
        assert "ThreatTypes" in phishing
        assert phishing["ThreatTypes"] != "NoThreatsFound"
        print(f"  ✓ Generated phishing email: {phishing['Subject'][:50]}")

        # Generate clean email
        clean = gen.generate_defender_metadata("clean")
        assert clean["ThreatTypes"] == "NoThreatsFound"
        print(f"  ✓ Generated clean email: {clean['Subject'][:50]}")

        # Generate batch
        batch = gen.generate_batch(3, 7)
        assert len(batch) == 10
        print(f"  ✓ Generated batch of {len(batch)} emails")

        return True
    except Exception as e:
        print(f"  ✗ Generator error: {e}")
        return False


def test_mdo_extractor():
    """Test MDO field extraction"""
    print("Testing MDO extractor...")
    try:
        from src.core.mdo_field_extractor import MDOFieldExtractor
        from src.generators.ollama_email_generator import OllamaEmailGenerator

        extractor = MDOFieldExtractor()
        gen = OllamaEmailGenerator()

        # Extract from generated email
        email = gen.generate_defender_metadata("phishing")
        features = extractor.extract(email)

        assert "subject" in features or "sender_domain" in features
        print(f"  ✓ Extracted {len(features)} features")
        return True
    except Exception as e:
        print(f"  ✗ Extractor error: {e}")
        return False


def test_auth_system():
    """Test authentication system"""
    print("Testing authentication...")
    try:
        from src.auth.security import (
            user_store, authenticate_user, create_tokens_for_user,
            decode_token, audit_logger
        )

        # Check default user exists
        admin = user_store.get_user("admin")
        if admin:
            print(f"  ✓ Admin user exists: {admin.username}")
        else:
            print("  ⚠ Admin user not found (will be created on first login)")

        # Test audit logging
        audit_logger.log_event("TEST_EVENT", "test_user", {"test": "data"})
        print("  ✓ Audit logging works")

        return True
    except Exception as e:
        print(f"  ✗ Auth error: {e}")
        return False


def test_ollama_connection():
    """Test Ollama service connectivity"""
    print("Testing Ollama connection...")
    try:
        import httpx
        with httpx.Client(timeout=5) as client:
            response = client.get("http://localhost:11434/api/tags")
            if response.status_code == 200:
                models = response.json().get("models", [])
                print(f"  ✓ Ollama running with {len(models)} models")
                for m in models[:3]:
                    print(f"    - {m['name']}")
                return True
    except Exception as e:
        print(f"  ⚠ Ollama not running (system will use rule-based mode)")
        return False


def test_data_files():
    """Test sanitized data files"""
    print("Testing data files...")
    try:
        import pandas as pd
        base_path = os.path.dirname(os.path.abspath(__file__))

        # Check user reports
        user_reports = os.path.join(base_path, "data/user-reported-anonymized.csv")
        if os.path.exists(user_reports):
            df = pd.read_csv(user_reports)
            print(f"  ✓ User reports: {len(df)} emails")
        else:
            print("  ⚠ User reports not found")

        # Check explorer data
        explorer = os.path.join(base_path, "data/explorer-anonymized.csv")
        if os.path.exists(explorer):
            df = pd.read_csv(explorer)
            print(f"  ✓ Explorer data: {len(df)} emails")
        else:
            print("  ⚠ Explorer data not found")

        return True
    except Exception as e:
        print(f"  ✗ Data error: {e}")
        return False


def main():
    print("=" * 60)
    print("  Email Triage System - Integration Test")
    print("=" * 60)

    results = []
    results.append(("Imports", test_imports()))
    results.append(("Email Generator", test_email_generator()))
    results.append(("MDO Extractor", test_mdo_extractor()))
    results.append(("Auth System", test_auth_system()))
    results.append(("Ollama", test_ollama_connection()))
    results.append(("Data Files", test_data_files()))

    print("\n" + "=" * 60)
    print("  Test Summary")
    print("=" * 60)

    passed = sum(1 for _, r in results if r)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {name}: {status}")

    print(f"\n  Total: {passed}/{total} tests passed")

    if passed == total:
        print("\n  🎉 System ready! Run ./start.sh to launch dashboard")
    else:
        print("\n  ⚠ Some tests failed. Check errors above.")

    print("=" * 60)


if __name__ == "__main__":
    main()
