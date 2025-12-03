#!/usr/bin/env python3
"""
Unit tests for authentication and security module
Tests JWT auth, RBAC, password policies, and audit logging
"""
import pytest
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.auth.security import (
    get_password_hash, verify_password, validate_password_strength,
    is_default_password, check_permission, create_tokens_for_user,
    decode_token, UserInDB
)


class TestPasswordSecurity:
    """Test password hashing and validation"""

    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "SecurePassword123!"
        hashed = get_password_hash(password)

        # Hashed password should not equal plaintext
        assert hashed != password

        # Verification should succeed
        assert verify_password(password, hashed) is True

        # Wrong password should fail
        assert verify_password("WrongPassword", hashed) is False

    def test_password_strength_validation(self):
        """Test password strength requirements"""
        # Valid password
        valid, msg = validate_password_strength("SecurePass123!")
        assert valid is True

        # Too short
        valid, msg = validate_password_strength("Short1!")
        assert valid is False
        assert "12 characters" in msg

        # No uppercase
        valid, msg = validate_password_strength("securepass123!")
        assert valid is False
        assert "uppercase" in msg

        # No lowercase
        valid, msg = validate_password_strength("SECUREPASS123!")
        assert valid is False
        assert "lowercase" in msg

        # No number
        valid, msg = validate_password_strength("SecurePassword!")
        assert valid is False
        assert "number" in msg

        # No special character
        valid, msg = validate_password_strength("SecurePass123")
        assert valid is False
        assert "special character" in msg

        # Common password
        valid, msg = validate_password_strength("password123")
        assert valid is False
        assert "common password" in msg

    def test_default_password_detection(self):
        """Test detection of default password"""
        assert is_default_password("changeme123") is True
        assert is_default_password("SecurePass123!") is False


class TestRBAC:
    """Test Role-Based Access Control"""

    def test_admin_permissions(self):
        """Test admin role has all permissions"""
        assert check_permission("admin", "can_view_queue") is True
        assert check_permission("admin", "can_triage") is True
        assert check_permission("admin", "can_view_audit") is True
        assert check_permission("admin", "can_manage_users") is True
        assert check_permission("admin", "can_export_data") is True

    def test_analyst_permissions(self):
        """Test analyst role permissions"""
        assert check_permission("analyst", "can_view_queue") is True
        assert check_permission("analyst", "can_triage") is True
        assert check_permission("analyst", "can_export_data") is True

        # Should NOT have admin permissions
        assert check_permission("analyst", "can_manage_users") is False
        assert check_permission("analyst", "can_view_audit") is False

    def test_auditor_permissions(self):
        """Test auditor role permissions"""
        assert check_permission("auditor", "can_view_queue") is True
        assert check_permission("auditor", "can_view_audit") is True

        # Should NOT be able to triage or manage
        assert check_permission("auditor", "can_triage") is False
        assert check_permission("auditor", "can_manage_users") is False

    def test_invalid_role(self):
        """Test invalid role returns False"""
        assert check_permission("invalid_role", "can_view_queue") is False

    def test_invalid_permission(self):
        """Test invalid permission returns False"""
        assert check_permission("admin", "invalid_permission") is False


class TestJWTTokens:
    """Test JWT token creation and validation"""

    def test_token_creation(self):
        """Test JWT token creation for user"""
        user = UserInDB(
            username="testuser",
            email="test@example.com",
            role="analyst",
            hashed_password="fakehash",
            disabled=False,
            created_at=datetime.utcnow().isoformat()
        )

        token = create_tokens_for_user(user)

        assert token.access_token is not None
        assert token.refresh_token is not None
        assert token.token_type == "bearer"

    def test_token_decode(self):
        """Test JWT token decoding"""
        user = UserInDB(
            username="testuser",
            email="test@example.com",
            role="analyst",
            hashed_password="fakehash",
            disabled=False,
            created_at=datetime.utcnow().isoformat()
        )

        token = create_tokens_for_user(user)

        # Decode access token
        decoded = decode_token(token.access_token)

        assert decoded is not None
        assert decoded["sub"] == "testuser"
        assert decoded["role"] == "analyst"
        assert decoded["email"] == "test@example.com"

    def test_invalid_token(self):
        """Test decoding invalid token returns None"""
        invalid_token = "invalid.token.string"
        decoded = decode_token(invalid_token)
        assert decoded is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
