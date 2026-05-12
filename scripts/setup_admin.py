#!/usr/bin/env python3
"""
VERIDEX User Setup Script

Creates a new user (admin or analyst). Run for each user the system needs.
The first run typically creates the admin. Subsequent runs create analysts.
"""
import os
import sys
import secrets
import getpass
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.auth.security import get_password_hash, validate_password_strength, audit_logger
import yaml


VALID_ROLES = ("admin", "analyst")


def generate_secure_password(length=16):
    """Generate a cryptographically secure password"""
    return secrets.token_urlsafe(length)


def prompt_role():
    """Ask the operator which role this user should have."""
    print("\nChoose a role for this user:")
    print("  1. admin     - full permissions, can manage users and view audit log")
    print("  2. analyst   - can view queue, triage, override verdicts, export data")
    print("                 cannot manage users, cannot view security audit log")
    choice = input("\nRole (1 for admin, 2 for analyst): ").strip()
    if choice == "1":
        return "admin"
    if choice == "2":
        return "analyst"
    print("Invalid choice. Defaulting to analyst (least privilege).")
    return "analyst"


def prompt_username(default):
    """Ask the operator for the username, with a sensible default."""
    raw = input(f"\nUsername (default: {default}): ").strip()
    return raw if raw else default


def prompt_email(username):
    """Ask the operator for an email, with a sensible default."""
    default = f"{username}@localhost"
    raw = input(f"\nEmail (default: {default}): ").strip()
    return raw if raw else default


def prompt_password():
    """Either auto-generate or manually set a password, returning (password, was_auto_generated)."""
    print("\nPassword:")
    print("  1. Auto-generate a secure password (recommended)")
    print("  2. Set your own password (must meet security requirements)")
    choice = input("\nChoose option (1 or 2): ").strip()

    if choice == "1":
        password = generate_secure_password(16)
        print("\nGenerated secure password:")
        print(f"\n   {password}\n")
        print("IMPORTANT: Save this password securely.")
        print("It will not be shown again.\n")
        input("Press ENTER to continue, or Ctrl+C to cancel...")
        return password, True

    if choice == "2":
        print("\nPassword requirements:")
        print("  - Minimum 12 characters")
        print("  - At least one uppercase, one lowercase, one number, one special char")
        print("  - No common passwords")
        while True:
            password = getpass.getpass("\nEnter password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Passwords do not match. Try again.")
                continue
            is_valid, message = validate_password_strength(password)
            if not is_valid:
                print(f"Rejected: {message}")
                continue
            print("Password meets requirements.")
            return password, False

    print("Invalid choice. Exiting.")
    sys.exit(1)


def setup_user():
    """Interactive setup for a single user."""
    print("=" * 60)
    print("VERIDEX USER SETUP")
    print("=" * 60)
    print("\nCreate a new user for VERIDEX. Run this once per user.")

    role = prompt_role()
    default_username = "admin" if role == "admin" else "analyst"
    username = prompt_username(default_username)
    email = prompt_email(username)
    password, auto_generated = prompt_password()

    # Load existing user store if present
    store_path = Path(__file__).parent.parent / "data" / "users.yaml"
    store_path.parent.mkdir(parents=True, exist_ok=True)

    users = {}
    if store_path.exists():
        with open(store_path, "r") as f:
            users = yaml.safe_load(f) or {}

    if username in users:
        print(f"\nUser '{username}' already exists.")
        overwrite = input("Overwrite? (yes/no): ").strip().lower()
        if overwrite not in ("yes", "y"):
            print("Cancelled.")
            sys.exit(0)

    now = datetime.utcnow().isoformat()
    users[username] = {
        "username": username,
        "email": email,
        "role": role,
        "hashed_password": get_password_hash(password),
        "disabled": False,
        "created_at": now,
        "password_changed_at": now,
        "must_change_password": False,
    }

    with open(store_path, "w") as f:
        yaml.dump(users, f)

    # Log the user creation event into the immutable audit trail
    try:
        audit_logger.log_event(
            "USER_CREATED",
            "setup_script",
            {"target_user": username, "role": role, "auto_generated_password": auto_generated},
        )
    except Exception:
        # If the audit logger is not reachable for any reason, fail silently
        # rather than blocking user creation. The user store is the source of truth.
        pass

    print(f"\nUser created successfully.")
    print(f"  Store:    {store_path}")
    print(f"  Username: {username}")
    print(f"  Role:     {role}")
    print(f"  Email:    {email}")
    if auto_generated:
        print(f"  Password: {password}")
    print("\nKeep these credentials secure.")
    print("\nStart VERIDEX with:")
    print("   python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    try:
        setup_user()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
