#!/usr/bin/env python3
"""
VERIDEX Initial Admin Setup Script

Creates the admin user with a secure password.
Run this before first deployment.
"""
import os
import sys
import secrets
import getpass
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.auth.security import get_password_hash, validate_password_strength
import yaml


def generate_secure_password(length=16):
    """Generate a cryptographically secure password"""
    return secrets.token_urlsafe(length)


def setup_admin_user():
    """Interactive setup for admin user"""
    print("="*60)
    print("VERIDEX ADMIN SETUP")
    print("="*60)
    print("\nThis script will create the admin user for VERIDEX.")
    print("You can either:")
    print("  1. Auto-generate a secure password (recommended)")
    print("  2. Set your own password (must meet security requirements)")
    print()

    choice = input("Choose option (1 or 2): ").strip()

    if choice == "1":
        # Auto-generate secure password
        password = generate_secure_password(16)
        print("\n✅ Generated secure password:")
        print(f"\n   {password}\n")
        print("⚠️  IMPORTANT: Save this password securely!")
        print("   You will need it to log in to the dashboard.\n")

        confirm = input("Press ENTER to continue, or Ctrl+C to cancel...")

    elif choice == "2":
        # Manual password entry
        print("\nPassword Requirements:")
        print("  - Minimum 12 characters")
        print("  - At least one uppercase letter")
        print("  - At least one lowercase letter")
        print("  - At least one number")
        print("  - At least one special character")
        print("  - No common passwords\n")

        while True:
            password = getpass.getpass("Enter admin password: ")
            password_confirm = getpass.getpass("Confirm password: ")

            if password != password_confirm:
                print("❌ Passwords do not match. Try again.\n")
                continue

            # Validate password strength
            is_valid, message = validate_password_strength(password)
            if not is_valid:
                print(f"❌ {message}\n")
                continue

            print("✅ Password meets requirements")
            break
    else:
        print("❌ Invalid choice. Exiting.")
        sys.exit(1)

    # Create user store directory
    store_path = Path(__file__).parent.parent / "data" / "users.yaml"
    store_path.parent.mkdir(parents=True, exist_ok=True)

    # Create admin user
    from datetime import datetime

    users = {
        "admin": {
            "username": "admin",
            "email": "admin@localhost",
            "role": "admin",
            "hashed_password": get_password_hash(password),
            "disabled": False,
            "created_at": datetime.utcnow().isoformat(),
            "password_changed_at": datetime.utcnow().isoformat(),
            "must_change_password": False
        }
    }

    with open(store_path, 'w') as f:
        yaml.dump(users, f)

    print(f"\n✅ Admin user created successfully!")
    print(f"   User store: {store_path}")
    print(f"   Username: admin")
    if choice == "1":
        print(f"   Password: {password}")
    print("\n⚠️  Keep these credentials secure!")
    print("\nYou can now start VERIDEX with:")
    print("   python3 -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000")
    print("\n" + "="*60)


if __name__ == "__main__":
    try:
        setup_admin_user()
    except KeyboardInterrupt:
        print("\n\n❌ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
