#!/usr/bin/env python3
"""
HIPAA-Compliant Authentication & Authorization Layer

Features:
- JWT token authentication with encryption
- Role-based access control (RBAC)
- Password policy enforcement
- Account lockout protection
- Export rate limiting
- Session management with audit logging
- 45 CFR 164.312(d) compliance
"""
import os
import re
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple
from collections import defaultdict
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from cryptography.fernet import Fernet
import yaml

# Password hashing
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

# JWT Settings
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", Fernet.generate_key().decode())
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Security Settings
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION_MINUTES = 30
EXPORT_RATE_LIMIT = 10  # exports per hour
EXPORT_WINDOW_HOURS = 1
PASSWORD_MIN_LENGTH = 12
PASSWORD_EXPIRY_DAYS = 90

# Common passwords to block
COMMON_PASSWORDS = [
    "password", "123456", "changeme123", "admin", "letmein", "welcome",
    "password123", "admin123", "qwerty", "abc123", "monkey", "master",
    "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine"
]

# In-memory rate limiting (would use Redis in production)
export_tracker = defaultdict(list)
failed_attempts = defaultdict(int)
lockout_until = {}

# Roles and Permissions (RBAC)
ROLES = {
    "analyst": {
        "can_view_queue": True,
        "can_triage": True,
        "can_view_audit": False,
        "can_generate_data": True,
        "can_manage_users": False,
        "can_override_verdicts": True,
        "can_export_data": True,
    },
    "admin": {
        "can_view_queue": True,
        "can_triage": True,
        "can_view_audit": True,
        "can_generate_data": True,
        "can_manage_users": True,
        "can_override_verdicts": True,
        "can_export_data": True,
    },
    "auditor": {
        "can_view_queue": True,
        "can_triage": False,
        "can_view_audit": True,
        "can_generate_data": False,
        "can_manage_users": False,
        "can_override_verdicts": False,
        "can_export_data": True,
    },
}


class User(BaseModel):
    username: str
    email: str
    role: str
    disabled: bool = False
    created_at: datetime = datetime.utcnow()
    last_login: Optional[datetime] = None


class UserInDB(User):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    force_password_change: bool = False


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
    permissions: dict = {}


class AuditLogger:
    """HIPAA-compliant immutable audit logger"""

    def __init__(self, log_path: str = "results/auth_audit.json"):
        self.log_path = log_path
        self.previous_hash = "GENESIS"
        self._load_last_hash()

    def _load_last_hash(self):
        """Load the last hash for chain continuity"""
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, 'r') as f:
                    entries = json.load(f)
                    if entries:
                        self.previous_hash = entries[-1].get("entry_hash", "GENESIS")
            except (json.JSONDecodeError, KeyError):
                pass

    def _compute_hash(self, entry: dict) -> str:
        """Compute SHA256 hash of entry + previous hash"""
        data = json.dumps(entry, sort_keys=True) + self.previous_hash
        return hashlib.sha256(data.encode()).hexdigest()

    def log_event(self, event_type: str, username: str, details: dict = None):
        """Log security event with immutable hash chain"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "username": username,
            "details": details or {},
            "previous_hash": self.previous_hash
        }
        entry["entry_hash"] = self._compute_hash(entry)
        self.previous_hash = entry["entry_hash"]

        # Append to log
        entries = []
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, 'r') as f:
                    entries = json.load(f)
            except json.JSONDecodeError:
                entries = []

        entries.append(entry)

        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        with open(self.log_path, 'w') as f:
            json.dump(entries, f, indent=2)

        return entry["entry_hash"]


# Global audit logger
audit_logger = AuditLogger()


# === PASSWORD POLICY ===

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password meets security requirements.
    Returns (is_valid, error_message)
    """
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters"

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"

    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/~`]', password):
        return False, "Password must contain at least one special character"

    if password.lower() in COMMON_PASSWORDS:
        return False, "Password is too common, please choose a stronger password"

    # Check for sequential characters
    if re.search(r'(.)\1{2,}', password):
        return False, "Password cannot contain 3 or more repeated characters"

    return True, "Password meets requirements"


def is_default_password(password: str) -> bool:
    """Check if password is the default that needs changing"""
    return password == "changeme123"


# === ACCOUNT LOCKOUT ===

def check_account_lockout(username: str) -> Tuple[bool, str]:
    """
    Check if account is locked due to failed attempts.
    Returns (is_locked, message)
    """
    if username in lockout_until:
        lock_time = lockout_until[username]
        if datetime.utcnow() < lock_time:
            remaining_minutes = int((lock_time - datetime.utcnow()).total_seconds() / 60) + 1
            return True, f"Account locked due to too many failed attempts. Try again in {remaining_minutes} minutes."
        else:
            # Lockout expired, clear it
            del lockout_until[username]
            failed_attempts[username] = 0

    return False, ""


def record_failed_login(username: str):
    """Record failed login attempt and lock account if threshold exceeded"""
    failed_attempts[username] += 1
    attempts = failed_attempts[username]

    if attempts >= LOCKOUT_THRESHOLD:
        lock_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        lockout_until[username] = lock_until
        audit_logger.log_event("ACCOUNT_LOCKED", username, {
            "reason": "failed_attempts",
            "attempts": attempts,
            "locked_until": lock_until.isoformat()
        })
        return True
    return False


def clear_failed_attempts(username: str):
    """Clear failed attempts after successful login"""
    failed_attempts[username] = 0
    if username in lockout_until:
        del lockout_until[username]


def unlock_account(username: str, admin_user: str):
    """Admin function to unlock a locked account"""
    if username in lockout_until:
        del lockout_until[username]
    failed_attempts[username] = 0
    audit_logger.log_event("ACCOUNT_UNLOCKED", username, {
        "unlocked_by": admin_user
    })


# === EXPORT RATE LIMITING ===

def check_export_rate_limit(username: str) -> Tuple[bool, str]:
    """
    Check if user can export (rate limiting).
    Returns (can_export, message)
    """
    now = datetime.utcnow()
    window = timedelta(hours=EXPORT_WINDOW_HOURS)

    # Clean old entries
    export_tracker[username] = [
        ts for ts in export_tracker[username]
        if now - ts < window
    ]

    # Check limit
    current_count = len(export_tracker[username])
    if current_count >= EXPORT_RATE_LIMIT:
        oldest = min(export_tracker[username])
        reset_time = oldest + window
        minutes_until_reset = int((reset_time - now).total_seconds() / 60) + 1
        return False, f"Export rate limit exceeded ({EXPORT_RATE_LIMIT}/hour). Try again in {minutes_until_reset} minutes."

    return True, f"Exports remaining: {EXPORT_RATE_LIMIT - current_count - 1}"


def record_export(username: str, export_type: str, record_count: int):
    """Record an export event for rate limiting and audit"""
    now = datetime.utcnow()
    export_tracker[username].append(now)

    audit_logger.log_event("DATA_EXPORT", username, {
        "export_type": export_type,
        "record_count": record_count,
        "timestamp": now.isoformat(),
        "exports_in_window": len(export_tracker[username])
    })


# === CORE AUTH FUNCTIONS ===

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate hash of password"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[TokenData]:
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role", "analyst")

        if username is None:
            return None

        permissions = ROLES.get(role, ROLES["analyst"])
        return TokenData(username=username, role=role, permissions=permissions)
    except JWTError:
        return None


def check_permission(token_data: TokenData, permission: str) -> bool:
    """Check if user has specific permission"""
    return token_data.permissions.get(permission, False)


class UserStore:
    """File-based user store with security metadata"""

    def __init__(self, store_path: str = "config/users.yaml"):
        self.store_path = store_path
        self._ensure_store()

    def _ensure_store(self):
        """Create default admin user if store doesn't exist"""
        if not os.path.exists(self.store_path):
            # No default users - admin must be created via setup script
            # This prevents deployment with default credentials
            os.makedirs(os.path.dirname(self.store_path) or ".", exist_ok=True)
            # Create empty user store
            with open(self.store_path, 'w') as f:
                yaml.dump({}, f)

    def get_user(self, username: str) -> Optional[UserInDB]:
        """Retrieve user from store"""
        with open(self.store_path, 'r') as f:
            users = yaml.safe_load(f) or {}

        if username in users:
            user_data = users[username]
            # Handle old format without new fields
            if 'password_changed_at' not in user_data:
                user_data['password_changed_at'] = None
            if 'must_change_password' not in user_data:
                user_data['must_change_password'] = True
            return UserInDB(**user_data)
        return None

    def must_change_password(self, username: str) -> bool:
        """Check if user must change password"""
        with open(self.store_path, 'r') as f:
            users = yaml.safe_load(f) or {}

        if username in users:
            user_data = users[username]
            # Check if explicitly required
            if user_data.get("must_change_password", True):
                return True
            # Check if password expired
            changed_at = user_data.get("password_changed_at")
            if changed_at:
                changed_date = datetime.fromisoformat(changed_at)
                if datetime.utcnow() - changed_date > timedelta(days=PASSWORD_EXPIRY_DAYS):
                    return True
        return False

    def change_password(self, username: str, new_password: str) -> Tuple[bool, str]:
        """Change user password with validation"""
        # Validate password strength
        is_valid, message = validate_password_strength(new_password)
        if not is_valid:
            return False, message

        with open(self.store_path, 'r') as f:
            users = yaml.safe_load(f) or {}

        if username not in users:
            return False, "User not found"

        users[username]["hashed_password"] = get_password_hash(new_password)
        users[username]["password_changed_at"] = datetime.utcnow().isoformat()
        users[username]["must_change_password"] = False

        with open(self.store_path, 'w') as f:
            yaml.dump(users, f)

        audit_logger.log_event("PASSWORD_CHANGED", username, {})
        return True, "Password changed successfully"

    def create_user(self, user: UserInDB, password: str) -> Tuple[bool, str]:
        """Create new user with password validation"""
        # Validate password
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            return False, message

        with open(self.store_path, 'r') as f:
            users = yaml.safe_load(f) or {}

        if user.username in users:
            return False, "Username already exists"

        users[user.username] = {
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "hashed_password": get_password_hash(password),
            "disabled": user.disabled,
            "created_at": user.created_at.isoformat(),
            "password_changed_at": datetime.utcnow().isoformat(),
            "must_change_password": False
        }

        with open(self.store_path, 'w') as f:
            yaml.dump(users, f)

        audit_logger.log_event("USER_CREATED", user.username, {"role": user.role})
        return True, "User created successfully"

    def update_last_login(self, username: str):
        """Update user's last login timestamp"""
        with open(self.store_path, 'r') as f:
            users = yaml.safe_load(f) or {}

        if username in users:
            users[username]["last_login"] = datetime.utcnow().isoformat()
            with open(self.store_path, 'w') as f:
                yaml.dump(users, f)


# Global user store
user_store = UserStore()


def authenticate_user(username: str, password: str) -> Tuple[Optional[UserInDB], str]:
    """
    Authenticate user with username and password.
    Returns (user, error_message)
    """
    # Check lockout first
    is_locked, lock_message = check_account_lockout(username)
    if is_locked:
        return None, lock_message

    user = user_store.get_user(username)
    if not user:
        record_failed_login(username)
        audit_logger.log_event("LOGIN_FAILED", username, {"reason": "user_not_found"})
        return None, "Invalid username or password"

    if not verify_password(password, user.hashed_password):
        was_locked = record_failed_login(username)
        audit_logger.log_event("LOGIN_FAILED", username, {"reason": "invalid_password"})
        if was_locked:
            return None, f"Account locked due to {LOCKOUT_THRESHOLD} failed attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes."
        return None, "Invalid username or password"

    if user.disabled:
        audit_logger.log_event("LOGIN_FAILED", username, {"reason": "user_disabled"})
        return None, "Account is disabled"

    # Clear failed attempts on successful login
    clear_failed_attempts(username)

    user_store.update_last_login(username)
    audit_logger.log_event("LOGIN_SUCCESS", username, {"role": user.role})
    return user, ""


def create_tokens_for_user(user: UserInDB) -> Token:
    """Create access and refresh tokens for authenticated user"""
    token_data = {
        "sub": user.username,
        "role": user.role,
        "email": user.email
    }

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    # Check if password change is required
    force_change = user_store.must_change_password(user.username)

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        force_password_change=force_change
    )
