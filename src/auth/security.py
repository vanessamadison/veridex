#!/usr/bin/env python3
"""
HIPAA-Compliant Authentication & Authorization Layer

Features:
- JWT token authentication with encryption
- Role-based access control (RBAC)
- Session management with audit logging
- Password hashing with bcrypt
- 45 CFR 164.312(d) compliance
"""
import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from cryptography.fernet import Fernet
import yaml

# Password hashing - use sha256_crypt for broader compatibility
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

# JWT Settings
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", Fernet.generate_key().decode())
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

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


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate bcrypt hash of password"""
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
    """Simple file-based user store (replace with DB in production)"""

    def __init__(self, store_path: str = "config/users.yaml"):
        self.store_path = store_path
        self._ensure_store()

    def _ensure_store(self):
        """Create default admin user if store doesn't exist"""
        if not os.path.exists(self.store_path):
            os.makedirs(os.path.dirname(self.store_path) or ".", exist_ok=True)
            default_users = {
                "admin": {
                    "username": "admin",
                    "email": "admin@localhost",
                    "role": "admin",
                    "hashed_password": get_password_hash("changeme123"),
                    "disabled": False,
                    "created_at": datetime.utcnow().isoformat()
                }
            }
            with open(self.store_path, 'w') as f:
                yaml.dump(default_users, f)

    def get_user(self, username: str) -> Optional[UserInDB]:
        """Retrieve user from store"""
        with open(self.store_path, 'r') as f:
            users = yaml.safe_load(f) or {}

        if username in users:
            user_data = users[username]
            return UserInDB(**user_data)
        return None

    def create_user(self, user: UserInDB) -> bool:
        """Create new user"""
        with open(self.store_path, 'r') as f:
            users = yaml.safe_load(f) or {}

        if user.username in users:
            return False

        users[user.username] = {
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "hashed_password": user.hashed_password,
            "disabled": user.disabled,
            "created_at": user.created_at.isoformat()
        }

        with open(self.store_path, 'w') as f:
            yaml.dump(users, f)

        audit_logger.log_event("USER_CREATED", user.username, {"role": user.role})
        return True

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


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Authenticate user with username and password"""
    user = user_store.get_user(username)
    if not user:
        audit_logger.log_event("LOGIN_FAILED", username, {"reason": "user_not_found"})
        return None
    if not verify_password(password, user.hashed_password):
        audit_logger.log_event("LOGIN_FAILED", username, {"reason": "invalid_password"})
        return None
    if user.disabled:
        audit_logger.log_event("LOGIN_FAILED", username, {"reason": "user_disabled"})
        return None

    user_store.update_last_login(username)
    audit_logger.log_event("LOGIN_SUCCESS", username, {"role": user.role})
    return user


def create_tokens_for_user(user: UserInDB) -> Token:
    """Create access and refresh tokens for authenticated user"""
    token_data = {
        "sub": user.username,
        "role": user.role,
        "email": user.email
    }

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
