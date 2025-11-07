"""Authentication utilities: JWT tokens, password hashing, email validation."""

from __future__ import annotations

import bcrypt
import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from fastapi import HTTPException, status

from src.config import get_settings

# Email whitelist pattern (allow emails ending with @klu.ac.in)
WHITELISTED_EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@klu\.ac\.in$", re.IGNORECASE)


def _prepare_password(password: str) -> bytes:
    """
    Prepare password for bcrypt by hashing with SHA256 first.
    This solves the bcrypt 72-byte limitation and provides consistent behavior.
    Returns bytes that are exactly 64 characters (well under bcrypt's 72-byte limit).
    """
    # Hash with SHA256 and return the hex digest as bytes
    return hashlib.sha256(password.encode('utf-8')).hexdigest().encode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    prepared = _prepare_password(plain_password)
    return bcrypt.checkpw(prepared, hashed_password.encode('utf-8'))


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt (with SHA256 pre-hashing to avoid length limits)."""
    prepared = _prepare_password(password)
    hashed = bcrypt.hashpw(prepared, bcrypt.gensalt())
    return hashed.decode('utf-8')


def is_email_whitelisted(email: str) -> bool:
    """Check if email matches the whitelist pattern (@klu.ac.in)."""
    return bool(WHITELISTED_EMAIL_PATTERN.match(email))


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Dictionary containing the claims to encode
        expires_delta: Optional expiration time delta (defaults to settings value)
    
    Returns:
        Encoded JWT token string
    """
    settings = get_settings()
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=settings.access_token_expire_hours)
    
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """
    Decode and verify a JWT access token.
    
    Args:
        token: JWT token string
    
    Returns:
        Dictionary containing the decoded claims
    
    Raises:
        HTTPException: If token is invalid or expired
    """
    settings = get_settings()
    
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


def validate_password_strength(password: str) -> tuple[bool, Optional[str]]:
    """
    Validate password strength.
    
    Requirements:
    - At least 8 characters
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    
    return True, None


def validate_phone_number(phone: str) -> tuple[bool, Optional[str]]:
    """
    Validate Indian phone number format.
    
    Accepts formats:
    - 10 digits: 9876543210
    - With country code: +919876543210
    - With country code and spaces: +91 9876543210
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Remove spaces and dashes
    phone_clean = phone.replace(" ", "").replace("-", "")
    
    # Check for valid Indian phone number patterns
    patterns = [
        r"^\d{10}$",  # 10 digits
        r"^\+91\d{10}$",  # +91 followed by 10 digits
    ]
    
    for pattern in patterns:
        if re.match(pattern, phone_clean):
            return True, None
    
    return False, "Invalid phone number format. Use 10 digits or +91 followed by 10 digits"
