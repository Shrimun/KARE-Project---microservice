"""User service for handling user-related database operations."""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from src.models import UserCreate, UserInDB, SessionInDB, UserResponse
from src.auth import (
    get_password_hash,
    verify_password,
    is_email_whitelisted,
    validate_password_strength,
    validate_phone_number,
    create_access_token,
)
from src.config import get_settings

logger = logging.getLogger(__name__)


class UserService:
    """Service for managing users and sessions."""
    
    def __init__(self, database: AsyncIOMotorDatabase):
        self.db = database
        self.users_collection = database["users"]
        self.sessions_collection = database["sessions"]
    
    async def create_user(self, user_data: UserCreate, user_agent: Optional[str] = None, ip_address: Optional[str] = None) -> tuple[UserResponse, str]:
        """
        Create a new user account.
        
        Args:
            user_data: User registration data
            user_agent: Optional user agent string
            ip_address: Optional IP address
        
        Returns:
            Tuple of (UserResponse, access_token)
        
        Raises:
            HTTPException: If validation fails or user already exists
        """
        # Validate email whitelist
        if not is_email_whitelisted(user_data.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email must end with @klu.ac.in"
            )
        
        # Validate password strength
        is_valid, error_msg = validate_password_strength(user_data.password)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_msg
            )
        
        # Validate phone number
        is_valid, error_msg = validate_phone_number(user_data.phone_number)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_msg
            )
        
        # Check if user already exists
        existing_user = await self.users_collection.find_one({"email": user_data.email})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this email already exists"
            )
        
        # Create user document
        now = datetime.now(timezone.utc)
        user_id = secrets.token_urlsafe(16)
        
        hashed_password = get_password_hash(user_data.password)
        
        user_doc = {
            "user_id": user_id,
            "name": user_data.name,
            "email": user_data.email,
            "hashed_password": hashed_password,
            "department": user_data.department,
            "phone_number": user_data.phone_number,
            "created_at": now,
            "updated_at": now,
            "is_active": True,
        }
        
        # Insert user
        await self.users_collection.insert_one(user_doc)
        logger.info(f"Created new user: {user_data.email}")
        
        # Create access token
        token_data = {"sub": user_id, "email": user_data.email}
        access_token = create_access_token(token_data)
        
        # Create session
        await self._create_session(user_id, access_token, user_agent, ip_address)
        
        # Return user response
        user_response = UserResponse(
            user_id=user_id,
            name=user_data.name,
            email=user_data.email,
            department=user_data.department,
            phone_number=user_data.phone_number,
            created_at=now,
        )
        
        return user_response, access_token
    
    async def authenticate_user(self, email: str, password: str, user_agent: Optional[str] = None, ip_address: Optional[str] = None) -> tuple[UserResponse, str]:
        """
        Authenticate a user and create a session.
        
        Args:
            email: User email
            password: User password
            user_agent: Optional user agent string
            ip_address: Optional IP address
        
        Returns:
            Tuple of (UserResponse, access_token)
        
        Raises:
            HTTPException: If authentication fails
        """
        # Find user by email
        user_doc = await self.users_collection.find_one({"email": email.lower()})
        
        if not user_doc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Verify password
        if not verify_password(password, user_doc["hashed_password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check if user is active
        if not user_doc.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is deactivated"
            )
        
        # Create access token
        token_data = {"sub": user_doc["user_id"], "email": user_doc["email"]}
        access_token = create_access_token(token_data)
        
        # Create session
        await self._create_session(user_doc["user_id"], access_token, user_agent, ip_address)
        
        logger.info(f"User logged in: {email}")
        
        # Return user response
        user_response = UserResponse(
            user_id=user_doc["user_id"],
            name=user_doc["name"],
            email=user_doc["email"],
            department=user_doc["department"],
            phone_number=user_doc["phone_number"],
            created_at=user_doc["created_at"],
        )
        
        return user_response, access_token
    
    async def get_user_by_id(self, user_id: str) -> Optional[UserInDB]:
        """Get user by user_id."""
        user_doc = await self.users_collection.find_one({"user_id": user_id})
        
        if not user_doc:
            return None
        
        return UserInDB(**user_doc)
    
    async def get_user_by_email(self, email: str) -> Optional[UserInDB]:
        """Get user by email."""
        user_doc = await self.users_collection.find_one({"email": email.lower()})
        
        if not user_doc:
            return None
        
        return UserInDB(**user_doc)
    
    async def logout_user(self, token: str) -> bool:
        """
        Logout a user by invalidating their session.
        
        Args:
            token: Access token to invalidate
        
        Returns:
            True if session was found and deleted
        """
        result = await self.sessions_collection.delete_one({"token": token})
        
        if result.deleted_count > 0:
            logger.info("User logged out successfully")
            return True
        
        return False
    
    async def validate_session(self, token: str) -> Optional[str]:
        """
        Validate a session token and return the user_id.
        
        Args:
            token: Access token to validate
        
        Returns:
            user_id if session is valid, None otherwise
        """
        session = await self.sessions_collection.find_one({"token": token})
        
        if not session:
            return None
        
        # Check if session has expired
        # Make expires_at timezone-aware if it isn't already
        expires_at = session["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        
        if expires_at < datetime.now(timezone.utc):
            # Delete expired session
            await self.sessions_collection.delete_one({"token": token})
            return None
        
        return session["user_id"]
    
    async def _create_session(self, user_id: str, token: str, user_agent: Optional[str] = None, ip_address: Optional[str] = None) -> None:
        """Create a new session for a user."""
        settings = get_settings()
        
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=settings.access_token_expire_hours)
        
        session_doc = {
            "session_id": secrets.token_urlsafe(16),
            "user_id": user_id,
            "token": token,
            "created_at": now,
            "expires_at": expires_at,
            "user_agent": user_agent,
            "ip_address": ip_address,
        }
        
        await self.sessions_collection.insert_one(session_doc)
