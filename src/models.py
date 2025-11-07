"""User and session models for authentication."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator


class UserCreate(BaseModel):
    """Request model for user signup."""
    name: str = Field(..., min_length=2, max_length=100, description="Full name of the user")
    email: EmailStr = Field(..., description="Email address (must end with @klu.ac.in)")
    password: str = Field(..., min_length=8, max_length=100, description="Password (min 8 characters)")
    department: str = Field(..., min_length=2, max_length=100, description="Department name")
    phone_number: str = Field(..., min_length=10, max_length=15, description="Phone number")
    
    @field_validator("email")
    @classmethod
    def validate_email_domain(cls, v: str) -> str:
        """Ensure email ends with @klu.ac.in"""
        if not v.lower().endswith("@klu.ac.in"):
            raise ValueError("Email must end with @klu.ac.in")
        return v.lower()
    
    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Trim and validate name."""
        name = v.strip()
        if not name:
            raise ValueError("Name cannot be empty")
        return name
    
    @field_validator("department")
    @classmethod
    def validate_department(cls, v: str) -> str:
        """Trim and validate department."""
        dept = v.strip()
        if not dept:
            raise ValueError("Department cannot be empty")
        return dept


class UserLogin(BaseModel):
    """Request model for user login."""
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., description="Password")


class UserResponse(BaseModel):
    """Response model for user data (without sensitive info)."""
    user_id: str = Field(..., description="Unique user identifier")
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    department: str = Field(..., description="Department")
    phone_number: str = Field(..., description="Phone number")
    created_at: datetime = Field(..., description="Account creation timestamp")
    
    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    """Response model for authentication tokens."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    user: UserResponse = Field(..., description="User information")


class UserInDB(BaseModel):
    """Internal model representing a user in the database."""
    user_id: str
    name: str
    email: str
    hashed_password: str
    department: str
    phone_number: str
    created_at: datetime
    updated_at: datetime
    is_active: bool = True


class SessionInDB(BaseModel):
    """Internal model representing a session in the database."""
    session_id: str
    user_id: str
    token: str
    created_at: datetime
    expires_at: datetime
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None


class LogoutResponse(BaseModel):
    """Response model for logout."""
    message: str = Field(..., description="Logout confirmation message")
    logged_out_at: datetime = Field(..., description="Logout timestamp")
