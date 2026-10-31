import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator
from app.models.user import SystemRole

# RFC 5322 compatible regex that also accommodates enterprise intranets (.local, .internal, etc.)
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_email_address(v: str) -> str:
    cleaned = v.strip().lower()
    if not EMAIL_REGEX.match(cleaned) or len(cleaned) > 255:
        raise ValueError("Invalid email address format")
    return cleaned


class UserCreate(BaseModel):
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=2, max_length=255)
    system_role: Optional[SystemRole] = SystemRole.SECURITY_TESTER

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_address(v)


class AdminUserCreate(BaseModel):
    """Administrative user provisioning schema for authorized platform administrators."""
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=2, max_length=255)
    system_role: SystemRole = SystemRole.SECURITY_TESTER
    is_active: bool = True

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_address(v)


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    system_role: SystemRole
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_address(v)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenPayload(BaseModel):
    sub: str
    exp: int
    iat: int
    email: Optional[str] = None
    role: Optional[str] = None
