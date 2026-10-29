from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class DetailedPermissionMatrixItem(BaseModel):
    role: str
    role_type: str  # SYSTEM or PROJECT
    description: str
    granted_permissions: List[str]


class DetailedPermissionMatrixResponse(BaseModel):
    available_permissions: List[str]
    system_roles: List[DetailedPermissionMatrixItem]
    project_roles: List[DetailedPermissionMatrixItem]


class AccessDenialAuditResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    project_id: Optional[str] = None
    endpoint: str
    http_method: str
    required_privilege: str
    held_privilege: Optional[str] = None
    denial_reason: str
    client_ip: Optional[str] = None
    denied_at: datetime

    class Config:
        from_attributes = True


class LogoutRequest(BaseModel):
    reason: Optional[str] = "USER_LOGOUT"


class LogoutResponse(BaseModel):
    status: str
    message: str
    revoked_token_id: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class RevokeUserTokensResponse(BaseModel):
    user_id: str
    revoked_before: datetime
    message: str
