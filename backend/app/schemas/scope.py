from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from app.models.scope import TargetType, AuthorizationStatus


class ScopeTargetCreate(BaseModel):
    target_value: str = Field(min_length=1, max_length=500, description="IP, CIDR, domain, or URL")
    description: Optional[str] = Field(default="", max_length=1000)


class ScopeTargetAuthorizeRequest(BaseModel):
    evidence: str = Field(
        min_length=5,
        max_length=2000,
        description="Written proof of authorization, Rules of Engagement reference, change ticket number, or signed approval document reference"
    )
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when authorization expires. If omitted, requires explicit periodic review."
    )


class ScopeTargetRevokeRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=1000, description="Mandatory operational or policy reason for scope revocation")


class ScopeTargetResponse(BaseModel):
    id: str
    project_id: str
    target_type: TargetType
    target_value: str
    description: str
    authorization_status: AuthorizationStatus
    authorization_evidence: str
    authorized_by_id: Optional[str] = None
    authorized_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    revoked_by_id: Optional[str] = None
    revoked_at: Optional[datetime] = None
    created_by_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ScopeExclusionCreate(BaseModel):
    target_value: str = Field(min_length=1, max_length=500, description="IP, CIDR, domain, or URL to strictly exclude")
    reason: str = Field(min_length=3, max_length=1000, description="Reason for exclusion, e.g. 3rd-party vendor, shared infrastructure, production payment gateway")


class ScopeExclusionResponse(BaseModel):
    id: str
    project_id: str
    target_type: TargetType
    target_value: str
    reason: str
    created_by_id: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScopeValidationRequest(BaseModel):
    target: str = Field(min_length=1, max_length=500, description="Candidate target to evaluate against project scope rules")


class ScopeValidationResponse(BaseModel):
    target: str
    normalized_target: str
    is_authorized: bool
    status: str
    reason: str
    matched_rule: Optional[Dict[str, Any]] = None
    matched_exclusion: Optional[Dict[str, Any]] = None
    evaluated_at: datetime
