from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

from app.models.governance import ApprovalWorkflowType, GovernanceApprovalStatus


class ProjectGovernancePolicyRead(BaseModel):
    id: str
    project_id: str
    enforce_separation_of_duties: bool
    allow_self_approval_override: bool
    require_two_person_rule_for_purge: bool
    require_lead_for_scope_authorization: bool
    require_lead_for_risk_acceptance: bool
    require_lead_for_remediation_approval: bool
    require_lead_for_model_promotion: bool
    policy_version: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ProjectGovernancePolicyUpdate(BaseModel):
    enforce_separation_of_duties: Optional[bool] = None
    allow_self_approval_override: Optional[bool] = None
    require_two_person_rule_for_purge: Optional[bool] = None
    require_lead_for_scope_authorization: Optional[bool] = None
    require_lead_for_risk_acceptance: Optional[bool] = None
    require_lead_for_remediation_approval: Optional[bool] = None
    require_lead_for_model_promotion: Optional[bool] = None


class ApprovalRequestRead(BaseModel):
    id: str
    project_id: str
    workflow_type: ApprovalWorkflowType
    resource_type: str
    resource_id: str
    status: GovernanceApprovalStatus
    title: str
    description: Optional[str] = None
    parameter_hash: str
    parameters_snapshot: Dict[str, Any]
    requester_id: str
    approver_id: Optional[str] = None
    executed_by_id: Optional[str] = None
    requested_at: datetime
    decided_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    invalidated_at: Optional[datetime] = None
    decision_reason: Optional[str] = None
    invalidation_reason: Optional[str] = None
    policy_version: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ApprovalRequestCreate(BaseModel):
    workflow_type: ApprovalWorkflowType
    resource_type: str
    resource_id: str
    title: str
    description: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


class ApprovalDecisionRequest(BaseModel):
    approved: bool
    reason: str = Field(..., min_length=3, description="Justification for approval or rejection decision")


class PermissionMatrixResponse(BaseModel):
    version: str
    roles: Dict[str, List[str]]
    matrix: List[Dict[str, Any]]
