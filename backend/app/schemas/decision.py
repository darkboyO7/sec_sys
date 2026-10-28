from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

from app.models.decision import ChangeType, DecisionActionType, DecisionStatus


class PostureChangeResponse(BaseModel):
    id: str
    project_id: str
    change_type: ChangeType
    target_resource: str
    title: str
    previous_state: Dict[str, Any]
    new_state: Dict[str, Any]
    evidence_summary: str
    confidence: float
    is_confirmed: bool
    created_at: datetime

    class Config:
        from_attributes = True


class SecurityDecisionResponse(BaseModel):
    id: str
    project_id: str
    action_type: DecisionActionType
    status: DecisionStatus
    title: str
    triggering_observation: str
    evidence_considered: Dict[str, Any]
    selected_action: str
    rationale: str
    confidence: float
    uncertainty: float
    target_id: Optional[str] = None
    target_resource: Optional[str] = None
    job_id: Optional[str] = None
    required_approval_role: Optional[str] = None
    approved_by_id: Optional[str] = None
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    execution_outcome: Optional[Dict[str, Any]] = None
    posture_improvement_measured: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class DecisionEvaluationRequest(BaseModel):
    include_reassessment: bool = True
    include_validation: bool = True
    include_verification: bool = True


class DecisionActionExecutionRequest(BaseModel):
    notes: Optional[str] = "Executed autonomous security decision"
    force: bool = False


class ClosedLoopOverviewResponse(BaseModel):
    project_id: str
    active_posture: str
    total_posture_changes: int
    unresolved_changes: int
    proposed_decisions_count: int
    executed_decisions_count: int
    recent_changes: List[PostureChangeResponse]
    pending_decisions: List[SecurityDecisionResponse]
    verified_improvements_count: int
