from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.models.adaptive_defense import AdaptiveMorphState, AdaptiveTransitionTrigger


class MorphStateHistoryRead(BaseModel):
    id: str
    posture_id: str
    from_state: AdaptiveMorphState
    to_state: AdaptiveMorphState
    trigger: AdaptiveTransitionTrigger
    evidence_rationale: str
    triggered_by_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class MorphStatePostureRead(BaseModel):
    id: str
    project_id: str
    current_state: AdaptiveMorphState
    previous_state: Optional[AdaptiveMorphState] = None
    state_version: int
    kill_switch_active: bool
    kill_switch_engaged_at: Optional[datetime] = None
    kill_switch_reason: Optional[str] = None
    monitoring_cadence_multiplier: float
    active_recommendations: List[Dict[str, Any]]
    recovery_prerequisites: List[Dict[str, Any]]
    last_transition_at: datetime
    last_evaluated_at: datetime

    class Config:
        from_attributes = True


class KillSwitchEngageRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500, description="Mandatory reason for engaging emergency kill switch")


class KillSwitchDisengageRequest(BaseModel):
    justification: str = Field(..., min_length=3, max_length=500, description="Mandatory justification for disengaging kill switch")


class ManualTransitionRequest(BaseModel):
    to_state: AdaptiveMorphState = Field(..., description="Target adaptive defensive state")
    justification: str = Field(..., min_length=3, max_length=500, description="Mandatory justification for manual posture transition")
