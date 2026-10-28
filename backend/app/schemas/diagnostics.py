from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ComponentHealthModel(BaseModel):
    component_id: str
    name: str
    status: str
    last_successful_check: Optional[str] = None
    last_failure: Optional[str] = None
    message: str
    dependencies: Dict[str, Any] = Field(default_factory=dict)
    is_live_check: bool = True
    details: Dict[str, Any] = Field(default_factory=dict)


class SystemHealthResponse(BaseModel):
    timestamp: str
    overall_status: str
    healthy_count: int
    degraded_count: int
    unhealthy_count: int
    components: Dict[str, ComponentHealthModel]
    environment: str
    version: str


class DiagnosticFindingModel(BaseModel):
    id: Optional[str] = None
    check_id: str
    category: str
    severity: str
    confidence: str
    title: str
    description: str
    observed_issue: str
    affected_entities: List[Any] = Field(default_factory=list)
    recommended_action: str
    recovery_action_available: Optional[str] = None


class DiagnosticRunResponse(BaseModel):
    run_id: str
    project_id: str
    timestamp: str
    total_checks: int
    passed_checks: int
    warning_checks: int
    failed_checks: int
    summary: str
    findings: List[DiagnosticFindingModel] = Field(default_factory=list)


class RecoveryActionRequest(BaseModel):
    action_type: str
    target_entity_type: str
    target_entity_id: Optional[str] = None
    target_resource: Optional[str] = None
    reason: str = ""


class RecoveryActionResponse(BaseModel):
    recovery_id: str
    project_id: str
    action_type: str
    outcome: str
    pre_condition: Dict[str, Any] = Field(default_factory=dict)
    post_condition: Dict[str, Any] = Field(default_factory=dict)
    verification_notes: str = ""
    ledger_record_id: Optional[str] = None


class FailurePatternModel(BaseModel):
    id: str
    pattern_key: str
    category: str
    occurrence_count: int
    first_observed_at: str
    last_observed_at: str
    affected_targets: List[str] = Field(default_factory=list)
    sample_error_message: str
    advisory_recommendation: str


class ContinuousImprovementResponse(BaseModel):
    project_id: str
    patterns_updated: int
    total_patterns: int
    patterns: List[FailurePatternModel] = Field(default_factory=list)
