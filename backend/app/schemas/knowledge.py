from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict
from app.models.knowledge import KnowledgeDependencyType, AttackPathStatus, ReconciliationStatus
from app.models.graph import EpistemicStatus


class KnowledgeDependencyRead(BaseModel):
    id: str
    project_id: str
    source_entity_type: str
    source_entity_id: str
    source_version: Optional[str] = None
    dependent_entity_type: str
    dependent_entity_id: str
    dependency_type: str
    is_valid: bool
    invalidated_at: Optional[datetime] = None
    invalidation_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AttackPathStepExplanation(BaseModel):
    step: int
    from_node: Dict[str, Any]
    to_node: Dict[str, Any]
    edge_id: str
    relationship_type: str
    status: str
    epistemic_status: str
    confidence: float
    is_authoritative: bool
    is_simulated: bool
    supporting_evidence: str
    required_assumptions: List[str]
    unverified_conditions: List[str]
    invalidation_triggers: List[str]


class ExplainableAttackPathRead(BaseModel):
    id: str
    project_id: str
    name: str
    start_node_id: str
    target_node_id: str
    path_status: str
    cumulative_confidence: float
    risk_impact_score: float
    step_count: int
    is_scope_compliant: bool
    scope_violations: List[Dict[str, Any]]
    steps_explanation: List[Dict[str, Any]]
    chokepoints: List[Dict[str, Any]]
    calculation_version: str
    input_hashes: Dict[str, Any]
    is_stale: bool
    is_invalidated: bool
    invalidation_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReconciliationTriggerRequest(BaseModel):
    auto_repair: bool = True


class KnowledgeReconciliationAuditRead(BaseModel):
    id: str
    project_id: str
    run_by_user_id: Optional[str] = None
    status: str
    total_nodes_audited: int
    total_relationships_audited: int
    dangling_references_detected: int
    duplicate_relationships_detected: int
    invalid_types_detected: int
    missing_provenance_detected: int
    stale_conclusions_detected: int
    scope_violations_detected: int
    contradictions_detected: int
    auto_repaired_count: int
    manual_review_required_count: int
    reconciliation_log: List[Dict[str, Any]]
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class FindingEpistemicExplanation(BaseModel):
    finding_id: str
    title: str
    severity: str
    lifecycle_status: str
    validation_status: str
    confidence: str
    epistemic_status: str
    is_authoritative: bool
    is_simulated: bool
    evidence_items: List[Dict[str, Any]]
    validation_history: List[Dict[str, Any]]
    contextual_risk: Optional[Dict[str, Any]] = None
    dependent_attack_paths: List[Dict[str, Any]] = []
    dependencies: List[KnowledgeDependencyRead] = []


class RelationshipEpistemicExplanation(BaseModel):
    relationship_id: str
    source_node: Dict[str, Any]
    target_node: Dict[str, Any]
    relationship_type: str
    status: str
    epistemic_status: str
    confidence: float
    is_authoritative: bool
    is_simulated: bool
    provenance: str
    evidence_reference: Optional[str] = None
    derivation_rule: Optional[str] = None
    required_assumptions: List[str] = []
    unverified_conditions: List[str] = []
    invalidation_triggers: List[str] = []
    verification_history: List[Dict[str, Any]] = []
