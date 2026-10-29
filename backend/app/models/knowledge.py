import enum
from sqlalchemy import (
    Column,
    String,
    Float,
    Integer,
    Boolean,
    ForeignKey,
    Enum,
    DateTime,
    JSON,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class KnowledgeDependencyType(str, enum.Enum):
    PREREQUISITE = "PREREQUISITE"
    EVIDENCE_SUPPORT = "EVIDENCE_SUPPORT"
    TOPOLOGY_LINK = "TOPOLOGY_LINK"
    INPUT_SCORE = "INPUT_SCORE"
    SCOPE_BOUNDARY = "SCOPE_BOUNDARY"
    ATTACK_PATH_STEP = "ATTACK_PATH_STEP"


class KnowledgeDependencyRecord(Base, TimestampMixin):
    """
    Persistent mapping of dependencies between authoritative source records
    (Assets, Findings, Observations, ScopeTargets, GraphRelationships)
    and downstream derived knowledge (RiskAssessments, AttackPaths, Recommendations).
    Guarantees fine-grained invalidation cascades without unbounded recursive loops.
    """
    __tablename__ = "knowledge_dependency_records"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "source_entity_type",
            "source_entity_id",
            "dependent_entity_type",
            "dependent_entity_id",
            name="uq_knowledge_dep_endpoints",
        ),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    source_entity_type = Column(String(50), nullable=False, index=True)
    source_entity_id = Column(String(255), nullable=False, index=True)
    source_version = Column(String(64), nullable=True)

    dependent_entity_type = Column(String(50), nullable=False, index=True)
    dependent_entity_id = Column(String(255), nullable=False, index=True)
    dependency_type = Column(String(50), default=KnowledgeDependencyType.TOPOLOGY_LINK.value, nullable=False)

    is_valid = Column(Boolean, default=True, nullable=False, index=True)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)
    invalidation_reason = Column(Text, nullable=True)

    # Relationship
    project = relationship("Project")


class AttackPathStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"          # All relationships confirmed by fresh empirical observations
    PLAUSIBLE = "PLAUSIBLE"        # Inferred topology without confirmed exploitation
    HYPOTHETICAL = "HYPOTHETICAL"  # Speculative reachability based on CVE heuristics or unobserved paths
    STALE = "STALE"                # Prerequisite observations have expired
    CONTRADICTED = "CONTRADICTED"  # Underlying services or configurations conflict with path requirements
    INVALIDATED = "INVALIDATED"    # Ports closed, assets removed, or out-of-scope


class ExplainableAttackPathRecord(Base, TimestampMixin):
    """
    Evidence-backed, explainable attack path record (Prompt 21).
    Distinguishes verified edges, assumed prerequisites, missing evidence,
    unverified conditions, and scope boundaries.
    """
    __tablename__ = "explainable_attack_paths"

    id = Column(String(64), primary_key=True)  # Deterministic SHA-256 fingerprint
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String(255), nullable=False)
    start_node_id = Column(String(36), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    target_node_id = Column(String(36), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)

    path_status = Column(Enum(AttackPathStatus), default=AttackPathStatus.PLAUSIBLE, nullable=False, index=True)
    cumulative_confidence = Column(Float, default=1.0, nullable=False)
    risk_impact_score = Column(Float, default=50.0, nullable=False)
    step_count = Column(Integer, default=1, nullable=False)

    is_scope_compliant = Column(Boolean, default=True, nullable=False, index=True)
    scope_violations = Column(JSON, default=list, nullable=False)

    # Detailed per-step explainability:
    # [{ "step": 1, "from_node": "...", "to_node": "...", "edge_id": "...", "epistemic_status": "...",
    #    "supporting_evidence": "...", "required_assumptions": "...", "unverified_conditions": "...",
    #    "invalidation_triggers": "..." }]
    steps_explanation = Column(JSON, default=list, nullable=False)
    chokepoints = Column(JSON, default=list, nullable=False)
    calculation_version = Column(String(50), default="v2.1.0", nullable=False)
    input_hashes = Column(JSON, default=dict, nullable=False)

    is_stale = Column(Boolean, default=False, nullable=False, index=True)
    is_invalidated = Column(Boolean, default=False, nullable=False, index=True)
    invalidation_reason = Column(Text, nullable=True)

    # Relationships
    project = relationship("Project")
    start_node = relationship("GraphNode", foreign_keys=[start_node_id])
    target_node = relationship("GraphNode", foreign_keys=[target_node_id])


class ReconciliationStatus(str, enum.Enum):
    COMPLETED = "COMPLETED"
    IN_PROGRESS = "IN_PROGRESS"
    FAILED = "FAILED"
    PARTIALLY_REPAIRED = "PARTIALLY_REPAIRED"


class KnowledgeReconciliationAudit(Base, TimestampMixin):
    """
    Auditable knowledge graph reconciliation log (Prompt 21).
    Detects dangling references, duplicate edges, invalid types,
    stale conclusions, scope boundary violations, and executes deterministic repairs.
    """
    __tablename__ = "knowledge_reconciliation_audits"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    run_by_user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    status = Column(Enum(ReconciliationStatus), default=ReconciliationStatus.COMPLETED, nullable=False, index=True)

    total_nodes_audited = Column(Integer, default=0, nullable=False)
    total_relationships_audited = Column(Integer, default=0, nullable=False)
    dangling_references_detected = Column(Integer, default=0, nullable=False)
    duplicate_relationships_detected = Column(Integer, default=0, nullable=False)
    invalid_types_detected = Column(Integer, default=0, nullable=False)
    missing_provenance_detected = Column(Integer, default=0, nullable=False)
    stale_conclusions_detected = Column(Integer, default=0, nullable=False)
    scope_violations_detected = Column(Integer, default=0, nullable=False)
    contradictions_detected = Column(Integer, default=0, nullable=False)

    auto_repaired_count = Column(Integer, default=0, nullable=False)
    manual_review_required_count = Column(Integer, default=0, nullable=False)
    reconciliation_log = Column(JSON, default=list, nullable=False)

    started_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    project = relationship("Project")
    run_by_user = relationship("User", foreign_keys=[run_by_user_id])
