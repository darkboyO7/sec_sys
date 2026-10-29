import enum
from sqlalchemy import (
    Column,
    String,
    Float,
    Boolean,
    ForeignKey,
    Enum,
    DateTime,
    JSON,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class GraphNodeCategory(str, enum.Enum):
    # Core Context & Boundaries
    PROJECT = "PROJECT"
    BUSINESS_SERVICE = "BUSINESS_SERVICE"

    # Infrastructure & Network
    ASSET = "ASSET"
    HOST = "HOST"
    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    DATA_STORE = "DATA_STORE"

    # Application & Software Components
    APPLICATION = "APPLICATION"
    WEB_APPLICATION = "WEB_APPLICATION"
    API_ENDPOINT = "API_ENDPOINT"
    SERVICE = "SERVICE"
    SOFTWARE_COMPONENT = "SOFTWARE_COMPONENT"
    PACKAGE = "PACKAGE"
    DEPENDENCY = "DEPENDENCY"

    # Identity & Authorization
    IDENTITY = "IDENTITY"
    ROLE = "ROLE"
    PERMISSION = "PERMISSION"

    # Security & Findings
    VULNERABILITY = "VULNERABILITY"
    FINDING = "FINDING"
    EVIDENCE = "EVIDENCE"
    ASSESSMENT = "ASSESSMENT"
    REMEDIATION = "REMEDIATION"
    SECURITY_CONTROL = "SECURITY_CONTROL"


class RelationshipType(str, enum.Enum):
    CONTAINS = "CONTAINS"
    RESOLVES_TO = "RESOLVES_TO"
    EXPOSES = "EXPOSES"
    RUNS = "RUNS"
    DEPENDS_ON = "DEPENDS_ON"
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    CAN_ACCESS = "CAN_ACCESS"
    AFFECTED_BY = "AFFECTED_BY"
    PROTECTED_BY = "PROTECTED_BY"
    MITIGATES = "MITIGATES"
    OBSERVED_ON = "OBSERVED_ON"
    OBSERVED_AT = "OBSERVED_AT"
    DERIVED_FROM = "DERIVED_FROM"
    REMEDIATED_BY = "REMEDIATED_BY"
    BELONGS_TO = "BELONGS_TO"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    VERIFIED_BY = "VERIFIED_BY"


class EpistemicStatus(str, enum.Enum):
    """
    Formal epistemic status categorization for nodes, relationships, and derived security knowledge (Prompt 21).
    Distinguishes observed facts from hypotheses, derived conclusions, stale records, and contradictions.
    """
    OBSERVED_FACT = "OBSERVED_FACT"          # Directly supported by a recorded empirical observation
    CORROBORATED_FACT = "CORROBORATED_FACT"  # Supported by >= 2 independent, compatible sources
    DERIVED_CONCLUSION = "DERIVED_CONCLUSION"# Computed from explicitly identified source records & rules
    HYPOTHESIS = "HYPOTHESIS"                # Plausible but unverified (e.g. inferred service or CVE link)
    UNKNOWN = "UNKNOWN"                      # Insufficient information to reach a conclusion
    CONTRADICTED = "CONTRADICTED"            # Relevant evidence supports incompatible interpretations
    STALE = "STALE"                          # Freshness requirements are no longer met
    INVALIDATED = "INVALIDATED"              # Supporting assumptions or prerequisite evidence are no longer valid


class RelationshipStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    HYPOTHETICAL = "HYPOTHETICAL"
    STALE = "STALE"
    SUPERSEDED = "SUPERSEDED"
    OBSERVED_FACT = "OBSERVED_FACT"
    CORROBORATED_FACT = "CORROBORATED_FACT"
    DERIVED_CONCLUSION = "DERIVED_CONCLUSION"
    CONTRADICTED = "CONTRADICTED"
    INVALIDATED = "INVALIDATED"
    UNKNOWN = "UNKNOWN"


class GraphNode(Base, TimestampMixin):
    """
    Node entity in the Universal Security Knowledge Graph.
    Can represent an Asset, Service, Vulnerability, Finding, Security Control, or Identity.
    """
    __tablename__ = "graph_nodes"
    __table_args__ = (
        UniqueConstraint("project_id", "category", "entity_id", name="uq_graph_node_project_category_entity"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    category = Column(Enum(GraphNodeCategory), nullable=False, index=True)
    label = Column(String(255), nullable=False)

    entity_id = Column(String(36), nullable=True, index=True)
    entity_type = Column(String(100), nullable=True)
    properties = Column(JSON, default=dict, nullable=False)
    epistemic_status = Column(String(30), default=EpistemicStatus.OBSERVED_FACT.value, nullable=False)

    # Prompt 21 Knowledge Integrity & Provenance Fields
    is_authoritative = Column(Boolean, default=True, nullable=False)
    is_simulated = Column(Boolean, default=False, nullable=False)
    provenance = Column(String(255), default="AUTOMATED_INGESTION", nullable=False)
    evidence_reference = Column(String(255), nullable=True)
    derivation_rule = Column(String(100), nullable=True)
    input_sources = Column(JSON, default=list, nullable=False)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)
    invalidation_reason = Column(Text, nullable=True)
    contradiction_notes = Column(Text, nullable=True)

    # Relationships
    project = relationship("Project")
    outgoing_relationships = relationship(
        "GraphRelationship",
        foreign_keys="GraphRelationship.source_node_id",
        back_populates="source_node",
        cascade="all, delete-orphan",
    )
    incoming_relationships = relationship(
        "GraphRelationship",
        foreign_keys="GraphRelationship.target_node_id",
        back_populates="target_node",
        cascade="all, delete-orphan",
    )


class GraphRelationship(Base, TimestampMixin):
    """
    Typed directed relationship edge connecting two graph nodes within a project context.
    Captures provenance, confidence, and verification status (VERIFIED vs INFERRED vs HYPOTHETICAL vs STALE).
    """
    __tablename__ = "graph_relationships"
    __table_args__ = (
        UniqueConstraint("project_id", "source_node_id", "target_node_id", "relationship_type", name="uq_graph_rel_project_endpoints_type"),
        Index("ix_graph_relationships_proj_src_tgt", "project_id", "source_node_id", "target_node_id"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    source_node_id = Column(String(36), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)
    target_node_id = Column(String(36), ForeignKey("graph_nodes.id", ondelete="CASCADE"), nullable=False, index=True)

    relationship_type = Column(Enum(RelationshipType), nullable=False, index=True)
    status = Column(Enum(RelationshipStatus), default=RelationshipStatus.VERIFIED, nullable=False, index=True)
    confidence = Column(Float, default=1.0, nullable=False)

    provenance = Column(String(255), default="AUTOMATED_INGESTION", nullable=False)
    evidence_reference = Column(String(255), nullable=True)
    properties = Column(JSON, default=dict, nullable=False)
    verification_history = Column(JSON, default=list, nullable=False)
    observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Prompt 21 Knowledge Semantics, Freshness & Epistemic Tracking
    epistemic_status = Column(String(30), default=EpistemicStatus.OBSERVED_FACT.value, nullable=False)
    is_authoritative = Column(Boolean, default=True, nullable=False)
    is_simulated = Column(Boolean, default=False, nullable=False)
    derivation_rule = Column(String(100), nullable=True)
    input_sources = Column(JSON, default=list, nullable=False)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)
    invalidation_reason = Column(Text, nullable=True)
    contradiction_notes = Column(Text, nullable=True)
    freshness_expires_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    project = relationship("Project")
    source_node = relationship("GraphNode", foreign_keys=[source_node_id], back_populates="outgoing_relationships")
    target_node = relationship("GraphNode", foreign_keys=[target_node_id], back_populates="incoming_relationships")
