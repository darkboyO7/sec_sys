import enum
from sqlalchemy import Column, String, Float, ForeignKey, Enum, DateTime, JSON, UniqueConstraint
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


class RelationshipStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    HYPOTHETICAL = "HYPOTHETICAL"
    STALE = "STALE"
    SUPERSEDED = "SUPERSEDED"


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
    epistemic_status = Column(String(20), default="VERIFIED", nullable=False)

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

    # Relationships
    project = relationship("Project")
    source_node = relationship("GraphNode", foreign_keys=[source_node_id], back_populates="outgoing_relationships")
    target_node = relationship("GraphNode", foreign_keys=[target_node_id], back_populates="incoming_relationships")
