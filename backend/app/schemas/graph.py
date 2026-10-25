from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.graph import GraphNodeCategory, RelationshipType, RelationshipStatus


class GraphNodeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    category: GraphNodeCategory
    label: str
    entity_id: Optional[str] = None
    entity_type: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class GraphRelationshipRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    source_node_id: str
    target_node_id: str
    relationship_type: RelationshipType
    status: RelationshipStatus
    confidence: float
    provenance: str
    evidence_reference: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime
    created_at: datetime


class GraphRelationshipCreate(BaseModel):
    source_node_id: str
    target_node_id: str
    relationship_type: RelationshipType
    status: RelationshipStatus = RelationshipStatus.VERIFIED
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    provenance: str = Field("MANUAL_ANALYST", max_length=255)
    evidence_reference: Optional[str] = Field(None, max_length=255)
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphNeighborhoodResponse(BaseModel):
    root_node_id: str
    max_depth: int = 2
    nodes: List[Dict[str, Any]]
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]]
    total_nodes: int
    total_edges: int
    truncated: bool
