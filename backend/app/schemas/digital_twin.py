from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field, model_validator


class SecuritySnapshotCreate(BaseModel):
    snapshot_label: Optional[str] = Field(None, min_length=3, max_length=255)
    name: Optional[str] = Field(None, min_length=3, max_length=255)
    as_of_time: Optional[datetime] = None

    @model_validator(mode="before")
    @classmethod
    def normalize_label(cls, data: Any) -> Any:
        if isinstance(data, dict):
            label = data.get("snapshot_label") or data.get("name")
            if not label:
                raise ValueError("snapshot_label or name is required (minimum 3 characters)")
            data["snapshot_label"] = label
            data["name"] = label
        return data


class SecuritySnapshotRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    snapshot_label: str
    snapshot_timestamp: datetime
    captured_by_id: Optional[str] = None
    assets_count: int
    findings_count: int
    risk_summary: Dict[str, Any] = Field(default_factory=dict)
    manifest_sha256: str
    created_at: datetime
    updated_at: datetime


class SnapshotCompareRequest(BaseModel):
    snapshot_a_id: str
    snapshot_b_id: str


class SnapshotDiffResponse(BaseModel):
    snapshot_a_id: str
    snapshot_b_id: str
    snapshot_a_label: str
    snapshot_b_label: str
    snapshot_a_timestamp: datetime
    snapshot_b_timestamp: datetime
    new_findings: List[Dict[str, Any]] = Field(default_factory=list)
    resolved_findings: List[Dict[str, Any]] = Field(default_factory=list)
    recurring_findings: List[Dict[str, Any]] = Field(default_factory=list)
    changed_findings: List[Dict[str, Any]] = Field(default_factory=list)
    unresolved_findings: List[Dict[str, Any]] = Field(default_factory=list)
    added_assets: List[Dict[str, Any]] = Field(default_factory=list)
    removed_assets: List[Dict[str, Any]] = Field(default_factory=list)
    risk_drift: Dict[str, Any] = Field(default_factory=dict)
    summary: Dict[str, Any] = Field(default_factory=dict)


class ReconstructStateResponse(BaseModel):
    project_id: str
    as_of_timestamp: datetime
    assets: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    risk_summary: Dict[str, Any] = Field(default_factory=dict)
    state_sha256: str
