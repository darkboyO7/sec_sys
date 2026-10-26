from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field
from app.models.regression import RegressionAlertType, AlertSeverity, AlertStatus


class RegressionBaselineCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255)
    snapshot_id: Optional[str] = None
    risk_score_threshold_delta: float = Field(default=5.0, ge=0.5, le=50.0)
    evidence_stale_days: int = Field(default=30, ge=1, le=365)


class RegressionBaselineRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    snapshot_id: Optional[str] = None
    name: str
    is_active: bool
    risk_score_threshold_delta: float
    evidence_stale_days: int
    created_at: datetime
    updated_at: datetime


class RegressionAlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    alert_type: RegressionAlertType
    severity: AlertSeverity
    status: AlertStatus
    title: str
    description: str
    evidence_rationale: str
    baseline_reference: Optional[str] = None
    current_reference: Optional[str] = None
    target_resource: str
    fingerprint: str
    acknowledged_by_id: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AlertAcknowledgeRequest(BaseModel):
    notes: Optional[str] = Field(default=None, max_length=1000)


class AlertResolveRequest(BaseModel):
    resolution_notes: str = Field(..., min_length=3, max_length=1000)
    dismiss: bool = False


class RegressionEvaluationResponse(BaseModel):
    project_id: str
    evaluated_at: datetime
    alerts_generated: int
    active_alerts_count: int
    alerts: List[RegressionAlertRead]
