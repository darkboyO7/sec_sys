from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.models.learning import DatasetSplit, ModelStatus, PredictionType, PredictionEvaluationStatus


class DatasetCurateRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=100, description="Dataset title")
    version: str = Field(..., min_length=1, max_length=32, description="Semantic dataset version tag")


class DatasetRecordRead(BaseModel):
    id: str
    split: DatasetSplit
    source_entity_type: str
    source_entity_id: str
    features: Dict[str, Any]
    label: str
    provenance_digest: str
    created_at: datetime

    class Config:
        from_attributes = True


class LearningDatasetRead(BaseModel):
    id: str
    project_id: str
    name: str
    version: str
    dataset_hash: str
    total_records: int
    train_count: int
    val_count: int
    test_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class ModelRegisterRequest(BaseModel):
    model_name: str = Field(..., min_length=3, max_length=100, description="Model family name")
    version: str = Field(..., min_length=1, max_length=32, description="Candidate model version")
    model_type: str = Field("GRADIENT_BOOSTED_DECISION_TREE", max_length=50)
    dataset_id: str = Field(..., description="ID of curated dataset to link")
    hyperparameters: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ModelApprovalRequest(BaseModel):
    approved: bool = Field(..., description="True if approved, False if rejected")
    approval_notes: str = Field(..., min_length=3, max_length=1000, description="Mandatory governance justification")


class ModelRollbackRequest(BaseModel):
    rollback_target_id: Optional[str] = Field(None, description="Optional explicit target model ID; defaults to preceding active")
    reason: str = Field(..., min_length=3, max_length=500, description="Mandatory operational rollback justification")


class GovernedModelRead(BaseModel):
    id: str
    project_id: str
    model_name: str
    version: str
    model_type: str
    status: ModelStatus
    dataset_id: str
    metrics: Dict[str, Any]
    hyperparameters: Dict[str, Any]
    is_active: bool
    activated_at: Optional[datetime] = None
    approved_by_id: Optional[str] = None
    approved_at: Optional[datetime] = None
    approval_notes: Optional[str] = None
    rollback_target_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class PredictionRecordRequest(BaseModel):
    target_entity_type: str = Field(..., min_length=2, max_length=50, description="Target entity category (finding, asset, remediation)")
    target_entity_id: str = Field(..., min_length=1, max_length=36, description="Identifier of target entity")
    prediction_type: PredictionType = Field(..., description="Category of prediction")
    predicted_outcome: str = Field(..., min_length=1, max_length=255, description="Inferred or predicted outcome")
    confidence_score: float = Field(0.5, ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    feature_snapshot: Dict[str, Any] = Field(default_factory=dict, description="Feature dictionary captured at inference time")
    model_id: Optional[str] = Field(None, description="Optional ID of active GovernedModel")
    model_version: Optional[str] = Field("heuristic-v1.0", max_length=32, description="Model version tag")
    rule_version: Optional[str] = Field(None, max_length=32, description="Optional rule-set version")
    limitations: Optional[str] = Field(None, description="Known epistemic caveats or limitations")
    decision_action_taken: Optional[str] = Field(None, max_length=255, description="Initial triage action taken")
    expected_evaluation_horizon: Optional[datetime] = Field(None, description="When outcome should be evaluated")


class PredictionEvaluateRequest(BaseModel):
    actual_outcome: str = Field(..., min_length=1, max_length=255, description="Observed real-world outcome")
    outcome_evidence: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Supporting evidence details")
    status_override: Optional[PredictionEvaluationStatus] = Field(None, description="Optional manual status override")
    notes: Optional[str] = Field(None, max_length=500, description="Optional evaluation notes")


class PredictionInvalidateRequest(BaseModel):
    reason: str = Field(..., min_length=5, max_length=500, description="Reason for invalidating prediction")


class PredictionLedgerRead(BaseModel):
    id: str
    project_id: str
    model_id: Optional[str] = None
    model_version: str
    rule_version: Optional[str] = None
    target_entity_type: str
    target_entity_id: str
    prediction_type: PredictionType
    feature_snapshot: Dict[str, Any]
    predicted_outcome: str
    confidence_score: float
    limitations: Optional[str] = None
    decision_action_taken: Optional[str] = None
    expected_evaluation_horizon: Optional[datetime] = None
    actual_outcome: Optional[str] = None
    outcome_evidence: Optional[Dict[str, Any]] = None
    evaluation_status: PredictionEvaluationStatus
    invalidation_reason: Optional[str] = None
    evaluated_at: Optional[datetime] = None
    evaluated_by_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ModelDriftMetricsRead(BaseModel):
    total_predictions: int
    evaluated_count: int
    pending_count: int
    accurate_count: int
    inaccurate_count: int
    accuracy_rate: float
    brier_score: float
    drift_alert: bool
    status: str
