from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.models.learning import DatasetSplit, ModelStatus


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
