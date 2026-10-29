from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field


class LearningInventoryItem(BaseModel):
    component_name: str
    prediction_type: str
    objective: str
    input_features: List[str]
    decision_impact: str
    governance_mode: str
    online_self_tuning: bool


class CurateTimeAwareDatasetRequest(BaseModel):
    name: str = Field(..., min_length=2)
    version: str = Field(..., min_length=1)
    split_strategy: Optional[str] = "TEMPORAL_AWARE"


class RunControlledExperimentRequest(BaseModel):
    model_id: str
    experiment_name: str = Field(..., min_length=3)
    split_strategy: Optional[str] = "TEMPORAL_AWARE"
    force_pass_baseline: Optional[bool] = False


class ExperimentResponse(BaseModel):
    id: str
    project_id: str
    model_id: str
    dataset_id: str
    experiment_name: str
    split_strategy: str
    training_sample_size: int
    test_sample_size: int
    class_imbalance_ratio: float
    data_leakage_detected: bool
    leakage_details: List[str] = []
    insufficient_data_flag: bool
    baseline_model_id: Optional[str] = None
    metrics: Dict[str, Any] = {}
    distribution_shift_detected: bool
    decision_outcome: str
    decision_rationale: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class DistributionShiftResponse(BaseModel):
    model_id: str
    project_id: str
    distribution_shift_detected: bool
    evaluated_count: int
    accuracy_rate: float
    brier_score: float
    status: str
    recommended_action: str
