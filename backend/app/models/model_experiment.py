import enum
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    JSON,
    Text,
    Index,
)
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class SplitStrategy(str, enum.Enum):
    TEMPORAL_AWARE = "TEMPORAL_AWARE"
    STRATIFIED_HASH = "STRATIFIED_HASH"
    CHRONOLOGICAL_WINDOW = "CHRONOLOGICAL_WINDOW"


class ExperimentDecision(str, enum.Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED_INFERIOR_METRICS = "REJECTED_INFERIOR_METRICS"
    REJECTED_LEAKAGE = "REJECTED_LEAKAGE"
    REJECTED_INSUFFICIENT_DATA = "REJECTED_INSUFFICIENT_DATA"
    PENDING_REVIEW = "PENDING_REVIEW"


class ModelControlledExperiment(Base, TimestampMixin):
    """
    Controlled Experiment, Evaluation Run, and Defensible Model Benchmark Record (Prompt 38).
    Tracks empirical evaluation on held-out test partitions, temporal leakage checks,
    class imbalance, calibration uncertainty, and decision justifications.
    """
    __tablename__ = "model_controlled_experiments"
    __table_args__ = (
        Index("ix_model_exp_proj_decision", "project_id", "decision_outcome"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    model_id = Column(String(36), ForeignKey("governed_models.id", ondelete="CASCADE"), nullable=False, index=True)
    dataset_id = Column(String(36), ForeignKey("learning_datasets.id", ondelete="CASCADE"), nullable=False, index=True)

    experiment_name = Column(String(255), nullable=False)
    split_strategy = Column(Enum(SplitStrategy), default=SplitStrategy.TEMPORAL_AWARE, nullable=False)

    training_sample_size = Column(Integer, default=0, nullable=False)
    test_sample_size = Column(Integer, default=0, nullable=False)
    class_imbalance_ratio = Column(Float, default=1.0, nullable=False)

    temporal_range_start = Column(DateTime(timezone=True), nullable=True)
    temporal_range_end = Column(DateTime(timezone=True), nullable=True)

    data_leakage_detected = Column(Boolean, default=False, nullable=False)
    leakage_details = Column(JSON, default=list, nullable=False)
    insufficient_data_flag = Column(Boolean, default=False, nullable=False)

    baseline_model_id = Column(String(36), ForeignKey("governed_models.id", ondelete="SET NULL"), nullable=True)
    metrics = Column(JSON, default=dict, nullable=False)

    distribution_shift_detected = Column(Boolean, default=False, nullable=False)
    decision_outcome = Column(Enum(ExperimentDecision), default=ExperimentDecision.PENDING_REVIEW, nullable=False, index=True)
    decision_rationale = Column(Text, nullable=True)

    evaluated_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    project = relationship("Project")
    model = relationship("GovernedModel", foreign_keys=[model_id])
    dataset = relationship("LearningDataset", foreign_keys=[dataset_id])
    baseline_model = relationship("GovernedModel", foreign_keys=[baseline_model_id])
    evaluated_by = relationship("User", foreign_keys=[evaluated_by_id])
