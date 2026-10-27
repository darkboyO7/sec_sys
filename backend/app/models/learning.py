import enum
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Enum, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import generate_uuid, utc_now


class DatasetSplit(str, enum.Enum):
    TRAIN = "TRAIN"
    VALIDATION = "VALIDATION"
    TEST = "TEST"


class ModelStatus(str, enum.Enum):
    CANDIDATE = "CANDIDATE"
    EVALUATED = "EVALUATED"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    ROLLED_BACK = "ROLLED_BACK"


class PredictionType(str, enum.Enum):
    FALSE_POSITIVE_LIKELIHOOD = "FALSE_POSITIVE_LIKELIHOOD"
    EXPLOITATION_PROBABILITY = "EXPLOITATION_PROBABILITY"
    REMEDIATION_EFFORT_HOURS = "REMEDIATION_EFFORT_HOURS"
    RISK_SCORE_FORECAST = "RISK_SCORE_FORECAST"
    ATTACK_PATH_REACHABILITY = "ATTACK_PATH_REACHABILITY"


class PredictionEvaluationStatus(str, enum.Enum):
    PENDING = "PENDING"
    VERIFIED_ACCURATE = "VERIFIED_ACCURATE"
    VERIFIED_INACCURATE = "VERIFIED_INACCURATE"
    INCONCLUSIVE = "INCONCLUSIVE"
    EXPIRED = "EXPIRED"
    INVALIDATED = "INVALIDATED"


class LearningDataset(Base):
    """
    Controlled Training/Evaluation Dataset (Phase 19).
    Persists immutable, versioned, privacy-minimized datasets derived exclusively
    from verified operational records and analyst outcomes.
    """
    __tablename__ = "learning_datasets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    version = Column(String(32), nullable=False)
    dataset_hash = Column(String(64), nullable=False, index=True)  # SHA-256 of canonical records

    total_records = Column(Integer, default=0, nullable=False)
    train_count = Column(Integer, default=0, nullable=False)
    val_count = Column(Integer, default=0, nullable=False)
    test_count = Column(Integer, default=0, nullable=False)

    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    project = relationship("Project", backref="learning_datasets")
    creator = relationship("User")
    records = relationship("DatasetRecord", back_populates="dataset", cascade="all, delete-orphan")


class DatasetRecord(Base):
    """
    Individual data point within a versioned learning dataset with strict provenance.
    """
    __tablename__ = "dataset_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    dataset_id = Column(String(36), ForeignKey("learning_datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    split = Column(Enum(DatasetSplit), nullable=False, index=True)

    source_entity_type = Column(String(50), nullable=False)  # finding, verification, analyst_decision
    source_entity_id = Column(String(36), nullable=False, index=True)
    features = Column(JSON, nullable=False)
    label = Column(String(50), nullable=False, index=True)
    provenance_digest = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    dataset = relationship("LearningDataset", back_populates="records")


class GovernedModel(Base):
    """
    Governed Machine Learning / Analytical Model artifact.
    Enforces reproducible evaluation, explicit human approval gate, and rollback controls.
    """
    __tablename__ = "governed_models"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    model_name = Column(String(100), nullable=False, index=True)
    version = Column(String(32), nullable=False)
    model_type = Column(String(50), nullable=False)
    status = Column(Enum(ModelStatus), default=ModelStatus.CANDIDATE, nullable=False, index=True)

    dataset_id = Column(String(36), ForeignKey("learning_datasets.id", ondelete="RESTRICT"), nullable=False, index=True)
    metrics = Column(JSON, default=dict, nullable=False)
    hyperparameters = Column(JSON, default=dict, nullable=False)

    is_active = Column(Boolean, default=False, nullable=False, index=True)
    activated_at = Column(DateTime(timezone=True), nullable=True)

    approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approval_notes = Column(Text, nullable=True)

    rollback_target_id = Column(String(36), ForeignKey("governed_models.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    project = relationship("Project", backref="governed_models")
    dataset = relationship("LearningDataset")
    approver = relationship("User", foreign_keys=[approved_by_id])
    rollback_target = relationship("GovernedModel", remote_side=[id])


class PredictionLedger(Base):
    """
    Persistent Prediction and Outcome Ledger (Phase 19.1 / Part X, Section 20).
    Maintains an immutable record of analytical and ML predictions:
    - Immutable feature snapshot captured at prediction time.
    - Explicit model and rule versioning.
    - Asynchronous observation and recording of real-world outcomes.
    - Outcome verification, accuracy drift tracking, and invalidation controls.
    - Predictions are strictly decoupled from verified security observations.
    """
    __tablename__ = "prediction_ledger"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    model_id = Column(String(36), ForeignKey("governed_models.id", ondelete="SET NULL"), nullable=True, index=True)
    model_version = Column(String(32), nullable=False, default="heuristic-v1.0")
    rule_version = Column(String(32), nullable=True)

    target_entity_type = Column(String(50), nullable=False, index=True)  # finding, asset, remediation, attack_path
    target_entity_id = Column(String(36), nullable=False, index=True)
    prediction_type = Column(Enum(PredictionType), nullable=False, index=True)

    feature_snapshot = Column(JSON, nullable=False, default=dict)
    predicted_outcome = Column(String(255), nullable=False)
    confidence_score = Column(Float, nullable=False, default=0.5)
    limitations = Column(Text, nullable=True)
    decision_action_taken = Column(String(255), nullable=True)

    expected_evaluation_horizon = Column(DateTime(timezone=True), nullable=True)
    actual_outcome = Column(String(255), nullable=True)
    outcome_evidence = Column(JSON, nullable=True)
    evaluation_status = Column(Enum(PredictionEvaluationStatus), default=PredictionEvaluationStatus.PENDING, nullable=False, index=True)
    invalidation_reason = Column(Text, nullable=True)

    evaluated_at = Column(DateTime(timezone=True), nullable=True)
    evaluated_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    project = relationship("Project", backref="prediction_ledger_entries")
    model = relationship("GovernedModel", backref="predictions")
    evaluator = relationship("User", foreign_keys=[evaluated_by_id])
