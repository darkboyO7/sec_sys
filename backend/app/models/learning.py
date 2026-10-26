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
