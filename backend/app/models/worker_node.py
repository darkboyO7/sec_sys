"""
Worker Node Model for Enterprise Scalability & Distributed Execution.
Tracks registered worker instances (local subprocesses and distributed worker nodes),
their capabilities, concurrency capacity, authentication token hashes, and heartbeat status.
"""
import enum
from sqlalchemy import Column, String, Integer, Enum, DateTime, JSON, Boolean
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class WorkerType(str, enum.Enum):
    LOCAL_SUBPROCESS = "LOCAL_SUBPROCESS"
    DISTRIBUTED_NODE = "DISTRIBUTED_NODE"


class WorkerStatus(str, enum.Enum):
    ONLINE = "ONLINE"
    BUSY = "BUSY"
    DRAINING = "DRAINING"
    OFFLINE = "OFFLINE"
    DEAD = "DEAD"
    DEACTIVATED = "DEACTIVATED"


class WorkerNode(Base, TimestampMixin):
    """
    Persistent registry of worker instances in the execution pool.
    Supports authenticated registration, capacity-based job claiming,
    heartbeat monitoring, and dead worker lease recovery.
    """
    __tablename__ = "worker_nodes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    worker_id = Column(String(100), unique=True, nullable=False, index=True)
    worker_type = Column(Enum(WorkerType), default=WorkerType.LOCAL_SUBPROCESS, nullable=False)
    hostname = Column(String(255), nullable=False)
    pid = Column(Integer, nullable=True)

    status = Column(Enum(WorkerStatus), default=WorkerStatus.ONLINE, nullable=False, index=True)
    concurrency_slots = Column(Integer, default=4, nullable=False)
    active_jobs_count = Column(Integer, default=0, nullable=False)

    capabilities = Column(JSON, default=list, nullable=False)
    registered_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_heartbeat_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    auth_token_hash = Column(String(128), nullable=False)
    session_token_hash = Column(String(128), nullable=True, index=True)
    session_expires_at = Column(DateTime(timezone=True), nullable=True)
    is_deactivated = Column(Boolean, default=False, nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
