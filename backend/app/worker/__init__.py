"""
Worker execution package for isolated scanner execution.
Supports both Windows-native subprocess execution and distributed execution engines.
"""
from app.worker.execution_interface import (
    BaseWorkerExecutionEngine,
    WorkerRegistrationRequest,
    WorkerRegistrationResponse,
    WorkerHeartbeatRequest,
    WorkerHeartbeatResponse,
    WorkerNodeSummary,
    DeadLetterJobRecord,
)
from app.worker.local_engine import LocalSubprocessWorkerEngine
from app.worker.distributed_engine import DistributedWorkerEngine
from app.worker.engine_factory import get_worker_engine
from app.worker.worker_registry import worker_registry, WorkerAuthenticationError
from app.worker.ipc_schemas import WorkerIPCRequest, WorkerIPCResponse

__all__ = [
    "BaseWorkerExecutionEngine",
    "LocalSubprocessWorkerEngine",
    "DistributedWorkerEngine",
    "get_worker_engine",
    "worker_registry",
    "WorkerAuthenticationError",
    "WorkerRegistrationRequest",
    "WorkerRegistrationResponse",
    "WorkerHeartbeatRequest",
    "WorkerHeartbeatResponse",
    "WorkerNodeSummary",
    "DeadLetterJobRecord",
    "WorkerIPCRequest",
    "WorkerIPCResponse",
]
