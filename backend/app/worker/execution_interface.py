"""
Worker Execution Interface & IPC Data Contracts.
Defines abstract execution engine interface independent of local process runner,
supporting both Windows local subprocess execution and distributed worker nodes.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Callable
from pydantic import BaseModel, Field
from datetime import datetime

from app.services.scanner_adapters.base import AdapterResult
from app.worker.ipc_schemas import WorkerIPCRequest


class WorkerRegistrationRequest(BaseModel):
    worker_id: str = Field(..., description="Unique worker instance identifier")
    worker_type: str = Field("DISTRIBUTED_NODE", description="LOCAL_SUBPROCESS or DISTRIBUTED_NODE")
    hostname: str = Field(..., description="Hostname or container ID of worker node")
    pid: Optional[int] = Field(None, description="Host process ID")
    concurrency_slots: int = Field(4, ge=1, le=64, description="Max concurrent jobs this worker accepts")
    capabilities: List[str] = Field(default_factory=list, description="List of supported adapter types")
    auth_token: str = Field(..., description="Authentication token provided during cluster provisioning")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Platform and hardware metadata")


class WorkerRegistrationResponse(BaseModel):
    success: bool
    worker_id: str
    status: str
    session_token: str
    heartbeat_interval_seconds: int
    message: str


class WorkerHeartbeatRequest(BaseModel):
    worker_id: str
    session_token: str
    active_job_ids: List[str] = Field(default_factory=list)
    system_metrics: Dict[str, Any] = Field(default_factory=dict)


class WorkerHeartbeatResponse(BaseModel):
    acknowledged: bool
    worker_id: str
    status: str
    canceled_job_ids: List[str] = Field(default_factory=list)
    reclaim_required: bool = False


class WorkerNodeSummary(BaseModel):
    id: str
    worker_id: str
    worker_type: str
    hostname: str
    pid: Optional[int]
    status: str
    concurrency_slots: int
    active_jobs_count: int
    capabilities: List[str]
    registered_at: str
    last_heartbeat_at: str
    is_alive: bool


class DeadLetterJobRecord(BaseModel):
    job_id: str
    project_id: str
    target_input: str
    adapter_name: str
    attempt_count: int
    retry_count: int
    max_retries: int
    dead_letter_reason: Optional[str]
    dead_letter_at: Optional[str]
    failure_category: Optional[str]
    error_message: Optional[str]


class BaseWorkerExecutionEngine(ABC):
    """
    Abstract worker execution engine interface.
    Decouples job dispatch, execution, lifecycle, and teardown
    from the specific process or distributed runner implementation.
    """

    @abstractmethod
    def claim_job(
        self,
        worker_id: str,
        capabilities: Optional[List[str]] = None,
        db: Optional[Any] = None,
    ) -> Optional[Any]:
        """
        Atomically claims a QUEUED job for the given worker.
        Returns the claimed AssessmentJob or None if no matching jobs are available.
        """
        pass

    @abstractmethod
    def execute_job(
        self,
        request: WorkerIPCRequest,
        cancellation_check: Optional[Callable[[], bool]] = None,
        on_spawn: Optional[Callable[[int], None]] = None,
    ) -> AdapterResult:
        """
        Executes a job payload under the engine's isolation boundary.
        Returns the normalized AdapterResult.
        """
        pass

    @abstractmethod
    def heartbeat(
        self,
        worker_id: str,
        active_job_ids: Optional[List[str]] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Records worker heartbeat and retrieves pending cancellation commands.
        """
        pass

    @abstractmethod
    def cancel_job(
        self,
        job_id: str,
        reason: str = "Operator requested cancellation",
        db: Optional[Any] = None,
    ) -> bool:
        """
        Cancels an in-flight or queued job.
        """
        pass

    @abstractmethod
    def report_outcome(
        self,
        job_id: str,
        worker_id: str,
        result: AdapterResult,
        db: Optional[Any] = None,
    ) -> bool:
        """
        Records the final execution result and releases the worker slot.
        """
        pass

    @abstractmethod
    def get_worker_health(self) -> Dict[str, Any]:
        """
        Returns engine health, active concurrency, and diagnostics.
        """
        pass
