"""
Worker Engine Factory.
Provides single entry point for instantiating or resolving the active worker execution engine.
"""
from typing import Optional
from app.core.config import settings
from app.worker.execution_interface import BaseWorkerExecutionEngine
from app.worker.local_engine import LocalSubprocessWorkerEngine
from app.worker.distributed_engine import DistributedWorkerEngine

_local_engine_instance: Optional[LocalSubprocessWorkerEngine] = None
_distributed_engine_instance: Optional[DistributedWorkerEngine] = None


def get_worker_engine() -> BaseWorkerExecutionEngine:
    """
    Returns the configured execution engine instance.
    Defaults to LocalSubprocessWorkerEngine (preserving Windows local subprocess execution).
    """
    global _local_engine_instance, _distributed_engine_instance

    backend = (getattr(settings, "WORKER_BACKEND", "LOCAL") or "LOCAL").upper()

    if backend in ("DISTRIBUTED", "CELERY", "REDIS"):
        if _distributed_engine_instance is None:
            _distributed_engine_instance = DistributedWorkerEngine()
        return _distributed_engine_instance

    # Default: LocalSubprocessWorkerEngine
    if _local_engine_instance is None:
        _local_engine_instance = LocalSubprocessWorkerEngine()
    return _local_engine_instance
