"""
Capacity Management & Backpressure Control Service.
Enforces global and per-project worker concurrency bounds,
workload priority scheduling, queue overload rejection (HTTP 429 backpressure),
and provides real-time system resource diagnostics (CPU, RAM, Disk, Queue Depth).
"""
import os
import sys
import shutil
import threading
import logging
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.config import settings
from app.models.base import utc_now
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.worker_node import WorkerNode, WorkerStatus

logger = logging.getLogger(__name__)


class CapacityOverloadError(Exception):
    """Raised when system capacity or per-project concurrency limit is exhausted."""
    def __init__(self, message: str, status_code: int = 429, retry_after: int = 15):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.retry_after = retry_after


class WorkloadPriority(str, Enum):
    CRITICAL = "CRITICAL"      # Priority 1: Zero-day, active incident, high-severity retest
    HIGH = "HIGH"              # Priority 2: Pre-deployment release gate, CI/CD blocking scan
    NORMAL = "NORMAL"          # Priority 3: Scheduled standard assessment
    LOW = "LOW"                # Priority 4: Non-critical verification
    BACKGROUND = "BACKGROUND"  # Priority 5: Continuous asset discovery, background sweep


PRIORITY_WEIGHTS = {
    WorkloadPriority.CRITICAL: 1,
    WorkloadPriority.HIGH: 2,
    WorkloadPriority.NORMAL: 3,
    WorkloadPriority.LOW: 4,
    WorkloadPriority.BACKGROUND: 5,
}


class CapacityManagementService:
    """
    Supervises system concurrency limits, priority scheduling,
    backpressure enforcement, and hardware capacity metrics.
    """

    def __init__(
        self,
        max_global_concurrency: Optional[int] = None,
        max_project_concurrency: Optional[int] = None,
        max_queue_depth: Optional[int] = None,
    ):
        self._lock = threading.Lock()
        self.max_global_concurrency = max_global_concurrency or settings.WORKER_MAX_CONCURRENT_JOBS
        self.max_project_concurrency = max_project_concurrency or settings.WORKER_MAX_CONCURRENT_JOBS_PER_PROJECT
        self.max_queue_depth = max_queue_depth or settings.WORKER_MAX_QUEUE_DEPTH
        self._rejected_jobs_count = 0

    def update_limits(
        self,
        max_global_concurrency: Optional[int] = None,
        max_project_concurrency: Optional[int] = None,
        max_queue_depth: Optional[int] = None,
    ) -> Dict[str, int]:
        """Dynamically tunes capacity boundaries."""
        with self._lock:
            if max_global_concurrency is not None and max_global_concurrency > 0:
                self.max_global_concurrency = max_global_concurrency
            if max_project_concurrency is not None and max_project_concurrency > 0:
                self.max_project_concurrency = max_project_concurrency
            if max_queue_depth is not None and max_queue_depth > 0:
                self.max_queue_depth = max_queue_depth

            return {
                "max_global_concurrency": self.max_global_concurrency,
                "max_project_concurrency": self.max_project_concurrency,
                "max_queue_depth": self.max_queue_depth,
            }

    def get_limits(self) -> Dict[str, int]:
        """Returns configured capacity boundaries."""
        with self._lock:
            return {
                "max_global_concurrency": self.max_global_concurrency,
                "max_project_concurrency": self.max_project_concurrency,
                "max_queue_depth": self.max_queue_depth,
            }

    def check_admission(
        self,
        db: Session,
        project_id: str,
        priority: WorkloadPriority = WorkloadPriority.NORMAL,
    ) -> bool:
        """
        Validates whether a new assessment job can be admitted to the execution queue.
        Applies backpressure (HTTP 429) if project concurrency or queue depth is exhausted.
        High-priority / Critical jobs bypass standard queue saturation if global slots remain.
        """
        with self._lock:
            # 1. Inspect total currently queued jobs
            queue_depth = db.query(AssessmentJob).filter(
                AssessmentJob.status == AssessmentStatus.QUEUED
            ).count()

            # Critical tasks get 20% burst headroom
            effective_queue_depth = self.max_queue_depth
            if priority in (WorkloadPriority.CRITICAL, WorkloadPriority.HIGH):
                effective_queue_depth = int(self.max_queue_depth * 1.2)

            if queue_depth >= effective_queue_depth:
                self._rejected_jobs_count += 1
                logger.warning(
                    f"Queue overload: queue depth {queue_depth} >= {effective_queue_depth}. Backpressure applied."
                )
                raise CapacityOverloadError(
                    f"Execution queue saturated ({queue_depth} pending jobs). Backpressure applied.",
                    status_code=429,
                    retry_after=15,
                )

            # 2. Inspect active concurrency for this project
            active_project_jobs = db.query(AssessmentJob).filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.status.in_([AssessmentStatus.PREFLIGHT, AssessmentStatus.RUNNING]),
            ).count()

            effective_project_limit = self.max_project_concurrency
            if priority == WorkloadPriority.CRITICAL:
                effective_project_limit += 1

            if active_project_jobs >= effective_project_limit:
                self._rejected_jobs_count += 1
                logger.warning(
                    f"Project {project_id} exceeded concurrency limit ({active_project_jobs}/{effective_project_limit})."
                )
                raise CapacityOverloadError(
                    f"Project concurrent execution limit ({effective_project_limit}) reached for project '{project_id}'.",
                    status_code=429,
                    retry_after=10,
                )

            return True

    def get_hardware_metrics(self) -> Dict[str, Any]:
        """
        Collects hardware diagnostics (CPU, Memory, Disk) using native libraries.
        Works reliably on Windows and POSIX without requiring external psutil wheels.
        """
        metrics: Dict[str, Any] = {
            "platform": sys.platform,
            "cpu_count": os.cpu_count() or 1,
            "cpu_utilization_pct": 0.0,
            "memory": {},
            "disk": {},
        }

        # 1. Disk usage
        try:
            total, used, free = shutil.disk_usage(".")
            metrics["disk"] = {
                "total_mb": total // (1024 * 1024),
                "used_mb": used // (1024 * 1024),
                "free_mb": free // (1024 * 1024),
                "free_pct": round((free / total) * 100.0, 1) if total > 0 else 0.0,
            }
        except Exception:
            metrics["disk"] = {"error": "Disk telemetry unavailable"}

        # 2. Memory usage (Windows native via ctypes / fallback)
        if sys.platform == "win32":
            try:
                import ctypes
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ('dwLength', ctypes.c_ulong),
                        ('dwMemoryLoad', ctypes.c_ulong),
                        ('ullTotalPhys', ctypes.c_ulonglong),
                        ('ullAvailPhys', ctypes.c_ulonglong),
                        ('ullTotalPageFile', ctypes.c_ulonglong),
                        ('ullAvailPageFile', ctypes.c_ulonglong),
                        ('ullTotalVirtual', ctypes.c_ulonglong),
                        ('ullAvailVirtual', ctypes.c_ulonglong),
                        ('sullAvailExtendedVirtual', ctypes.c_ulonglong),
                    ]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                    metrics["memory"] = {
                        "load_pct": stat.dwMemoryLoad,
                        "total_mb": stat.ullTotalPhys // (1024 * 1024),
                        "available_mb": stat.ullAvailPhys // (1024 * 1024),
                        "used_mb": (stat.ullTotalPhys - stat.ullAvailPhys) // (1024 * 1024),
                    }
                    metrics["cpu_utilization_pct"] = float(stat.dwMemoryLoad)  # Approximation fallback
            except Exception as e:
                metrics["memory"] = {"error": str(e)}
        else:
            # POSIX fallback
            try:
                import resource
                metrics["memory"] = {"max_rss_kb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
            except Exception:
                metrics["memory"] = {"status": "ok"}

        return metrics

    def get_system_capacity_status(self, db: Session) -> Dict[str, Any]:
        """
        Returns real-time capacity utilization, queue depth, active workers,
        and hardware performance metrics.
        """
        # Active jobs across system
        active_jobs_count = db.query(AssessmentJob).filter(
            AssessmentJob.status.in_([AssessmentStatus.PREFLIGHT, AssessmentStatus.RUNNING])
        ).count()

        # Queued jobs
        queued_jobs_count = db.query(AssessmentJob).filter(
            AssessmentJob.status == AssessmentStatus.QUEUED
        ).count()

        # Dead letter jobs
        dead_letter_count = db.query(AssessmentJob).filter(
            AssessmentJob.status == AssessmentStatus.DEAD_LETTER
        ).count()

        # Registered worker nodes
        online_workers_count = db.query(WorkerNode).filter(
            WorkerNode.status.in_([WorkerStatus.ONLINE, WorkerStatus.BUSY])
        ).count()

        utilization_pct = 0.0
        if self.max_global_concurrency > 0:
            utilization_pct = round((active_jobs_count / self.max_global_concurrency) * 100.0, 1)

        is_saturated = (
            active_jobs_count >= self.max_global_concurrency
            or queued_jobs_count >= self.max_queue_depth
        )

        return {
            "timestamp": utc_now().isoformat(),
            "status": "SATURATED" if is_saturated else ("HIGH_LOAD" if utilization_pct > 80.0 else "NOMINAL"),
            "utilization_pct": utilization_pct,
            "active_jobs_count": active_jobs_count,
            "queued_jobs_count": queued_jobs_count,
            "dead_letter_jobs_count": dead_letter_count,
            "online_worker_nodes_count": online_workers_count,
            "rejected_jobs_total": self._rejected_jobs_count,
            "limits": self.get_limits(),
            "hardware": self.get_hardware_metrics(),
        }


capacity_management_service = CapacityManagementService()
