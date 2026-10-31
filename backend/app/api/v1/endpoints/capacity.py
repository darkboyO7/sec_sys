"""
Capacity Management & System Resource Telemetry API.
Provides operational visibility into execution concurrency, queue depth,
backpressure saturation, and system hardware metrics (CPU, RAM, Disk).
"""
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.deps import get_current_user, require_system_roles
from app.models.user import User, SystemRole
from app.services.capacity_management_service import capacity_management_service

router = APIRouter()


class CapacityLimitsUpdateRequest(BaseModel):
    max_global_concurrency: Optional[int] = Field(None, ge=1, le=256)
    max_project_concurrency: Optional[int] = Field(None, ge=1, le=64)
    max_queue_depth: Optional[int] = Field(None, ge=5, le=5000)


@router.get("/status")
def get_capacity_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([
        SystemRole.ADMIN,
        SystemRole.SECURITY_LEAD,
        SystemRole.AUDITOR,
        SystemRole.SECURITY_TESTER,
    ])),
) -> Dict[str, Any]:
    """
    Returns real-time capacity status, queue depth, utilization %,
    active workers count, dead-letter job count, and hardware metrics.
    """
    return capacity_management_service.get_system_capacity_status(db)


@router.get("/limits")
def get_capacity_limits(
    current_user: User = Depends(require_system_roles([
        SystemRole.ADMIN,
        SystemRole.SECURITY_LEAD,
        SystemRole.AUDITOR,
    ])),
) -> Dict[str, int]:
    """
    Returns configured concurrency and queue depth limits.
    """
    return capacity_management_service.get_limits()


@router.put("/limits")
def update_capacity_limits(
    req: CapacityLimitsUpdateRequest,
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN])),
) -> Dict[str, int]:
    """
    Dynamically tunes concurrency and queue limits without restarting services.
    Requires ADMIN privileges.
    """
    return capacity_management_service.update_limits(
        max_global_concurrency=req.max_global_concurrency,
        max_project_concurrency=req.max_project_concurrency,
        max_queue_depth=req.max_queue_depth,
    )
