"""
VAPT Platform — Unified Security Operations Experience Endpoints (Prompt 30).
Exposes the Operations Cockpit summary, 12 Core Questions Answers, and Actionable Priority Queue.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.deps import get_current_user, require_system_roles
from app.models.user import User, SystemRole
from app.schemas.unified_operations import (
    UnifiedOpsDashboardResponse,
    PriorityQueueResponse,
)
from app.services.operations_cockpit_service import operations_cockpit_service

router = APIRouter()


@router.get("/summary", response_model=UnifiedOpsDashboardResponse, summary="Get Unified Operations Cockpit Summary")
def get_cockpit_summary(
    project_id: Optional[str] = Query(None, description="Optional project ID to filter operations telemetry"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns unified operations posture and answers the 12 Core Operator Questions
    directly synthesized from live database telemetry.
    """
    return operations_cockpit_service.get_unified_operations_summary(db=db, project_id=project_id)


@router.get("/priority-queue", response_model=PriorityQueueResponse, summary="Get Actionable Security Priority Queue")
def get_priority_queue(
    project_id: Optional[str] = Query(None, description="Optional project ID filter"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns unified actionable priority queue ordered by urgency and impact,
    identifying critical findings, pending approvals, and failed assessments.
    """
    return operations_cockpit_service.get_actionable_priority_queue(db=db, project_id=project_id)


@router.post("/priority-queue/{item_id}/dismiss", summary="Dismiss Item from Priority Queue")
def dismiss_priority_queue_item(
    item_id: str,
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """Dismisses an acknowledged item from the operator queue."""
    operations_cockpit_service.dismiss_item(item_id=item_id)
    return {"status": "DISMISSED", "item_id": item_id}
