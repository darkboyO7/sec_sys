from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectMember, ProjectRole
from app.models.audit import AuditEvent
from app.schemas.audit import AuditLedgerResponse, AuditEventResponse
from app.api.deps import get_current_user

router = APIRouter()


@router.get("/", response_model=AuditLedgerResponse)
def get_audit_ledger(
    project_id: Optional[str] = Query(None, description="Filter audit events by project ID"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    outcome: Optional[str] = Query(None, description="Filter by outcome (SUCCESS, DENIED, FAILURE)"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve immutable audit log records.
    Admins and Auditors can view global events.
    Standard users can view audit events for projects where they hold membership.
    """
    query = db.query(AuditEvent)

    # Authorization filter
    if current_user.system_role not in (SystemRole.ADMIN, SystemRole.AUDITOR):
        # Find projects where user is a member
        user_projects = (
            db.query(ProjectMember.project_id)
            .filter(ProjectMember.user_id == current_user.id)
            .all()
        )
        allowed_project_ids = [p[0] for p in user_projects]

        if project_id:
            if project_id not in allowed_project_ids:
                return AuditLedgerResponse(total=0, items=[])
            query = query.filter(AuditEvent.project_id == project_id)
        else:
            query = query.filter(AuditEvent.project_id.in_(allowed_project_ids))
    else:
        if project_id:
            query = query.filter(AuditEvent.project_id == project_id)

    if action:
        query = query.filter(AuditEvent.action == action)
    if outcome:
        query = query.filter(AuditEvent.outcome == outcome)

    total = query.count()
    events = query.order_by(AuditEvent.timestamp.desc()).offset(offset).limit(limit).all()

    return AuditLedgerResponse(
        total=total,
        items=[AuditEventResponse.model_validate(e) for e in events],
    )
