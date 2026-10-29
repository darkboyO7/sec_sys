from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectRole, ProjectMember
from app.models.governance import ApprovalWorkflowType, GovernanceApprovalStatus, ApprovalRequestRecord
from app.schemas.governance import (
    ProjectGovernancePolicyRead,
    ProjectGovernancePolicyUpdate,
    ApprovalRequestRead,
    ApprovalRequestCreate,
    ApprovalDecisionRequest,
    PermissionMatrixResponse,
)
from app.services.governance_service import ProjectGovernanceService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter(prefix="/projects/{project_id}/governance", tags=["Governance & Separation of Duties"])


@router.get("/policy", response_model=ProjectGovernancePolicyRead)
def get_project_governance_policy(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve current governance and Separation of Duties policy for a project workspace."""
    verify_project_access(project_id, current_user, db)
    policy = ProjectGovernanceService.get_or_create_policy(db, project_id)
    return policy


@router.put("/policy", response_model=ProjectGovernancePolicyRead)
def update_project_governance_policy(
    project_id: str,
    payload: ProjectGovernancePolicyUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update project governance policy (SoD enforcement, self-approval overrides, two-person rules).
    Requires Project LEAD or System ADMIN.
    """
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    client_ip = get_client_ip(request)

    policy = ProjectGovernanceService.update_policy(
        db=db,
        project_id=project_id,
        updates=payload.model_dump(exclude_unset=True),
        actor=current_user,
        client_ip=client_ip,
    )
    return policy


@router.get("/approvals", response_model=List[ApprovalRequestRead])
def list_approval_requests(
    project_id: str,
    status_filter: Optional[GovernanceApprovalStatus] = Query(None, alias="status"),
    workflow_filter: Optional[ApprovalWorkflowType] = Query(None, alias="workflow"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List approval requests for project with status and workflow filters."""
    verify_project_access(project_id, current_user, db)
    query = db.query(ApprovalRequestRecord).filter(ApprovalRequestRecord.project_id == project_id)

    if status_filter:
        query = query.filter(ApprovalRequestRecord.status == status_filter)
    if workflow_filter:
        query = query.filter(ApprovalRequestRecord.workflow_type == workflow_filter)

    return query.order_by(ApprovalRequestRecord.requested_at.desc()).offset(offset).limit(limit).all()


@router.post("/approvals", response_model=ApprovalRequestRead, status_code=status.HTTP_201_CREATED)
def request_approval(
    project_id: str,
    payload: ApprovalRequestCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Submit an approval request for a sensitive security workflow.
    Requires LEAD or TESTER role (read-only VIEWER / AUDITOR cannot request approvals).
    """
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER])
    client_ip = get_client_ip(request)

    approval = ProjectGovernanceService.request_approval(
        db=db,
        project_id=project_id,
        workflow_type=payload.workflow_type,
        resource_type=payload.resource_type,
        resource_id=payload.resource_id,
        title=payload.title,
        parameters=payload.parameters,
        requester=current_user,
        description=payload.description,
        client_ip=client_ip,
    )
    return approval


@router.get("/approvals/{approval_id}", response_model=ApprovalRequestRead)
def get_approval_request(
    project_id: str,
    approval_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve details of a single approval request."""
    verify_project_access(project_id, current_user, db)
    approval = (
        db.query(ApprovalRequestRecord)
        .filter(
            ApprovalRequestRecord.id == approval_id,
            ApprovalRequestRecord.project_id == project_id,
        )
        .first()
    )
    if not approval:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Approval request '{approval_id}' not found.")
    return approval


@router.post("/approvals/{approval_id}/decide", response_model=ApprovalRequestRead)
def decide_approval_request(
    project_id: str,
    approval_id: str,
    payload: ApprovalDecisionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Decide an approval request (APPROVE or REJECT).
    Requires Project LEAD or System ADMIN.
    Strictly enforces Separation of Duties: Requester cannot approve their own request
    unless single-operator override is active.
    """
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    client_ip = get_client_ip(request)

    # Determine project role for approver
    approver_role = ProjectRole.LEAD if current_user.system_role == SystemRole.ADMIN else None
    if not approver_role:
        member = (
            db.query(ProjectMember)
            .filter(ProjectMember.project_id == project_id, ProjectMember.user_id == current_user.id)
            .first()
        )
        approver_role = member.role if member else None

    try:
        approval = ProjectGovernanceService.decide_approval(
            db=db,
            project_id=project_id,
            approval_id=approval_id,
            approver=current_user,
            approved=payload.approved,
            reason=payload.reason,
            approver_role=approver_role,
            client_ip=client_ip,
        )
        return approval
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@router.get("/matrix", response_model=PermissionMatrixResponse)
def get_permission_matrix(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve the formal system & project RBAC permission matrix."""
    verify_project_access(project_id, current_user, db)
    return ProjectGovernanceService.get_permission_matrix()
