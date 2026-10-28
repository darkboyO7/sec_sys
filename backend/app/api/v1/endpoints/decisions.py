from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api import deps
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.decision import SecurityDecisionRecord, PostureChangeRecord, DecisionStatus
from app.schemas.decision import (
    SecurityDecisionResponse,
    PostureChangeResponse,
    DecisionEvaluationRequest,
    DecisionActionExecutionRequest,
    ClosedLoopOverviewResponse,
)
from app.services.security_decision_service import SecurityDecisionService
from app.services.change_detection_service import ChangeDetectionService

router = APIRouter(prefix="/projects/{project_id}", tags=["Autonomous Security Decisions & Closed Loop"])


def _verify_project_access(project_id: str, current_user: User, db: Session) -> ProjectMember:
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project '{project_id}' not found.")

    if current_user.system_role == SystemRole.ADMIN:
        member = db.query(ProjectMember).filter(ProjectMember.project_id == project_id, ProjectMember.user_id == current_user.id).first()
        if not member:
            return ProjectMember(project_id=project_id, user_id=current_user.id, role=ProjectRole.LEAD)
        return member

    member = db.query(ProjectMember).filter(ProjectMember.project_id == project_id, ProjectMember.user_id == current_user.id).first()
    if not member:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: User is not a member of this project.")
    return member


@router.get("/decisions", response_model=List[SecurityDecisionResponse])
def list_security_decisions(
    project_id: str,
    status_filter: Optional[DecisionStatus] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
):
    _verify_project_access(project_id, current_user, db)
    query = db.query(SecurityDecisionRecord).filter(SecurityDecisionRecord.project_id == project_id)
    if status_filter:
        query = query.filter(SecurityDecisionRecord.status == status_filter)
    return query.order_by(SecurityDecisionRecord.created_at.desc()).limit(limit).all()


@router.post("/decisions/evaluate", response_model=List[SecurityDecisionResponse])
def evaluate_security_decisions(
    project_id: str,
    req: Optional[DecisionEvaluationRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
):
    _verify_project_access(project_id, current_user, db)
    return SecurityDecisionService.evaluate_and_propose_decisions(db=db, project_id=project_id)


@router.post("/decisions/{decision_id}/approve", response_model=SecurityDecisionResponse)
def approve_security_decision(
    project_id: str,
    decision_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
):
    member = _verify_project_access(project_id, current_user, db)
    if member.role != ProjectRole.LEAD and current_user.system_role != SystemRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only Project LEAD or System ADMIN can approve security decisions.")

    decision = db.query(SecurityDecisionRecord).filter(SecurityDecisionRecord.id == decision_id, SecurityDecisionRecord.project_id == project_id).first()
    if not decision:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not found.")

    decision.status = DecisionStatus.APPROVED
    decision.approved_by_id = current_user.id
    db.commit()
    db.refresh(decision)
    return decision


@router.post("/decisions/{decision_id}/execute", response_model=SecurityDecisionResponse)
def execute_security_decision(
    project_id: str,
    decision_id: str,
    req: Optional[DecisionActionExecutionRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
):
    member = _verify_project_access(project_id, current_user, db)
    try:
        return SecurityDecisionService.execute_decision(
            db=db,
            project_id=project_id,
            decision_id=decision_id,
            actor=current_user,
            actor_role=member.role,
            force=req.force if req else False,
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@router.get("/changes", response_model=List[PostureChangeResponse])
def list_posture_changes(
    project_id: str,
    confirmed_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
):
    _verify_project_access(project_id, current_user, db)
    return ChangeDetectionService.list_posture_changes(db=db, project_id=project_id, limit=limit, confirmed_only=confirmed_only)


@router.get("/closed-loop/overview", response_model=ClosedLoopOverviewResponse)
def get_closed_loop_overview(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
):
    _verify_project_access(project_id, current_user, db)
    return SecurityDecisionService.get_closed_loop_overview(db=db, project_id=project_id)
