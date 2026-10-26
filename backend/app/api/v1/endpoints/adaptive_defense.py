from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.adaptive_defense import MorphStatePosture, MorphStateHistory
from app.schemas.adaptive_defense import (
    MorphStatePostureRead,
    MorphStateHistoryRead,
    KillSwitchEngageRequest,
    KillSwitchDisengageRequest,
    ManualTransitionRequest,
)
from app.services.adaptive_defense_service import AdaptiveDefenseService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


@router.get(
    "/projects/{project_id}/adaptive-defense/posture",
    response_model=MorphStatePostureRead,
    status_code=status.HTTP_200_OK,
    summary="Get current adaptive defensive posture and monitoring cadence",
)
def get_posture(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return AdaptiveDefenseService.get_or_create_project_posture(project_id, db)


@router.post(
    "/projects/{project_id}/adaptive-defense/evaluate",
    response_model=MorphStatePostureRead,
    status_code=status.HTTP_200_OK,
    summary="Evaluate operational signals and update adaptive morph-state posture",
)
def evaluate_posture(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    try:
        posture = AdaptiveDefenseService.evaluate_adaptive_posture(
            project_id=project_id,
            db=db,
            actor=current_user,
            client_ip=client_ip,
        )
        return posture
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/adaptive-defense/kill-switch/engage",
    response_model=MorphStatePostureRead,
    status_code=status.HTTP_200_OK,
    summary="Emergency Kill Switch: immediately halts adaptive automation and locks to MANUAL_REVIEW_REQUIRED",
)
def engage_kill_switch(
    project_id: str,
    payload: KillSwitchEngageRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    client_ip = get_client_ip(request)

    try:
        posture = AdaptiveDefenseService.engage_kill_switch(
            project_id=project_id,
            reason=payload.reason,
            user=current_user,
            db=db,
            client_ip=client_ip,
        )
        return posture
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/adaptive-defense/kill-switch/disengage",
    response_model=MorphStatePostureRead,
    status_code=status.HTTP_200_OK,
    summary="Disengage Emergency Kill Switch and restore operational baseline (Lead/Admin gate)",
)
def disengage_kill_switch(
    project_id: str,
    payload: KillSwitchDisengageRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )
    client_ip = get_client_ip(request)

    try:
        posture = AdaptiveDefenseService.disengage_kill_switch(
            project_id=project_id,
            justification=payload.justification,
            user=current_user,
            db=db,
            client_ip=client_ip,
        )
        return posture
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/adaptive-defense/transition",
    response_model=MorphStatePostureRead,
    status_code=status.HTTP_200_OK,
    summary="Manually transition posture state with operator justification (Lead/Admin gate)",
)
def manual_transition(
    project_id: str,
    payload: ManualTransitionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )
    client_ip = get_client_ip(request)

    try:
        posture = AdaptiveDefenseService.transition_manually(
            project_id=project_id,
            target_state=payload.to_state,
            justification=payload.justification,
            user=current_user,
            db=db,
            client_ip=client_ip,
        )
        return posture
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/adaptive-defense/history",
    response_model=List[MorphStateHistoryRead],
    status_code=status.HTTP_200_OK,
    summary="List full immutable transition history for project posture",
)
def list_history(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    posture = AdaptiveDefenseService.get_or_create_project_posture(project_id, db)
    return (
        db.query(MorphStateHistory)
        .filter(MorphStateHistory.posture_id == posture.id)
        .order_by(MorphStateHistory.created_at.desc())
        .all()
    )
