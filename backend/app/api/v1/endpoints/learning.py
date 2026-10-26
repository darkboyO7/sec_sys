from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.learning import LearningDataset, GovernedModel, ModelStatus
from app.schemas.learning import (
    DatasetCurateRequest,
    LearningDatasetRead,
    ModelRegisterRequest,
    ModelApprovalRequest,
    ModelRollbackRequest,
    GovernedModelRead,
)
from app.services.learning_service import ModelGovernanceService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


@router.post(
    "/projects/{project_id}/learning/datasets/curate",
    response_model=LearningDatasetRead,
    status_code=status.HTTP_201_CREATED,
    summary="Curate versioned, privacy-minimized learning dataset from verified project records",
)
def curate_dataset(
    project_id: str,
    payload: DatasetCurateRequest,
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
        dataset = ModelGovernanceService.curate_dataset(
            project_id=project_id,
            name=payload.name,
            version=payload.version,
            user=current_user,
            db=db,
            client_ip=client_ip,
        )
        return dataset
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/learning/datasets",
    response_model=List[LearningDatasetRead],
    status_code=status.HTTP_200_OK,
    summary="List curated learning datasets for project",
)
def list_datasets(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return (
        db.query(LearningDataset)
        .filter(LearningDataset.project_id == project_id)
        .order_by(LearningDataset.created_at.desc())
        .all()
    )


@router.post(
    "/projects/{project_id}/learning/models/register",
    response_model=GovernedModelRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a candidate machine learning model artifact",
)
def register_model(
    project_id: str,
    payload: ModelRegisterRequest,
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
        model = ModelGovernanceService.register_model(
            project_id=project_id,
            model_name=payload.model_name,
            version=payload.version,
            model_type=payload.model_type,
            dataset_id=payload.dataset_id,
            hyperparameters=payload.hyperparameters,
            actor=current_user,
            db=db,
            client_ip=client_ip,
        )
        return model
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/learning/models/{model_id}/evaluate",
    response_model=GovernedModelRead,
    status_code=status.HTTP_200_OK,
    summary="Execute reproducible evaluation on held-out test data",
)
def evaluate_model(
    project_id: str,
    model_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    try:
        model = ModelGovernanceService.evaluate_model(
            project_id=project_id,
            model_id=model_id,
            db=db,
            actor=current_user,
            client_ip=client_ip,
        )
        return model
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/learning/models/{model_id}/approve",
    response_model=GovernedModelRead,
    status_code=status.HTTP_200_OK,
    summary="Human governance approval gate for evaluated model",
)
def approve_model(
    project_id: str,
    model_id: str,
    payload: ModelApprovalRequest,
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
        model = ModelGovernanceService.approve_model(
            project_id=project_id,
            model_id=model_id,
            approved=payload.approved,
            approval_notes=payload.approval_notes,
            reviewer=current_user,
            db=db,
            client_ip=client_ip,
        )
        return model
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/learning/models/{model_id}/activate",
    response_model=GovernedModelRead,
    status_code=status.HTTP_200_OK,
    summary="Deploy approved model to ACTIVE status with automatic rollback target linking",
)
def activate_model(
    project_id: str,
    model_id: str,
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
        model = ModelGovernanceService.activate_model(
            project_id=project_id,
            model_id=model_id,
            actor=current_user,
            db=db,
            client_ip=client_ip,
        )
        return model
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/learning/models/{model_id}/rollback",
    response_model=GovernedModelRead,
    status_code=status.HTTP_200_OK,
    summary="Atomic emergency rollback to preceding active model version",
)
def rollback_model(
    project_id: str,
    model_id: str,
    payload: ModelRollbackRequest,
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
        reactivated = ModelGovernanceService.rollback_model(
            project_id=project_id,
            model_id=model_id,
            reason=payload.reason,
            user=current_user,
            db=db,
            rollback_target_id=payload.rollback_target_id,
            client_ip=client_ip,
        )
        return reactivated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/learning/models",
    response_model=List[GovernedModelRead],
    status_code=status.HTTP_200_OK,
    summary="List all governed models for project",
)
def list_models(
    project_id: str,
    status_filter: Optional[ModelStatus] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    query = db.query(GovernedModel).filter(GovernedModel.project_id == project_id)
    if status_filter:
        query = query.filter(GovernedModel.status == status_filter)
    return query.order_by(GovernedModel.created_at.desc()).all()
