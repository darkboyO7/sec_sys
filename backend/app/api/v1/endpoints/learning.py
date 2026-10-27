from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.learning import (
    LearningDataset,
    GovernedModel,
    ModelStatus,
    PredictionLedger,
    PredictionType,
    PredictionEvaluationStatus,
)
from app.schemas.learning import (
    DatasetCurateRequest,
    LearningDatasetRead,
    ModelRegisterRequest,
    ModelApprovalRequest,
    ModelRollbackRequest,
    GovernedModelRead,
    PredictionRecordRequest,
    PredictionEvaluateRequest,
    PredictionInvalidateRequest,
    PredictionLedgerRead,
    ModelDriftMetricsRead,
)
from app.services.learning_service import ModelGovernanceService, PredictionLedgerService
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


# --- Prediction Ledger Endpoints (Phase 19.1 / Part X, Section 20) ---


@router.post(
    "/projects/{project_id}/learning/predictions",
    response_model=PredictionLedgerRead,
    status_code=status.HTTP_201_CREATED,
    summary="Record an immutable prediction in the persistent ledger before action is taken",
)
def record_prediction(
    project_id: str,
    payload: PredictionRecordRequest,
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
        entry = PredictionLedgerService.record_prediction(
            project_id=project_id,
            target_entity_type=payload.target_entity_type,
            target_entity_id=payload.target_entity_id,
            prediction_type=payload.prediction_type,
            predicted_outcome=payload.predicted_outcome,
            confidence_score=payload.confidence_score,
            feature_snapshot=payload.feature_snapshot,
            model_id=payload.model_id,
            model_version=payload.model_version or "heuristic-v1.0",
            rule_version=payload.rule_version,
            limitations=payload.limitations,
            decision_action_taken=payload.decision_action_taken,
            expected_evaluation_horizon=payload.expected_evaluation_horizon,
            actor_id=current_user.id,
            client_ip=client_ip,
            db=db,
        )
        return entry
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/learning/predictions",
    response_model=List[PredictionLedgerRead],
    status_code=status.HTTP_200_OK,
    summary="Query prediction ledger records with filtering and pagination",
)
def list_predictions(
    project_id: str,
    target_entity_type: Optional[str] = Query(None),
    target_entity_id: Optional[str] = Query(None),
    prediction_type: Optional[PredictionType] = Query(None),
    evaluation_status: Optional[PredictionEvaluationStatus] = Query(None),
    model_version: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)

    query = db.query(PredictionLedger).filter(PredictionLedger.project_id == project_id)
    if target_entity_type:
        query = query.filter(PredictionLedger.target_entity_type == target_entity_type)
    if target_entity_id:
        query = query.filter(PredictionLedger.target_entity_id == target_entity_id)
    if prediction_type:
        query = query.filter(PredictionLedger.prediction_type == prediction_type)
    if evaluation_status:
        query = query.filter(PredictionLedger.evaluation_status == evaluation_status)
    if model_version:
        query = query.filter(PredictionLedger.model_version == model_version)

    return query.order_by(PredictionLedger.created_at.desc()).offset(offset).limit(limit).all()


@router.post(
    "/projects/{project_id}/learning/predictions/{prediction_id}/evaluate",
    response_model=PredictionLedgerRead,
    status_code=status.HTTP_200_OK,
    summary="Evaluate an observed real-world outcome against a pending prediction",
)
def evaluate_prediction(
    project_id: str,
    prediction_id: str,
    payload: PredictionEvaluateRequest,
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
        evaluated = PredictionLedgerService.evaluate_prediction(
            prediction_id=prediction_id,
            project_id=project_id,
            actual_outcome=payload.actual_outcome,
            outcome_evidence=payload.outcome_evidence,
            user=current_user,
            status_override=payload.status_override,
            notes=payload.notes,
            client_ip=client_ip,
            db=db,
        )
        return evaluated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/learning/predictions/{prediction_id}/invalidate",
    response_model=PredictionLedgerRead,
    status_code=status.HTTP_200_OK,
    summary="Invalidate a prediction due to corrupted features or invalid scope",
)
def invalidate_prediction(
    project_id: str,
    prediction_id: str,
    payload: PredictionInvalidateRequest,
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
        invalidated = PredictionLedgerService.invalidate_prediction(
            prediction_id=prediction_id,
            project_id=project_id,
            reason=payload.reason,
            user=current_user,
            client_ip=client_ip,
            db=db,
        )
        return invalidated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/learning/predictions/drift",
    response_model=ModelDriftMetricsRead,
    status_code=status.HTTP_200_OK,
    summary="Calculate empirical prediction accuracy, Brier calibration, and drift alerts",
)
def get_prediction_drift_metrics(
    project_id: str,
    model_version: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return PredictionLedgerService.calculate_drift_metrics(
        project_id=project_id,
        model_version=model_version,
        db=db,
    )
