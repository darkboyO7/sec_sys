from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.model_experiment import ModelControlledExperiment, SplitStrategy, ExperimentDecision
from app.schemas.model_experiment import (
    LearningInventoryItem,
    CurateTimeAwareDatasetRequest,
    RunControlledExperimentRequest,
    ExperimentResponse,
    DistributionShiftResponse,
)
from app.schemas.learning import LearningDatasetRead
from app.services.experiment_service import ControlledExperimentService
from app.api.deps import get_current_user, verify_project_access

router = APIRouter()


@router.get(
    "/system/learning/inventory",
    response_model=List[LearningInventoryItem],
    status_code=status.HTTP_200_OK,
    summary="List inventory of all adaptive learning, risk scoring, and recommendation components",
)
def get_adaptive_learning_inventory(
    current_user: User = Depends(get_current_user),
):
    """
    Returns platform-wide catalog of models, inputs, prediction objectives,
    and decision impact. Enforces that no component operates with unsupervised online self-tuning (Prompt 38 Req 1).
    """
    items = ControlledExperimentService.get_adaptive_learning_inventory()
    return items


@router.post(
    "/projects/{project_id}/learning/datasets/time-aware",
    response_model=LearningDatasetRead,
    status_code=status.HTTP_201_CREATED,
    summary="Curate a versioned dataset snapshot using chronological time-aware partitioning",
)
def curate_time_aware_dataset(
    project_id: str,
    payload: CurateTimeAwareDatasetRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Partitions verified outcome records into train/validation/test chronologically,
    strictly eliminating temporal data leakage (Prompt 38 Req 4, 5).
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    strategy = SplitStrategy.TEMPORAL_AWARE
    if payload.split_strategy:
        try:
            strategy = SplitStrategy(payload.split_strategy)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid split strategy: {payload.split_strategy}",
            )

    try:
        dataset = ControlledExperimentService.curate_time_aware_dataset(
            db=db,
            project_id=project_id,
            name=payload.name,
            version=payload.version,
            user=current_user,
            split_strategy=strategy,
        )
        return dataset
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/learning/experiments/run",
    response_model=ExperimentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute controlled evaluation experiment on held-out test data",
)
def run_controlled_experiment(
    project_id: str,
    payload: RunControlledExperimentRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes controlled benchmark experiment against held-out test partition.
    Checks data leakage, class imbalance, calibration, and regression against baseline (Prompt 38 Req 6-10).
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    strategy = SplitStrategy.TEMPORAL_AWARE
    if payload.split_strategy:
        try:
            strategy = SplitStrategy(payload.split_strategy)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid split strategy: {payload.split_strategy}",
            )

    try:
        experiment = ControlledExperimentService.run_controlled_experiment(
            db=db,
            project_id=project_id,
            model_id=payload.model_id,
            experiment_name=payload.experiment_name,
            split_strategy=strategy,
            actor=current_user,
            force_pass_baseline=payload.force_pass_baseline or False,
        )
        return experiment
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/learning/experiments",
    response_model=List[ExperimentResponse],
    status_code=status.HTTP_200_OK,
    summary="Query controlled experiments and evaluation decision ledger",
)
def list_controlled_experiments(
    project_id: str,
    model_id: Optional[str] = Query(None, description="Filter by model ID"),
    decision: Optional[str] = Query(None, description="Filter by decision outcome"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves decision ledger linking model versions, datasets, evaluation results, and approvals (Prompt 38 Req 11).
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER, ProjectRole.VIEWER],
    )
    query = db.query(ModelControlledExperiment).filter(ModelControlledExperiment.project_id == project_id)
    if model_id:
        query = query.filter(ModelControlledExperiment.model_id == model_id)
    if decision:
        query = query.filter(ModelControlledExperiment.decision_outcome == decision)

    experiments = query.order_by(ModelControlledExperiment.created_at.desc()).all()
    return experiments


@router.get(
    "/projects/{project_id}/learning/experiments/{experiment_id}",
    response_model=ExperimentResponse,
    status_code=status.HTTP_200_OK,
    summary="Get detailed metrics and leakage analysis for an experiment",
)
def get_controlled_experiment(
    project_id: str,
    experiment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves detailed experiment record, including calibration uncertainty, sample sizes, and leakage findings.
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER, ProjectRole.VIEWER],
    )
    experiment = (
        db.query(ModelControlledExperiment)
        .filter(
            ModelControlledExperiment.id == experiment_id,
            ModelControlledExperiment.project_id == project_id,
        )
        .first()
    )
    if not experiment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Experiment not found.")
    return experiment


@router.get(
    "/projects/{project_id}/learning/models/{model_id}/distribution-shift",
    response_model=DistributionShiftResponse,
    status_code=status.HTTP_200_OK,
    summary="Detect distribution shift and performance degradation without unsafe automatic updates",
)
def detect_distribution_shift(
    project_id: str,
    model_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Monitors drift in real-world prediction accuracy and Brier calibration score (Prompt 38 Req 13).
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER, ProjectRole.VIEWER],
    )
    shift_data = ControlledExperimentService.detect_distribution_shift(
        db=db,
        project_id=project_id,
        model_id=model_id,
    )
    return shift_data
