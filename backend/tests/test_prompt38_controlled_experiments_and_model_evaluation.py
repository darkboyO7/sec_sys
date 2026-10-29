import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi import status

from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.learning import (
    LearningDataset,
    DatasetRecord,
    DatasetSplit,
    GovernedModel,
    ModelStatus,
    PredictionType,
)
from app.models.model_experiment import (
    ModelControlledExperiment,
    SplitStrategy,
    ExperimentDecision,
)
from app.models.base import utc_now
from app.core.security import create_access_token, hash_password
from app.services.experiment_service import ControlledExperimentService
from app.services.learning_service import ModelGovernanceService


def auth_header_for_user(user: User) -> dict:
    token = create_access_token(
        subject=user.id,
        claims={"role": user.system_role.value, "email": user.email},
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def exp_org(db):
    org = Organization(name="ML Governance Corp", slug=f"ml-gov-{uuid.uuid4().hex[:6]}")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@pytest.fixture
def exp_users(db, exp_org):
    pw = hash_password("SecurePassword!123")
    lead = User(
        email=f"lead_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Lead Security Analyst",
        hashed_password=pw,
        is_active=True,
        system_role=SystemRole.SECURITY_LEAD,
    )
    scientist = User(
        email=f"scientist_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Staff Data Scientist",
        hashed_password=pw,
        is_active=True,
        system_role=SystemRole.SECURITY_TESTER,
    )
    viewer = User(
        email=f"viewer_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Auditor Viewer",
        hashed_password=pw,
        is_active=True,
        system_role=SystemRole.VIEWER,
    )
    db.add_all([lead, scientist, viewer])
    db.commit()
    db.refresh(lead)
    db.refresh(scientist)
    db.refresh(viewer)
    return {"lead": lead, "scientist": scientist, "viewer": viewer}


@pytest.fixture
def exp_project(db, exp_org, exp_users):
    proj = Project(
        name="Experiment Benchmark Project",
        description="Prompt 38 controlled experiments and model benchmark evaluation",
        organization_id=exp_org.id,
    )
    db.add(proj)
    db.commit()
    db.refresh(proj)

    m1 = ProjectMember(project_id=proj.id, user_id=exp_users["lead"].id, role=ProjectRole.LEAD)
    m2 = ProjectMember(project_id=proj.id, user_id=exp_users["scientist"].id, role=ProjectRole.TESTER)
    m3 = ProjectMember(project_id=proj.id, user_id=exp_users["viewer"].id, role=ProjectRole.VIEWER)
    db.add_all([m1, m2, m3])
    db.commit()
    return proj


def test_adaptive_learning_inventory_catalog(client, exp_users):
    """Req 1: Verify inventory of components that learn from outcomes, with zero unsupervised online self-tuning."""
    headers = auth_header_for_user(exp_users["lead"])
    response = client.get("/api/v1/system/learning/inventory", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) >= 5

    names = [item["component_name"] for item in data]
    assert "False Positive Predictor" in names
    assert "Exploitation Probability Engine" in names
    assert "Remediation Effort Estimator" in names
    assert "Risk Score Forecasting" in names
    assert "Attack Path Reachability Ranker" in names

    for item in data:
        assert item["online_self_tuning"] is False
        assert item["governance_mode"] == "SUPERVISED_OFFLINE"
        assert len(item["input_features"]) > 0


def test_time_aware_chronological_dataset_curation(client, db, exp_project, exp_users):
    """Req 4, 5: Verify dataset curation with chronological time-aware partitioning."""
    headers = auth_header_for_user(exp_users["scientist"])
    payload = {
        "name": "Chronological Finding Dataset",
        "version": "v1.0.0",
        "split_strategy": "TEMPORAL_AWARE",
    }
    response = client.post(
        f"/api/v1/projects/{exp_project.id}/learning/datasets/time-aware",
        json=payload,
        headers=headers,
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["name"] == "Chronological Finding Dataset"
    assert data["version"] == "v1.0.0"
    assert data["total_records"] >= 20
    assert data["train_count"] > 0
    assert data["test_count"] > 0

    # Verify temporal ordering in database
    records = db.query(DatasetRecord).filter(DatasetRecord.dataset_id == data["id"]).order_by(DatasetRecord.created_at.asc()).all()
    train_dates = [r.created_at for r in records if r.split == DatasetSplit.TRAIN]
    test_dates = [r.created_at for r in records if r.split == DatasetSplit.TEST]
    if train_dates and test_dates:
        assert max(train_dates) <= min(test_dates)


def test_controlled_experiment_clean_run(client, db, exp_project, exp_users):
    """Req 6, 7, 8, 9: Run controlled benchmark experiment on clean held-out test partition."""
    # 1. Curate clean dataset
    dataset = ControlledExperimentService.curate_time_aware_dataset(
        db=db,
        project_id=exp_project.id,
        name="Clean Benchmark Set",
        version="v1.1.0",
        user=exp_users["scientist"],
        split_strategy=SplitStrategy.TEMPORAL_AWARE,
    )

    # 2. Register candidate model
    model = ModelGovernanceService.register_model(
        project_id=exp_project.id,
        model_name="VulnClassifier",
        version="1.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=dataset.id,
        hyperparameters={"n_estimators": 100, "max_depth": 5},
        actor=exp_users["scientist"],
        db=db,
    )

    headers = auth_header_for_user(exp_users["scientist"])
    payload = {
        "model_id": model.id,
        "experiment_name": "Initial Controlled Benchmark",
        "split_strategy": "TEMPORAL_AWARE",
    }
    response = client.post(
        f"/api/v1/projects/{exp_project.id}/learning/experiments/run",
        json=payload,
        headers=headers,
    )
    assert response.status_code == status.HTTP_201_CREATED
    exp_data = response.json()
    assert exp_data["model_id"] == model.id
    assert exp_data["data_leakage_detected"] is False
    assert exp_data["insufficient_data_flag"] is False
    assert exp_data["decision_outcome"] == "ACCEPTED"

    metrics = exp_data["metrics"]
    assert "f1_score" in metrics
    assert "brier_score" in metrics
    assert "expected_calibration_error" in metrics
    assert metrics["test_sample_size"] > 0


def test_data_leakage_detection_identical_digests(client, db, exp_project, exp_users):
    """Req 4, 14: Inject duplicate feature digest into test split and verify detection & rejection."""
    dataset = ControlledExperimentService.curate_time_aware_dataset(
        db=db,
        project_id=exp_project.id,
        name="Leakage Test Set",
        version="v1.2.0",
        user=exp_users["scientist"],
    )

    # Contaminate test split with a train digest
    train_record = db.query(DatasetRecord).filter(
        DatasetRecord.dataset_id == dataset.id,
        DatasetRecord.split == DatasetSplit.TRAIN,
    ).first()
    test_record = db.query(DatasetRecord).filter(
        DatasetRecord.dataset_id == dataset.id,
        DatasetRecord.split == DatasetSplit.TEST,
    ).first()

    test_record.provenance_digest = train_record.provenance_digest
    db.commit()

    model = ModelGovernanceService.register_model(
        project_id=exp_project.id,
        model_name="VulnClassifierLeakage",
        version="1.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=dataset.id,
        hyperparameters={"n_estimators": 50},
        actor=exp_users["scientist"],
        db=db,
    )

    headers = auth_header_for_user(exp_users["scientist"])
    payload = {
        "model_id": model.id,
        "experiment_name": "Leakage Contaminated Evaluation",
    }
    response = client.post(
        f"/api/v1/projects/{exp_project.id}/learning/experiments/run",
        json=payload,
        headers=headers,
    )
    assert response.status_code == status.HTTP_201_CREATED
    exp_data = response.json()
    assert exp_data["data_leakage_detected"] is True
    assert exp_data["decision_outcome"] == "REJECTED_LEAKAGE"
    assert any("Identical feature digest" in msg for msg in exp_data["leakage_details"])


def test_temporal_leakage_detection(client, db, exp_project, exp_users):
    """Req 4, 5, 14: Inject test record with timestamp earlier than train record and verify rejection."""
    dataset = ControlledExperimentService.curate_time_aware_dataset(
        db=db,
        project_id=exp_project.id,
        name="Temporal Leakage Set",
        version="v1.3.0",
        user=exp_users["scientist"],
    )

    # Reverse timestamp order between a train and test record
    test_record = db.query(DatasetRecord).filter(
        DatasetRecord.dataset_id == dataset.id,
        DatasetRecord.split == DatasetSplit.TEST,
    ).first()
    test_record.created_at = utc_now() - timedelta(days=999)
    db.commit()

    model = ModelGovernanceService.register_model(
        project_id=exp_project.id,
        model_name="VulnClassifierTemporal",
        version="1.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=dataset.id,
        hyperparameters={"n_estimators": 50},
        actor=exp_users["scientist"],
        db=db,
    )

    headers = auth_header_for_user(exp_users["scientist"])
    payload = {
        "model_id": model.id,
        "experiment_name": "Temporal Leakage Evaluation",
    }
    response = client.post(
        f"/api/v1/projects/{exp_project.id}/learning/experiments/run",
        json=payload,
        headers=headers,
    )
    assert response.status_code == status.HTTP_201_CREATED
    exp_data = response.json()
    assert exp_data["data_leakage_detected"] is True
    assert exp_data["decision_outcome"] == "REJECTED_LEAKAGE"
    assert any("Temporal leakage detected" in msg for msg in exp_data["leakage_details"])


def test_insufficient_sample_size_reporting(client, db, exp_project, exp_users):
    """Req 8, 14, 15: Low sample size must be reported as insufficient data rather than fabricating synthetic outcomes."""
    # Create tiny dataset manually with only 3 records (< 10 threshold)
    ds = LearningDataset(
        project_id=exp_project.id,
        name="Tiny Dataset",
        version="v0.0.1",
        dataset_hash="tinyhash123",
        total_records=3,
        train_count=2,
        val_count=0,
        test_count=1,
        created_by_id=exp_users["scientist"].id,
    )
    db.add(ds)
    db.flush()

    for idx, split in [(1, DatasetSplit.TRAIN), (2, DatasetSplit.TRAIN), (3, DatasetSplit.TEST)]:
        rec = DatasetRecord(
            dataset_id=ds.id,
            split=split,
            source_entity_type="finding",
            source_entity_id=f"f-{idx}",
            features={"severity": "HIGH"},
            label="TRUE_POSITIVE",
            provenance_digest=f"digest-{idx}",
            created_at=utc_now() + timedelta(days=idx),
        )
        db.add(rec)
    db.commit()

    model = ModelGovernanceService.register_model(
        project_id=exp_project.id,
        model_name="VulnClassifierTiny",
        version="1.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=ds.id,
        hyperparameters={"n_estimators": 10},
        actor=exp_users["scientist"],
        db=db,
    )

    headers = auth_header_for_user(exp_users["scientist"])
    payload = {
        "model_id": model.id,
        "experiment_name": "Insufficient Sample Size Benchmark",
    }
    response = client.post(
        f"/api/v1/projects/{exp_project.id}/learning/experiments/run",
        json=payload,
        headers=headers,
    )
    assert response.status_code == status.HTTP_201_CREATED
    exp_data = response.json()
    assert exp_data["insufficient_data_flag"] is True
    assert exp_data["decision_outcome"] == "REJECTED_INSUFFICIENT_DATA"
    assert "below minimum statistical significance threshold" in exp_data["decision_rationale"]


def test_baseline_regression_rejection(client, db, exp_project, exp_users):
    """Req 6, 9: Candidate that performs worse than active baseline must be rejected."""
    dataset = ControlledExperimentService.curate_time_aware_dataset(
        db=db,
        project_id=exp_project.id,
        name="Baseline Comparison Set",
        version="v1.4.0",
        user=exp_users["scientist"],
    )

    # 1. Create baseline model with high F1 score (0.95) and active status
    baseline_model = GovernedModel(
        project_id=exp_project.id,
        model_name="RegressionDetector",
        version="1.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=dataset.id,
        hyperparameters={},
        status=ModelStatus.ACTIVE,
        is_active=True,
        metrics={"f1_score": 1.0, "brier_score": 0.005},
    )
    db.add(baseline_model)
    db.commit()

    # 2. Create candidate model evaluated against lower metrics
    candidate_model = GovernedModel(
        project_id=exp_project.id,
        model_name="RegressionDetector",
        version="2.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=dataset.id,
        hyperparameters={},
        status=ModelStatus.CANDIDATE,
        is_active=False,
    )
    db.add(candidate_model)
    db.commit()

    headers = auth_header_for_user(exp_users["scientist"])
    payload = {
        "model_id": candidate_model.id,
        "experiment_name": "Regression Check Evaluation",
    }
    response = client.post(
        f"/api/v1/projects/{exp_project.id}/learning/experiments/run",
        json=payload,
        headers=headers,
    )
    assert response.status_code == status.HTTP_201_CREATED
    exp_data = response.json()
    assert exp_data["baseline_model_id"] == baseline_model.id
    # Candidate should fail baseline comparison
    assert exp_data["decision_outcome"] == "REJECTED_INFERIOR_METRICS"
    assert "regresses against active baseline" in exp_data["decision_rationale"]


def test_model_approval_separation_of_duties(db, exp_project, exp_users):
    """Req 10, SoD: Dataset/model creator cannot self-approve model promotion."""
    dataset = ControlledExperimentService.curate_time_aware_dataset(
        db=db,
        project_id=exp_project.id,
        name="SoD Test Set",
        version="v1.5.0",
        user=exp_users["scientist"],
    )

    model = GovernedModel(
        project_id=exp_project.id,
        model_name="SoDModel",
        version="1.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=dataset.id,
        hyperparameters={},
        status=ModelStatus.EVALUATED,
        metrics={"precision": 0.85, "recall": 0.85, "f1_score": 0.85},
    )
    db.add(model)
    db.commit()

    # Creator (scientist) attempts to self-approve -> Must fail with PermissionError
    with pytest.raises(PermissionError, match="Separation of Duties violation"):
        ModelGovernanceService.approve_model(
            project_id=exp_project.id,
            model_id=model.id,
            approved=True,
            approval_notes="Self-approval by scientist",
            reviewer=exp_users["scientist"],
            db=db,
        )

    # Independent reviewer (Lead) approves -> Must succeed
    approved_model = ModelGovernanceService.approve_model(
        project_id=exp_project.id,
        model_id=model.id,
        approved=True,
        approval_notes="Approved by independent security lead",
        reviewer=exp_users["lead"],
        db=db,
    )
    assert approved_model.status == ModelStatus.APPROVED
    assert approved_model.approved_by_id == exp_users["lead"].id


def test_model_activation_and_atomic_rollback(db, exp_project, exp_users):
    """Req 11, 12: Promotion activates model and links rollback target; rollback restores prior version."""
    dataset = ControlledExperimentService.curate_time_aware_dataset(
        db=db,
        project_id=exp_project.id,
        name="Rollback Test Set",
        version="v1.6.0",
        user=exp_users["scientist"],
    )

    # 1. Active initial model (v1)
    m1 = GovernedModel(
        project_id=exp_project.id,
        model_name="RollbackModel",
        version="1.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=dataset.id,
        hyperparameters={},
        status=ModelStatus.ACTIVE,
        is_active=True,
        metrics={"precision": 0.85, "recall": 0.85, "f1_score": 0.85},
    )
    db.add(m1)
    db.commit()

    # 2. Approved candidate model (v2)
    m2 = GovernedModel(
        project_id=exp_project.id,
        model_name="RollbackModel",
        version="2.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=dataset.id,
        hyperparameters={},
        status=ModelStatus.APPROVED,
        is_active=False,
        metrics={"precision": 0.88, "recall": 0.88, "f1_score": 0.88},
    )
    db.add(m2)
    db.commit()

    # Activate v2 -> m1 demoted, m2 active, m2.rollback_target_id == m1.id
    active_m2 = ModelGovernanceService.activate_model(
        project_id=exp_project.id,
        model_id=m2.id,
        actor=exp_users["lead"],
        db=db,
    )
    assert active_m2.is_active is True
    assert active_m2.status == ModelStatus.ACTIVE
    assert active_m2.rollback_target_id == m1.id

    db.refresh(m1)
    assert m1.is_active is False
    assert m1.status == ModelStatus.DEPRECATED

    # Perform atomic rollback on m2 -> m2 rolled back, m1 reactivated
    restored_m1 = ModelGovernanceService.rollback_model(
        project_id=exp_project.id,
        model_id=m2.id,
        reason="Production distribution shift detected",
        user=exp_users["lead"],
        db=db,
    )
    assert restored_m1.id == m1.id
    assert restored_m1.is_active is True
    assert restored_m1.status == ModelStatus.ACTIVE

    db.refresh(m2)
    assert m2.is_active is False
    assert m2.status == ModelStatus.ROLLED_BACK


def test_distribution_shift_detection(client, exp_project, exp_users, db):
    """Req 13: Detect distribution shift without automatic unsafe self-tuning."""
    dataset = ControlledExperimentService.curate_time_aware_dataset(
        db=db,
        project_id=exp_project.id,
        name="Shift Test Set",
        version="v1.7.0",
        user=exp_users["scientist"],
    )
    model = GovernedModel(
        project_id=exp_project.id,
        model_name="ShiftDetectorModel",
        version="1.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=dataset.id,
        hyperparameters={},
        status=ModelStatus.ACTIVE,
        is_active=True,
        metrics={"f1_score": 0.85},
    )
    db.add(model)
    db.commit()

    headers = auth_header_for_user(exp_users["lead"])
    response = client.get(
        f"/api/v1/projects/{exp_project.id}/learning/models/{model.id}/distribution-shift",
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["model_id"] == model.id
    assert "distribution_shift_detected" in data
    assert "status" in data
    assert "recommended_action" in data


def test_decision_ledger_api_query(client, db, exp_project, exp_users):
    """Req 11: Query experiment decision ledger via REST API."""
    dataset = ControlledExperimentService.curate_time_aware_dataset(
        db=db,
        project_id=exp_project.id,
        name="Ledger Test Set",
        version="v1.8.0",
        user=exp_users["scientist"],
    )
    model = GovernedModel(
        project_id=exp_project.id,
        model_name="LedgerModel",
        version="1.0.0",
        model_type="FALSE_POSITIVE_LIKELIHOOD",
        dataset_id=dataset.id,
        hyperparameters={},
        status=ModelStatus.CANDIDATE,
        is_active=False,
    )
    db.add(model)
    db.commit()

    # Run experiment
    ControlledExperimentService.run_controlled_experiment(
        db=db,
        project_id=exp_project.id,
        model_id=model.id,
        experiment_name="Decision Ledger Test Exp",
        actor=exp_users["scientist"],
    )

    headers = auth_header_for_user(exp_users["viewer"])
    response = client.get(
        f"/api/v1/projects/{exp_project.id}/learning/experiments",
        headers=headers,
    )
    assert response.status_code == status.HTTP_200_OK
    experiments = response.json()
    assert len(experiments) >= 1
    exp_entry = experiments[0]
    assert exp_entry["project_id"] == exp_project.id
    assert "decision_outcome" in exp_entry
    assert "metrics" in exp_entry

    # Query single experiment by ID
    exp_id = exp_entry["id"]
    detail_res = client.get(
        f"/api/v1/projects/{exp_project.id}/learning/experiments/{exp_id}",
        headers=headers,
    )
    assert detail_res.status_code == status.HTTP_200_OK
    detail_data = detail_res.json()
    assert detail_data["id"] == exp_id
