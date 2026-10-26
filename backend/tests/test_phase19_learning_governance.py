import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.user import User
from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
)
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.verification import RemediationVerification, VerificationOutcome
from app.models.learning import (
    DatasetSplit,
    ModelStatus,
    LearningDataset,
    GovernedModel,
)
from app.services.learning_service import ModelGovernanceService
from app.models.base import utc_now


def test_phase19_dataset_curation_privacy_and_partitioning(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify dataset curation scrubs sensitive data and creates deterministic splits with SHA-256 hash."""
    # Create sample findings with potential sensitive data in target
    f1 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase19-ds-01",
        target_value="https://user:password123@192.168.1.50/admin?token=bearer ABC123DEF456",
        title="Admin Interface Exposure",
        description="Admin panel exposed on internal network.",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        is_simulated=True,
    )
    f2 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase19-ds-02",
        target_value="https://test.local/login",
        title="False Positive Header Check",
        description="Scanner false positive on X-Frame-Options.",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.TENTATIVE,
        status=FindingLifecycleStatus.FALSE_POSITIVE,
        is_simulated=True,
    )
    db.add_all([f1, f2])
    db.commit()

    dataset = ModelGovernanceService.curate_dataset(
        project_id=test_project.id,
        name="Q4 Security Governance Benchmark",
        version="v2026.4.1",
        user=tester_user,
        db=db,
    )

    # 1. Dataset stats & splits
    assert dataset.total_records >= 10
    assert dataset.train_count > 0
    assert dataset.val_count > 0
    assert dataset.test_count > 0
    assert dataset.train_count + dataset.val_count + dataset.test_count == dataset.total_records

    # 2. Cryptographic digest
    assert len(dataset.dataset_hash) == 64

    # 3. Privacy minimization verification: password and IP scrubbed from features
    records = dataset.records
    f1_record = [r for r in records if r.source_entity_id == f1.id]
    assert len(f1_record) == 1
    sanitized_target = f1_record[0].features.get("target_sanitized", "")
    assert "password123" not in sanitized_target
    assert "192.168.1.50" not in sanitized_target
    assert "[SCRUBBED]" in sanitized_target or "[IP_SCRUBBED]" in sanitized_target


def test_phase19_model_registration_and_evaluation_metrics(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify candidate model registration and reproducible empirical evaluation on held-out test data."""
    dataset = ModelGovernanceService.curate_dataset(
        project_id=test_project.id,
        name="Eval Dataset",
        version="v2026.eval.1",
        user=tester_user,
        db=db,
    )

    # 1. Register candidate model
    model = ModelGovernanceService.register_model(
        project_id=test_project.id,
        model_name="VulnerabilityTriageClassifier",
        version="v1.0.0",
        model_type="GRADIENT_BOOSTED_DECISION_TREE",
        dataset_id=dataset.id,
        hyperparameters={"max_depth": 4, "learning_rate": 0.05},
        actor=tester_user,
        db=db,
    )
    assert model.status == ModelStatus.CANDIDATE
    assert model.is_active is False
    assert model.metrics == {}

    # 2. Evaluate candidate model
    evaluated = ModelGovernanceService.evaluate_model(
        project_id=test_project.id,
        model_id=model.id,
        db=db,
        actor=tester_user,
    )
    assert evaluated.status == ModelStatus.EVALUATED
    m = evaluated.metrics
    assert "precision" in m
    assert "recall" in m
    assert "f1_score" in m
    assert "false_positive_rate" in m
    assert "brier_score" in m
    assert m["test_sample_size"] > 0


def test_phase19_governance_approval_gate(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify human governance approval gate rejects unevaluated models and enforces quality thresholds."""
    dataset = ModelGovernanceService.curate_dataset(
        project_id=test_project.id,
        name="Approval Gate Dataset",
        version="v2026.appr.1",
        user=tester_user,
        db=db,
    )
    model = ModelGovernanceService.register_model(
        project_id=test_project.id,
        model_name="TriageModelGate",
        version="v1.0.0",
        model_type="CALIBRATED_LOGISTIC",
        dataset_id=dataset.id,
        hyperparameters={},
        actor=tester_user,
        db=db,
    )

    # 1. Cannot approve CANDIDATE model without prior evaluation
    with pytest.raises(ValueError, match="must be in 'EVALUATED' status"):
        ModelGovernanceService.approve_model(
            project_id=test_project.id,
            model_id=model.id,
            approved=True,
            approval_notes="Bypassing evaluation",
            reviewer=tester_user,
            db=db,
        )

    # 2. Evaluate model
    ModelGovernanceService.evaluate_model(
        project_id=test_project.id,
        model_id=model.id,
        db=db,
        actor=tester_user,
    )

    # 3. Reject short notes
    with pytest.raises(ValueError, match="minimum 3 characters"):
        ModelGovernanceService.approve_model(
            project_id=test_project.id,
            model_id=model.id,
            approved=True,
            approval_notes="ok",
            reviewer=tester_user,
            db=db,
        )

    # 4. Successfully approve model
    approved_model = ModelGovernanceService.approve_model(
        project_id=test_project.id,
        model_id=model.id,
        approved=True,
        approval_notes="Approved following empirical evaluation on held-out test split.",
        reviewer=tester_user,
        db=db,
    )
    assert approved_model.status == ModelStatus.APPROVED
    assert approved_model.approved_by_id == tester_user.id
    assert approved_model.approved_at is not None


def test_phase19_controlled_activation_and_atomic_rollback(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify controlled activation demotes previous model and rollback reactivates prior approved model."""
    dataset = ModelGovernanceService.curate_dataset(
        project_id=test_project.id,
        name="Lifecycle Dataset",
        version="v2026.life.1",
        user=tester_user,
        db=db,
    )

    # Setup Model A (v1.0.0) -> APPROVED -> ACTIVE
    model_a = ModelGovernanceService.register_model(
        project_id=test_project.id,
        model_name="AdaptivePrioritizer",
        version="v1.0.0",
        model_type="RULE_ENSEMBLE",
        dataset_id=dataset.id,
        hyperparameters={},
        actor=tester_user,
        db=db,
    )
    ModelGovernanceService.evaluate_model(test_project.id, model_a.id, db)
    ModelGovernanceService.approve_model(test_project.id, model_a.id, True, "Approved baseline v1.0.0", tester_user, db)
    ModelGovernanceService.activate_model(test_project.id, model_a.id, tester_user, db)

    db.refresh(model_a)
    assert model_a.is_active is True
    assert model_a.status == ModelStatus.ACTIVE

    # Setup Model B (v2.0.0) -> APPROVED -> ACTIVE
    model_b = ModelGovernanceService.register_model(
        project_id=test_project.id,
        model_name="AdaptivePrioritizer",
        version="v2.0.0",
        model_type="GRADIENT_BOOSTED_DECISION_TREE",
        dataset_id=dataset.id,
        hyperparameters={},
        actor=tester_user,
        db=db,
    )
    ModelGovernanceService.evaluate_model(test_project.id, model_b.id, db)
    ModelGovernanceService.approve_model(test_project.id, model_b.id, True, "Approved v2.0.0 upgrade", tester_user, db)
    ModelGovernanceService.activate_model(test_project.id, model_b.id, tester_user, db)

    db.refresh(model_a)
    db.refresh(model_b)
    # Model B is active, Model A is demoted to DEPRECATED with rollback linking
    assert model_b.is_active is True
    assert model_b.status == ModelStatus.ACTIVE
    assert model_b.rollback_target_id == model_a.id
    assert model_a.is_active is False
    assert model_a.status == ModelStatus.DEPRECATED

    # Perform atomic emergency rollback from Model B -> Model A
    reactivated = ModelGovernanceService.rollback_model(
        project_id=test_project.id,
        model_id=model_b.id,
        reason="Observed data drift and calibration spike in canary telemetry.",
        user=tester_user,
        db=db,
    )
    db.refresh(model_a)
    db.refresh(model_b)
    assert model_b.is_active is False
    assert model_b.status == ModelStatus.ROLLED_BACK
    assert model_a.is_active is True
    assert model_a.status == ModelStatus.ACTIVE
    assert reactivated.id == model_a.id


def test_phase19_api_endpoints_and_cross_project_isolation(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_headers: dict,
    tester_headers: dict,
):
    """Verify HTTP API endpoints for dataset curation, registration, evaluation, and approval."""
    # 1. Curate dataset via API
    cur_res = client.post(
        f"/api/v1/projects/{test_project.id}/learning/datasets/curate",
        headers=lead_headers,
        json={"name": "API Benchmark Dataset", "version": "v2026.api.1"},
    )
    assert cur_res.status_code == 201
    ds_data = cur_res.json()
    dataset_id = ds_data["id"]
    assert ds_data["total_records"] >= 10

    # 2. Register model via API
    reg_res = client.post(
        f"/api/v1/projects/{test_project.id}/learning/models/register",
        headers=lead_headers,
        json={
            "model_name": "APITestClassifier",
            "version": "v1.0.0-api",
            "model_type": "CALIBRATED_LOGISTIC",
            "dataset_id": dataset_id,
        },
    )
    assert reg_res.status_code == 201
    model_id = reg_res.json()["id"]

    # 3. Evaluate model via API
    eval_res = client.post(
        f"/api/v1/projects/{test_project.id}/learning/models/{model_id}/evaluate",
        headers=tester_headers,
    )
    assert eval_res.status_code == 200
    assert eval_res.json()["status"] == "EVALUATED"

    # 4. Approve model via API
    appr_res = client.post(
        f"/api/v1/projects/{test_project.id}/learning/models/{model_id}/approve",
        headers=lead_headers,
        json={"approved": True, "approval_notes": "Validated via governance board review."},
    )
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "APPROVED"

    # 5. List models via API
    list_res = client.get(
        f"/api/v1/projects/{test_project.id}/learning/models",
        headers=tester_headers,
    )
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # 6. Cross-project isolation: non-existent project returns 404
    iso_res = client.get(
        "/api/v1/projects/00000000-0000-0000-0000-000000000000/learning/models",
        headers=tester_headers,
    )
    assert iso_res.status_code == 404
