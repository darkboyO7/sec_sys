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
    PredictionType,
    PredictionEvaluationStatus,
    LearningDataset,
    DatasetRecord,
    GovernedModel,
    PredictionLedger,
)
from app.services.learning_service import ModelGovernanceService, PredictionLedgerService
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


def test_phase19_1_prediction_ledger_service_lifecycle(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Validate the persistent prediction ledger service lifecycle:
    - Recording predictions with feature snapshot sanitization.
    - Status evaluation against real observed outcomes.
    - Calibration & Brier score calculations.
    - Invalidation governance.
    """
    # 1. Record a prediction with sensitive tokens in feature snapshot
    raw_features = {
        "cve": "CVE-2023-12345",
        "service": "https://user:secretpass@10.0.0.1/api",
        "auth_header": "Bearer tok_abcdef123456",
        "open_ports": [80, 443],
    }

    pred_entry = PredictionLedgerService.record_prediction(
        project_id=test_project.id,
        target_entity_type="finding",
        target_entity_id="f-test-001",
        prediction_type=PredictionType.FALSE_POSITIVE_LIKELIHOOD,
        predicted_outcome="FALSE_POSITIVE",
        confidence_score=0.88,
        feature_snapshot=raw_features,
        model_version="heuristic-classifier-v1",
        limitations="Trained on static header signatures only",
        decision_action_taken="DEFERRED_PRIORITY",
        actor_id=lead_user.id,
        db=db,
    )

    assert pred_entry.id is not None
    assert pred_entry.evaluation_status == PredictionEvaluationStatus.PENDING
    assert pred_entry.predicted_outcome == "FALSE_POSITIVE"
    assert pred_entry.confidence_score == 0.88

    # Verify sensitive data was sanitized in feature snapshot
    saved_features = pred_entry.feature_snapshot
    assert "secretpass" not in str(saved_features)
    assert "tok_abcdef123456" not in str(saved_features)
    assert "[AUTH_SCRUBBED]" in str(saved_features) or "[SCRUBBED]" in str(saved_features)

    # 2. Evaluate prediction with matching outcome -> VERIFIED_ACCURATE
    evaluated = PredictionLedgerService.evaluate_prediction(
        prediction_id=pred_entry.id,
        project_id=test_project.id,
        actual_outcome="FALSE_POSITIVE",
        outcome_evidence={"analyst_triage": "Confirmed header is not active in production."},
        user=lead_user,
        db=db,
    )
    assert evaluated.evaluation_status == PredictionEvaluationStatus.VERIFIED_ACCURATE
    assert evaluated.actual_outcome == "FALSE_POSITIVE"
    assert evaluated.evaluated_at is not None

    # 3. Attempting to re-evaluate raises ValueError
    with pytest.raises(ValueError, match="already been finalized"):
        PredictionLedgerService.evaluate_prediction(
            prediction_id=pred_entry.id,
            project_id=test_project.id,
            actual_outcome="CONFIRMED",
            db=db,
        )

    # 4. Record a numeric prediction and evaluate with tolerance
    num_pred = PredictionLedgerService.record_prediction(
        project_id=test_project.id,
        target_entity_type="remediation",
        target_entity_id="rem-test-001",
        prediction_type=PredictionType.REMEDIATION_EFFORT_HOURS,
        predicted_outcome="5.0",
        confidence_score=0.75,
        feature_snapshot={"component": "openssl_upgrade"},
        model_version="effort-estimator-v1",
        actor_id=lead_user.id,
        db=db,
    )
    # Outcome 5.5 is within 20% tolerance of 5.0 -> accurate
    eval_num = PredictionLedgerService.evaluate_prediction(
        prediction_id=num_pred.id,
        project_id=test_project.id,
        actual_outcome="5.5",
        user=lead_user,
        db=db,
    )
    assert eval_num.evaluation_status == PredictionEvaluationStatus.VERIFIED_ACCURATE

    # 5. Record another prediction and invalidate it
    inval_pred = PredictionLedgerService.record_prediction(
        project_id=test_project.id,
        target_entity_type="asset",
        target_entity_id="ast-test-001",
        prediction_type=PredictionType.EXPLOITATION_PROBABILITY,
        predicted_outcome="0.95",
        confidence_score=0.90,
        feature_snapshot={"ip": "10.0.0.5"},
        actor_id=lead_user.id,
        db=db,
    )
    invalidated = PredictionLedgerService.invalidate_prediction(
        prediction_id=inval_pred.id,
        project_id=test_project.id,
        reason="Target asset was decommissioned during evaluation window.",
        user=lead_user,
        db=db,
    )
    assert invalidated.evaluation_status == PredictionEvaluationStatus.INVALIDATED
    assert "decommissioned" in invalidated.invalidation_reason

    # 6. Verify drift and calibration metrics
    drift = PredictionLedgerService.calculate_drift_metrics(
        project_id=test_project.id,
        db=db,
    )
    assert drift["total_predictions"] >= 3
    assert drift["evaluated_count"] >= 2
    assert drift["accuracy_rate"] == 1.0  # Both evaluated predictions were accurate
    assert drift["drift_alert"] is False
    assert drift["status"] == "STABLE"


def test_phase19_1_prediction_ledger_api_endpoints(
    client: TestClient,
    test_project: Project,
    lead_headers: dict,
    tester_headers: dict,
):
    """Verify REST API endpoints for recording, listing, evaluating, and invalidating predictions."""
    # 1. Record prediction via API
    pred_payload = {
        "target_entity_type": "finding",
        "target_entity_id": "finding-uuid-001",
        "prediction_type": "FALSE_POSITIVE_LIKELIHOOD",
        "predicted_outcome": "FALSE_POSITIVE",
        "confidence_score": 0.85,
        "feature_snapshot": {"cve": "CVE-2024-0001", "vector": "NETWORK"},
        "model_version": "heuristic-v1.0",
        "limitations": "Evaluated against local policy rules",
        "decision_action_taken": "MANUAL_REVIEW_FLAGGED",
    }
    create_res = client.post(
        f"/api/v1/projects/{test_project.id}/learning/predictions",
        headers=tester_headers,
        json=pred_payload,
    )
    assert create_res.status_code == 201
    pred_data = create_res.json()
    pred_id = pred_data["id"]
    assert pred_data["evaluation_status"] == "PENDING"
    assert pred_data["confidence_score"] == 0.85

    # 2. List predictions via API with filters
    list_res = client.get(
        f"/api/v1/projects/{test_project.id}/learning/predictions?target_entity_type=finding",
        headers=tester_headers,
    )
    assert list_res.status_code == 200
    items = list_res.json()
    assert len(items) >= 1
    assert any(p["id"] == pred_id for p in items)

    # 3. Evaluate prediction via API
    eval_res = client.post(
        f"/api/v1/projects/{test_project.id}/learning/predictions/{pred_id}/evaluate",
        headers=tester_headers,
        json={
            "actual_outcome": "FALSE_POSITIVE",
            "outcome_evidence": {"source": "analyst_verification"},
            "notes": "Verified by security analyst",
        },
    )
    assert eval_res.status_code == 200
    assert eval_res.json()["evaluation_status"] == "VERIFIED_ACCURATE"
    assert eval_res.json()["actual_outcome"] == "FALSE_POSITIVE"

    # 4. Record second prediction and invalidate it
    pred2_res = client.post(
        f"/api/v1/projects/{test_project.id}/learning/predictions",
        headers=tester_headers,
        json={
            "target_entity_type": "asset",
            "target_entity_id": "asset-uuid-002",
            "prediction_type": "EXPLOITATION_PROBABILITY",
            "predicted_outcome": "HIGH",
            "confidence_score": 0.60,
            "feature_snapshot": {"ports": [22]},
        },
    )
    assert pred2_res.status_code == 201
    pred2_id = pred2_res.json()["id"]

    inval_res = client.post(
        f"/api/v1/projects/{test_project.id}/learning/predictions/{pred2_id}/invalidate",
        headers=lead_headers,
        json={"reason": "Asset excluded from project scope after scan"},
    )
    assert inval_res.status_code == 200
    assert inval_res.json()["evaluation_status"] == "INVALIDATED"

    # 5. Get drift metrics via API
    drift_res = client.get(
        f"/api/v1/projects/{test_project.id}/learning/predictions/drift",
        headers=tester_headers,
    )
    assert drift_res.status_code == 200
    drift_data = drift_res.json()
    assert "accuracy_rate" in drift_data
    assert "brier_score" in drift_data
    assert "status" in drift_data


def test_phase19_inferior_candidate_rejected_and_baseline_preserved(
    db,
    test_project: Project,
    lead_user: User,
):
    # 1. Curate dataset
    dataset = LearningDataset(
        project_id=test_project.id,
        name="Baseline Test Dataset",
        version="1.0.0",
        dataset_hash="hash123",
        total_records=10,
        train_count=6,
        val_count=2,
        test_count=2,
    )
    db.add(dataset)
    db.commit()

    # Add test records
    r1 = DatasetRecord(
        dataset_id=dataset.id,
        split=DatasetSplit.TEST,
        source_entity_type="finding",
        source_entity_id="f-1",
        features={"severity": "HIGH"},
        label="TRUE_POSITIVE",
        provenance_digest="dig1",
    )
    r2 = DatasetRecord(
        dataset_id=dataset.id,
        split=DatasetSplit.TEST,
        source_entity_type="finding",
        source_entity_id="f-2",
        features={"severity": "LOW"},
        label="FALSE_POSITIVE",
        provenance_digest="dig2",
    )
    db.add_all([r1, r2])
    db.commit()

    # 2. Register, evaluate, approve, and activate Baseline Model A
    model_a = ModelGovernanceService.register_model(
        project_id=test_project.id,
        model_name="vuln_classifier",
        version="1.0.0",
        model_type="heuristic_classifier",
        dataset_id=dataset.id,
        hyperparameters={},
        actor=lead_user,
        db=db,
    )
    ModelGovernanceService.evaluate_model(project_id=test_project.id, model_id=model_a.id, db=db)
    ModelGovernanceService.approve_model(
        project_id=test_project.id,
        model_id=model_a.id,
        approved=True,
        approval_notes="Approved baseline",
        reviewer=lead_user,
        db=db,
    )
    ModelGovernanceService.activate_model(project_id=test_project.id, model_id=model_a.id, actor=lead_user, db=db)
    db.refresh(model_a)
    assert model_a.is_active is True
    base_f1 = model_a.metrics["f1_score"]

    # 3. Register Candidate Model B
    model_b = ModelGovernanceService.register_model(
        project_id=test_project.id,
        model_name="vuln_classifier",
        version="1.1.0-cand",
        model_type="heuristic_classifier",
        dataset_id=dataset.id,
        hyperparameters={},
        actor=lead_user,
        db=db,
    )
    ModelGovernanceService.evaluate_model(project_id=test_project.id, model_id=model_b.id, db=db)
    db.refresh(model_b)

    # Artificially set candidate metrics lower than baseline to test rejection gate
    m = dict(model_b.metrics)
    m["f1_score"] = round(base_f1 - 0.20, 4)
    m["baseline_comparison"]["candidate_f1"] = m["f1_score"]
    m["baseline_comparison"]["candidate_meets_acceptance"] = False
    model_b.metrics = m
    db.commit()

    # 4. Attempting to approve inferior candidate raises ValueError and rejects model
    with pytest.raises(ValueError, match="Candidate model fails acceptance criteria"):
        ModelGovernanceService.approve_model(
            project_id=test_project.id,
            model_id=model_b.id,
            approved=True,
            approval_notes="Should fail acceptance",
            reviewer=lead_user,
            db=db,
        )

    # 5. Baseline Model A remains active and untouched!
    db.refresh(model_a)
    assert model_a.is_active is True
    assert model_a.status == ModelStatus.ACTIVE

    db.refresh(model_b)
    assert model_b.is_active is False
    assert model_b.status == ModelStatus.EVALUATED
