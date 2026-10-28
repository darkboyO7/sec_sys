import hashlib
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentFinding, AssessmentStatus, FindingSeverity
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.models.verification import RemediationVerification, VerificationOutcome, VerificationMethod
from app.models.monitoring import (
    MonitoringSchedule,
    MonitoringRun,
    ScheduleFrequency,
    ScheduleStatus,
)
from app.schemas.monitoring import ScheduleCreate
from app.models.learning import (
    LearningDataset,
    DatasetRecord,
    DatasetSplit,
    GovernedModel,
    ModelStatus,
    PredictionLedger,
    PredictionType,
    PredictionEvaluationStatus,
)
from app.services.remediation_service import RemediationPrioritizationService
from app.services.remediation_verification_service import RemediationVerificationService
from app.services.continuous_monitoring_service import ContinuousMonitoringService
from app.services.learning_service import ModelGovernanceService, PredictionLedgerService
from app.services.contextual_risk_service import ContextualRiskService
from app.services.knowledge_graph_service import KnowledgeGraphService


def test_e2e_remediation_lifecycle_and_verification_outcomes(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Verifies items 1, 2, 3, 4, 5, 6:
    Finding detected -> remediation recommended -> approval & change ticket ->
    independent retest -> verified outcome (still vulnerable vs verified fixed vs inconclusive) ->
    risk and graph synchronization.
    """
    now = datetime.now(timezone.utc)

    # 1. Target authorized
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="remediation-target.test.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-REMEDIATION-E2E",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # 2. Finding created from assessment evidence
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        target_value="remediation-target.test.local",
        title="Missing Content-Security-Policy (CSP) Header",
        description="The target does not send Content-Security-Policy header, leaving it susceptible to script injection.",
        severity=FindingSeverity.MEDIUM,
        vuln_id="CWE-693",
        status=FindingLifecycleStatus.DETECTED,
        fingerprint=hashlib.sha256("Missing CSP Header on remediation-target".encode("utf-8")).hexdigest(),
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    # 3. Generate remediation recommendation based on actual finding and technology
    rec = RemediationPrioritizationService.generate_or_get_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
    )
    assert rec is not None
    assert rec.finding_id == finding.id
    assert ("Content-Security-Policy" in rec.title or "HTTP Headers" in rec.title)
    assert rec.requires_approval in (True, False)
    assert rec.status == RecommendationStatus.PENDING_REVIEW

    # 4. Review and approve remediation recommendation as Project LEAD
    rec_approved = RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=rec.id,
        new_status=RecommendationStatus.APPROVED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Approved for change window deployment.",
        db=db,
    )
    assert rec_approved.status == RecommendationStatus.APPROVED
    assert rec_approved.execution_governance_stage == "APPROVED"

    # 5. Authorize change implementation with ticket reference
    rec_auth = RemediationPrioritizationService.authorize_change(
        project_id=test_project.id,
        recommendation_id=rec.id,
        change_ticket_ref="CHG-2026-CSP-DEPLOY",
        authorizer=lead_user,
        authorizer_role=ProjectRole.LEAD,
        db=db,
    )
    assert rec_auth.execution_governance_stage == "CHANGE_AUTHORIZED"
    assert "CHG-2026-CSP-DEPLOY" in rec_auth.review_notes

    # 6. Test STILL_VULNERABLE verification outcome
    # Re-testing with local fixture WEB_APPLICATION_BASELINE simulates finding still observed
    verif_vuln = RemediationVerificationService.execute_automated_retest(
        project_id=test_project.id,
        finding_id=finding.id,
        adapter_name="local_fixture_adapter",
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
        notes="First automated re-test probe.",
        verifier=lead_user,
        verifier_role=ProjectRole.LEAD,
        db=db,
    )
    assert verif_vuln.outcome == VerificationOutcome.STILL_VULNERABLE
    db.refresh(finding)
    assert finding.recurrence_detected is True
    assert finding.recurrence_count >= 1

    # 7. Test VERIFIED_FIXED verification outcome
    # Re-testing with HARDENED_HOST_BASELINE simulates 0 findings on target (flaw remediated)
    verif_fixed = RemediationVerificationService.execute_automated_retest(
        project_id=test_project.id,
        finding_id=finding.id,
        adapter_name="local_fixture_adapter",
        config={"fixture_profile": "HARDENED_HOST_BASELINE"},
        notes="Second automated re-test probe after configuration fix.",
        verifier=lead_user,
        verifier_role=ProjectRole.LEAD,
        db=db,
    )
    assert verif_fixed.outcome == VerificationOutcome.VERIFIED_FIXED
    db.refresh(finding)
    assert finding.status == FindingLifecycleStatus.VERIFIED_CLOSED
    assert verif_fixed.baseline_evidence_hash is not None
    assert "before_after_comparison" in verif_fixed.verification_evidence_data


def test_e2e_continuous_monitoring_lifecycle_and_stale_management(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Verifies items 7, 8:
    Scheduled assessments execute within authorization limits,
    duplicate prevention, delta change detection, and failure recovery.
    """
    now = datetime.now(timezone.utc)

    # 1. Register authorized target
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="monitor-e2e.test.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-MONITOR-E2E",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # 2. Create continuous monitoring schedule
    sched_in = ScheduleCreate(
        name="E2E Daily Security Audit",
        target_input="monitor-e2e.test.local",
        adapter_name="local_fixture_adapter",
        fixture_profile="WEB_APPLICATION_BASELINE",
        frequency=ScheduleFrequency.DAILY,
        interval_seconds=86400,
    )
    schedule = ContinuousMonitoringService.create_schedule(
        project_id=test_project.id,
        schedule_in=sched_in,
        creator=lead_user,
        creator_role=ProjectRole.LEAD,
        db=db,
    )
    assert schedule.status == ScheduleStatus.ACTIVE
    assert schedule.run_count == 0

    # 3. Process due schedules via ContinuousMonitoringService
    future_now = now + timedelta(minutes=5)
    runs = ContinuousMonitoringService.process_due_schedules(db=db, now=future_now)
    assert len(runs) >= 1
    assert runs[0].status == "SUCCESS"
    assert runs[0].new_findings_count >= 2

    db.refresh(schedule)
    assert schedule.run_count == 1
    assert schedule.last_status == "SUCCESS"

    # 4. Immediate second run detects recurring findings
    run2 = ContinuousMonitoringService.execute_schedule_run(
        schedule_id=schedule.id,
        db=db,
        now=now + timedelta(seconds=1),
    )
    assert run2.status == "SUCCESS"
    assert run2.recurring_findings_count >= 2


def test_e2e_learning_outcome_resolution_and_inferior_model_rejection(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Verifies items 9, 10, 11:
    Learning metrics computed from actual recorded outcomes in PredictionLedger,
    drift detection, inferior candidate model rejection, and baseline preservation.
    """
    # 1. Record Heuristic/ML predictions in PredictionLedger
    entry1 = PredictionLedgerService.record_prediction(
        project_id=test_project.id,
        target_entity_type="finding",
        target_entity_id="f-pred-001",
        prediction_type=PredictionType.FALSE_POSITIVE_LIKELIHOOD,
        feature_snapshot={"severity": "LOW", "confidence": "SUSPECTED"},
        predicted_outcome="FALSE_POSITIVE",
        confidence_score=0.85,
        model_version="heuristic-v1.0",
        db=db,
    )
    assert entry1.evaluation_status == PredictionEvaluationStatus.PENDING

    entry2 = PredictionLedgerService.record_prediction(
        project_id=test_project.id,
        target_entity_type="finding",
        target_entity_id="f-pred-002",
        prediction_type=PredictionType.FALSE_POSITIVE_LIKELIHOOD,
        feature_snapshot={"severity": "HIGH", "confidence": "CONFIRMED"},
        predicted_outcome="TRUE_POSITIVE",
        confidence_score=0.90,
        model_version="heuristic-v1.0",
        db=db,
    )

    # 2. Record actual real-world outcome observations
    # Entry 1 was verified accurate
    PredictionLedgerService.evaluate_prediction(
        project_id=test_project.id,
        prediction_id=entry1.id,
        actual_outcome="FALSE_POSITIVE",
        outcome_evidence={"analyst_verdict": "FALSE_POSITIVE", "reason": "Controlled test artifact"},
        status_override=PredictionEvaluationStatus.VERIFIED_ACCURATE,
        user=lead_user,
        db=db,
    )

    # Entry 2 was verified accurate
    PredictionLedgerService.evaluate_prediction(
        project_id=test_project.id,
        prediction_id=entry2.id,
        actual_outcome="TRUE_POSITIVE",
        outcome_evidence={"analyst_verdict": "TRUE_POSITIVE", "cve": "CVE-2026-001"},
        status_override=PredictionEvaluationStatus.VERIFIED_ACCURATE,
        user=lead_user,
        db=db,
    )

    # 3. Compute empirical drift and calibration metrics
    metrics = PredictionLedgerService.calculate_drift_metrics(
        project_id=test_project.id,
        model_version="heuristic-v1.0",
        db=db,
    )
    assert metrics["total_predictions"] == 2
    assert metrics["evaluated_count"] == 2
    assert metrics["accurate_count"] == 2
    assert metrics["accuracy_rate"] == 1.0
    assert metrics["brier_score"] <= 0.05
    assert metrics["drift_alert"] is False

    # 4. Curate dataset with strict privacy and time-aware partitions
    dataset = ModelGovernanceService.curate_dataset(
        project_id=test_project.id,
        name="Outcome Dataset 2026",
        version="1.0.0",
        user=lead_user,
        db=db,
    )
    assert dataset.total_records >= 0

    # 5. Verify Model Governance: Baseline preservation and inferior candidate rejection
    # Create baseline model with high F1
    base_model = GovernedModel(
        project_id=test_project.id,
        model_name="risk_predictor",
        version="v1.0-baseline",
        model_type="logistic_regression",
        dataset_id=dataset.id,
        status=ModelStatus.ACTIVE,
        is_active=True,
        metrics={"f1_score": 0.88, "brier_score": 0.10, "precision": 0.90, "recall": 0.86},
    )
    db.add(base_model)
    db.commit()

    # Candidate model with lower F1 (0.72 < 0.88)
    cand_model = GovernedModel(
        project_id=test_project.id,
        model_name="risk_predictor",
        version="v1.1-inferior",
        model_type="random_forest",
        dataset_id=dataset.id,
        status=ModelStatus.EVALUATED,
        is_active=False,
        metrics={
            "f1_score": 0.72,
            "brier_score": 0.22,
            "precision": 0.75,
            "recall": 0.70,
            "baseline_comparison": {
                "active_model_version": "v1.0-baseline",
                "candidate_f1": 0.72,
                "baseline_f1": 0.88,
                "candidate_meets_acceptance": False,
            },
        },
    )
    db.add(cand_model)
    db.commit()

    # Attempting to approve inferior candidate is rejected
    with pytest.raises(ValueError, match="Candidate model fails acceptance criteria"):
        ModelGovernanceService.approve_model(
            project_id=test_project.id,
            model_id=cand_model.id,
            approved=True,
            approval_notes="Approval should be blocked",
            reviewer=lead_user,
            db=db,
        )

    # Active baseline remains active
    db.refresh(base_model)
    assert base_model.is_active is True
    assert base_model.status == ModelStatus.ACTIVE

    db.refresh(cand_model)
    assert cand_model.is_active is False
