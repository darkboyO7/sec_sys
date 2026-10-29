"""
Comprehensive Deterministic Test Suite for Prompt 19:
Detection Quality, False-Positive Control & Evidence-Driven Intelligence.
"""

import hashlib
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.finding import (
    FindingValidationStatus,
    FindingLifecycleStatus,
    VulnerabilityFinding,
    ValidationTransition,
)
from app.models.assessment import (
    AssessmentJob,
    AssessmentFinding,
    FindingEvidence,
    FindingSeverity,
    FindingConfidence,
    AssessmentStatus,
)
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.base import utc_now
from app.services.finding_validation_service import (
    FindingValidationService,
    InvalidValidationTransitionError,
    ValidationAuthorizationError,
)
from app.services.detection_quality_service import DetectionQualityService
from app.services.validation_fixture_framework import (
    DeterministicFixtureFramework,
    PositiveExposedFixture,
    NegativeCleanFixture,
    UnavailableFixture,
    AmbiguousFixture,
    RemediatedFixture,
)
from app.services.finding_deduplication_service import FindingDeduplicationService
from app.services.learning_service import ModelGovernanceService


def test_validation_status_enum_and_allowed_transitions():
    """Verify all 9 epistemic validation states and deterministic FSM transitions."""
    expected_states = {
        "DETECTED",
        "EVIDENCE_PENDING",
        "EVIDENCE_SUPPORTED",
        "INDEPENDENTLY_REPRODUCED",
        "CONFIRMED_TRUE_POSITIVE",
        "CONFIRMED_FALSE_POSITIVE",
        "INCONCLUSIVE",
        "UNABLE_TO_VERIFY",
        "RESOLVED_AFTER_RETEST",
    }
    actual_states = {s.value for s in FindingValidationStatus}
    assert actual_states == expected_states

    # Valid transitions
    assert FindingValidationService.can_transition_validation(
        FindingValidationStatus.DETECTED, FindingValidationStatus.EVIDENCE_SUPPORTED
    )
    assert FindingValidationService.can_transition_validation(
        FindingValidationStatus.EVIDENCE_SUPPORTED, FindingValidationStatus.INDEPENDENTLY_REPRODUCED
    )
    assert FindingValidationService.can_transition_validation(
        FindingValidationStatus.INDEPENDENTLY_REPRODUCED, FindingValidationStatus.CONFIRMED_TRUE_POSITIVE
    )
    assert FindingValidationService.can_transition_validation(
        FindingValidationStatus.CONFIRMED_TRUE_POSITIVE, FindingValidationStatus.RESOLVED_AFTER_RETEST
    )
    assert FindingValidationService.can_transition_validation(
        FindingValidationStatus.EVIDENCE_SUPPORTED, FindingValidationStatus.CONFIRMED_FALSE_POSITIVE
    )

    # Invalid transitions
    assert not FindingValidationService.can_transition_validation(
        FindingValidationStatus.DETECTED, FindingValidationStatus.RESOLVED_AFTER_RETEST
    )
    assert not FindingValidationService.can_transition_validation(
        FindingValidationStatus.DETECTED, FindingValidationStatus.DETECTED
    )


def test_validation_transition_service_execution(db: Session, test_project: Project, lead_user: User):
    """Test legal transition updates finding and records immutable transition audit."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-test-trans-1",
        target_value="https://test.local",
        title="Missing Security Header",
        description="Strict-Transport-Security missing",
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.DETECTED,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        is_simulated=True,
    )
    db.add(finding)
    db.commit()

    updated = FindingValidationService.transition_validation_status(
        finding=finding,
        to_status=FindingValidationStatus.EVIDENCE_PENDING,
        validation_method="AUTOMATED_INGESTION",
        actor=lead_user,
        actor_role=ProjectRole.LEAD,
        reason="Awaiting supplementary scanner corroboration.",
        db=db,
    )
    db.commit()

    assert updated.validation_status == FindingValidationStatus.EVIDENCE_PENDING
    assert updated.validation_method == "AUTOMATED_INGESTION"

    transitions = (
        db.query(ValidationTransition)
        .filter(ValidationTransition.finding_id == finding.id)
        .all()
    )
    assert len(transitions) == 1
    assert transitions[0].from_status == FindingValidationStatus.DETECTED
    assert transitions[0].to_status == FindingValidationStatus.EVIDENCE_PENDING
    assert transitions[0].actor_id == lead_user.id


def test_validation_rbac_viewer_blocked(db: Session, test_project: Project, lead_user: User):
    """Viewer cannot alter finding validation states."""
    viewer = User(
        email="viewer-rbac@acme.local",
        hashed_password="pw",
        full_name="Read Only Viewer",
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    db.add(viewer)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-viewer-test",
        target_value="https://test.local",
        title="Info Exposure",
        description="Banner disclosure",
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.DETECTED,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.FIRM,
    )
    db.add(finding)
    db.commit()

    with pytest.raises(ValidationAuthorizationError):
        FindingValidationService.transition_validation_status(
            finding=finding,
            to_status=FindingValidationStatus.EVIDENCE_PENDING,
            validation_method="MANUAL",
            actor=viewer,
            actor_role=ProjectRole.VIEWER,
            reason="Attempt by viewer",
            db=db,
        )


def test_validation_rbac_false_positive_requires_lead(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
    lead_user: User,
    lead_headers: dict,
):
    """Only Project Lead or Admin can mark a finding as CONFIRMED_FALSE_POSITIVE."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-fp-rbac",
        target_value="https://test.local",
        title="CORS Misconfiguration",
        description="Permissive Access-Control-Allow-Origin",
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.EVIDENCE_SUPPORTED,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
    )
    db.add(finding)
    db.commit()

    # Tester attempts -> 403 Forbidden
    res_tester = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/validation",
        headers=tester_headers,
        json={
            "to_status": "CONFIRMED_FALSE_POSITIVE",
            "reason": "Host is behind an internal reverse proxy gateway.",
            "validation_method": "MANUAL_ANALYSIS",
        },
    )
    assert res_tester.status_code == 403

    # Lead attempts with valid justification -> 200 OK
    res_lead = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/validation",
        headers=lead_headers,
        json={
            "to_status": "CONFIRMED_FALSE_POSITIVE",
            "reason": "Host is behind an internal reverse proxy gateway with strict origins.",
            "validation_method": "SECURITY_LEAD_REVIEW",
        },
    )
    assert res_lead.status_code == 200
    data = res_lead.json()
    assert data["validation_status"] == "CONFIRMED_FALSE_POSITIVE"
    assert data["status"] == "FALSE_POSITIVE"


def test_false_positive_justification_minimum_length(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_headers: dict,
):
    """CONFIRMED_FALSE_POSITIVE requires a technical justification of at least 10 characters."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-justification-test",
        target_value="https://test.local",
        title="Open Redirect",
        description="Redirect parameter unvalidated",
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.EVIDENCE_SUPPORTED,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
    )
    db.add(finding)
    db.commit()

    # Too short (<10 chars) -> 400 Bad Request
    res_short = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/validation",
        headers=lead_headers,
        json={
            "to_status": "CONFIRMED_FALSE_POSITIVE",
            "reason": "not a bug",
            "validation_method": "MANUAL",
        },
    )
    assert res_short.status_code == 400


def test_cryptographic_evidence_required_for_confirmed_true_positive(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """Cannot mark finding as CONFIRMED_TRUE_POSITIVE without valid cryptographic evidence."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-evidence-required",
        target_value="https://test.local",
        title="SQL Injection",
        description="Error-based SQLi",
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.EVIDENCE_SUPPORTED,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.FIRM,
    )
    db.add(finding)
    db.commit()

    # Attempt without evidence -> fails
    with pytest.raises(InvalidValidationTransitionError) as exc:
        FindingValidationService.transition_validation_status(
            finding=finding,
            to_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
            validation_method="TEST",
            actor=lead_user,
            actor_role=ProjectRole.LEAD,
            reason="Confirmed by manual inspection without attaching evidence.",
            db=db,
        )
    assert "without valid, cryptographically hashed evidence" in str(exc.value.detail)

    # Attach verified observation with SHA-256 evidence
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://test.local",
        adapter_name="live_network_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    obs = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        canonical_finding_id=finding.id,
        title=finding.title,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        target_value="https://test.local",
    )
    db.add(obs)
    db.commit()

    payload_text = "HTTP/1.1 500 Syntax error in SQL query near SELECT * FROM users"
    ev = FindingEvidence(
        finding_id=obs.id,
        evidence_type="RAW_HTTP_RESPONSE",
        payload=payload_text,
        sha256_hash=hashlib.sha256(payload_text.encode("utf-8")).hexdigest(),
    )
    db.add(ev)
    db.commit()

    # Now attempt transition -> succeeds
    updated = FindingValidationService.transition_validation_status(
        finding=finding,
        to_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
        validation_method="CRYPTOGRAPHIC_EVIDENCE_ATTACHED",
        actor=lead_user,
        actor_role=ProjectRole.LEAD,
        reason="Cryptographic SQL execution evidence confirmed.",
        db=db,
    )
    db.commit()
    assert updated.validation_status == FindingValidationStatus.CONFIRMED_TRUE_POSITIVE
    assert updated.status == FindingLifecycleStatus.CONFIRMED


def test_ai_prediction_blocked_from_confirming_without_evidence(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """AI prediction cannot promote a finding to CONFIRMED_TRUE_POSITIVE without verified evidence."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-ai-guardrail",
        target_value="https://test.local",
        title="Remote Code Execution",
        description="Potential RCE",
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.EVIDENCE_SUPPORTED,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.FIRM,
    )
    db.add(finding)
    db.commit()

    with pytest.raises(InvalidValidationTransitionError) as exc:
        FindingValidationService.transition_validation_status(
            finding=finding,
            to_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
            validation_method="AI_ASSISTANT_PREDICTION",
            actor=lead_user,
            actor_role=ProjectRole.LEAD,
            reason="AI model classified this as high confidence exploit.",
            db=db,
            is_ai_generated=True,
        )
    assert "AI-generated predictions cannot confirm" in str(exc.value.detail)


def test_transient_failure_handling_fixture():
    """Unavailable target must produce UNABLE_TO_VERIFY, NEVER false positive or true positive."""
    res = DeterministicFixtureFramework.run_benchmark_scenario("unavailable")
    assert res["reported_validation_status"] == "UNABLE_TO_VERIFY"
    assert res["valid_failure_handling"] is True
    assert res["false_positives"] == 0
    assert res["true_positives"] == 0


def test_ambiguous_fixture_handling():
    """Inconsistent alternating responses must be classified as INCONCLUSIVE."""
    res = DeterministicFixtureFramework.run_benchmark_scenario("ambiguous")
    assert res["reported_validation_status"] == "INCONCLUSIVE"
    assert res["valid_ambiguity_handling"] is True


def test_retest_recurrence_detection(db: Session, test_project: Project):
    """Re-observing a previously resolved finding reopens it and flags recurrence_detected=True."""
    expected_fp = FindingDeduplicationService.compute_fingerprint(
        target_value="https://test.local/api",
        title="Missing CSRF Token",
    )
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint=expected_fp,
        target_value="https://test.local/api",
        title="Missing CSRF Token",
        description="State-changing POST lacks anti-CSRF token",
        status=FindingLifecycleStatus.VERIFIED_CLOSED,
        validation_status=FindingValidationStatus.RESOLVED_AFTER_RETEST,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        verified_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    member = db.query(ProjectMember).filter(ProjectMember.project_id == test_project.id).first()
    user_id = member.user_id if member else None

    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://test.local/api",
        adapter_name="live_network_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.COMPLETED,
        created_by_id=user_id,
    )
    db.add(job)
    db.commit()

    # New observation of the resolved finding occurs in subsequent scan
    raw_obs = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        title="Missing CSRF Token",
        description="State-changing POST lacks anti-CSRF token",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        target_value="https://test.local/api",
    )
    db.add(raw_obs)
    db.commit()

    payload_text = "POST /api/transfer without csrf token"
    ev = FindingEvidence(
        finding_id=raw_obs.id,
        evidence_type="HTTP_FORM",
        payload=payload_text,
        sha256_hash=hashlib.sha256(payload_text.encode("utf-8")).hexdigest(),
    )
    db.add(ev)
    db.commit()

    canonical = FindingDeduplicationService.ingest_job_findings(job=job, raw_findings=[raw_obs], db=db)
    db.commit()

    assert len(canonical) == 1
    reopened = canonical[0]
    assert reopened.id == finding.id
    assert reopened.recurrence_detected is True
    assert reopened.recurrence_count >= 1
    assert reopened.status == FindingLifecycleStatus.REOPENED
    assert reopened.validation_status == FindingValidationStatus.CONFIRMED_TRUE_POSITIVE


def test_cross_component_fingerprinting_deduplication(db: Session, test_project: Project):
    """Findings on distinct components produce distinct canonical records; identical findings merge."""
    member = db.query(ProjectMember).filter(ProjectMember.project_id == test_project.id).first()
    user_id = member.user_id if member else None

    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://test.local",
        adapter_name="passive_header_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.COMPLETED,
        created_by_id=user_id,
    )
    db.add(job)
    db.commit()

    raw1 = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        title="Missing HSTS",
        description="HSTS omitted",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        target_value="https://test.local/api/v1",
    )
    raw2 = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        title="Missing HSTS",
        description="HSTS omitted",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        target_value="https://test.local/admin",
    )
    db.add_all([raw1, raw2])
    db.commit()

    canonical = FindingDeduplicationService.ingest_job_findings(job=job, raw_findings=[raw1, raw2], db=db)
    db.commit()

    # Distinct targets (/api/v1 vs /admin) -> 2 separate canonical findings
    assert len(canonical) == 2
    assert canonical[0].fingerprint != canonical[1].fingerprint

    # Repeated scan of the first component merges into existing canonical finding
    raw1_repeat = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        title="Missing HSTS",
        description="HSTS omitted",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        target_value="https://test.local/api/v1",
    )
    db.add(raw1_repeat)
    db.commit()

    canonical_repeat = FindingDeduplicationService.ingest_job_findings(job=job, raw_findings=[raw1_repeat], db=db)
    db.commit()
    assert len(canonical_repeat) == 1
    assert canonical_repeat[0].id == canonical[0].id
    assert canonical_repeat[0].occurrence_count >= 2


def test_deterministic_fixture_ground_truth_evaluation():
    """Positive exposed fixture achieves 1.0 precision and recall against ground truth."""
    res_pos = DeterministicFixtureFramework.run_benchmark_scenario("positive_exposed")
    assert res_pos["precision"] == 1.0
    assert res_pos["recall"] == 1.0
    assert res_pos["false_positives"] == 0
    assert res_pos["true_positives"] == 6

    res_neg = DeterministicFixtureFramework.run_benchmark_scenario("negative_clean")
    assert res_neg["precision"] == 1.0
    assert res_neg["false_positive_rate"] == 0.0
    assert res_neg["false_positives"] == 0
    assert res_neg["true_negatives"] == 6


def test_honest_denominator_calculations(db: Session, test_project: Project):
    """FPR denominator strictly reflects reviewed findings; discloses sample sizes."""
    # Create 3 unreviewed findings
    for i in range(3):
        f = VulnerabilityFinding(
            project_id=test_project.id,
            fingerprint=f"fp-denom-unrev-{i}",
            target_value="https://test.local",
            title=f"Unreviewed Issue {i}",
            description="Pending analyst review",
            status=FindingLifecycleStatus.DETECTED,
            validation_status=FindingValidationStatus.DETECTED,
            severity=FindingSeverity.LOW,
            confidence=FindingConfidence.TENTATIVE,
        )
        db.add(f)
    db.commit()

    # Zero reviewed findings -> FPR is 0.0 with honest denominator string
    metrics = DetectionQualityService.calculate_project_quality_metrics(test_project.id, db)
    assert metrics["sample_sizes"]["reviewed_findings"] == 0
    assert metrics["metrics"]["confirmed_false_positive_rate"] == 0.0
    assert "0 / 0" in metrics["disclosed_denominators"]["confirmed_false_positive_rate"]

    # Mark 1 finding as reviewed and CONFIRMED_FALSE_POSITIVE
    f0 = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.fingerprint == "fp-denom-unrev-0").first()
    f0.validation_status = FindingValidationStatus.CONFIRMED_FALSE_POSITIVE
    f0.reviewed_at = utc_now()
    db.commit()

    updated_metrics = DetectionQualityService.calculate_project_quality_metrics(test_project.id, db)
    assert updated_metrics["sample_sizes"]["reviewed_findings"] == 1
    assert updated_metrics["metrics"]["confirmed_false_positive_rate"] == 1.0
    assert updated_metrics["disclosed_denominators"]["confirmed_false_positive_rate"] == "1 / 1"


def test_quality_overview_api(client: TestClient, test_project: Project, tester_headers: dict):
    """GET /projects/{project_id}/quality/overview returns comprehensive metrics and warnings."""
    res = client.get(
        f"/api/v1/projects/{test_project.id}/quality/overview",
        headers=tester_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["project_id"] == test_project.id
    assert "metrics" in data
    assert "sample_sizes" in data
    assert "disclosed_denominators" in data
    assert "validation_status_distribution" in data
    assert "quality_warnings" in data


def test_fixture_benchmarks_api(client: TestClient, test_project: Project, tester_headers: dict):
    """GET /projects/{project_id}/quality/fixtures executes benchmarks against all 4 testbeds."""
    res = client.get(
        f"/api/v1/projects/{test_project.id}/quality/fixtures",
        headers=tester_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["framework_version"] == DeterministicFixtureFramework.VERSION
    scenarios = data["benchmark_scenarios"]
    assert "positive_exposed" in scenarios
    assert "negative_clean" in scenarios
    assert "unavailable" in scenarios
    assert "ambiguous" in scenarios
    assert scenarios["positive_exposed"]["precision"] == 1.0
    assert scenarios["unavailable"]["reported_validation_status"] == "UNABLE_TO_VERIFY"


def test_finding_provenance_cryptographic_verification_api(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
):
    """Provenance endpoint verifies cryptographic integrity of raw evidence payloads."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-crypto-prov-api",
        target_value="https://test.local",
        title="Information Leak",
        description="Server header reveals Linux kernel",
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.EVIDENCE_SUPPORTED,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.FIRM,
    )
    db.add(finding)
    db.commit()

    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://test.local",
        adapter_name="live_network_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.COMPLETED,
        created_by_id=tester_user.id,
    )
    db.add(job)
    db.commit()

    obs = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        canonical_finding_id=finding.id,
        title=finding.title,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.FIRM,
        target_value="https://test.local",
    )
    db.add(obs)
    db.commit()

    payload_text = "Server: Apache/2.4.41 (Ubuntu)"
    sha256 = hashlib.sha256(payload_text.encode("utf-8")).hexdigest()
    ev = FindingEvidence(
        finding_id=obs.id,
        evidence_type="RAW_HEADER",
        payload=payload_text,
        sha256_hash=sha256,
    )
    db.add(ev)
    db.commit()

    res = client.get(
        f"/api/v1/projects/{test_project.id}/quality/findings/{finding.id}/provenance",
        headers=tester_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["finding_id"] == finding.id
    assert data["cryptographic_integrity_verified"] is True
    assert data["observations"][0]["evidence_items"][0]["is_cryptographically_valid"] is True
    assert data["observations"][0]["evidence_items"][0]["recorded_sha256"] == sha256


def test_learning_governance_excludes_unverified_and_inconclusive(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """ModelGovernanceService.curate_dataset excludes unverified, inconclusive, and unable_to_verify findings."""
    # 1. Unverified finding (EVIDENCE_PENDING, DETECTED)
    f_unverified = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-learn-unver",
        target_value="https://test.local",
        title="Unverified CVE-2024-1111",
        description="Unverified",
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.EVIDENCE_PENDING,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.TENTATIVE,
    )
    # 2. Inconclusive finding
    f_inconclusive = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-learn-inconc",
        target_value="https://test.local",
        title="Inconclusive Vulnerability",
        description="Flaky observations",
        status=FindingLifecycleStatus.INCONCLUSIVE,
        validation_status=FindingValidationStatus.INCONCLUSIVE,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.TENTATIVE,
    )
    # 3. Confirmed finding
    f_confirmed = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-learn-conf",
        target_value="https://test.local",
        title="Confirmed True Positive CVE-2024-2222",
        description="Proven vulnerability",
        status=FindingLifecycleStatus.CONFIRMED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=False,
    )
    db.add_all([f_unverified, f_inconclusive, f_confirmed])
    db.commit()

    dataset = ModelGovernanceService.curate_dataset(
        project_id=test_project.id,
        name="governed_training_set",
        version="v1.0.0",
        user=lead_user,
        db=db,
        allow_synthetic_benchmark=False,
    )

    finding_record_ids = [r.source_entity_id for r in dataset.records if r.source_entity_type == "finding"]
    assert f_confirmed.id in finding_record_ids
    assert f_unverified.id not in finding_record_ids
    assert f_inconclusive.id not in finding_record_ids


def test_tenant_isolation_on_quality_and_validation(
    client: TestClient,
    db: Session,
    test_project: Project,
    outsider_headers: dict,
):
    """Users outside project/organization cannot access detection quality or transition findings."""
    res_overview = client.get(
        f"/api/v1/projects/{test_project.id}/quality/overview",
        headers=outsider_headers,
    )
    assert res_overview.status_code in (403, 404)

    res_val = client.post(
        f"/api/v1/projects/{test_project.id}/findings/some-id/validation",
        headers=outsider_headers,
        json={
            "to_status": "CONFIRMED_TRUE_POSITIVE",
            "reason": "Outsider attempt",
        },
    )
    assert res_val.status_code in (403, 404)
