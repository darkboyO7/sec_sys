import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
    ValidationOutcome,
)
from app.models.assessment import (
    AssessmentJob,
    AssessmentFinding,
    AssessmentStatus,
    FindingSeverity,
    FindingConfidence,
)
from app.services.finding_validation_service import FindingValidationService
from app.services.finding_deduplication_service import FindingDeduplicationService
from app.models.base import utc_now


def test_evidence_quality_score_calculation(db: Session, test_project: Project, tester_user: User):
    """Verify objective calculation of evidence quality score under various signals."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-test-quality-1",
        target_value="https://test.local",
        title="SQL Injection",
        description="High risk SQLi",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        has_contradictions=False,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    # 1. Baseline certain finding
    score = FindingValidationService.calculate_evidence_quality_score(finding, db)
    assert score == 1.0

    # 2. Contradiction penalty
    finding.has_contradictions = True
    score_contra = FindingValidationService.calculate_evidence_quality_score(finding, db)
    assert score_contra < 1.0
    assert score_contra == 0.65

    # 3. Tentative confidence penalty
    finding.has_contradictions = False
    finding.confidence = FindingConfidence.TENTATIVE
    score_tentative = FindingValidationService.calculate_evidence_quality_score(finding, db)
    assert score_tentative == 0.75

    # 4. Stale evidence decay (> 30 days)
    finding.confidence = FindingConfidence.CERTAIN
    finding.last_observed_at = utc_now() - timedelta(days=45)
    score_stale = FindingValidationService.calculate_evidence_quality_score(finding, db)
    assert score_stale == 0.8


def test_analyst_validate_finding_confirmed(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
):
    """Test validating a finding as CONFIRMED updates status, quality score, and audit record."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-test-val-conf",
        target_value="https://test.local",
        title="Reflected XSS",
        description="XSS in query parameter",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        is_simulated=True,
    )
    db.add(finding)
    db.commit()

    response = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/validate",
        headers=tester_headers,
        json={
            "validation_outcome": "CONFIRMED",
            "analyst_review_notes": "Verified payload execution via headless browser.",
            "evidence_quality_score": 0.95,
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "CONFIRMED"
    assert data["validation_outcome"] == "CONFIRMED"
    assert data["evidence_quality_score"] == 0.95
    assert data["analyst_review_notes"] == "Verified payload execution via headless browser."
    assert data["reviewed_by_id"] == tester_user.id
    assert data["reviewed_at"] is not None


def test_analyst_validate_false_positive_rbac(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
    lead_user: User,
    lead_headers: dict,
):
    """Test that validating as FALSE_POSITIVE requires Project LEAD role."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-test-val-fp",
        target_value="https://test.local",
        title="Path Traversal",
        description="Apparent directory traversal",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        is_simulated=True,
    )
    db.add(finding)
    db.commit()

    # Regular member/tester attempts to validate as FALSE_POSITIVE -> 403 Forbidden
    res_forbidden = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/validate",
        headers=tester_headers,
        json={
            "validation_outcome": "FALSE_POSITIVE",
            "analyst_review_notes": "Input is sanitized by proxy.",
        },
    )
    assert res_forbidden.status_code == 403

    # Project Lead validates as FALSE_POSITIVE -> 200 OK
    res_ok = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/validate",
        headers=lead_headers,
        json={
            "validation_outcome": "FALSE_POSITIVE",
            "analyst_review_notes": "Input is confirmed sanitized by proxy WAF rule #4012.",
        },
    )
    assert res_ok.status_code == 200, res_ok.text
    data = res_ok.json()
    assert data["status"] == "FALSE_POSITIVE"
    assert data["validation_outcome"] == "FALSE_POSITIVE"


def test_recurrence_detection_on_reopening(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify that re-observing a previously closed/remediated finding triggers recurrence detection."""
    # Create canonical finding in VERIFIED_CLOSED state
    fp = FindingDeduplicationService.compute_fingerprint(
        target_value="https://test.local/login",
        vuln_id="CWE-798",
        title="Hardcoded Credentials in Script",
    )
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint=fp,
        target_value="https://test.local/login",
        title="Hardcoded Credentials in Script",
        description="Exposed test credentials in client script",
        status=FindingLifecycleStatus.VERIFIED_CLOSED,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        recurrence_detected=False,
        recurrence_count=0,
    )
    db.add(finding)
    db.commit()

    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://test.local/login",
        adapter_name="local_fixture_adapter",
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
        status=AssessmentStatus.RUNNING,
        created_by_id=tester_user.id,
    )
    db.add(job)
    db.commit()

    raw_finding = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        title="Hardcoded Credentials in Script",
        target_value="https://test.local/login",
        vuln_id="CWE-798",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        reproduction_steps="View script tag",
    )
    db.add(raw_finding)
    db.commit()

    # Ingest findings
    FindingDeduplicationService.ingest_job_findings(
        job=job,
        raw_findings=[raw_finding],
        db=db,
    )
    db.commit()

    db.refresh(finding)
    assert finding.status == FindingLifecycleStatus.REOPENED
    assert finding.recurrence_detected is True
    assert finding.recurrence_count == 1
