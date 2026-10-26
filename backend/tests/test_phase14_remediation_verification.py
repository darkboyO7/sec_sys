import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
)
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.verification import (
    RemediationVerification,
    VerificationOutcome,
    VerificationMethod,
)
from app.services.remediation_verification_service import RemediationVerificationService
from app.models.base import utc_now


def test_phase14_verified_fixed_lifecycle_closure(
    db: Session,
    test_project: Project,
    tester_user: User,
    lead_user: User,
):
    """Verify that only LEAD/ADMIN can confirm VERIFIED_FIXED and close a finding."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase14-closure-01",
        target_value="https://test.local/login",
        title="SQL Injection in Login Endpoint",
        description="Vulnerable parameter in auth endpoint.",
        status=FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    # 1. Non-lead tester cannot record VERIFIED_FIXED closure
    with pytest.raises(PermissionError, match="Only Project LEAD or System ADMIN can confirm VERIFIED_FIXED"):
        RemediationVerificationService.record_verification(
            project_id=test_project.id,
            finding_id=finding.id,
            outcome=VerificationOutcome.VERIFIED_FIXED,
            verification_criteria="Target rejects quote payloads with HTTP 400 and parameterized query executes safely.",
            verification_evidence_summary="Re-test confirmed quote injection payloads returned no DB errors or reflections.",
            notes="Attempted closure by tester",
            verifier=tester_user,
            verifier_role=ProjectRole.TESTER,
            db=db,
        )

    # 2. Lead records VERIFIED_FIXED
    verification = RemediationVerificationService.record_verification(
        project_id=test_project.id,
        finding_id=finding.id,
        outcome=VerificationOutcome.VERIFIED_FIXED,
        verification_criteria="Target rejects quote payloads with HTTP 400 and parameterized query executes safely.",
        verification_evidence_summary="Re-test confirmed quote injection payloads returned no DB errors or reflections.",
        notes="Code diff verified; parameterized queries deployed; re-test clean.",
        verifier=lead_user,
        verifier_role=ProjectRole.LEAD,
        db=db,
    )

    assert verification.id is not None
    assert verification.outcome == VerificationOutcome.VERIFIED_FIXED
    assert verification.baseline_evidence_hash == finding.fingerprint
    assert verification.verifier_id == lead_user.id

    # 3. Finding lifecycle state MUST be VERIFIED_CLOSED
    db.refresh(finding)
    assert finding.status == FindingLifecycleStatus.VERIFIED_CLOSED
    assert finding.verified_by_id == lead_user.id
    assert finding.verified_at is not None
    assert "[VERIFIED_FIXED]" in finding.verification_notes


def test_phase14_still_vulnerable_reopens_finding_and_tracks_recurrence(
    db: Session,
    test_project: Project,
    tester_user: User,
    lead_user: User,
):
    """Verify that a verification proving STILL_VULNERABLE reopens the finding and increments recurrence."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase14-recurrence-02",
        target_value="https://test.local/profile",
        title="Reflected XSS in Profile",
        description="Profile parameter unescaped.",
        status=FindingLifecycleStatus.VERIFIED_CLOSED,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        recurrence_count=0,
        recurrence_detected=False,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    # Independent verification detects that vulnerability is still present
    verification = RemediationVerificationService.record_verification(
        project_id=test_project.id,
        finding_id=finding.id,
        outcome=VerificationOutcome.STILL_VULNERABLE,
        verification_criteria="Output is escaped and HTML tags are sanitized.",
        verification_evidence_summary="Target reflected unencoded script tags: <script>alert(1)</script>.",
        notes="Verification probe confirmed vulnerability is still exploitable on target.",
        verifier=tester_user,
        verifier_role=ProjectRole.TESTER,
        db=db,
    )

    assert verification.outcome == VerificationOutcome.STILL_VULNERABLE

    # Finding MUST reopen and track recurrence
    db.refresh(finding)
    assert finding.status == FindingLifecycleStatus.REOPENED
    assert finding.recurrence_detected is True
    assert finding.recurrence_count == 1


def test_phase14_inconclusive_and_partial_remediation_never_closes(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify that INCONCLUSIVE or PARTIALLY_REMEDIATED results never close a finding."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase14-inconclusive-03",
        target_value="https://test.local/api/config",
        title="Weak SSL/TLS Cipher Enabled",
        description="Deprecated 3DES cipher suites allowed.",
        status=FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    # 1. Inconclusive test (e.g. network timeout during verification probe)
    inconclusive_ver = RemediationVerificationService.record_verification(
        project_id=test_project.id,
        finding_id=finding.id,
        outcome=VerificationOutcome.INCONCLUSIVE,
        verification_criteria="SSL handshake must reject 3DES suites.",
        verification_evidence_summary="Network timeout during TLS handshake probe; probe did not complete.",
        notes="Network glitch during probe; test inconclusive.",
        verifier=tester_user,
        verifier_role=ProjectRole.TESTER,
        db=db,
    )
    assert inconclusive_ver.outcome == VerificationOutcome.INCONCLUSIVE
    db.refresh(finding)
    # Finding MUST NOT be closed
    assert finding.status == FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION

    # 2. Partial remediation (e.g. TLS 1.0 disabled, but weak ciphers still present on TLS 1.2)
    partial_ver = RemediationVerificationService.record_verification(
        project_id=test_project.id,
        finding_id=finding.id,
        outcome=VerificationOutcome.PARTIALLY_REMEDIATED,
        verification_criteria="Disable all deprecated protocols and weak CBC cipher suites.",
        verification_evidence_summary="TLS 1.0 disabled, but CBC suites still accepted on TLS 1.2.",
        notes="Remediation is only partial; remaining cipher suites require further hardening.",
        verifier=tester_user,
        verifier_role=ProjectRole.TESTER,
        db=db,
    )
    assert partial_ver.outcome == VerificationOutcome.PARTIALLY_REMEDIATED
    db.refresh(finding)
    # Finding MUST NOT be closed; transitioned to REOPENED
    assert finding.status == FindingLifecycleStatus.REOPENED


def test_phase14_api_verification_endpoints_and_history(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_headers: dict,
    tester_headers: dict,
    lead_user: User,
):
    """Verify HTTP API endpoints for manual verification, automated re-test, and verification history."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase14-api-04",
        target_value="https://test.local/headers",
        title="Missing Content-Security-Policy Header",
        description="Web application does not return CSP header.",
        vuln_id="CWE-16",
        status=FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    # 1. Record manual verification (STILL_VULNERABLE) via API
    res1 = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/verify",
        headers=tester_headers,
        json={
            "outcome": "STILL_VULNERABLE",
            "verification_criteria": "CSP header present in HTTP response headers.",
            "verification_evidence_summary": "HTTP response lacks Content-Security-Policy header.",
            "notes": "First verification attempt showed fix was not yet deployed to target.",
        },
    )
    assert res1.status_code == 201
    ver1 = res1.json()
    assert ver1["outcome"] == "STILL_VULNERABLE"
    assert ver1["baseline_evidence_hash"] == finding.fingerprint

    # 2. Execute automated re-test using passive_header_adapter
    # When passive_header_adapter runs against a target without CSP in simulated mode, it observes headers
    res_retest = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/verify/retest",
        headers=lead_headers,
        json={
            "adapter_name": "passive_header_adapter",
            "config": {},
            "notes": "Automated verification re-test via passive_header_adapter.",
        },
    )
    assert res_retest.status_code == 201
    retest_data = res_retest.json()
    assert retest_data["outcome"] in ("VERIFIED_FIXED", "STILL_VULNERABLE")

    # 3. Query verification history for finding
    history_res = client.get(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/verifications",
        headers=tester_headers,
    )
    assert history_res.status_code == 200
    history = history_res.json()
    # At least two verification attempts recorded
    assert len(history) >= 2
    # Verify outcomes are accurately preserved in history
    outcomes = [item["outcome"] for item in history]
    assert "STILL_VULNERABLE" in outcomes

    # 4. Query single verification by ID
    single_res = client.get(
        f"/api/v1/projects/{test_project.id}/verifications/{ver1['id']}",
        headers=tester_headers,
    )
    assert single_res.status_code == 200
    assert single_res.json()["id"] == ver1["id"]
