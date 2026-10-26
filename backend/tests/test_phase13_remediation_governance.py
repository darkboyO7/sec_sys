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
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.services.remediation_service import RemediationPrioritizationService
from app.models.base import utc_now


def test_phase13_recommendation_generation_with_controls_and_effort(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify generated remediation recommendation includes root cause, effort, controls, and initial stage."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase13-sqli-01",
        target_value="https://test.local/api/search",
        title="SQL Injection in search query parameter",
        description="Dynamic string formatting allows SQL injection via search parameter.",
        vuln_id="CWE-89",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_or_get_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
    )

    assert rec.id is not None
    assert rec.action_type == "CODE_REFACTOR"
    assert rec.status == RecommendationStatus.PENDING_REVIEW
    assert rec.execution_governance_stage == "GENERATED"
    assert "parameterized" in rec.title.lower() or "parameterized" in rec.description.lower()
    assert rec.root_cause is not None
    assert "Dynamic SQL" in rec.root_cause
    assert rec.recommended_change is not None
    assert rec.estimated_effort is not None
    assert "MEDIUM" in rec.estimated_effort
    assert isinstance(rec.related_controls, list)
    assert any("16.11" in c or "SI-10" in c for c in rec.related_controls)
    assert rec.verification_criteria is not None
    assert rec.requires_approval is True
    assert rec.approval_role == "LEAD"


def test_phase13_review_governance_rbac(
    db: Session,
    test_project: Project,
    tester_user: User,
    lead_user: User,
):
    """Verify role-based controls on reviewing and approving remediation recommendations."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase13-xss-02",
        target_value="https://test.local/profile",
        title="Cross-Site Scripting (Reflected)",
        description="Reflected XSS in user profile name field.",
        vuln_id="CWE-79",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_or_get_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
    )
    assert rec.execution_governance_stage == "GENERATED"

    # Non-lead user (tester) cannot approve recommendation requiring LEAD role
    with pytest.raises(PermissionError):
        RemediationPrioritizationService.review_recommendation(
            project_id=test_project.id,
            recommendation_id=rec.id,
            new_status=RecommendationStatus.APPROVED,
            reviewer=tester_user,
            reviewer_role=ProjectRole.TESTER,
            review_notes="Attempted approval without proper authority",
            db=db,
        )

    # Lead user approves recommendation
    approved_rec = RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=rec.id,
        new_status=RecommendationStatus.APPROVED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Approved following code review and CSP evaluation.",
        db=db,
    )
    assert approved_rec.status == RecommendationStatus.APPROVED
    assert approved_rec.execution_governance_stage == "APPROVED"
    assert approved_rec.reviewed_by_id == lead_user.id


def test_phase13_change_authorization_governance_boundary(
    db: Session,
    test_project: Project,
    tester_user: User,
    lead_user: User,
):
    """Verify change authorization strictly requires APPROVED status, LEAD/ADMIN role, and change ticket ref."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase13-patch-03",
        target_value="https://test.local/libs",
        title="Outdated Component with Known CVE",
        description="Vulnerable library component requires upgrade.",
        vuln_id="CVE-2024-9999",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_or_get_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
    )

    # 1. Cannot authorize change when status is still PENDING_REVIEW
    with pytest.raises(ValueError, match="must be 'APPROVED' first"):
        RemediationPrioritizationService.authorize_change(
            project_id=test_project.id,
            recommendation_id=rec.id,
            change_ticket_ref="CHG-2026-001",
            authorizer=lead_user,
            authorizer_role=ProjectRole.LEAD,
            db=db,
        )

    # 2. Approve the recommendation first
    RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=rec.id,
        new_status=RecommendationStatus.APPROVED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Approved for maintenance window deployment.",
        db=db,
    )

    # 3. Non-lead user cannot authorize change
    with pytest.raises(PermissionError):
        RemediationPrioritizationService.authorize_change(
            project_id=test_project.id,
            recommendation_id=rec.id,
            change_ticket_ref="CHG-2026-001",
            authorizer=tester_user,
            authorizer_role=ProjectRole.TESTER,
            db=db,
        )

    # 4. Lead authorizes change with ticket reference
    authorized_rec = RemediationPrioritizationService.authorize_change(
        project_id=test_project.id,
        recommendation_id=rec.id,
        change_ticket_ref="CHG-PROD-2026-9042",
        authorizer=lead_user,
        authorizer_role=ProjectRole.LEAD,
        db=db,
    )

    assert authorized_rec.execution_governance_stage == "CHANGE_AUTHORIZED"
    assert "CHG-PROD-2026-9042" in authorized_rec.review_notes


def test_phase13_remediation_api_authorize_change(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_headers: dict,
    tester_headers: dict,
    lead_user: User,
):
    """Verify HTTP API endpoint for change authorization enforces authentication and role governance."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase13-api-04",
        target_value="https://test.local/headers",
        title="Missing Defensive Security Headers",
        description="Missing X-Content-Type-Options and Content-Security-Policy.",
        vuln_id="CWE-16",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.CERTAIN,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    # Generate recommendation via endpoint
    gen_res = client.get(
        f"/api/v1/projects/{test_project.id}/remediations/findings/{finding.id}",
        headers=tester_headers,
    )
    assert gen_res.status_code == 200
    rec_data = gen_res.json()
    rec_id = rec_data["id"]
    assert rec_data["execution_governance_stage"] == "GENERATED"
    assert rec_data["root_cause"] is not None

    # Attempt change authorization before approval -> 400 Bad Request
    auth_res = client.post(
        f"/api/v1/projects/{test_project.id}/risk/remediations/{rec_id}/authorize-change",
        headers=lead_headers,
        json={"change_ticket_ref": "CHG-SEC-7788"},
    )
    assert auth_res.status_code == 400

    # Approve recommendation as lead
    review_res = client.post(
        f"/api/v1/projects/{test_project.id}/risk/remediations/{rec_id}/review",
        headers=lead_headers,
        json={
            "status": "APPROVED",
            "review_notes": "Security headers approved for reverse-proxy injection.",
        },
    )
    assert review_res.status_code == 200
    assert review_res.json()["execution_governance_stage"] == "APPROVED"

    # Authorize change as member/tester -> 403 Forbidden
    auth_tester_res = client.post(
        f"/api/v1/projects/{test_project.id}/risk/remediations/{rec_id}/authorize-change",
        headers=tester_headers,
        json={"change_ticket_ref": "CHG-SEC-7788"},
    )
    assert auth_tester_res.status_code == 403

    # Authorize change as lead -> 200 OK
    auth_lead_res = client.post(
        f"/api/v1/projects/{test_project.id}/risk/remediations/{rec_id}/authorize-change",
        headers=lead_headers,
        json={"change_ticket_ref": "CHG-SEC-7788"},
    )
    assert auth_lead_res.status_code == 200
    updated_rec = auth_lead_res.json()
    assert updated_rec["execution_governance_stage"] == "CHANGE_AUTHORIZED"
    assert "CHG-SEC-7788" in updated_rec["review_notes"]
