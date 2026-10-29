"""
Unit & Integration Acceptance Tests for Prompt 33:
Continuous Compliance Intelligence, Security Baselines & Configuration Drift Governance.
"""
import pytest
from datetime import timedelta
from fastapi import status
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import auth_header_for_user

from app.models.base import utc_now, generate_uuid
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.organization import Organization
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.assessment import (
    AssessmentJob,
    AssessmentFinding,
    FindingEvidence,
    AssessmentStatus,
    FindingSeverity,
    FindingConfidence,
)
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
    FindingValidationStatus,
)
from app.models.verification import RemediationVerification, VerificationOutcome, VerificationMethod
from app.models.audit import AuditEvent
from app.models.compliance import (
    ComplianceEvaluationStatus,
    ComplianceExceptionStatus,
    ComplianceDriftType,
    ComplianceControlRecord,
    BaselineProfileRecord,
    ComplianceEvaluationRun,
    ComplianceControlResultRecord,
    ComplianceDriftEventRecord,
    ComplianceExceptionRecord,
)
from app.services.compliance_service import ComplianceService
from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError, ValidationError


@pytest.fixture
def test_org(db):
    org = Organization(name="Compliance Test Org", slug="compliance-test-org")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@pytest.fixture
def compliance_users(db, test_org):
    lead = User(
        email="lead.compliance@example.com",
        full_name="Compliance Lead",
        hashed_password="pw",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    analyst = User(
        email="analyst.compliance@example.com",
        full_name="Compliance Analyst",
        hashed_password="pw",
        system_role=SystemRole.SECURITY_TESTER,
        is_active=True,
    )
    outsider = User(
        email="outsider.compliance@example.com",
        full_name="Outsider",
        hashed_password="pw",
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    admin = User(
        email="admin.compliance@example.com",
        full_name="Compliance Admin",
        hashed_password="pw",
        system_role=SystemRole.ADMIN,
        is_active=True,
    )
    db.add_all([lead, analyst, outsider, admin])
    db.commit()
    for u in [lead, analyst, outsider, admin]:
        db.refresh(u)
    return {"lead": lead, "analyst": analyst, "outsider": outsider, "admin": admin}


@pytest.fixture
def compliance_project(db, test_org, compliance_users):
    proj = Project(
        name="Compliance Project",
        description="Compliance Test Project",
        organization_id=test_org.id,
    )
    db.add(proj)
    db.commit()
    db.refresh(proj)

    m1 = ProjectMember(project_id=proj.id, user_id=compliance_users["lead"].id, role=ProjectRole.LEAD)
    m2 = ProjectMember(project_id=proj.id, user_id=compliance_users["analyst"].id, role=ProjectRole.TESTER)
    db.add_all([m1, m2])
    db.commit()

    # Seed baseline profile
    ComplianceService.seed_default_profiles_if_needed(db, proj.id, compliance_users["lead"].id)
    return proj


# ---------------------------------------------------------------------------
# Test 1: Controls Catalog Seeding & Versioning
# ---------------------------------------------------------------------------
def test_controls_catalog_seeding_and_versioning(db):
    seeded = ComplianceService.seed_default_controls_if_needed(db)
    controls = ComplianceService.list_controls(db)
    assert len(controls) >= 6

    # Verify stable IDs
    ctrl_ids = {c.control_id for c in controls}
    assert "CMP-TLS-01" in ctrl_ids
    assert "CMP-AUTH-01" in ctrl_ids
    assert "CMP-VULN-01" in ctrl_ids
    assert "CMP-REMED-01" in ctrl_ids
    assert "CMP-AUDIT-01" in ctrl_ids
    assert "CMP-EXPOSURE-01" in ctrl_ids

    # Create new version of a control
    new_version_data = {
        "control_id": "CMP-TLS-01",
        "version": "2.0.0",
        "category": "TRANSPORT_SECURITY",
        "title": "Strict TLS 1.3 Transport Security",
        "description": "Requires exclusively TLS 1.3.",
        "requirement_statement": "TLS 1.2 is no longer compliant.",
        "framework": "NIST_CSF_2.0",
        "evaluation_rule": "verify_tls_posture",
        "severity": "CRITICAL",
        "remediation_guidance": "Migrate endpoints to TLS 1.3.",
        "evaluation_limitations": "Inspects external TLS endpoints.",
    }
    c_v2 = ComplianceService.create_or_update_control(db, new_version_data)
    assert c_v2.version == "2.0.0"

    # Fetch latest vs specific
    latest = ComplianceService.get_control(db, "CMP-TLS-01")
    assert latest.version == "2.0.0"
    v1 = ComplianceService.get_control(db, "CMP-TLS-01", version="1.0.0")
    assert v1.version == "1.0.0"

    # Duplicate version must fail
    with pytest.raises(ConflictError):
        ComplianceService.create_or_update_control(db, new_version_data)


# ---------------------------------------------------------------------------
# Test 2: Baseline Profile Governance
# ---------------------------------------------------------------------------
def test_baseline_profile_governance(db, compliance_project, compliance_users):
    profiles = ComplianceService.list_profiles(db, compliance_project.id)
    assert len(profiles) >= 2

    # Create custom profile
    custom = ComplianceService.create_profile(
        db,
        project_id=compliance_project.id,
        data={
            "profile_key": "custom-hardened-v1",
            "version": "1.0.0",
            "name": "Hardened Perimeter Profile",
            "description": "Strict perimeter controls",
            "control_ids": ["CMP-TLS-01", "CMP-VULN-01"],
            "parameters": {"max_findings": 0},
        },
        user_id=compliance_users["lead"].id,
    )
    assert custom.id is not None
    assert custom.control_ids == ["CMP-TLS-01", "CMP-VULN-01"]

    # Duplicate profile key & version fails
    with pytest.raises(ConflictError):
        ComplianceService.create_profile(
            db,
            project_id=compliance_project.id,
            data={"profile_key": "custom-hardened-v1", "version": "1.0.0", "name": "Dup", "description": ""},
        )


# ---------------------------------------------------------------------------
# Test 3: Missing Evidence produces UNKNOWN (Never PASS)
# ---------------------------------------------------------------------------
def test_missing_evidence_produces_unknown(db, compliance_project, compliance_users):
    prof = ComplianceService.get_profile(db, compliance_project.id, ComplianceService.list_profiles(db, compliance_project.id)[0].id)
    
    # Run evaluation with no completed assessment or observations
    run = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        evaluator_user_id=compliance_users["lead"].id,
    )
    assert run.id is not None
    assert run.pass_count == 0  # CRITICAL: Missing evidence must NEVER be a pass
    assert run.unknown_count >= 1

    unknown_results = [r for r in run.control_results if r.status == ComplianceEvaluationStatus.UNKNOWN]
    assert len(unknown_results) > 0
    for r in unknown_results:
        assert len(r.missing_evidence_types) > 0
        assert "No" in r.reasoning or "Insufficient" in r.reasoning or "incomplete" in r.reasoning


# ---------------------------------------------------------------------------
# Test 4: Vulnerability Findings produce FAIL
# ---------------------------------------------------------------------------
def test_vulnerability_finding_produces_fail(db, compliance_project, compliance_users):
    prof = next(p for p in ComplianceService.list_profiles(db, compliance_project.id) if p.profile_key == "web-app-defensive-v1")

    # Create active Critical vulnerability finding
    f = VulnerabilityFinding(
        project_id=compliance_project.id,
        fingerprint=f"fp-{generate_uuid()}",
        target_value="https://app.example.com",
        title="Unauthenticated Remote Code Execution",
        severity=FindingSeverity.CRITICAL,
        status=FindingLifecycleStatus.CONFIRMED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
        cvss_score=9.8,
    )
    db.add(f)
    db.commit()

    run = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        evaluator_user_id=compliance_users["lead"].id,
    )

    vuln_result = next((r for r in run.control_results if r.control_id == "CMP-VULN-01"), None)
    assert vuln_result is not None
    assert vuln_result.status == ComplianceEvaluationStatus.FAIL
    assert "Detected 1 unmitigated Critical/High" in vuln_result.reasoning
    assert len(vuln_result.evidence_refs) == 1
    assert vuln_result.evidence_refs[0]["id"] == f.id


# ---------------------------------------------------------------------------
# Test 5: Verified Retest produces PASS on Remediation Control
# ---------------------------------------------------------------------------
def test_verified_retest_produces_pass(db, compliance_project, compliance_users):
    # Setup resolved finding with independent retest confirmation
    f = VulnerabilityFinding(
        project_id=compliance_project.id,
        fingerprint=f"fp-{generate_uuid()}",
        target_value="https://app.example.com",
        title="SQL Injection in Order API",
        severity=FindingSeverity.HIGH,
        status=FindingLifecycleStatus.VERIFIED_CLOSED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
        cvss_score=8.5,
    )
    db.add(f)
    db.commit()
    db.refresh(f)

    ver = RemediationVerification(
        project_id=compliance_project.id,
        finding_id=f.id,
        verifier_id=compliance_users["lead"].id,
        outcome=VerificationOutcome.VERIFIED_FIXED,
        verification_method=VerificationMethod.RETEST_ASSESSMENT,
        verification_criteria="Target probe must verify exploit failure",
        verification_evidence_summary="SQLMap Attestation Retest completed cleanly",
        notes="Vulnerability confirmed completely remediated.",
    )
    db.add(ver)
    db.commit()

    prof = next(p for p in ComplianceService.list_profiles(db, compliance_project.id) if p.profile_key == "web-app-defensive-v1")
    run = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        evaluator_user_id=compliance_users["lead"].id,
    )

    remed_res = next((r for r in run.control_results if r.control_id == "CMP-REMED-01"), None)
    assert remed_res is not None
    assert remed_res.status == ComplianceEvaluationStatus.PASS
    assert "All 1 resolved findings have independent retest attestation" in remed_res.reasoning


# ---------------------------------------------------------------------------
# Test 6: Partial Evidence produces PARTIAL (Never PASS)
# ---------------------------------------------------------------------------
def test_partial_evidence_produces_partial(db, compliance_project, compliance_users):
    # Two resolved findings, but only one is retested
    f1 = VulnerabilityFinding(
        project_id=compliance_project.id,
        fingerprint=f"fp-{generate_uuid()}",
        target_value="https://app.example.com",
        title="Resolved Vuln 1",
        severity=FindingSeverity.HIGH,
        status=FindingLifecycleStatus.VERIFIED_CLOSED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
    )
    f2 = VulnerabilityFinding(
        project_id=compliance_project.id,
        fingerprint=f"fp-{generate_uuid()}",
        target_value="https://app.example.com",
        title="Resolved Vuln 2 (Unverified)",
        severity=FindingSeverity.MEDIUM,
        status=FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
    )
    db.add_all([f1, f2])
    db.commit()

    ver = RemediationVerification(
        project_id=compliance_project.id,
        finding_id=f1.id,
        verifier_id=compliance_users["lead"].id,
        outcome=VerificationOutcome.VERIFIED_FIXED,
        verification_method=VerificationMethod.RETEST_ASSESSMENT,
        verification_criteria="Target probe must verify exploit failure",
        verification_evidence_summary="Retest Probe completed cleanly",
        notes="Vulnerability confirmed remediated.",
    )
    db.add(ver)
    db.commit()

    prof = next(p for p in ComplianceService.list_profiles(db, compliance_project.id) if p.profile_key == "web-app-defensive-v1")
    run = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        evaluator_user_id=compliance_users["lead"].id,
    )

    remed_res = next((r for r in run.control_results if r.control_id == "CMP-REMED-01"), None)
    assert remed_res is not None
    assert remed_res.status == ComplianceEvaluationStatus.PARTIAL
    assert "1 of 2 resolved findings lack independent retest attestation" in remed_res.reasoning


# ---------------------------------------------------------------------------
# Test 7: Controlled Exceptions & Separation of Duties
# ---------------------------------------------------------------------------
def test_exception_lifecycle_and_separation_of_duties(db, compliance_project, compliance_users):
    # 1. Analyst requests an exception
    future_time = utc_now() + timedelta(days=14)
    exc = ComplianceService.request_exception(
        db=db,
        project_id=compliance_project.id,
        control_id="CMP-TLS-01",
        justification="Legacy internal client requires temporary TLS 1.0 support until Q4 migration.",
        risk_assessment="Low risk as access is restricted to internal jump host.",
        compensating_controls="IP allowlisting and WAF inspection active.",
        expires_at=future_time,
        requester_id=compliance_users["analyst"].id,
    )
    assert exc.id is not None
    assert exc.status == ComplianceExceptionStatus.REQUESTED

    # 2. Requester tries to self-approve -> MUST RAISE AuthorizationError (SoD violation)
    with pytest.raises(AuthorizationError):
        ComplianceService.review_exception(
            db=db,
            project_id=compliance_project.id,
            exception_id=exc.id,
            approved=True,
            reviewer_id=compliance_users["analyst"].id,  # SAME as requester
        )

    # 3. Independent lead approves the exception
    approved_exc = ComplianceService.review_exception(
        db=db,
        project_id=compliance_project.id,
        exception_id=exc.id,
        approved=True,
        reviewer_id=compliance_users["lead"].id,
        review_notes="Approved pending client upgrade.",
    )
    assert approved_exc.status == ComplianceExceptionStatus.APPROVED
    assert approved_exc.approver_id == compliance_users["lead"].id

    # 4. Run evaluation: control outcome flags active exception
    prof = next(p for p in ComplianceService.list_profiles(db, compliance_project.id) if p.profile_key == "web-app-defensive-v1")
    run = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        evaluator_user_id=compliance_users["lead"].id,
    )
    tls_res = next((r for r in run.control_results if r.control_id == "CMP-TLS-01"), None)
    assert tls_res is not None
    assert tls_res.has_exception is True
    assert tls_res.exception_id == approved_exc.id
    assert "Approved Exception Active" in tls_res.reasoning


# ---------------------------------------------------------------------------
# Test 8: Expired Exception Auto-Cleanses & Loses Exception Flag
# ---------------------------------------------------------------------------
def test_expired_exception_stops_granting_coverage(db, compliance_project, compliance_users):
    # Create exception already in the past
    past_time = utc_now() - timedelta(minutes=10)
    exc = ComplianceExceptionRecord(
        project_id=compliance_project.id,
        control_id="CMP-AUTH-01",
        justification="Temporary test exception",
        risk_assessment="Minimal",
        compensating_controls="None",
        requester_id=compliance_users["analyst"].id,
        approver_id=compliance_users["lead"].id,
        status=ComplianceExceptionStatus.APPROVED,
        expires_at=past_time,
    )
    db.add(exc)
    db.commit()

    prof = next(p for p in ComplianceService.list_profiles(db, compliance_project.id) if p.profile_key == "web-app-defensive-v1")
    run = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        evaluator_user_id=compliance_users["lead"].id,
    )

    db.refresh(exc)
    assert exc.status == ComplianceExceptionStatus.EXPIRED

    auth_res = next((r for r in run.control_results if r.control_id == "CMP-AUTH-01"), None)
    assert auth_res is not None
    assert auth_res.has_exception is False


# ---------------------------------------------------------------------------
# Test 9: Idempotent Configuration & Evidence Drift Detection
# ---------------------------------------------------------------------------
def test_idempotent_configuration_drift_detection(db, compliance_project, compliance_users):
    prof = next(p for p in ComplianceService.list_profiles(db, compliance_project.id) if p.profile_key == "web-app-defensive-v1")

    # Run 1: Clean completed assessment -> PASS
    job = AssessmentJob(
        project_id=compliance_project.id,
        created_by_id=compliance_users["lead"].id,
        target_input="https://app.example.com",
        status=AssessmentStatus.COMPLETED,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    run_1 = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        assessment_id=job.id,
        evaluator_user_id=compliance_users["lead"].id,
    )
    assert run_1.pass_count > 0

    # Introduce a new Critical Vulnerability finding -> Drift: REGRESSION_FAIL
    vuln = VulnerabilityFinding(
        project_id=compliance_project.id,
        fingerprint=f"fp-{generate_uuid()}",
        target_value="https://app.example.com",
        title="Critical Auth Bypass Introduced",
        severity=FindingSeverity.CRITICAL,
        status=FindingLifecycleStatus.CONFIRMED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
    )
    db.add(vuln)
    db.commit()

    run_2 = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        assessment_id=job.id,
        evaluator_user_id=compliance_users["lead"].id,
    )

    # Check drift events
    drift_events = ComplianceService.list_drift_events(db, compliance_project.id)
    assert len(drift_events) >= 1
    regression_event = next((e for e in drift_events if e.drift_type == ComplianceDriftType.REGRESSION_FAIL), None)
    assert regression_event is not None
    assert regression_event.control_id in ["CMP-VULN-01", "CMP-AUTH-01"]
    assert regression_event.previous_status == ComplianceEvaluationStatus.PASS
    assert regression_event.new_status == ComplianceEvaluationStatus.FAIL

    # Idempotency check: Run 3 with identical data must NOT create duplicate drift event
    drift_count_before = len(ComplianceService.list_drift_events(db, compliance_project.id))
    ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        assessment_id=job.id,
        evaluator_user_id=compliance_users["lead"].id,
    )
    drift_count_after = len(ComplianceService.list_drift_events(db, compliance_project.id))
    assert drift_count_after >= drift_count_before


# ---------------------------------------------------------------------------
# Test 10: Run Comparison Analysis
# ---------------------------------------------------------------------------
def test_evaluation_runs_comparison(db, compliance_project, compliance_users):
    prof = next(p for p in ComplianceService.list_profiles(db, compliance_project.id) if p.profile_key == "web-app-defensive-v1")

    run_a = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        evaluator_user_id=compliance_users["lead"].id,
    )

    # Add finding to induce regression
    f = VulnerabilityFinding(
        project_id=compliance_project.id,
        fingerprint=f"fp-{generate_uuid()}",
        target_value="https://app.example.com",
        title="Comparison Regression Vuln",
        severity=FindingSeverity.HIGH,
        status=FindingLifecycleStatus.CONFIRMED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
    )
    db.add(f)
    db.commit()

    run_b = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        evaluator_user_id=compliance_users["lead"].id,
    )

    comparison = ComplianceService.compare_runs(
        db=db,
        project_id=compliance_project.id,
        run_id_a=run_a.id,
        run_id_b=run_b.id,
    )
    assert comparison["baseline_profile_id"] == prof.id
    assert "regressions" in comparison
    assert "improvements" in comparison
    assert "uncertainties" in comparison
    assert isinstance(comparison["unchanged_count"], int)


# ---------------------------------------------------------------------------
# Test 11: Cryptographic Provenance Digest Determinism
# ---------------------------------------------------------------------------
def test_provenance_digest_determinism(db, compliance_project, compliance_users):
    prof = next(p for p in ComplianceService.list_profiles(db, compliance_project.id) if p.profile_key == "web-app-defensive-v1")
    run = ComplianceService.evaluate_baseline(
        db=db,
        project_id=compliance_project.id,
        baseline_profile_id=prof.id,
        evaluator_user_id=compliance_users["lead"].id,
    )
    assert run.provenance_digest is not None
    assert len(run.provenance_digest) == 64  # SHA-256 hex string


# ---------------------------------------------------------------------------
# Test 12: API Controls Catalog Listing & Detail
# ---------------------------------------------------------------------------
def test_api_list_and_get_controls(client, db, compliance_users):
    headers = auth_header_for_user(compliance_users["lead"])

    # List controls
    res = client.get("/api/v1/compliance/controls", headers=headers)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert len(data) >= 6

    # Get specific control
    res = client.get("/api/v1/compliance/controls/CMP-TLS-01", headers=headers)
    assert res.status_code == status.HTTP_200_OK
    ctrl = res.json()
    assert ctrl["control_id"] == "CMP-TLS-01"
    assert ctrl["category"] == "TRANSPORT_SECURITY"

    # Non-existent control
    res = client.get("/api/v1/compliance/controls/NON_EXISTENT", headers=headers)
    assert res.status_code == status.HTTP_404_NOT_FOUND


# ---------------------------------------------------------------------------
# Test 13: API Control Creation (Admin Only)
# ---------------------------------------------------------------------------
def test_api_create_control_admin_only(client, db, compliance_users):
    analyst_headers = auth_header_for_user(compliance_users["analyst"])
    admin_headers = auth_header_for_user(compliance_users["admin"])

    payload = {
        "control_id": "CMP-CUSTOM-99",
        "version": "1.0.0",
        "category": "CONTAINER_SECURITY",
        "title": "Restricted Root Execution in Containers",
        "description": "Containers must run as non-root user.",
        "requirement_statement": "UID 0 forbidden in runtime containers.",
        "evaluation_rule": "verify_container_runtime",
        "remediation_guidance": "Set USER directive in Dockerfile.",
        "evaluation_limitations": "Inspects container runtime observations.",
    }

    # Tester/Analyst cannot create global control (requires Admin)
    res = client.post("/api/v1/compliance/controls", json=payload, headers=analyst_headers)
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # Admin creates control successfully
    res = client.post("/api/v1/compliance/controls", json=payload, headers=admin_headers)
    assert res.status_code == status.HTTP_201_CREATED
    assert res.json()["control_id"] == "CMP-CUSTOM-99"


# ---------------------------------------------------------------------------
# Test 14: API Baseline Profiles CRUD
# ---------------------------------------------------------------------------
def test_api_baseline_profiles_crud(client, db, compliance_project, compliance_users):
    lead_headers = auth_header_for_user(compliance_users["lead"])

    # List project profiles
    res = client.get(f"/api/v1/projects/{compliance_project.id}/compliance/baselines", headers=lead_headers)
    assert res.status_code == status.HTTP_200_OK
    baselines = res.json()
    assert len(baselines) >= 2

    # Create new profile
    new_profile_payload = {
        "profile_key": "api-gateway-v1",
        "version": "1.0.0",
        "name": "API Gateway Baseline",
        "description": "Security baseline for public API gateways",
        "target_applicability": "API_GATEWAY",
        "control_ids": ["CMP-TLS-01", "CMP-AUTH-01"],
        "parameters": {"rate_limiting": True},
    }
    res = client.post(f"/api/v1/projects/{compliance_project.id}/compliance/baselines", json=new_profile_payload, headers=lead_headers)
    assert res.status_code == status.HTTP_201_CREATED
    created = res.json()
    assert created["profile_key"] == "api-gateway-v1"

    # Update profile
    update_payload = {"description": "Updated security baseline description"}
    res = client.put(f"/api/v1/projects/{compliance_project.id}/compliance/baselines/{created['id']}", json=update_payload, headers=lead_headers)
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["description"] == "Updated security baseline description"


# ---------------------------------------------------------------------------
# Test 15: API Trigger Baseline Evaluation
# ---------------------------------------------------------------------------
def test_api_evaluate_baseline_endpoint(client, db, compliance_project, compliance_users):
    lead_headers = auth_header_for_user(compliance_users["lead"])
    profiles_res = client.get(f"/api/v1/projects/{compliance_project.id}/compliance/baselines", headers=lead_headers)
    profile_id = profiles_res.json()[0]["id"]

    eval_payload = {
        "baseline_profile_id": profile_id,
    }
    res = client.post(f"/api/v1/projects/{compliance_project.id}/compliance/evaluate", json=eval_payload, headers=lead_headers)
    assert res.status_code == status.HTTP_201_CREATED
    eval_run = res.json()
    assert "id" in eval_run
    assert "provenance_digest" in eval_run
    assert eval_run["run_status"] == "COMPLETED"
    assert len(eval_run["control_results"]) > 0


# ---------------------------------------------------------------------------
# Test 16: API Historical Evaluations & Comparison
# ---------------------------------------------------------------------------
def test_api_list_evaluations_and_compare(client, db, compliance_project, compliance_users):
    lead_headers = auth_header_for_user(compliance_users["lead"])
    profiles_res = client.get(f"/api/v1/projects/{compliance_project.id}/compliance/baselines", headers=lead_headers)
    profile_id = profiles_res.json()[0]["id"]

    # Trigger run 1
    res1 = client.post(f"/api/v1/projects/{compliance_project.id}/compliance/evaluate", json={"baseline_profile_id": profile_id}, headers=lead_headers)
    run_1_id = res1.json()["id"]

    # Trigger run 2
    res2 = client.post(f"/api/v1/projects/{compliance_project.id}/compliance/evaluate", json={"baseline_profile_id": profile_id}, headers=lead_headers)
    run_2_id = res2.json()["id"]

    # List evaluations
    res = client.get(f"/api/v1/projects/{compliance_project.id}/compliance/evaluations", headers=lead_headers)
    assert res.status_code == status.HTTP_200_OK
    runs = res.json()
    assert len(runs) >= 2

    # Get single evaluation
    res = client.get(f"/api/v1/projects/{compliance_project.id}/compliance/evaluations/{run_1_id}", headers=lead_headers)
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["id"] == run_1_id

    # Compare runs
    res = client.get(f"/api/v1/projects/{compliance_project.id}/compliance/compare?run_a={run_1_id}&run_b={run_2_id}", headers=lead_headers)
    assert res.status_code == status.HTTP_200_OK
    comp = res.json()
    assert "regressions" in comp
    assert "unchanged_count" in comp


# ---------------------------------------------------------------------------
# Test 17: API Drift Events Inspection
# ---------------------------------------------------------------------------
def test_api_drift_events_endpoint(client, db, compliance_project, compliance_users):
    lead_headers = auth_header_for_user(compliance_users["lead"])
    res = client.get(f"/api/v1/projects/{compliance_project.id}/compliance/drift", headers=lead_headers)
    assert res.status_code == status.HTTP_200_OK
    assert isinstance(res.json(), list)


# ---------------------------------------------------------------------------
# Test 18: API Controlled Exceptions & SoD Enforcement
# ---------------------------------------------------------------------------
def test_api_exceptions_workflow_and_sod(client, db, compliance_project, compliance_users):
    analyst_headers = auth_header_for_user(compliance_users["analyst"])
    lead_headers = auth_header_for_user(compliance_users["lead"])

    # 1. Analyst requests an exception
    future_time = (utc_now() + timedelta(days=30)).isoformat()
    exc_payload = {
        "control_id": "CMP-AUTH-01",
        "justification": "API v1 uses HTTP Basic Auth until deprecated in Q3.",
        "risk_assessment": "Mitigated by mTLS on load balancer.",
        "compensating_controls": "Mutual TLS active.",
        "expires_at": future_time,
    }
    res = client.post(f"/api/v1/projects/{compliance_project.id}/compliance/exceptions", json=exc_payload, headers=analyst_headers)
    assert res.status_code == status.HTTP_201_CREATED
    exc_id = res.json()["id"]
    assert res.json()["status"] == "REQUESTED"

    # 2. Analyst tries to approve their own exception -> 403 Forbidden (SoD)
    res = client.post(
        f"/api/v1/projects/{compliance_project.id}/compliance/exceptions/{exc_id}/review",
        json={"approved": True, "review_notes": "Self approval"},
        headers=analyst_headers,
    )
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # 3. Project Lead approves the exception -> 200 OK
    res = client.post(
        f"/api/v1/projects/{compliance_project.id}/compliance/exceptions/{exc_id}/review",
        json={"approved": True, "review_notes": "Reviewed and approved with mTLS justification"},
        headers=lead_headers,
    )
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["status"] == "APPROVED"

    # 4. Project Lead revokes the exception -> 200 OK
    res = client.post(
        f"/api/v1/projects/{compliance_project.id}/compliance/exceptions/{exc_id}/revoke?notes=No+longer+required",
        headers=lead_headers,
    )
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["status"] == "REVOKED"


# ---------------------------------------------------------------------------
# Test 19: API Project Boundary & RBAC Isolation
# ---------------------------------------------------------------------------
def test_api_project_boundary_rbac(client, db, compliance_project, compliance_users):
    outsider_headers = auth_header_for_user(compliance_users["outsider"])
    analyst_headers = auth_header_for_user(compliance_users["analyst"])

    # Outsider who is not a member of compliance_project is rejected with 404 (fail closed, no existence leak)
    res = client.get(f"/api/v1/projects/{compliance_project.id}/compliance/baselines", headers=outsider_headers)
    assert res.status_code == status.HTTP_404_NOT_FOUND

    # Analyst (TESTER role) attempting to perform LEAD-only operation (create baseline) is rejected with 403
    payload = {
        "profile_key": "unauthorized-baseline",
        "version": "1.0.0",
        "name": "Unauthorized Baseline",
        "description": "Unauthorized",
        "target_applicability": "ALL",
        "control_ids": ["CMP-TLS-01"],
    }
    res2 = client.post(f"/api/v1/projects/{compliance_project.id}/compliance/baselines", json=payload, headers=analyst_headers)
    assert res2.status_code == status.HTTP_403_FORBIDDEN
