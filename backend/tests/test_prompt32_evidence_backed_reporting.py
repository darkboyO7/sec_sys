"""
VAPT Platform — Evidence-Backed Security Reporting, Verifiable Exports & Reproducible Assessment Results.
Test suite for Prompt 32.
"""
import io
import json
import hashlib
import tarfile
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.user import User, SystemRole
from app.models.project import Project
from app.models.scope import ScopeTarget, ScopeExclusion
from app.models.assessment import (
    AssessmentJob,
    AssessmentFinding,
    FindingEvidence,
    AssessmentStatus,
    FindingSeverity,
    FindingConfidence,
)
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.risk import RemediationRecommendation
from app.models.verification import RemediationVerification, VerificationOutcome, VerificationMethod
from app.models.report import ReportType, ReportFormat, ReportRecord
from app.models.base import utc_now
from app.services.canonical_report_service import (
    CanonicalReportService,
    sanitize_csv_cell,
    sanitize_html,
    redact_sensitive_strings,
)
from app.services.report_service import ReportGenerationService
from tests.conftest import auth_header_for_user


@pytest.fixture
def assessment_fixture(db: Session, test_project: Project, tester_user: User):
    """Sets up a realistic assessment with scope, findings, evidence, asset, and retest verification."""
    # 1. Scope Target
    scope = ScopeTarget(
        project_id=test_project.id,
        target_value="https://payment.internal.local",
        target_type="URL",
        authorization_status="AUTHORIZED",
        created_by_id=tester_user.id,
    )
    db.add(scope)
    db.flush()

    # 2. Asset
    asset = Asset(
        organization_id=test_project.organization_id,
        project_id=test_project.id,
        name="Internal Payment Gateway",
        canonical_identifier="https://payment.internal.local",
        asset_type=AssetType.WEB_APP,
        criticality=AssetCriticality.CRITICAL,
    )
    db.add(asset)
    db.flush()

    # 3. Assessment Job
    job = AssessmentJob(
        project_id=test_project.id,
        target_id=scope.id,
        target_input="https://payment.internal.local",
        adapter_name="scanner.http_header",
        adapter_version="1.2.0",
        policy_version="2026.1",
        status=AssessmentStatus.COMPLETED,
        progress_pct=100,
        queued_at=utc_now() - timedelta(minutes=15),
        started_at=utc_now() - timedelta(minutes=14),
        completed_at=utc_now() - timedelta(minutes=5),
        is_simulated=True,
        created_by_id=tester_user.id,
        summary_stats={
            "checks_attempted": 8,
            "checks_completed": 8,
            "checks_failed": 0,
            "skipped_checks": [],
        },
    )
    db.add(job)
    db.flush()

    # 4. Authoritative Vulnerability Finding & Assessment Finding
    vf = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint=f"fp-pay-cmd-{uuid.uuid4().hex[:8]}",
        target_value="https://payment.internal.local",
        title="Command Injection in Payment Webhook",
        description="Improper input validation allows command execution.",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        cvss_score=9.8,
        status=FindingLifecycleStatus.CONFIRMED,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(vf)
    db.flush()

    f1 = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        canonical_finding_id=vf.id,
        target_value="https://payment.internal.local/charge",
        title="Command Injection in Payment Webhook",
        description="Improper input validation allows command execution.",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        cvss_score=9.8,
    )
    db.add(f1)
    db.flush()

    ev1 = FindingEvidence(
        finding_id=f1.id,
        evidence_type="HTTP_EXCHANGE",
        payload="POST /charge HTTP/1.1\nHost: payment.internal.local\nPayload: ; id;\nResponse: uid=0(root)",
        sha256_hash=hashlib.sha256(b"POST /charge HTTP/1.1\nHost: payment.internal.local\nPayload: ; id;\nResponse: uid=0(root)").hexdigest(),
    )
    db.add(ev1)

    # 5. Remediation Recommendation
    rec = RemediationRecommendation(
        project_id=test_project.id,
        finding_id=vf.id,
        title="Sanitize Webhook Parameter Execution",
        action_type="CODE_PATCH",
        description="Escape shell metacharacters in webhook payload parser.",
        rationale="Eliminates remote command injection risk.",
        qualitative_benefit="Protects payment processing runtime integrity.",
        related_controls="AC-3, SI-10",
        prerequisites="Code review completed",
        operational_impact="LOW",
        rollback_procedure="Revert commit",
        verification_criteria="No shell execution",
        execution_governance_stage="CHANGE_AUTHORIZED",
    )
    db.add(rec)
    db.flush()

    # 6. Retest Verification
    ver = RemediationVerification(
        project_id=test_project.id,
        finding_id=vf.id,
        recommendation_id=rec.id,
        verification_method=VerificationMethod.RETEST_ASSESSMENT,
        outcome=VerificationOutcome.VERIFIED_FIXED,
        verification_criteria="Webhook rejects shell metacharacters with HTTP 400",
        verification_evidence_summary="Executed active probe; command was blocked.",
        verification_evidence_data={"http_status": 400, "probe_blocked": True},
        notes="Verified fixed in staging environment.",
        verifier_id=tester_user.id,
        verified_at=utc_now(),
    )
    db.add(ver)
    db.commit()

    return {
        "project": test_project,
        "job": job,
        "finding": f1,
        "evidence": ev1,
        "asset": asset,
        "scope": scope,
        "recommendation": rec,
        "verification": ver,
    }


# ==============================================================================
# TESTS
# ==============================================================================

def test_01_canonical_report_generation_from_persisted_records(
    db: Session,
    assessment_fixture: dict,
):
    """1. Generates canonical assessment manifest from persisted records with scope and provenance."""
    job = assessment_fixture["job"]
    proj = assessment_fixture["project"]

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=proj.id,
        assessment_id=job.id,
        db=db,
    )

    assert manifest.schema_version == "1.0.0"
    assert manifest.assessment_id == job.id
    assert manifest.project_id == proj.id
    assert manifest.assessment_status == "COMPLETED"
    assert manifest.coverage_summary.total_checks_completed == 8
    assert manifest.coverage_summary.coverage_gap_identified is False
    assert len(manifest.findings) == 1
    assert manifest.findings[0].severity == "CRITICAL"
    assert manifest.findings[0].has_missing_evidence is False
    assert len(manifest.findings[0].evidence_refs) == 1
    assert len(manifest.evidence_manifest) == 1
    assert manifest.retest_verifications[0].outcome == "VERIFIED_FIXED"
    assert len(manifest.provenance_digest) == 64


def test_02_incomplete_assessment_representation(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """2. Incomplete or failed assessments are explicitly flagged with coverage gaps."""
    job_partial = AssessmentJob(
        project_id=test_project.id,
        target_input="https://internal.service.local",
        adapter_name="scanner.tcp",
        status=AssessmentStatus.PARTIAL,
        progress_pct=40,
        queued_at=utc_now(),
        started_at=utc_now(),
        is_simulated=True,
        created_by_id=tester_user.id,
        summary_stats={
            "checks_attempted": 10,
            "checks_completed": 4,
            "checks_failed": 2,
            "skipped_checks": ["full_port_scan", "service_version_sweep"],
        },
    )
    db.add(job_partial)
    db.commit()

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=test_project.id,
        assessment_id=job_partial.id,
        db=db,
    )

    assert manifest.coverage_summary.is_incomplete is True
    assert manifest.coverage_summary.coverage_gap_identified is True
    assert manifest.coverage_summary.checks_failed_count == 2
    assert "full_port_scan" in manifest.coverage_summary.skipped_checks
    assert any("incomplete" in l.lower() for l in manifest.limitations)
    assert "unassessed components and surfaces are not certified secure" in manifest.coverage_summary.disclaimer


def test_03_findings_with_missing_evidence(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """3. Findings lacking raw corroborating evidence are flagged with has_missing_evidence=True."""
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://api.unverified.local",
        adapter_name="scanner.mock",
        status=AssessmentStatus.COMPLETED,
        is_simulated=True,
        created_by_id=tester_user.id,
    )
    db.add(job)
    db.flush()

    f_bare = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        target_value="https://api.unverified.local",
        title="Uncorroborated Finding",
        description="Finding without raw evidence.",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.TENTATIVE,
    )
    db.add(f_bare)
    db.commit()

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=test_project.id,
        assessment_id=job.id,
        db=db,
    )

    assert manifest.findings[0].has_missing_evidence is True
    assert manifest.coverage_summary.missing_evidence_count == 1
    assert manifest.coverage_summary.coverage_gap_identified is True
    assert any("lack direct raw cryptographic evidence" in l for l in manifest.limitations)


def test_04_uncertainty_and_contradictory_evidence_preservation():
    """4. Ensures contradictory observations and epistemic uncertainty fields are supported."""
    from app.schemas.canonical_report import CanonicalFindingRecord

    f = CanonicalFindingRecord(
        id="f-test-1",
        fingerprint="fp-test-1",
        title="Inconsistent TLS 1.0 State",
        description="Probe 1 detected TLS 1.0; Probe 2 negotiated TLS 1.3.",
        severity="MEDIUM",
        confidence="TENTATIVE",
        target="https://tls.local",
        status="NEEDS_VALIDATION",
        is_simulated=True,
        evidence_refs=["ev-01", "ev-02"],
        has_missing_evidence=False,
        contradictory_evidence_noted=True,
        uncertainty_rationale="Probes executed through disparate load balancer nodes yielded conflicting ciphers.",
    )
    assert f.contradictory_evidence_noted is True
    assert "conflicting ciphers" in f.uncertainty_rationale


def test_05_traceable_risk_score_and_methodology(
    db: Session,
    assessment_fixture: dict,
):
    """5. Methodology explicitly records scoring standards and validation models."""
    job = assessment_fixture["job"]
    proj = assessment_fixture["project"]

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=proj.id,
        assessment_id=job.id,
        db=db,
    )

    assert manifest.methodology["scoring_system"] == "CVSS_v3.1"
    assert manifest.methodology["adapter_name"] == "scanner.http_header"
    assert manifest.methodology["adapter_version"] == "1.2.0"
    assert manifest.methodology["is_simulated"] is True


def test_06_remediation_versus_verified_retest_outcomes(
    db: Session,
    assessment_fixture: dict,
):
    """6. Captures remediation approval stage and independent retest outcome side-by-side."""
    job = assessment_fixture["job"]
    proj = assessment_fixture["project"]

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=proj.id,
        assessment_id=job.id,
        db=db,
    )

    assert manifest.findings[0].remediation_status == "CHANGE_AUTHORIZED"
    assert manifest.findings[0].retest_outcome == "VERIFIED_FIXED"
    assert len(manifest.retest_verifications) == 1
    assert manifest.retest_verifications[0].outcome == "VERIFIED_FIXED"


def test_07_json_schema_validity_and_deterministic_serialization(
    db: Session,
    assessment_fixture: dict,
):
    """7. Validates JSON schema adherence and stable, deterministic field serialization."""
    job = assessment_fixture["job"]
    proj = assessment_fixture["project"]

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=proj.id,
        assessment_id=job.id,
        db=db,
    )

    json_str_1 = CanonicalReportService.render_json(manifest)
    json_str_2 = CanonicalReportService.render_json(manifest)
    assert json_str_1 == json_str_2

    parsed = json.loads(json_str_1)
    assert parsed["schema_version"] == "1.0.0"
    assert parsed["assessment_id"] == job.id
    assert "provenance_digest" in parsed


def test_08_html_escaping_and_unsafe_input_defense(
    db: Session,
    assessment_fixture: dict,
):
    """8. Ensures HTML rendering escapes malicious script tags and event handlers."""
    job = assessment_fixture["job"]
    proj = assessment_fixture["project"]

    # Invalidate with malicious title in manifest
    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=proj.id,
        assessment_id=job.id,
        db=db,
        title="<script>alert('XSS_ATTACK')</script>",
    )
    manifest.findings[0].title = "<img src=x onerror=alert('PWNED')>"

    html_doc = CanonicalReportService.render_html(manifest)
    assert "<script>" not in html_doc
    assert "&lt;script&gt;alert(&#x27;XSS_ATTACK&#x27;)&lt;/script&gt;" in html_doc
    assert "&lt;img src=x onerror=alert(&#x27;PWNED&#x27;)&gt;" in html_doc


def test_09_csv_formula_injection_defenses():
    """9. Neutralizes spreadsheet formula injection (=, +, -, @, \\t, \\r)."""
    assert sanitize_csv_cell("=cmd|'/C calc'!A0") == "'=cmd|'/C calc'!A0"
    assert sanitize_csv_cell("+2+5") == "'+2+5"
    assert sanitize_csv_cell("-SUM(A1:A5)") == "'-SUM(A1:A5)"
    assert sanitize_csv_cell("@SUM(A1:A5)") == "'@SUM(A1:A5)"
    assert sanitize_csv_cell("\tDDE") == "'\tDDE"
    assert sanitize_csv_cell("\rDDE") == "'\rDDE"
    assert sanitize_csv_cell("Normal Text") == "Normal Text"


def test_10_portable_assessment_bundle_packaging(
    db: Session,
    assessment_fixture: dict,
):
    """10. Packages canonical assessment into a verifiable .tar.gz bundle with checksums."""
    job = assessment_fixture["job"]
    proj = assessment_fixture["project"]

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=proj.id,
        assessment_id=job.id,
        db=db,
    )

    bundle_bytes, bundle_manifest = CanonicalReportService.create_assessment_bundle(manifest)
    assert len(bundle_bytes) > 0
    assert bundle_manifest.manifest_version == "1.0.0"
    assert "report.json" in bundle_manifest.files
    assert "findings.json" in bundle_manifest.files
    assert "sha256sums.txt" in bundle_manifest.files

    # Inspect archive contents
    bio = io.BytesIO(bundle_bytes)
    with tarfile.open(fileobj=bio, mode="r:gz") as tar:
        names = tar.getnames()
        assert "manifest.json" in names
        assert "report.json" in names
        assert "findings.json" in names
        assert "sha256sums.txt" in names


def test_11_bundle_digest_verification_success(
    db: Session,
    assessment_fixture: dict,
):
    """11. Verifies an untampered bundle passes cryptographic validation-only inspection."""
    job = assessment_fixture["job"]
    proj = assessment_fixture["project"]

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=proj.id,
        assessment_id=job.id,
        db=db,
    )
    bundle_bytes, _ = CanonicalReportService.create_assessment_bundle(manifest)

    result = CanonicalReportService.verify_assessment_bundle(bundle_bytes)
    assert result.is_valid is True
    assert result.inspection_mode == "validation_only"
    assert len(result.violations) == 0
    assert len(result.corrupted_files) == 0
    assert len(result.checked_files) >= 5
    assert result.assessment_summary["assessment_id"] == job.id


def test_12_bundle_tamper_detection_corrupted_digest(
    db: Session,
    assessment_fixture: dict,
):
    """12. Detects altered file contents inside a bundle and flags corrupted_files."""
    job = assessment_fixture["job"]
    proj = assessment_fixture["project"]

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=proj.id,
        assessment_id=job.id,
        db=db,
    )
    bundle_bytes, _ = CanonicalReportService.create_assessment_bundle(manifest)

    # Read archive, tamper with findings.json, re-archive without updating manifest
    tampered_files = {}
    bio_in = io.BytesIO(bundle_bytes)
    with tarfile.open(fileobj=bio_in, mode="r:gz") as tar_in:
        for m in tar_in.getmembers():
            f = tar_in.extractfile(m)
            tampered_files[m.name] = f.read()

    # Tamper with findings.json
    tampered_files["findings.json"] = b"TAMPERED_CONTENT_MALICIOUS_INJECTION"

    bio_out = io.BytesIO()
    with tarfile.open(fileobj=bio_out, mode="w:gz") as tar_out:
        for fname, data in tampered_files.items():
            ti = tarfile.TarInfo(name=fname)
            ti.size = len(data)
            ti.mtime = int(datetime.now(timezone.utc).timestamp())
            tar_out.addfile(ti, io.BytesIO(data))

    tampered_bundle_bytes = bio_out.getvalue()
    result = CanonicalReportService.verify_assessment_bundle(tampered_bundle_bytes)

    assert result.is_valid is False
    assert "findings.json" in result.corrupted_files


def test_13_bundle_unsupported_schema_version_rejection(
    db: Session,
    assessment_fixture: dict,
):
    """13. Rejects bundle with unsupported manifest_version."""
    job = assessment_fixture["job"]
    proj = assessment_fixture["project"]

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=proj.id,
        assessment_id=job.id,
        db=db,
    )
    bundle_bytes, _ = CanonicalReportService.create_assessment_bundle(manifest)

    # Tamper manifest.json version to 99.0
    tampered_files = {}
    bio_in = io.BytesIO(bundle_bytes)
    with tarfile.open(fileobj=bio_in, mode="r:gz") as tar_in:
        for m in tar_in.getmembers():
            f = tar_in.extractfile(m)
            tampered_files[m.name] = f.read()

    m_data = json.loads(tampered_files["manifest.json"].decode("utf-8"))
    m_data["manifest_version"] = "99.0"
    tampered_files["manifest.json"] = json.dumps(m_data).encode("utf-8")

    bio_out = io.BytesIO()
    with tarfile.open(fileobj=bio_out, mode="w:gz") as tar_out:
        for fname, data in tampered_files.items():
            ti = tarfile.TarInfo(name=fname)
            ti.size = len(data)
            ti.mtime = int(datetime.now(timezone.utc).timestamp())
            tar_out.addfile(ti, io.BytesIO(data))

    result = CanonicalReportService.verify_assessment_bundle(bio_out.getvalue())
    assert result.is_valid is False
    assert any("Unsupported bundle/manifest schema version" in v for v in result.violations)


def test_14_bundle_path_traversal_rejection():
    """14. Safely rejects bundles containing path traversal members (../../evil)."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tar:
        # Malicious traversal member
        data = b"malicious"
        ti = tarfile.TarInfo(name="../../evil.sh")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))

        m_data = b'{"manifest_version": "1.0.0", "bundle_version": "1.0.0", "files": {}}'
        ti_m = tarfile.TarInfo(name="manifest.json")
        ti_m.size = len(m_data)
        tar.addfile(ti_m, io.BytesIO(m_data))

    result = CanonicalReportService.verify_assessment_bundle(bio.getvalue())
    assert result.is_valid is False
    assert any("Illegal path traversal detected" in v for v in result.violations)


def test_15_bundle_oversized_bomb_rejection():
    """15. Rejects oversized archives exceeding size threshold."""
    oversized_bytes = b"0" * (51 * 1024 * 1024)  # 51 MB (limit is 50 MB)
    result = CanonicalReportService.verify_assessment_bundle(oversized_bytes)
    assert result.is_valid is False
    assert any("exceeds limit" in v for v in result.violations)


def test_16_validation_only_leaves_database_unmutated(
    db: Session,
    assessment_fixture: dict,
):
    """16. Confirms bundle verification has zero side-effects on database records."""
    job = assessment_fixture["job"]
    proj = assessment_fixture["project"]

    manifest = CanonicalReportService.build_assessment_manifest(
        project_id=proj.id,
        assessment_id=job.id,
        db=db,
    )
    bundle_bytes, _ = CanonicalReportService.create_assessment_bundle(manifest)

    # Record counts before
    count_jobs_before = db.query(AssessmentJob).count()
    count_findings_before = db.query(AssessmentFinding).count()
    count_reports_before = db.query(ReportRecord).count()

    # Execute verification
    result = CanonicalReportService.verify_assessment_bundle(bundle_bytes)
    assert result.is_valid is True

    # Record counts after
    count_jobs_after = db.query(AssessmentJob).count()
    count_findings_after = db.query(AssessmentFinding).count()
    count_reports_after = db.query(ReportRecord).count()

    assert count_jobs_before == count_jobs_after
    assert count_findings_before == count_findings_after
    assert count_reports_before == count_reports_after


def test_17_cross_project_and_unauthorized_access_rejected(
    client: TestClient,
    assessment_fixture: dict,
    admin_user: User,
):
    """17. API enforces strict project isolation; foreign projects get 403/404."""
    job = assessment_fixture["job"]
    headers = auth_header_for_user(admin_user)

    # Attempt access with nonexistent or foreign project ID
    res = client.get(
        f"/api/v1/projects/foreign-proj-999/assessments/{job.id}/report/canonical",
        headers=headers,
    )
    assert res.status_code in (403, 404)

    # Attempt export with foreign project ID
    res_export = client.get(
        f"/api/v1/projects/foreign-proj-999/assessments/{job.id}/report/export?format=JSON",
        headers=headers,
    )
    assert res_export.status_code in (403, 404)


def test_18_sensitive_credential_redaction_in_evidence():
    """18. Explicitly redacts Authorization bearer tokens and passwords from evidence strings."""
    raw_payload = (
        "GET /api/v1/secure HTTP/1.1\n"
        "Host: api.test.local\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake_token\n"
        "Cookie: session=xyz; api_key='sk_live_998877665544332211'\n"
        "Body: password=SuperSecretPassword123!\n"
    )

    redacted_text, was_redacted = redact_sensitive_strings(raw_payload)
    assert was_redacted is True
    assert "fake_token" not in redacted_text
    assert "[REDACTED_BEARER_TOKEN]" in redacted_text
    assert "SuperSecretPassword123!" not in redacted_text
    assert "[REDACTED_PASSWORD]" in redacted_text
    assert "sk_live_" not in redacted_text
    assert "[REDACTED_API_KEY]" in redacted_text
