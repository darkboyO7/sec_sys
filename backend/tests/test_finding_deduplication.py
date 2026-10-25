import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
    FindingTransition,
)
from app.models.assessment import (
    AssessmentJob,
    AssessmentFinding,
    AssessmentStatus,
    FindingSeverity,
    FindingConfidence,
)
from app.services.finding_deduplication_service import FindingDeduplicationService

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture
def db_session():
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def setup_env(db_session):
    user = User(
        email="operator@test.local",
        hashed_password="pw",
        full_name="Assessment Operator",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    org = Organization(name="Dedup Org", slug="dedup-org")
    db_session.add(org)
    db_session.flush()

    project = Project(
        name="Security Lab",
        organization_id=org.id,
        description="Testing deduplication",
    )
    db_session.add_all([user, project])
    db_session.flush()

    mem = ProjectMember(project_id=project.id, user_id=user.id, role=ProjectRole.LEAD)
    db_session.add(mem)
    db_session.commit()

    return {"user": user, "project": project}


def test_deterministic_fingerprint_normalization():
    # 1. Trailing slashes and scheme casing should produce identical fingerprint
    fp1 = FindingDeduplicationService.compute_fingerprint(
        target_value="https://api.example.com/",
        vuln_id="CVE-2026-1049",
        title="SQL Injection in Login Endpoint",
    )
    fp2 = FindingDeduplicationService.compute_fingerprint(
        target_value="http://api.example.com",
        vuln_id="cve-2026-1049",
        title="  sql   injection in   login endpoint  ",
    )
    assert fp1 == fp2
    assert len(fp1) == 64

    # 2. Distinct vulnerability produces different fingerprint
    fp3 = FindingDeduplicationService.compute_fingerprint(
        target_value="https://api.example.com",
        vuln_id="CWE-79",
        title="Reflected XSS",
    )
    assert fp1 != fp3


def test_first_detection_creates_canonical_and_links(db_session, setup_env):
    env = setup_env
    user = env["user"]
    project = env["project"]

    job = AssessmentJob(
        project_id=project.id,
        target_input="https://api.example.com",
        created_by_id=user.id,
        status=AssessmentStatus.RUNNING,
    )
    db_session.add(job)
    db_session.commit()

    raw_finding = AssessmentFinding(
        job_id=job.id,
        project_id=project.id,
        target_value="https://api.example.com",
        title="Outdated Spring Boot Framework",
        description="Spring Boot 2.4.x is end-of-life",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        vuln_id="CVE-2025-4321",
        cvss_score=7.5,
    )
    db_session.add(raw_finding)
    db_session.commit()

    canonical_list = FindingDeduplicationService.ingest_job_findings(
        job=job,
        raw_findings=[raw_finding],
        db=db_session,
    )

    assert len(canonical_list) == 1
    canonical = canonical_list[0]
    assert canonical.occurrence_count == 1
    assert canonical.status == FindingLifecycleStatus.DETECTED
    assert canonical.title == raw_finding.title
    assert raw_finding.canonical_finding_id == canonical.id

    # Check initial transition recorded
    transitions = (
        db_session.query(FindingTransition)
        .filter(FindingTransition.finding_id == canonical.id)
        .all()
    )
    assert len(transitions) == 1
    assert transitions[0].to_status == FindingLifecycleStatus.DETECTED


def test_subsequent_detection_deduplicates_and_increments(db_session, setup_env):
    env = setup_env
    user = env["user"]
    project = env["project"]

    job1 = AssessmentJob(
        project_id=project.id,
        target_input="https://api.example.com",
        created_by_id=user.id,
        status=AssessmentStatus.COMPLETED,
    )
    job2 = AssessmentJob(
        project_id=project.id,
        target_input="https://api.example.com",
        created_by_id=user.id,
        status=AssessmentStatus.COMPLETED,
    )
    db_session.add_all([job1, job2])
    db_session.commit()

    # Ingestion 1
    raw1 = AssessmentFinding(
        job_id=job1.id,
        project_id=project.id,
        target_value="https://api.example.com",
        title="Open SSH Port with Password Auth",
        description="SSH exposed",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
    )
    db_session.add(raw1)
    db_session.commit()
    FindingDeduplicationService.ingest_job_findings(job=job1, raw_findings=[raw1], db=db_session)

    # Ingestion 2 from subsequent job
    raw2 = AssessmentFinding(
        job_id=job2.id,
        project_id=project.id,
        target_value="https://api.example.com/",
        title="open ssh port with password auth",
        description="SSH exposed on secondary scan",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
    )
    db_session.add(raw2)
    db_session.commit()
    FindingDeduplicationService.ingest_job_findings(job=job2, raw_findings=[raw2], db=db_session)

    # Total canonical findings in project should still be exactly 1
    all_canonicals = (
        db_session.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.project_id == project.id)
        .all()
    )
    assert len(all_canonicals) == 1
    canonical = all_canonicals[0]
    assert canonical.occurrence_count == 2
    assert raw1.canonical_finding_id == canonical.id
    assert raw2.canonical_finding_id == canonical.id


def test_reopening_on_previously_closed_finding(db_session, setup_env):
    env = setup_env
    user = env["user"]
    project = env["project"]

    job1 = AssessmentJob(
        project_id=project.id,
        target_input="192.168.1.10",
        created_by_id=user.id,
        status=AssessmentStatus.COMPLETED,
    )
    db_session.add(job1)
    db_session.commit()

    raw1 = AssessmentFinding(
        job_id=job1.id,
        project_id=project.id,
        target_value="192.168.1.10",
        title="Default Admin Credentials",
        description="admin/admin active",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
    )
    db_session.add(raw1)
    db_session.commit()
    FindingDeduplicationService.ingest_job_findings(job=job1, raw_findings=[raw1], db=db_session)

    canonical = db_session.query(VulnerabilityFinding).first()
    # Mark it as VERIFIED_CLOSED
    canonical.status = FindingLifecycleStatus.VERIFIED_CLOSED
    db_session.commit()

    # Now a new scan re-observes this vulnerability on the target!
    job2 = AssessmentJob(
        project_id=project.id,
        target_input="192.168.1.10",
        created_by_id=user.id,
        status=AssessmentStatus.COMPLETED,
    )
    db_session.add(job2)
    db_session.commit()

    raw2 = AssessmentFinding(
        job_id=job2.id,
        project_id=project.id,
        target_value="192.168.1.10",
        title="Default Admin Credentials",
        description="admin/admin observed again in regression test",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
    )
    db_session.add(raw2)
    db_session.commit()

    FindingDeduplicationService.ingest_job_findings(job=job2, raw_findings=[raw2], db=db_session)

    db_session.refresh(canonical)
    assert canonical.status == FindingLifecycleStatus.REOPENED
    assert canonical.occurrence_count == 2

    # Verify that a REOPENED transition was logged
    reopen_trans = (
        db_session.query(FindingTransition)
        .filter(
            FindingTransition.finding_id == canonical.id,
            FindingTransition.to_status == FindingLifecycleStatus.REOPENED,
        )
        .first()
    )
    assert reopen_trans is not None
    assert "re-detected" in reopen_trans.reason


def test_contradictory_evidence_preservation(db_session, setup_env):
    env = setup_env
    user = env["user"]
    project = env["project"]

    job1 = AssessmentJob(
        project_id=project.id,
        target_input="https://shop.corp.local",
        created_by_id=user.id,
        status=AssessmentStatus.COMPLETED,
    )
    job2 = AssessmentJob(
        project_id=project.id,
        target_input="https://shop.corp.local",
        created_by_id=user.id,
        status=AssessmentStatus.COMPLETED,
    )
    db_session.add_all([job1, job2])
    db_session.commit()

    # Initial scan reports CRITICAL / CERTAIN
    raw1 = AssessmentFinding(
        job_id=job1.id,
        project_id=project.id,
        target_value="https://shop.corp.local",
        title="Remote Code Execution via File Upload",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
    )
    db_session.add(raw1)
    db_session.commit()
    FindingDeduplicationService.ingest_job_findings(job=job1, raw_findings=[raw1], db=db_session)

    canonical = db_session.query(VulnerabilityFinding).first()
    assert not canonical.has_contradictions

    # Subsequent scan reports MEDIUM / TENTATIVE (divergent / uncertain signal)
    raw2 = AssessmentFinding(
        job_id=job2.id,
        project_id=project.id,
        target_value="https://shop.corp.local",
        title="Remote Code Execution via File Upload",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.TENTATIVE,
    )
    db_session.add(raw2)
    db_session.commit()
    FindingDeduplicationService.ingest_job_findings(job=job2, raw_findings=[raw2], db=db_session)

    db_session.refresh(canonical)
    assert canonical.has_contradictions is True
    assert len(canonical.contradiction_notes) == 1
    assert canonical.contradiction_notes[0]["observed_severity"] == "MEDIUM"
    assert canonical.contradiction_notes[0]["canonical_severity"] == "CRITICAL"
