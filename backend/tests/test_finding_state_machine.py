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
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.base import utc_now
from app.services.finding_lifecycle_service import (
    FindingLifecycleService,
    InvalidFindingTransitionError,
    FindingAuthorizationError,
)

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
def setup_users_and_project(db_session):
    admin = User(
        email="admin@test.local",
        hashed_password="pw",
        full_name="Global Admin",
        system_role=SystemRole.ADMIN,
        is_active=True,
    )
    lead_user = User(
        email="lead@test.local",
        hashed_password="pw",
        full_name="Project Lead",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    analyst_user = User(
        email="analyst@test.local",
        hashed_password="pw",
        full_name="Security Analyst",
        system_role=SystemRole.SECURITY_TESTER,
        is_active=True,
    )
    org = Organization(name="Test Org", slug="test-org")
    db_session.add(org)
    db_session.flush()

    project = Project(
        name="Target Project",
        organization_id=org.id,
        description="Phase 3 Target",
    )
    db_session.add_all([admin, lead_user, analyst_user, project])
    db_session.flush()

    mem_lead = ProjectMember(project_id=project.id, user_id=lead_user.id, role=ProjectRole.LEAD)
    mem_analyst = ProjectMember(project_id=project.id, user_id=analyst_user.id, role=ProjectRole.TESTER)
    db_session.add_all([mem_lead, mem_analyst])
    db_session.commit()

    return {
        "admin": admin,
        "lead": lead_user,
        "analyst": analyst_user,
        "project": project,
    }


def test_valid_finding_lifecycle_transitions(db_session, setup_users_and_project):
    env = setup_users_and_project
    lead = env["lead"]
    project = env["project"]

    finding = VulnerabilityFinding(
        project_id=project.id,
        fingerprint="fp12345",
        target_value="https://api.internal.corp",
        title="SQL Injection in auth route",
        description="Unsanitized parameter in /login",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
    )
    db_session.add(finding)
    db_session.commit()

    # Step 1: DETECTED -> CONFIRMED
    FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.CONFIRMED,
        actor=lead,
        actor_role=ProjectRole.LEAD,
        reason="Verified reproduction payload in lab environment.",
        db=db_session,
    )
    assert finding.status == FindingLifecycleStatus.CONFIRMED

    # Step 2: CONFIRMED -> REMEDIATION_PROPOSED
    FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.REMEDIATION_PROPOSED,
        actor=lead,
        actor_role=ProjectRole.LEAD,
        reason="Patch with parameterized queries prepared in PR #42.",
        remediation_notes="Use SQLAlchemy parameterized binding",
        db=db_session,
    )
    assert finding.status == FindingLifecycleStatus.REMEDIATION_PROPOSED
    assert finding.remediation_notes == "Use SQLAlchemy parameterized binding"

    # Step 3: REMEDIATION_PROPOSED -> REMEDIATION_APPROVED
    FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.REMEDIATION_APPROVED,
        actor=lead,
        actor_role=ProjectRole.LEAD,
        reason="Security Lead approved PR #42 for deployment.",
        db=db_session,
    )
    assert finding.status == FindingLifecycleStatus.REMEDIATION_APPROVED

    # Step 4: REMEDIATION_APPROVED -> REMEDIATION_ATTEMPTED
    FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.REMEDIATION_ATTEMPTED,
        actor=lead,
        actor_role=ProjectRole.LEAD,
        reason="Deployed patch to staging environment.",
        db=db_session,
    )
    assert finding.status == FindingLifecycleStatus.REMEDIATION_ATTEMPTED

    # Step 5: REMEDIATION_ATTEMPTED -> REMEDIATED_PENDING_VERIFICATION
    FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
        actor=lead,
        actor_role=ProjectRole.LEAD,
        reason="Target ready for automated regression verification.",
        db=db_session,
    )
    assert finding.status == FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION

    # Step 6: REMEDIATED_PENDING_VERIFICATION -> VERIFIED_CLOSED
    FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.VERIFIED_CLOSED,
        actor=lead,
        actor_role=ProjectRole.LEAD,
        reason="Executed automated verification suite; vulnerability confirmed absent.",
        verification_notes="Re-scan confirmed no injection is possible on /login.",
        db=db_session,
    )
    assert finding.status == FindingLifecycleStatus.VERIFIED_CLOSED
    assert finding.verified_at is not None
    assert finding.verified_by_id == lead.id


def test_illegal_transitions_rejected(db_session, setup_users_and_project):
    env = setup_users_and_project
    lead = env["lead"]
    project = env["project"]

    finding = VulnerabilityFinding(
        project_id=project.id,
        fingerprint="fp999",
        target_value="https://api.internal.corp",
        title="Information Disclosure",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.FIRM,
    )
    db_session.add(finding)
    db_session.commit()

    # Direct jump from DETECTED to VERIFIED_CLOSED is strictly illegal
    with pytest.raises(InvalidFindingTransitionError) as exc_info:
        FindingLifecycleService.transition_finding(
            finding=finding,
            to_status=FindingLifecycleStatus.VERIFIED_CLOSED,
            actor=lead,
            actor_role=ProjectRole.LEAD,
            reason="Closing prematurely without remediation or verification pipeline.",
            db=db_session,
        )
    assert "Illegal finding lifecycle transition" in str(exc_info.value)


def test_false_positive_disposition_enforces_lead_and_reason(db_session, setup_users_and_project):
    env = setup_users_and_project
    lead = env["lead"]
    analyst = env["analyst"]
    project = env["project"]

    finding = VulnerabilityFinding(
        project_id=project.id,
        fingerprint="fp-fp",
        target_value="10.0.0.1",
        title="Weak SSL/TLS Cipher",
        status=FindingLifecycleStatus.DETECTED,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
    )
    db_session.add(finding)
    db_session.commit()

    # Analyst cannot mark FALSE_POSITIVE (must be LEAD or ADMIN)
    with pytest.raises(FindingAuthorizationError) as exc:
        FindingLifecycleService.transition_finding(
            finding=finding,
            to_status=FindingLifecycleStatus.FALSE_POSITIVE,
            actor=analyst,
            actor_role=ProjectRole.TESTER,
            reason="I think this is a false positive based on manual probe.",
            db=db_session,
        )
    assert "Only a Project LEAD or System ADMIN" in str(exc.value)

    # Lead with too short reason is rejected
    with pytest.raises(InvalidFindingTransitionError) as exc:
        FindingLifecycleService.transition_finding(
            finding=finding,
            to_status=FindingLifecycleStatus.FALSE_POSITIVE,
            actor=lead,
            actor_role=ProjectRole.LEAD,
            reason="short",
            db=db_session,
        )
    assert "at least 10 characters" in str(exc.value)

    # Lead with valid justification succeeds
    FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.FALSE_POSITIVE,
        actor=lead,
        actor_role=ProjectRole.LEAD,
        reason="Verified that TLS 1.0 is disabled at the upstream ingress load balancer.",
        db=db_session,
    )
    assert finding.status == FindingLifecycleStatus.FALSE_POSITIVE
    assert finding.false_positive_by_id == lead.id
    assert finding.false_positive_at is not None


def test_accepted_risk_enforces_controls_and_expiration(db_session, setup_users_and_project):
    env = setup_users_and_project
    lead = env["lead"]
    analyst = env["analyst"]
    project = env["project"]

    finding = VulnerabilityFinding(
        project_id=project.id,
        fingerprint="fp-risk",
        target_value="https://legacy.corp.internal",
        title="Outdated OpenSSL Library",
        status=FindingLifecycleStatus.CONFIRMED,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
    )
    db_session.add(finding)
    db_session.commit()

    # Non-lead rejected
    with pytest.raises(FindingAuthorizationError):
        FindingLifecycleService.transition_finding(
            finding=finding,
            to_status=FindingLifecycleStatus.ACCEPTED_RISK,
            actor=analyst,
            actor_role=ProjectRole.TESTER,
            reason="Accepting risk for legacy server.",
            expires_at=utc_now() + timedelta(days=30),
            compensating_controls="Network isolation",
            db=db_session,
        )

    # Missing expiration rejected
    with pytest.raises(InvalidFindingTransitionError) as exc:
        FindingLifecycleService.transition_finding(
            finding=finding,
            to_status=FindingLifecycleStatus.ACCEPTED_RISK,
            actor=lead,
            actor_role=ProjectRole.LEAD,
            reason="Business justification: legacy system undergoing deprecation.",
            expires_at=None,
            compensating_controls="Strict firewall whitelist",
            db=db_session,
        )
    assert "mandatory expiration date" in str(exc.value)

    # Past expiration date rejected
    with pytest.raises(InvalidFindingTransitionError) as exc:
        FindingLifecycleService.transition_finding(
            finding=finding,
            to_status=FindingLifecycleStatus.ACCEPTED_RISK,
            actor=lead,
            actor_role=ProjectRole.LEAD,
            reason="Business justification: legacy system undergoing deprecation.",
            expires_at=utc_now() - timedelta(days=1),
            compensating_controls="Strict firewall whitelist",
            db=db_session,
        )
    assert "must be in the future" in str(exc.value)

    # Valid acceptance succeeds
    future_date = utc_now() + timedelta(days=90)
    FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.ACCEPTED_RISK,
        actor=lead,
        actor_role=ProjectRole.LEAD,
        reason="System retirement scheduled for Q3 2026; risk accepted by CISO.",
        expires_at=future_date,
        compensating_controls="WAF virtual patch rule #9021 and VPN boundary restriction.",
        db=db_session,
    )
    assert finding.status == FindingLifecycleStatus.ACCEPTED_RISK
    assert finding.risk_accepted_by_id == lead.id
    assert finding.compensating_controls == "WAF virtual patch rule #9021 and VPN boundary restriction."


def test_sweep_expired_accepted_risks(db_session, setup_users_and_project):
    env = setup_users_and_project
    lead = env["lead"]
    project = env["project"]

    now = utc_now()

    # Expired finding
    f_expired = VulnerabilityFinding(
        project_id=project.id,
        fingerprint="fp-exp1",
        target_value="10.0.0.5",
        title="Expired Risk Finding",
        status=FindingLifecycleStatus.ACCEPTED_RISK,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        risk_accepted_at=now - timedelta(days=60),
        risk_accepted_expires_at=now - timedelta(days=1),  # Overdue
        risk_accepted_by_id=lead.id,
        compensating_controls="Air-gapped lab network",
    )

    # Still valid finding
    f_valid = VulnerabilityFinding(
        project_id=project.id,
        fingerprint="fp-valid1",
        target_value="10.0.0.6",
        title="Active Accepted Risk",
        status=FindingLifecycleStatus.ACCEPTED_RISK,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        risk_accepted_at=now,
        risk_accepted_expires_at=now + timedelta(days=30),  # Not overdue
        risk_accepted_by_id=lead.id,
        compensating_controls="Air-gapped lab network",
    )

    db_session.add_all([f_expired, f_valid])
    db_session.commit()

    count = FindingLifecycleService.sweep_expired_accepted_risks(
        project_id=project.id,
        db=db_session,
        actor=lead,
    )
    assert count == 1
    db_session.refresh(f_expired)
    db_session.refresh(f_valid)

    assert f_expired.status == FindingLifecycleStatus.EXPIRED
    assert f_valid.status == FindingLifecycleStatus.ACCEPTED_RISK
