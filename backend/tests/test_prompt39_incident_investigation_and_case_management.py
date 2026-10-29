import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi import status

from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.finding import (
    VulnerabilityFinding,
    FindingSeverity,
    FindingConfidence,
    FindingLifecycleStatus,
)
from app.models.incident import (
    IncidentCase,
    CaseSeverity,
    CaseStatus,
    RelationshipType,
    CorrelationType,
    IncidentCaseAsset,
    IncidentCaseFinding,
    IncidentCaseEvidence,
    IncidentCaseTransition,
    IncidentCaseNote,
)
from app.models.base import utc_now
from app.core.security import create_access_token, hash_password
from app.services.incident_service import IncidentInvestigationService


def auth_header_for_user(user: User) -> dict:
    token = create_access_token(
        subject=user.id,
        claims={"role": user.system_role.value, "email": user.email},
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def inc_org(db):
    org = Organization(name="Incident Ops Org", slug=f"inc-org-{uuid.uuid4().hex[:6]}")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@pytest.fixture
def inc_users(db, inc_org):
    pw = hash_password("LeadPass123!")
    lead = User(
        email=f"lead_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Lead Incident Commander",
        hashed_password=pw,
        is_active=True,
        system_role=SystemRole.SECURITY_LEAD,
    )
    investigator = User(
        email=f"investigator_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Staff Incident Investigator",
        hashed_password=pw,
        is_active=True,
        system_role=SystemRole.SECURITY_TESTER,
    )
    viewer = User(
        email=f"viewer_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Incident Auditor Viewer",
        hashed_password=pw,
        is_active=True,
        system_role=SystemRole.VIEWER,
    )
    db.add_all([lead, investigator, viewer])
    db.commit()
    db.refresh(lead)
    db.refresh(investigator)
    db.refresh(viewer)
    return {"lead": lead, "investigator": investigator, "viewer": viewer}


@pytest.fixture
def inc_project(db, inc_org, inc_users):
    proj = Project(
        name="Security Case Management Project",
        description="Prompt 39 evidence-preserving incident case testing",
        organization_id=inc_org.id,
    )
    db.add(proj)
    db.commit()
    db.refresh(proj)

    m1 = ProjectMember(project_id=proj.id, user_id=inc_users["lead"].id, role=ProjectRole.LEAD)
    m2 = ProjectMember(project_id=proj.id, user_id=inc_users["investigator"].id, role=ProjectRole.TESTER)
    m3 = ProjectMember(project_id=proj.id, user_id=inc_users["viewer"].id, role=ProjectRole.VIEWER)
    db.add_all([m1, m2, m3])
    db.commit()
    return proj


@pytest.fixture
def inc_assets(db, inc_project):
    a1 = Asset(
        project_id=inc_project.id,
        organization_id=inc_project.organization_id,
        name="Production Web Portal",
        canonical_identifier="https://portal.bank.corp",
        asset_type=AssetType.WEB_APP,
        criticality=AssetCriticality.HIGH,
        status=AssetStatus.ACTIVE,
    )
    a2 = Asset(
        project_id=inc_project.id,
        organization_id=inc_project.organization_id,
        name="Gateway Server IP",
        canonical_identifier="198.51.100.25",
        asset_type=AssetType.IP_ADDRESS,
        criticality=AssetCriticality.MEDIUM,
        status=AssetStatus.ACTIVE,
    )
    db.add_all([a1, a2])
    db.commit()
    db.refresh(a1)
    db.refresh(a2)
    return [a1, a2]


@pytest.fixture
def inc_findings(db, inc_project, inc_assets):
    f1 = VulnerabilityFinding(
        project_id=inc_project.id,
        asset_id=inc_assets[0].id,
        fingerprint="fp-sqli-auth-login-01",
        title="SQL Injection in Authentication API",
        vuln_id="CVE-2026-1101",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        description="Exploitable SQL injection vulnerability on login endpoint",
        target_value="https://portal.bank.corp/api/login",
    )
    f2 = VulnerabilityFinding(
        project_id=inc_project.id,
        asset_id=inc_assets[1].id,
        fingerprint="fp-ssh-weak-auth-02",
        title="Open SSH Port with Password Authentication",
        vuln_id="CWE-287",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        description="SSH daemon permitting weak authentication",
        target_value="198.51.100.25:22",
    )
    db.add_all([f1, f2])
    db.commit()
    db.refresh(f1)
    db.refresh(f2)
    return [f1, f2]


def test_incident_case_creation_and_numbering(client, inc_project, inc_users):
    """Req 1, 2: Create security incident case and verify sequential numbering and initial state."""
    headers = auth_header_for_user(inc_users["investigator"])
    payload = {
        "title": "Suspected Credential Stuffing & Lateral Pivot",
        "description": "High volume of anomalous authentication failures observed on external portal.",
        "severity": "HIGH",
        "lead_investigator_id": inc_users["investigator"].id,
        "assigned_team": "SOC-Blue-Team",
    }
    response = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases",
        json=payload,
        headers=headers,
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["case_number"].startswith("INC-")
    assert data["status"] == "OPEN"
    assert data["severity"] == "HIGH"
    assert data["lead_investigator_id"] == inc_users["investigator"].id
    assert len(data["transitions"]) == 1
    assert data["transitions"][0]["to_status"] == "OPEN"


def test_link_asset_with_relationship_type(client, inc_project, inc_users, inc_assets):
    """Req 2, 4, 5: Link assets with explicit relationship classification (PRIMARY_TARGET, PIVOT_VECTOR)."""
    case = IncidentInvestigationService.create_case(
        db=client.app.state.test_db if hasattr(client.app.state, "test_db") else None or inc_project._sa_instance_state.session,
        project_id=inc_project.id,
        title="Lateral Movement Case",
        severity=CaseSeverity.HIGH,
        lead_investigator_id=inc_users["lead"].id,
        actor=inc_users["lead"],
    )

    headers = auth_header_for_user(inc_users["investigator"])
    # Link primary target
    res1 = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/assets",
        json={
            "asset_id": inc_assets[0].id,
            "relationship_type": "PRIMARY_TARGET",
            "confidence": 0.95,
            "notes": "Web portal targeted by initial exploitation payload",
        },
        headers=headers,
    )
    assert res1.status_code == status.HTTP_201_CREATED

    # Link pivot vector
    res2 = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/assets",
        json={
            "asset_id": inc_assets[1].id,
            "relationship_type": "PIVOT_VECTOR",
            "confidence": 0.70,
            "notes": "Secondary internal gateway observed receiving connections",
        },
        headers=headers,
    )
    assert res2.status_code == status.HTTP_201_CREATED

    # Verify detail
    detail_res = client.get(f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}", headers=headers)
    assert detail_res.status_code == status.HTTP_200_OK
    detail = detail_res.json()
    assert len(detail["linked_assets"]) == 2


def test_link_finding_with_causation_vs_correlation(client, inc_project, inc_users, inc_findings):
    """Req 4, 5: Distinguish confirmed causation from temporal correlation; never confuse them."""
    db = inc_project._sa_instance_state.session
    case = IncidentInvestigationService.create_case(
        db=db,
        project_id=inc_project.id,
        title="Exploitation Causation Test",
        severity=CaseSeverity.CRITICAL,
        actor=inc_users["lead"],
    )

    headers = auth_header_for_user(inc_users["investigator"])

    # 1. Confirmed Causation finding
    res1 = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/findings",
        json={
            "finding_id": inc_findings[0].id,
            "correlation_type": "CONFIRMED_CAUSATION",
            "confidence": 1.0,
            "rationale": "Direct SQL error telemetry in server logs matches scanner exploit payload",
        },
        headers=headers,
    )
    assert res1.status_code == status.HTTP_201_CREATED

    # 2. Temporal coincidence finding (observed around same time, but unrelated service)
    res2 = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/findings",
        json={
            "finding_id": inc_findings[1].id,
            "correlation_type": "TEMPORAL_COINCIDENCE",
            "confidence": 0.30,
            "rationale": "SSH port scan observed during same hour window; no authentication log overlap",
        },
        headers=headers,
    )
    assert res2.status_code == status.HTTP_201_CREATED

    # Verify breakdown
    corr_res = client.get(f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/correlations", headers=headers)
    assert corr_res.status_code == status.HTTP_200_OK
    corr = corr_res.json()
    assert len(corr["confirmed_causation"]) == 1
    assert corr["confirmed_causation"][0]["finding_id"] == inc_findings[0].id
    assert len(corr["temporal_coincidences"]) == 1
    assert corr["temporal_coincidences"][0]["finding_id"] == inc_findings[1].id


def test_attach_evidence_snapshot_and_digest(client, inc_project, inc_users):
    """Req 3, 7: Attach immutable evidence snapshot with SHA-256 digest without modifying original evidence."""
    db = inc_project._sa_instance_state.session
    case = IncidentInvestigationService.create_case(
        db=db,
        project_id=inc_project.id,
        title="Evidence Preservation Case",
        actor=inc_users["investigator"],
    )

    headers = auth_header_for_user(inc_users["investigator"])
    payload = {
        "evidence_summary": "Captured PCAP network packet trace showing POST /api/login SQL injection attempt",
        "is_contradictory": False,
        "provenance_details": {
            "sensor": "zeek-ids-sensor-01",
            "packet_count": 142,
            "capture_time": utc_now().isoformat(),
        },
    }
    response = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/evidence",
        json=payload,
        headers=headers,
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "digest" in data
    assert len(data["digest"]) == 64  # SHA-256


def test_preserve_contradictory_evidence_and_hypotheses(client, inc_project, inc_users):
    """Req 6: Allow investigators to document alternative explanations and preserve contradictory evidence."""
    db = inc_project._sa_instance_state.session
    case = IncidentInvestigationService.create_case(
        db=db,
        project_id=inc_project.id,
        title="Alternative Hypothesis Investigation",
        actor=inc_users["investigator"],
    )

    headers = auth_header_for_user(inc_users["investigator"])

    # 1. Record contradictory evidence (e.g. WAF blocked the payload)
    ev_res = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/evidence",
        json={
            "evidence_summary": "Edge WAF access logs confirm all anomalous payloads returned HTTP 403 Forbidden",
            "is_contradictory": True,
            "provenance_details": {"waf_rule": "SQLi-Filter-942100"},
        },
        headers=headers,
    )
    assert ev_res.status_code == status.HTTP_201_CREATED

    # 2. Record alternative hypothesis note
    note_res = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/notes",
        json={
            "content": "Alternative Hypothesis: Attack was an automated internet spray fully blocked by WAF, not targeted breach.",
            "note_type": "HYPOTHESIS",
            "is_alternative_hypothesis": True,
        },
        headers=headers,
    )
    assert note_res.status_code == status.HTTP_201_CREATED

    # Verify correlations breakdown reflects contradictory evidence
    corr_res = client.get(f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/correlations", headers=headers)
    assert corr_res.status_code == status.HTTP_200_OK
    corr = corr_res.json()
    assert corr["contradictory_evidence_count"] >= 1
    assert corr["alternative_hypotheses_count"] >= 1


def test_controlled_case_closure_and_reopening(client, inc_project, inc_users):
    """Req 9, 10: Case closure requires detailed summary; reopening requires explicit justification."""
    db = inc_project._sa_instance_state.session
    case = IncidentInvestigationService.create_case(
        db=db,
        project_id=inc_project.id,
        title="Lifecycle Transition Test",
        lead_investigator_id=inc_users["investigator"].id,
        actor=inc_users["investigator"],
    )

    headers = auth_header_for_user(inc_users["lead"])

    # 1. Transition OPEN -> TRIAGED
    r1 = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/transition",
        json={"to_status": "TRIAGED", "reason": "Initial triage confirmed legitimate anomaly"},
        headers=headers,
    )
    assert r1.status_code == status.HTTP_200_OK
    assert r1.json()["status"] == "TRIAGED"

    # 2. Transition TRIAGED -> INVESTIGATING
    r2 = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/transition",
        json={"to_status": "INVESTIGATING", "reason": "Assigned to SOC tier 2 team"},
        headers=headers,
    )
    assert r2.status_code == status.HTTP_200_OK
    assert r2.json()["status"] == "INVESTIGATING"

    # 3. Transition INVESTIGATING -> CLOSED (Attempt without closure summary -> Fails)
    r3_fail = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/transition",
        json={"to_status": "CLOSED", "reason": "Investigation complete"},
        headers=headers,
    )
    assert r3_fail.status_code == status.HTTP_400_BAD_REQUEST

    # Attempt with valid closure summary -> Succeeds
    r3 = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/transition",
        json={
            "to_status": "CLOSED",
            "reason": "Root cause confirmed and remediated",
            "closure_summary": "Root cause identified as outdated third-party library; patch deployed and independently verified.",
            "is_containment_verified": True,
        },
        headers=headers,
    )
    assert r3.status_code == status.HTTP_200_OK
    closed_case = r3.json()
    assert closed_case["status"] == "CLOSED"
    assert closed_case["closed_at"] is not None

    # 4. Reopening closed case (Requires justification)
    r4_fail = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/transition",
        json={"to_status": "REOPENED", "reason": "New findings observed"},
        headers=headers,
    )
    assert r4_fail.status_code == status.HTTP_400_BAD_REQUEST

    r4 = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/transition",
        json={
            "to_status": "REOPENED",
            "reason": "Secondary pivot observed on same network segment",
            "reopening_rationale": "Subsequent telemetry indicates attacker may have established secondary persistence.",
        },
        headers=headers,
    )
    assert r4.status_code == status.HTTP_200_OK
    reopened = r4.json()
    assert reopened["status"] == "REOPENED"
    assert reopened["reopened_at"] is not None


def test_case_closure_separation_of_duties(client, inc_project, inc_users):
    """Req 9, SoD: Lead investigator cannot self-approve case closure when SoD policy is enforced."""
    db = inc_project._sa_instance_state.session
    case = IncidentInvestigationService.create_case(
        db=db,
        project_id=inc_project.id,
        title="SoD Case Closure Test",
        lead_investigator_id=inc_users["investigator"].id,
        actor=inc_users["investigator"],
    )

    # Lead investigator (investigator) attempts to self-close case -> Must be rejected with 403 Forbidden
    headers_investigator = auth_header_for_user(inc_users["investigator"])
    res_self = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/transition",
        json={
            "to_status": "CLOSED",
            "reason": "Investigator closing own case",
            "closure_summary": "Self closure attempt without independent security lead review.",
        },
        headers=headers_investigator,
    )
    assert res_self.status_code == status.HTTP_403_FORBIDDEN
    assert "Separation of Duties violation" in res_self.json()["detail"]

    # Independent Security Lead approves closure -> Succeeds
    headers_lead = auth_header_for_user(inc_users["lead"])
    res_lead = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/transition",
        json={
            "to_status": "CLOSED",
            "reason": "Independent Lead approval of investigation closure",
            "closure_summary": "Case reviewed and closed by independent security lead after evidence validation.",
        },
        headers=headers_lead,
    )
    assert res_lead.status_code == status.HTTP_200_OK
    assert res_lead.json()["status"] == "CLOSED"


def test_investigation_timeline_provenance(client, inc_project, inc_users):
    """Req 7: Chronological timeline preserving historical transitions and provenance."""
    db = inc_project._sa_instance_state.session
    case = IncidentInvestigationService.create_case(
        db=db,
        project_id=inc_project.id,
        title="Timeline Audit Test",
        actor=inc_users["lead"],
    )

    headers = auth_header_for_user(inc_users["viewer"])

    # Fetch timeline
    res = client.get(f"/api/v1/projects/{inc_project.id}/incidents/cases/{case.id}/timeline", headers=headers)
    assert res.status_code == status.HTTP_200_OK
    timeline = res.json()
    assert len(timeline) >= 1
    assert timeline[0]["event_type"] == "STATUS_TRANSITION"


def test_rbac_and_workspace_isolation(client, inc_project, inc_users):
    """Req 13: Read-only Viewer cannot create cases or transition status."""
    headers_viewer = auth_header_for_user(inc_users["viewer"])

    # Viewer attempts to create case -> Forbidden
    res_create = client.post(
        f"/api/v1/projects/{inc_project.id}/incidents/cases",
        json={"title": "Unauthorized Case Creation"},
        headers=headers_viewer,
    )
    assert res_create.status_code == status.HTTP_403_FORBIDDEN
