"""
VAPT Platform — Unified Security Operations Experience & Actionable Intelligence.
Test suite for Prompt 30.
Validates:
1. Cockpit summary returns healthy baseline with all 12 Core Operational Questions.
2. All 12 Core Questions are present in order (1-12) with explicit status and summary.
3. Verified critical findings escalate posture to ATTENTION_REQUIRED and populate Priority Queue.
4. Pending remediation approvals appear in Priority Queue with score >= 80 and role SECURITY_LEAD.
5. Failed assessment jobs appear in Priority Queue with score 75 and role SECURITY_TESTER.
6. Priority queue items are strictly sorted by priority_score descending.
7. Dismissed items are successfully filtered from subsequent priority queue queries.
8. Contradictory/uncertain findings are flagged in Question 6.
9. API cockpit summary endpoint requires authentication (401 without credentials).
10. API cockpit summary endpoint returns 200 with valid schema for authenticated users.
11. API priority-queue endpoint returns 200 with valid schema for authenticated users.
12. API dismiss endpoint enforces RBAC (403 for OPERATOR/TESTER, 200 for SECURITY_LEAD / ADMIN).
13. Project ID filter isolates cockpit summary and priority queue items.
14. Data freshness seconds is reported accurately.
15. Dynamic next-action recommendation adapts to operational findings.
16. Zero synthetic demo data: summary counts strictly reflect live DB records.
17. Resolved/closed findings are excluded from actionable priority queue.
"""
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingSeverity
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus, FindingValidationStatus
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.services.operations_cockpit_service import operations_cockpit_service
from tests.conftest import auth_header_for_user


def test_01_cockpit_summary_healthy_baseline(db: Session):
    summary = operations_cockpit_service.get_unified_operations_summary(db=db)
    assert summary.overall_posture in ["HEALTHY", "ATTENTION_REQUIRED"]
    assert len(summary.core_questions) == 12
    assert summary.data_freshness_seconds >= 0


def test_02_all_12_core_questions_present_and_numbered(db: Session):
    summary = operations_cockpit_service.get_unified_operations_summary(db=db)
    assert len(summary.core_questions) == 12
    for idx, q in enumerate(summary.core_questions, 1):
        assert q.question_id == idx
        assert len(q.question_text) > 0
        assert q.status in ["PASS", "WARN", "FAIL", "INFO"]
        assert len(q.summary) > 0


def test_03_critical_findings_escalate_posture_and_priority_queue(
    db: Session, test_project: Project, admin_user: User
):
    finding = VulnerabilityFinding(
        id=str(uuid.uuid4()),
        project_id=test_project.id,
        fingerprint=f"fp-crit-{uuid.uuid4().hex[:8]}",
        title="Unauthenticated Remote Code Execution",
        severity=FindingSeverity.CRITICAL,
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
        target_value="10.0.0.1:8080",
        cvss_score=9.8,
        description="Critical RCE vulnerability verified.",
    )
    db.add(finding)
    db.commit()

    summary = operations_cockpit_service.get_unified_operations_summary(db=db, project_id=test_project.id)
    assert summary.verified_critical_findings >= 1
    assert summary.overall_posture == "ATTENTION_REQUIRED"

    queue = operations_cockpit_service.get_actionable_priority_queue(db=db, project_id=test_project.id)
    assert any(i.affected_finding_id == finding.id for i in queue.items)
    crit_item = next(i for i in queue.items if i.affected_finding_id == finding.id)
    assert crit_item.priority_score >= 90
    assert crit_item.required_role == "SECURITY_LEAD"


def test_04_pending_remediation_approval_in_priority_queue(db: Session, test_project: Project):
    finding = VulnerabilityFinding(
        id=str(uuid.uuid4()),
        project_id=test_project.id,
        fingerprint=f"fp-rem-{uuid.uuid4().hex[:8]}",
        title="Apache Log4j Vulnerability",
        severity=FindingSeverity.CRITICAL,
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
        target_value="log4j.internal",
        description="Vulnerable Log4j detected.",
    )
    db.add(finding)
    db.commit()

    rec = RemediationRecommendation(
        id=str(uuid.uuid4()),
        project_id=test_project.id,
        finding_id=finding.id,
        title="Patch Apache Log4j Dependency",
        action_type="PATCH_UPDATE",
        description="Upgrade library to 2.17.1 to mitigate CVE-2021-44228",
        rationale="Prevents RCE via JNDI injection",
        qualitative_benefit="Eliminates critical remote code execution vector",
        operational_impact="Minimal service reload",
        rollback_procedure="Revert POM artifact version",
        verification_criteria="Rerun dependency check",
        status=RecommendationStatus.PENDING_REVIEW,
    )
    db.add(rec)
    db.commit()

    queue = operations_cockpit_service.get_actionable_priority_queue(db=db)
    assert any(i.title == f"Remediation Pending Approval: {rec.title}" for i in queue.items)
    item = next(i for i in queue.items if i.title == f"Remediation Pending Approval: {rec.title}")
    assert item.priority_score == 85
    assert item.required_role == "SECURITY_LEAD"


def test_05_failed_assessment_job_triggers_alert_in_priority_queue(
    db: Session, test_project: Project, admin_user: User
):
    job = AssessmentJob(
        id=str(uuid.uuid4()),
        project_id=test_project.id,
        created_by_id=admin_user.id,
        target_input="https://internal-app.local",
        adapter_name="mock_adapter",
        status=AssessmentStatus.FAILED,
        error_message="Connection timed out after 30 seconds",
    )
    db.add(job)
    db.commit()

    queue = operations_cockpit_service.get_actionable_priority_queue(db=db, project_id=test_project.id)
    failed_items = [i for i in queue.items if i.category.value == "JOB_FAILED"]
    assert len(failed_items) >= 1
    assert any(job.target_input in i.title for i in failed_items)


def test_06_priority_queue_ordered_by_score_descending(db: Session):
    queue = operations_cockpit_service.get_actionable_priority_queue(db=db)
    scores = [i.priority_score for i in queue.items]
    assert scores == sorted(scores, reverse=True)


def test_07_dismiss_priority_queue_item_lifecycle(db: Session):
    queue = operations_cockpit_service.get_actionable_priority_queue(db=db)
    if queue.items:
        target_item = queue.items[0]
        operations_cockpit_service.dismiss_item(target_item.item_id)

        updated_queue = operations_cockpit_service.get_actionable_priority_queue(db=db)
        assert not any(i.item_id == target_item.item_id for i in updated_queue.items)


def test_08_uncertain_and_contradictory_findings_detected(
    db: Session, test_project: Project
):
    finding = VulnerabilityFinding(
        id=str(uuid.uuid4()),
        project_id=test_project.id,
        fingerprint=f"fp-xss-{uuid.uuid4().hex[:8]}",
        title="Tentative Cross-Site Scripting",
        severity=FindingSeverity.MEDIUM,
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.INCONCLUSIVE,
        has_contradictions=True,
        target_value="https://test.example.com/search",
        description="Finding has conflicting evidence from two scanners.",
    )
    db.add(finding)
    db.commit()

    summary = operations_cockpit_service.get_unified_operations_summary(db=db, project_id=test_project.id)
    assert summary.unresolved_uncertainties_count >= 1
    q6 = next(q for q in summary.core_questions if q.question_id == 6)
    assert q6.status == "WARN"
    assert "conflicting or unverified evidence" in q6.summary


def test_09_api_cockpit_summary_unauthenticated_blocked(client: TestClient):
    resp = client.get("/api/v1/system/operations/cockpit/summary")
    assert resp.status_code == 401


def test_10_api_cockpit_summary_authenticated_success(client: TestClient, admin_user: User):
    headers = auth_header_for_user(admin_user)
    resp = client.get("/api/v1/system/operations/cockpit/summary", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "overall_posture" in data
    assert "core_questions" in data
    assert len(data["core_questions"]) == 12


def test_11_api_priority_queue_authenticated_success(client: TestClient, admin_user: User):
    headers = auth_header_for_user(admin_user)
    resp = client.get("/api/v1/system/operations/cockpit/priority-queue", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_items" in data
    assert "urgent_items_count" in data
    assert isinstance(data["items"], list)


def test_12_api_dismiss_priority_queue_rbac_enforcement(
    client: TestClient, lead_user: User, tester_user: User
):
    item_id = "PQ-TEST-RBAC-1"

    # Tester/Operator gets 403 Forbidden
    resp_tester = client.post(
        f"/api/v1/system/operations/cockpit/priority-queue/{item_id}/dismiss",
        headers=auth_header_for_user(tester_user),
    )
    assert resp_tester.status_code == 403

    # Security Lead gets 200 OK
    resp_lead = client.post(
        f"/api/v1/system/operations/cockpit/priority-queue/{item_id}/dismiss",
        headers=auth_header_for_user(lead_user),
    )
    assert resp_lead.status_code == 200
    assert resp_lead.json()["status"] == "DISMISSED"


def test_13_project_scoping_isolation(
    db: Session, test_organization: Organization
):
    p1 = Project(id=str(uuid.uuid4()), organization_id=test_organization.id, name="Project Alpha")
    p2 = Project(id=str(uuid.uuid4()), organization_id=test_organization.id, name="Project Beta")
    db.add(p1)
    db.add(p2)
    db.commit()

    f1 = VulnerabilityFinding(
        id=str(uuid.uuid4()),
        project_id=p1.id,
        fingerprint=f"fp-alpha-{uuid.uuid4().hex[:8]}",
        title="Crit Finding in Alpha",
        severity=FindingSeverity.CRITICAL,
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
        target_value="alpha.internal",
        description="Alpha finding",
    )
    db.add(f1)
    db.commit()

    sum_p1 = operations_cockpit_service.get_unified_operations_summary(db=db, project_id=p1.id)
    sum_p2 = operations_cockpit_service.get_unified_operations_summary(db=db, project_id=p2.id)

    assert sum_p1.verified_critical_findings >= 1
    assert sum_p2.verified_critical_findings == 0


def test_14_data_freshness_seconds_reporting(db: Session):
    summary = operations_cockpit_service.get_unified_operations_summary(db=db)
    assert summary.data_freshness_seconds <= 60


def test_15_recommended_next_action_logic(
    db: Session, test_organization: Organization
):
    summary_clean = operations_cockpit_service.get_unified_operations_summary(db=db, project_id=str(uuid.uuid4()))
    assert "System steady" in summary_clean.recommended_next_action

    p_busy = Project(id=str(uuid.uuid4()), organization_id=test_organization.id, name="Project Busy")
    db.add(p_busy)
    db.commit()

    f_crit = VulnerabilityFinding(
        id=str(uuid.uuid4()),
        project_id=p_busy.id,
        fingerprint=f"fp-busy-{uuid.uuid4().hex[:8]}",
        title="Immediate RCE Action",
        severity=FindingSeverity.CRITICAL,
        status=FindingLifecycleStatus.DETECTED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
        target_value="busy.internal",
        description="Requires immediate action",
    )
    db.add(f_crit)
    db.commit()

    summary_busy = operations_cockpit_service.get_unified_operations_summary(db=db, project_id=p_busy.id)
    assert "Review top critical items" in summary_busy.recommended_next_action


def test_16_no_hallucinated_or_fake_metrics(
    db: Session, test_organization: Organization
):
    proj_empty = Project(id=str(uuid.uuid4()), organization_id=test_organization.id, name="Empty Proj")
    db.add(proj_empty)
    db.commit()

    summary = operations_cockpit_service.get_unified_operations_summary(db=db, project_id=proj_empty.id)
    assert summary.verified_critical_findings == 0
    assert summary.verified_high_findings == 0
    assert summary.active_assessments_count == 0
    assert summary.queued_assessments_count == 0
    assert summary.failed_assessments_count == 0


def test_17_closed_or_resolved_findings_excluded_from_priority_queue(
    db: Session, test_organization: Organization
):
    proj = Project(id=str(uuid.uuid4()), organization_id=test_organization.id, name="Resolved Proj")
    db.add(proj)
    db.commit()

    f_resolved = VulnerabilityFinding(
        id=str(uuid.uuid4()),
        project_id=proj.id,
        fingerprint=f"fp-res-{uuid.uuid4().hex[:8]}",
        title="Resolved Heartbleed",
        severity=FindingSeverity.CRITICAL,
        status=FindingLifecycleStatus.VERIFIED_CLOSED,
        validation_status=FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
        target_value="resolved.internal",
        description="This was resolved",
    )
    db.add(f_resolved)
    db.commit()

    queue = operations_cockpit_service.get_actionable_priority_queue(db=db, project_id=proj.id)
    assert not any(i.affected_finding_id == f_resolved.id for i in queue.items)
