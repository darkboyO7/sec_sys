import pytest
import hashlib
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.assessment import AssessmentJob, AssessmentFinding, AssessmentStatus, FindingSeverity
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.models.decision import (
    PostureChangeRecord,
    SecurityDecisionRecord,
    ChangeType,
    DecisionActionType,
    DecisionStatus,
)
from app.services.change_detection_service import ChangeDetectionService
from app.services.security_decision_service import SecurityDecisionService
from app.services.remediation_service import RemediationPrioritizationService
from app.services.contextual_risk_service import ContextualRiskService


def test_posture_change_detection_and_persistence(db: Session, test_project: Project, lead_user: User):
    """
    Verifies that ChangeDetectionService records confirmed deltas and distinguishes
    them from failed or timed-out scans.
    """
    now = datetime.now(timezone.utc)
    target = "http://127.0.0.1:9090"

    # Job 1: Initial completed assessment with 1 finding
    job1 = AssessmentJob(
        project_id=test_project.id,
        target_input=target,
        adapter_name="live_network_auditor_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(job1)
    db.commit()

    f1 = AssessmentFinding(
        job_id=job1.id,
        project_id=test_project.id,
        target_value=target,
        title="Missing Content-Security-Policy (CSP)",
        severity=FindingSeverity.HIGH,
        is_simulated=False,
    )
    db.add(f1)
    db.commit()

    # Job 2: Failed assessment -> Fails closed, does NOT claim findings resolved
    failed_job = AssessmentJob(
        project_id=test_project.id,
        target_input=target,
        adapter_name="live_network_auditor_adapter",
        status=AssessmentStatus.FAILED,
        failure_category="CONNECTION_REFUSED",
        created_by_id=lead_user.id,
    )
    db.add(failed_job)
    db.commit()

    changes_failed = ChangeDetectionService.analyze_assessment_deltas(
        db=db, project_id=test_project.id, current_job=failed_job
    )
    assert len(changes_failed) == 1
    assert changes_failed[0].is_confirmed is False
    assert "failed or timed out" in changes_failed[0].title

    # Job 3: Subsequent successful assessment where finding is now fixed (0 findings)
    job3 = AssessmentJob(
        project_id=test_project.id,
        target_input=target,
        adapter_name="live_network_auditor_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(job3)
    db.commit()

    changes_resolved = ChangeDetectionService.analyze_assessment_deltas(
        db=db, project_id=test_project.id, current_job=job3
    )
    assert any(c.change_type == ChangeType.RESOLVED_FINDING for c in changes_resolved)
    resolved_change = next(c for c in changes_resolved if c.change_type == ChangeType.RESOLVED_FINDING)
    assert resolved_change.is_confirmed is True
    assert "No Longer Observed" in resolved_change.title


def test_security_decision_proposal_deduplication(db: Session, test_project: Project, lead_user: User):
    """
    Verifies that the Security Decision Engine evaluates project exposures,
    proposes prioritized decisions, and avoids duplicate proposals.
    """
    now = datetime.now(timezone.utc)

    # Create active critical finding
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        target_value="http://127.0.0.1:8888",
        title="Untrusted TLS Certificate Authority",
        description="The target presents a self-signed or invalid certificate root.",
        severity=FindingSeverity.HIGH,
        vuln_id="CWE-295",
        status=FindingLifecycleStatus.DETECTED,
        fingerprint=hashlib.sha256("untrusted-tls-f2".encode("utf-8")).hexdigest(),
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    # First evaluation pass
    decisions1 = SecurityDecisionService.evaluate_and_propose_decisions(db=db, project_id=test_project.id)
    assert len(decisions1) >= 1
    prioritize_dec = next((d for d in decisions1 if d.action_type == DecisionActionType.PRIORITIZE_REMEDIATION), None)
    assert prioritize_dec is not None
    assert prioritize_dec.target_id == finding.id
    assert prioritize_dec.status == DecisionStatus.PROPOSED
    assert prioritize_dec.required_approval_role == "LEAD"

    # Second evaluation pass: Must deduplicate and NOT spawn duplicate proposals
    decisions2 = SecurityDecisionService.evaluate_and_propose_decisions(db=db, project_id=test_project.id)
    new_for_same = [d for d in decisions2 if d.action_type == DecisionActionType.PRIORITIZE_REMEDIATION and d.target_id == finding.id]
    assert len(new_for_same) == 0


def test_security_decision_execution_with_governance(db: Session, test_project: Project, lead_user: User):
    """
    Verifies that gated decisions enforce Lead approval and measure posture improvement upon execution.
    """
    analyst_user = User(
        email="analyst_p6@example.com",
        full_name="Analyst P6",
        hashed_password="pw",
        is_active=True,
    )
    db.add(analyst_user)
    db.flush()

    member_analyst = ProjectMember(
        project_id=test_project.id,
        user_id=analyst_user.id,
        role=ProjectRole.TESTER,
    )
    db.add(member_analyst)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        target_value="http://127.0.0.1:8888",
        title="Missing X-Frame-Options",
        description="Clickjacking vulnerability",
        severity=FindingSeverity.HIGH,
        vuln_id="CWE-1021",
        status=FindingLifecycleStatus.DETECTED,
        fingerprint=hashlib.sha256("xframe-f3".encode("utf-8")).hexdigest(),
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    # Propose decision
    decisions = SecurityDecisionService.evaluate_and_propose_decisions(db=db, project_id=test_project.id)
    decision = next(d for d in decisions if d.target_id == finding.id)

    # Tester attempt to execute gated decision without approval -> PermissionError
    with pytest.raises(PermissionError) as exc_info:
        SecurityDecisionService.execute_decision(
            db=db,
            project_id=test_project.id,
            decision_id=decision.id,
            actor=analyst_user,
            actor_role=ProjectRole.TESTER,
        )
    assert "requires explicit LEAD approval" in str(exc_info.value)

    # Project LEAD executes decision
    executed_dec = SecurityDecisionService.execute_decision(
        db=db,
        project_id=test_project.id,
        decision_id=decision.id,
        actor=lead_user,
        actor_role=ProjectRole.LEAD,
    )
    assert executed_dec.status == DecisionStatus.EXECUTED
    assert executed_dec.executed_at is not None
    assert executed_dec.execution_outcome is not None
    assert "guidance_title" in executed_dec.execution_outcome or "recommendation_id" in executed_dec.execution_outcome
    assert executed_dec.posture_improvement_measured is not None


def test_closed_loop_overview_telemetry(db: Session, test_project: Project, lead_user: User):
    """
    Verifies that get_closed_loop_overview synthesizes active feedback metrics.
    """
    overview = SecurityDecisionService.get_closed_loop_overview(db=db, project_id=test_project.id)
    assert overview["project_id"] == test_project.id
    assert "active_posture" in overview
    assert "total_posture_changes" in overview
    assert "proposed_decisions_count" in overview
    assert "executed_decisions_count" in overview
    assert isinstance(overview["recent_changes"], list)
    assert isinstance(overview["pending_decisions"], list)


def test_decisions_rest_api_lifecycle(client: TestClient, lead_headers: dict, test_project: Project, db: Session):
    """
    Verifies the closed loop REST API endpoints via TestClient.
    """
    headers = lead_headers

    # 1. Create a critical finding to trigger a proposal
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        target_value="http://127.0.0.1:7777",
        title="Missing Strict-Transport-Security (API Test)",
        description="SSL stripping exposure",
        severity=FindingSeverity.HIGH,
        vuln_id="CWE-319",
        status=FindingLifecycleStatus.DETECTED,
        fingerprint=hashlib.sha256("hsts-api-p6".encode("utf-8")).hexdigest(),
    )
    db.add(finding)
    db.commit()

    # 2. Trigger autonomous decision evaluation
    eval_res = client.post(f"/api/v1/projects/{test_project.id}/decisions/evaluate", headers=headers)
    assert eval_res.status_code == 200
    decisions = eval_res.json()
    assert len(decisions) >= 1
    target_dec = next((d for d in decisions if d["target_id"] == finding.id), decisions[0])

    # 3. Approve decision as Project LEAD
    app_res = client.post(f"/api/v1/projects/{test_project.id}/decisions/{target_dec['id']}/approve", headers=headers)
    assert app_res.status_code == 200
    assert app_res.json()["status"] == DecisionStatus.APPROVED.value

    # 4. Execute decision
    exec_res = client.post(f"/api/v1/projects/{test_project.id}/decisions/{target_dec['id']}/execute", headers=headers)
    assert exec_res.status_code == 200
    assert exec_res.json()["status"] == DecisionStatus.EXECUTED.value

    # 5. Fetch closed-loop overview
    overview_res = client.get(f"/api/v1/projects/{test_project.id}/closed-loop/overview", headers=headers)
    assert overview_res.status_code == 200
    data = overview_res.json()
    assert data["project_id"] == test_project.id
    assert data["executed_decisions_count"] >= 1


def test_reassess_changed_asset_fails_closed_when_out_of_scope(db: Session, test_project: Project, lead_user: User):
    """
    Verifies that autonomous actions fail closed if the target is out of scope.
    """
    out_of_scope_target = "http://192.168.100.200:8080"
    change = ChangeDetectionService.record_change(
        db=db,
        project_id=test_project.id,
        change_type=ChangeType.CONFIG_CHANGED,
        target_resource=out_of_scope_target,
        title=f"Configuration modified on {out_of_scope_target}",
        previous_state={},
        new_state={"modified": True},
        evidence_summary="Config changed",
        confidence=1.0,
        is_confirmed=True,
    )

    decisions = SecurityDecisionService.evaluate_and_propose_decisions(db=db, project_id=test_project.id)
    reassess_dec = next(d for d in decisions if d.target_id == out_of_scope_target)

    executed = SecurityDecisionService.execute_decision(
        db=db,
        project_id=test_project.id,
        decision_id=reassess_dec.id,
        actor=lead_user,
        actor_role=ProjectRole.LEAD,
    )
    assert executed.status == DecisionStatus.REJECTED
    assert "Execution boundary denied" in executed.execution_outcome["error"]
