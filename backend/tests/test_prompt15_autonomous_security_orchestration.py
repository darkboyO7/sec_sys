import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.verification import RemediationVerification, VerificationOutcome, VerificationMethod
from app.models.orchestration import (
    OrchestrationState,
    OrchestrationEventType,
    OrchestrationActionType,
    OutcomeMeasurementStatus,
    EventProcessingStatus,
    InvalidationStatus,
    OrchestrationEventRecord,
    OrchestrationWorkflowRecord,
    DependencyInvalidationRecord,
    AdaptiveOptimizationRecord,
)
from app.models.decision import AutonomousPolicyRecord
from app.services.orchestration_state_machine import (
    OrchestrationStateMachine,
    OrchestrationTransitionError,
    ConcurrencyLockError,
)
from app.services.event_processing_service import EventProcessingService
from app.services.decision_planner_service import DecisionPlannerService
from app.services.dependency_invalidation_service import DependencyInvalidationService
from app.services.closed_loop_measurement_service import ClosedLoopMeasurementService
from app.services.adaptive_optimization_service import AdaptiveOptimizationService
from app.services.autonomous_orchestration_engine import (
    AutonomousOrchestrationEngine,
    OrchestrationAuthorizationError,
)
from app.services.policy_engine import PolicyEngineService


# ==============================================================================
# Scenario 1: Valid Authorized Event Produces Justified Assessment Recommendation
# ==============================================================================
def test_scenario_01_valid_authorized_event_produces_recommendation(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="api.internal.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    event, is_new, msg = EventProcessingService.ingest_event(
        db=db,
        project_id=test_project.id,
        event_type=OrchestrationEventType.CONFIG_CHANGED,
        target_resource="api.internal.corp",
        payload={"diff": "TLS ciphers updated"},
    )
    assert is_new
    assert event.status == EventProcessingStatus.RECEIVED

    plan = DecisionPlannerService.plan_next_action(
        db=db,
        project_id=test_project.id,
        event=event,
    )

    assert plan["action_type"] == OrchestrationActionType.REASSESS_CHANGED_ASSET
    assert plan["is_authorized"] is True
    assert "TLS ciphers" in str(event.payload)


# ==============================================================================
# Scenario 2: Duplicate Event Does Not Create Duplicate Work (Coalesced within Window)
# ==============================================================================
def test_scenario_02_duplicate_event_does_not_create_duplicate_work(
    db: Session,
    test_project: Project,
):
    event1, is_new1, _ = EventProcessingService.ingest_event(
        db=db,
        project_id=test_project.id,
        event_type=OrchestrationEventType.CONFIG_CHANGED,
        target_resource="192.168.1.50",
        payload={"service": "nginx"},
    )
    assert is_new1

    # Second delivery with identical signature within window
    event2, is_new2, msg2 = EventProcessingService.ingest_event(
        db=db,
        project_id=test_project.id,
        event_type=OrchestrationEventType.CONFIG_CHANGED,
        target_resource="192.168.1.50",
        payload={"service": "nginx"},
    )
    assert not is_new2
    assert "coalesced" in msg2.lower()
    assert event2.id == event1.id
    assert event2.coalesced_count == 2


# ==============================================================================
# Scenario 3: Target Authorization Revoked Before Execution Blocks Queued Action
# ==============================================================================
def test_scenario_03_revoked_target_authorization_blocks_execution(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="10.0.0.15",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    event, is_new, _ = EventProcessingService.ingest_event(
        db=db,
        project_id=test_project.id,
        event_type=OrchestrationEventType.CONFIG_CHANGED,
        target_resource="10.0.0.15",
    )
    wf = AutonomousOrchestrationEngine.create_or_resume_workflow(db=db, project_id=test_project.id, event=event)

    # Move to ACTION_QUEUED while authorized
    OrchestrationStateMachine.transition(wf, OrchestrationState.CONTEXT_GATHERED)
    OrchestrationStateMachine.transition(wf, OrchestrationState.DECISION_PENDING)
    wf.recommended_action = OrchestrationActionType.REASSESS_CHANGED_ASSET
    OrchestrationStateMachine.transition(wf, OrchestrationState.ACTION_QUEUED)
    db.commit()

    # Adversarial action: Revoke scope authorization right before execution
    target.authorization_status = AuthorizationStatus.REVOKED
    db.commit()

    # Attempt to execute workflow cycle
    res = AutonomousOrchestrationEngine.execute_workflow_cycle(db=db, workflow_id=wf.id)
    assert wf.state == OrchestrationState.FAILED
    assert "denial" in wf.failure_reason.lower() or "revoked" in wf.failure_reason.lower() or "not authorized" in wf.failure_reason.lower()


# ==============================================================================
# Scenario 4: New Scope Exclusion Invalidates Previously Accepted Recommendation
# ==============================================================================
def test_scenario_04_scope_exclusion_invalidates_accepted_recommendation(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="172.16.0.22",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    event, _, _ = EventProcessingService.ingest_event(
        db=db,
        project_id=test_project.id,
        event_type=OrchestrationEventType.CONFIG_CHANGED,
        target_resource="172.16.0.22",
    )
    wf = AutonomousOrchestrationEngine.create_or_resume_workflow(db=db, project_id=test_project.id, event=event)

    # Move to ACTION_QUEUED
    OrchestrationStateMachine.transition(wf, OrchestrationState.CONTEXT_GATHERED)
    OrchestrationStateMachine.transition(wf, OrchestrationState.DECISION_PENDING)
    wf.recommended_action = OrchestrationActionType.REASSESS_CHANGED_ASSET
    OrchestrationStateMachine.transition(wf, OrchestrationState.ACTION_QUEUED)
    db.commit()

    # Emergency exclusion added
    exclusion = ScopeExclusion(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="172.16.0.22",
        reason="Critical infrastructure protected",
        created_by_id=lead_user.id,
    )
    db.add(exclusion)
    db.commit()

    res = AutonomousOrchestrationEngine.execute_workflow_cycle(db=db, workflow_id=wf.id)
    assert wf.state == OrchestrationState.FAILED
    assert "denial" in wf.failure_reason.lower() or "excluded" in wf.failure_reason.lower()


# ==============================================================================
# Scenario 5: Relevant Asset Change Invalidates Dependent Derived Records
# ==============================================================================
def test_scenario_05_asset_change_invalidates_derived_records(
    db: Session,
    test_project: Project,
):
    asset = Asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        name="Production Database Host",
        canonical_identifier="db-prod-01",
        asset_type=AssetType.HOST,
        criticality=AssetCriticality.CRITICAL,
    )
    db.add(asset)
    db.commit()

    inv = DependencyInvalidationService.invalidate_for_asset_change(
        db=db,
        project_id=test_project.id,
        asset_id=asset.id,
    )
    assert inv.invalidation_type == "ASSET_CHANGED"
    assert inv.recalculation_status == InvalidationStatus.PENDING

    processed = DependencyInvalidationService.process_pending_recalculations(
        db=db,
        project_id=test_project.id,
    )
    assert processed >= 1
    assert inv.recalculation_status == InvalidationStatus.RECALCULATED


# ==============================================================================
# Scenario 6: Failed Assessment Follows Bounded Retry Rules
# ==============================================================================
def test_scenario_06_failed_assessment_bounded_retries(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    wf = OrchestrationWorkflowRecord(
        project_id=test_project.id,
        state=OrchestrationState.FAILED,
        target_resource="192.168.1.1",
        attempt_count=3,
        max_retries=3,
    )
    db.add(wf)
    db.commit()

    with pytest.raises(OrchestrationTransitionError) as exc:
        AutonomousOrchestrationEngine.retry_workflow(
            db=db,
            workflow_id=wf.id,
            user=lead_user,
        )
    assert "maximum retry attempts" in str(exc.value).lower()


# ==============================================================================
# Scenario 7: Interrupted Workflow Recovers Safely without Duplicating Actions
# ==============================================================================
def test_scenario_07_interrupted_workflow_recovers_without_duplication(
    db: Session,
    test_project: Project,
):
    past_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    wf = OrchestrationWorkflowRecord(
        project_id=test_project.id,
        state=OrchestrationState.ACTION_RUNNING,
        target_resource="10.0.0.1",
        locked_by="crashed-worker-pid-9999",
        locked_at=past_time,
        lock_expires_at=past_time + timedelta(seconds=60),  # expired 4 mins ago
    )
    db.add(wf)
    db.commit()

    recovered = OrchestrationStateMachine.recover_expired_leases(db=db, project_id=test_project.id)
    assert recovered == 1
    assert wf.state == OrchestrationState.SUSPENDED
    assert wf.locked_by is None
    assert "expired" in wf.suspension_reason.lower()


# ==============================================================================
# Scenario 8: Verified Finding Produces Remediation Recommendation
# ==============================================================================
def test_scenario_08_verified_finding_produces_remediation_recommendation(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        target_value="api.internal",
        fingerprint=hashlib.sha256(b"sqli-1").hexdigest(),
        title="SQL Injection in Auth Endpoint",
        vuln_id="CVE-2026-9999",
        status=FindingLifecycleStatus.CONFIRMED,
        severity=FindingSeverity.CRITICAL,
        first_detected_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc),
    )
    db.add(finding)
    db.commit()

    event = OrchestrationEventRecord(
        project_id=test_project.id,
        event_type=OrchestrationEventType.FINDING_DETECTED,
        target_resource="api.internal",
        payload={"finding_id": finding.id, "is_disruptive": False},
        dedup_key="finding-1",
    )
    db.add(event)
    db.commit()

    plan = DecisionPlannerService.plan_next_action(db=db, project_id=test_project.id, event=event)
    assert plan["action_type"] in (
        OrchestrationActionType.RECOMMEND_REMEDIATION,
        OrchestrationActionType.REQUEST_HUMAN_APPROVAL,
    )
    assert plan["references"]["finding_id"] == finding.id


# ==============================================================================
# Scenario 9: Remediation Requiring Approval Cannot Execute Without It
# ==============================================================================
def test_scenario_09_remediation_requiring_approval_cannot_execute_without_it(
    db: Session,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    wf = OrchestrationWorkflowRecord(
        project_id=test_project.id,
        state=OrchestrationState.AWAITING_APPROVAL,
        target_resource="core-router",
        recommended_action=OrchestrationActionType.RECOMMEND_REMEDIATION,
        required_approval_role="LEAD",
    )
    db.add(wf)
    db.commit()

    # Tester user cannot approve
    with pytest.raises(OrchestrationAuthorizationError):
        AutonomousOrchestrationEngine.approve_workflow(
            db=db,
            workflow_id=wf.id,
            user=tester_user,
            user_role=ProjectRole.TESTER,
        )

    # Lead user can approve
    wf_approved = AutonomousOrchestrationEngine.approve_workflow(
        db=db,
        workflow_id=wf.id,
        user=lead_user,
        user_role=ProjectRole.LEAD,
        notes="Approved by Lead",
    )
    assert wf_approved.state == OrchestrationState.ACTION_QUEUED
    assert wf_approved.approved_by_id == lead_user.id


# ==============================================================================
# Scenario 10: Inconclusive Retest Cannot Close Finding
# ==============================================================================
def test_scenario_10_inconclusive_retest_cannot_close_finding(
    db: Session,
    test_project: Project,
):
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        target_value="http://app.internal/profile",
        fingerprint=hashlib.sha256(b"xss-1").hexdigest(),
        title="Cross-Site Scripting in User Profile",
        status=FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
        severity=FindingSeverity.HIGH,
        first_detected_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc),
    )
    db.add(finding)
    db.commit()

    verification = RemediationVerification(
        project_id=test_project.id,
        finding_id=finding.id,
        verification_method=VerificationMethod.RETEST_ASSESSMENT,
        outcome=VerificationOutcome.INCONCLUSIVE,
        verification_criteria="Target port closed or filter active",
        verification_evidence_summary="Target timed out during verification scan",
        notes="Retest scan inconclusive",
        verified_at=datetime.now(timezone.utc),
    )
    db.add(verification)
    db.commit()

    wf = OrchestrationWorkflowRecord(
        project_id=test_project.id,
        state=OrchestrationState.VERIFYING_OUTCOME,
        target_resource="http://app.internal/profile",
        verification_id=verification.id,
    )
    db.add(wf)
    db.commit()

    res = ClosedLoopMeasurementService.evaluate_and_record_outcome(
        db=db,
        workflow=wf,
        initial_snapshot={"risk_score": 75.0, "verified_closed_count": 0},
        execution_result={"status": "COMPLETED"},
        verification_id=verification.id,
    )

    assert wf.outcome_status == OutcomeMeasurementStatus.OUTCOME_INCONCLUSIVE
    assert finding.status != FindingLifecycleStatus.VERIFIED_CLOSED


# ==============================================================================
# Scenario 11: Successful Retest Updates Downstream State Consistently
# ==============================================================================
def test_scenario_11_successful_retest_updates_downstream_state(
    db: Session,
    test_project: Project,
):
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        target_value="https://api.corp",
        fingerprint=hashlib.sha256(b"tls-1").hexdigest(),
        title="Weak SSL/TLS Cipher Enabled",
        status=FindingLifecycleStatus.VERIFIED_CLOSED,
        severity=FindingSeverity.MEDIUM,
        first_detected_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc),
    )
    db.add(finding)
    db.commit()

    verification = RemediationVerification(
        project_id=test_project.id,
        finding_id=finding.id,
        verification_method=VerificationMethod.RETEST_ASSESSMENT,
        outcome=VerificationOutcome.VERIFIED_FIXED,
        verification_criteria="Cipher suite 3DES-CBC no longer accepted",
        verification_evidence_summary="Handshake rejected weak cipher suites",
        notes="Remediation verified fixed",
        verified_at=datetime.now(timezone.utc),
    )
    db.add(verification)
    db.commit()

    wf = OrchestrationWorkflowRecord(
        project_id=test_project.id,
        state=OrchestrationState.VERIFYING_OUTCOME,
        target_resource="https://api.corp",
        verification_id=verification.id,
    )
    db.add(wf)
    db.commit()

    res = ClosedLoopMeasurementService.evaluate_and_record_outcome(
        db=db,
        workflow=wf,
        initial_snapshot={"risk_score": 60.0, "verified_closed_count": 0},
        execution_result={"status": "COMPLETED"},
        verification_id=verification.id,
    )

    assert wf.outcome_status == OutcomeMeasurementStatus.FINDING_VERIFIED_RESOLVED


# ==============================================================================
# Scenario 12: Evidence Integrity Failure Suspends Dependent Conclusions
# ==============================================================================
def test_scenario_12_evidence_integrity_failure_suspends_conclusions(
    db: Session,
    test_project: Project,
):
    event = OrchestrationEventRecord(
        project_id=test_project.id,
        event_type=OrchestrationEventType.INTEGRITY_ALERT,
        target_resource="evidence-sha-mismatch",
        payload={"alert_detail": "Evidence digest modified after scan"},
        dedup_key="integrity-alert-1",
    )
    db.add(event)
    db.commit()

    plan = DecisionPlannerService.plan_next_action(db=db, project_id=test_project.id, event=event)
    assert plan["action_type"] == OrchestrationActionType.SUSPEND_ACTIVITY
    assert "integrity breach" in plan["rationale"].lower()


# ==============================================================================
# Scenario 13: Resource Limit Prevents Additional Work Without Losing Event History
# ==============================================================================
def test_scenario_13_resource_limit_prevents_unlimited_work(
    db: Session,
    test_project: Project,
):
    # Saturate event queue
    for i in range(EventProcessingService.MAX_PROJECT_QUEUED_EVENTS):
        ev = OrchestrationEventRecord(
            project_id=test_project.id,
            event_type=OrchestrationEventType.SCAN_COMPLETED,
            target_resource=f"host-{i}",
            dedup_key=f"saturation-{i}",
            status=EventProcessingStatus.RECEIVED,
        )
        db.add(ev)
    db.commit()

    # Ingest 51st event
    ev_overflow, is_new, msg = EventProcessingService.ingest_event(
        db=db,
        project_id=test_project.id,
        event_type=OrchestrationEventType.SCAN_COMPLETED,
        target_resource="host-overflow",
    )

    assert not is_new
    assert ev_overflow.status == EventProcessingStatus.REJECTED
    assert "saturated" in ev_overflow.rejection_reason.lower()


# ==============================================================================
# Scenario 14: Recovery Action Cannot Bypass Policy Enforcement
# ==============================================================================
def test_scenario_14_recovery_action_cannot_bypass_policy_enforcement(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    policy = PolicyEngineService.get_or_create_policy(db=db, project_id=test_project.id)
    policy.is_suspended = True
    policy.suspension_reason = "Emergency Safety Lock"
    db.commit()

    wf = OrchestrationWorkflowRecord(
        project_id=test_project.id,
        state=OrchestrationState.SUSPENDED,
        target_resource="192.168.1.10",
        recommended_action=OrchestrationActionType.REASSESS_CHANGED_ASSET,
    )
    db.add(wf)
    db.commit()

    with pytest.raises(OrchestrationAuthorizationError) as exc:
        AutonomousOrchestrationEngine.resume_workflow(
            db=db,
            workflow_id=wf.id,
            user=lead_user,
        )
    assert "policy is suspended" in str(exc.value).lower()


# ==============================================================================
# Scenario 15: Model Update that Fails Evaluation Does Not Change Accepted Behavior
# ==============================================================================
def test_scenario_15_model_update_failing_evaluation_is_rejected(
    db: Session,
    test_project: Project,
):
    rec = AdaptiveOptimizationService.evaluate_optimization_proposal(
        db=db,
        project_id=test_project.id,
        optimization_name="REDUCE_SCAN_CADENCE_LOW_RISK",
        objective="Decrease scan frequency on static assets",
        evaluation_metric="accuracy_score",
        baseline_value=0.90,
        evaluated_value=0.75,  # Below threshold
        threshold_value=0.88,
        dataset_summary={"sample_size": 200},
        rollback_payload={"cadence": "DAILY"},
    )

    assert rec.is_accepted is False
    assert "failed threshold" in rec.rejection_reason.lower()


# ==============================================================================
# Scenario 16: Tenant Boundaries Preserved Across Orchestration and Audit Records
# ==============================================================================
def test_scenario_16_tenant_isolation_in_orchestration(
    db: Session,
    test_project: Project,
    client: TestClient,
    lead_headers: dict,
    outsider_headers: dict,
):
    event, _, _ = EventProcessingService.ingest_event(
        db=db,
        project_id=test_project.id,
        event_type=OrchestrationEventType.CONFIG_CHANGED,
        target_resource="tenant-protected.host",
    )

    # Lead user on project can access dashboard
    resp_lead = client.get(f"/api/v1/orchestration/{test_project.id}/dashboard", headers=lead_headers)
    assert resp_lead.status_code == 200
    assert resp_lead.json()["project_id"] == test_project.id

    # Outsider user is blocked by 403 Forbidden or 404 Not Found (fail-closed tenant protection)
    resp_outsider = client.get(f"/api/v1/orchestration/{test_project.id}/dashboard", headers=outsider_headers)
    assert resp_outsider.status_code in (403, 404)


# ==============================================================================
# Scenario 17: UI Reflects Persisted Workflow State Rather Than Stale Cached Status
# ==============================================================================
def test_scenario_17_api_reflects_persisted_workflow_state(
    db: Session,
    test_project: Project,
    client: TestClient,
    lead_headers: dict,
):
    wf = OrchestrationWorkflowRecord(
        project_id=test_project.id,
        state=OrchestrationState.DECISION_PENDING,
        target_resource="db.live",
        recommended_action=OrchestrationActionType.REASSESS_CHANGED_ASSET,
    )
    db.add(wf)
    db.commit()

    # Mutate to ACTION_RUNNING
    OrchestrationStateMachine.transition(wf, OrchestrationState.ACTION_QUEUED)
    OrchestrationStateMachine.transition(wf, OrchestrationState.ACTION_RUNNING)
    db.commit()

    resp = client.get(f"/api/v1/orchestration/{test_project.id}/workflows/{wf.id}", headers=lead_headers)
    assert resp.status_code == 200
    assert resp.json()["state"] == "ACTION_RUNNING"


# ==============================================================================
# Scenario 18: Replaying Completed Event Cannot Silently Rewrite Historical Outcome
# ==============================================================================
def test_scenario_18_replaying_completed_event_is_immutable(
    db: Session,
    test_project: Project,
):
    event, is_new, _ = EventProcessingService.ingest_event(
        db=db,
        project_id=test_project.id,
        event_type=OrchestrationEventType.SCAN_COMPLETED,
        target_resource="host-historical",
        payload={"scan_id": "historical-123"},
    )
    wf = AutonomousOrchestrationEngine.create_or_resume_workflow(db=db, project_id=test_project.id, event=event)

    # Complete workflow
    OrchestrationStateMachine.transition(wf, OrchestrationState.CONTEXT_GATHERED)
    OrchestrationStateMachine.transition(wf, OrchestrationState.DECISION_PENDING)
    OrchestrationStateMachine.transition(wf, OrchestrationState.ACTION_QUEUED)
    OrchestrationStateMachine.transition(wf, OrchestrationState.ACTION_RUNNING)
    OrchestrationStateMachine.transition(wf, OrchestrationState.VERIFYING_OUTCOME)
    wf.outcome_status = OutcomeMeasurementStatus.ACTION_EXECUTED_SUCCESSFULLY
    OrchestrationStateMachine.transition(wf, OrchestrationState.COMPLETED)
    EventProcessingService.mark_event_processed(db=db, event=event)
    db.commit()

    initial_completed_at = wf.completed_at
    assert initial_completed_at is not None

    # Replay attempt: terminal workflow cannot be transitioned back or rewritten
    with pytest.raises(OrchestrationTransitionError):
        OrchestrationStateMachine.transition(wf, OrchestrationState.ACTION_RUNNING)

    db.refresh(wf)
    assert wf.state == OrchestrationState.COMPLETED
    assert wf.completed_at == initial_completed_at
