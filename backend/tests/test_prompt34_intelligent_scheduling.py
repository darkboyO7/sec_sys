"""
Unit & Integration Acceptance Tests for Prompt 34:
Intelligent Assessment Scheduling, Risk-Based Prioritization & Resource-Aware Orchestration.
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
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    FindingSeverity,
)
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
)
from app.models.verification import RemediationVerification, VerificationOutcome, VerificationMethod
from app.models.compliance import ComplianceControlResultRecord, ComplianceEvaluationStatus
from app.models.drift import ExposureDriftRecord, DriftType, DriftMateriality
from app.models.scheduling import (
    QueueItemStatus,
    PriorityBand,
    EligibilityStatus,
    SchedulerDecisionType,
    TriggerSourceType,
    AssessmentQueueItem,
    SchedulerDecisionRecord,
    SchedulerPolicyRecord,
)
from app.services.scheduling_service import SchedulingService
from app.schemas.scheduling import QueueItemCreate, SchedulerPolicyUpdate
from app.core.exceptions import ValidationError, NotFoundError


@pytest.fixture
def test_org(db):
    org = Organization(name="Scheduling Test Org", slug="sched-test-org")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@pytest.fixture
def sched_users(db, test_org):
    lead = User(
        email="lead.sched@example.com",
        full_name="Scheduling Lead",
        hashed_password="pw",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    tester = User(
        email="tester.sched@example.com",
        full_name="Scheduling Tester",
        hashed_password="pw",
        system_role=SystemRole.SECURITY_TESTER,
        is_active=True,
    )
    viewer = User(
        email="viewer.sched@example.com",
        full_name="Scheduling Viewer",
        hashed_password="pw",
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    outsider = User(
        email="outsider.sched@example.com",
        full_name="Outsider Sched",
        hashed_password="pw",
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    db.add_all([lead, tester, viewer, outsider])
    db.commit()
    for u in [lead, tester, viewer, outsider]:
        db.refresh(u)
    return {"lead": lead, "tester": tester, "viewer": viewer, "outsider": outsider}


@pytest.fixture
def sched_project(db, test_org, sched_users):
    proj = Project(
        name="Scheduling Project",
        description="Scheduling Test Project",
        organization_id=test_org.id,
    )
    db.add(proj)
    db.commit()
    db.refresh(proj)

    m1 = ProjectMember(project_id=proj.id, user_id=sched_users["lead"].id, role=ProjectRole.LEAD)
    m2 = ProjectMember(project_id=proj.id, user_id=sched_users["tester"].id, role=ProjectRole.TESTER)
    m3 = ProjectMember(project_id=proj.id, user_id=sched_users["viewer"].id, role=ProjectRole.VIEWER)
    db.add_all([m1, m2, m3])
    db.commit()

    # Seed default policy
    SchedulingService.get_or_create_policy(db, proj.id)
    return proj


# ---------------------------------------------------------------------------
# Test 1: Deterministic Multi-Signal Priority Calculation
# ---------------------------------------------------------------------------
def test_deterministic_priority_calculation(db, test_org, sched_project):
    pid = sched_project.id
    target = "https://core-api.example.com"

    # Add Critical Asset
    asset = Asset(
        organization_id=test_org.id,
        project_id=pid,
        name="Core API",
        canonical_identifier=target,
        asset_type=AssetType.WEB_APP,
        criticality=AssetCriticality.CRITICAL,  # +30
        status=AssetStatus.ACTIVE,
    )
    # Add Critical Finding
    finding = VulnerabilityFinding(
        project_id=pid,
        title="Critical RCE",
        target_value=target,
        severity=FindingSeverity.CRITICAL,  # +25
        status=FindingLifecycleStatus.CONFIRMED,
        fingerprint=f"fp-{generate_uuid()}",
    )
    # Add Drift Event
    drift = ExposureDriftRecord(
        project_id=pid,
        target_resource=target,
        drift_type=DriftType.SERVICE_ADDED,
        materiality=DriftMateriality.MATERIAL,
        materiality_reason="Unregistered service exposed",
        title="Exposure Drift",
        previous_state={},
        new_state={},
        evidence_references=[],
    )
    db.add_all([asset, finding, drift])
    db.commit()

    prio = SchedulingService.calculate_priority(db, pid, target, "local_fixture_adapter")

    # Base: 20 + Crit Asset: 30 + Finding: 25 + Drift: 15 + Freshness (no prior scan): 20 = 110 -> clamped to 100.0
    assert prio.computed_priority == 100.0
    assert prio.priority_band == PriorityBand.CRITICAL
    assert "Base: 20" in prio.summary
    assert "Criticality: +30.0" in prio.summary
    assert "Findings: +25.0" in prio.summary
    assert "Drift: +15.0" in prio.summary
    assert prio.policy_version == "scheduling_v1.0"


# ---------------------------------------------------------------------------
# Test 2: Missing or Stale Evidence Affects Priority Correctly
# ---------------------------------------------------------------------------
def test_missing_or_stale_evidence_affects_priority_correctly(db, sched_project, sched_users):
    pid = sched_project.id
    target_unregistered = "https://unknown-host.example.com"

    # Case A: Coverage gap (never assessed before)
    prio_gap = SchedulingService.calculate_priority(db, pid, target_unregistered, "local_fixture_adapter")
    assert prio_gap.factors["evidence_staleness"]["contribution"] == 20.0
    assert prio_gap.factors["evidence_staleness"]["raw_value"] == "COVERAGE_GAP_NO_PRIOR_SCAN"
    assert "asset_criticality" in prio_gap.missing_evidence_signals

    # Case B: Stale assessment (> 30 days old)
    old_time = utc_now() - timedelta(days=35)
    old_job = AssessmentJob(
        project_id=pid,
        target_input=target_unregistered,
        status=AssessmentStatus.COMPLETED,
        completed_at=old_time,
        created_by_id=sched_users["lead"].id,
    )
    db.add(old_job)
    db.commit()

    prio_stale = SchedulingService.calculate_priority(db, pid, target_unregistered, "local_fixture_adapter")
    assert prio_stale.factors["evidence_staleness"]["contribution"] == 15.0
    assert "STALE_OVER_30_DAYS" in prio_stale.factors["evidence_staleness"]["raw_value"]

    # Case C: Fresh assessment (< 14 days old)
    fresh_time = utc_now() - timedelta(days=2)
    fresh_job = AssessmentJob(
        project_id=pid,
        target_input=target_unregistered,
        status=AssessmentStatus.COMPLETED,
        completed_at=fresh_time,
        created_by_id=sched_users["lead"].id,
    )
    db.add(fresh_job)
    db.commit()

    prio_fresh = SchedulingService.calculate_priority(db, pid, target_unregistered, "local_fixture_adapter")
    assert prio_fresh.factors["evidence_staleness"]["contribution"] == 0.0
    assert "FRESH" in prio_fresh.factors["evidence_staleness"]["raw_value"]


# ---------------------------------------------------------------------------
# Test 3: Priority Never Bypasses Scope or Authorization
# ---------------------------------------------------------------------------
def test_priority_never_bypasses_scope(db, sched_project, sched_users):
    pid = sched_project.id
    target_out_of_scope = "https://external-forbidden.org"

    # Define an authorized scope target
    scope = ScopeTarget(
        project_id=pid,
        target_type=TargetType.URL,
        target_value="https://internal.example.com",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=sched_users["lead"].id,
    )
    db.add(scope)
    db.commit()

    # Attempting to enqueue out-of-scope target must fail closed regardless of theoretical priority
    req = QueueItemCreate(target_input=target_out_of_scope)
    with pytest.raises(ValidationError) as exc:
        SchedulingService.enqueue_assessment(db, pid, sched_users["tester"].id, req)

    assert "outside authorized scope" in str(exc.value)

    # Verify decision ledger logged the rejection
    decision = db.query(SchedulerDecisionRecord).filter(
        SchedulerDecisionRecord.project_id == pid,
        SchedulerDecisionRecord.target_input == target_out_of_scope,
    ).first()
    assert decision is not None
    assert decision.decision_type == SchedulerDecisionType.REJECT


# ---------------------------------------------------------------------------
# Test 4: Explicit Scope Exclusions Take Absolute Precedence
# ---------------------------------------------------------------------------
def test_explicit_scope_exclusions_precedence(db, sched_project, sched_users):
    pid = sched_project.id
    target = "https://internal.example.com/sensitive-db"

    # Add inclusion for broad domain
    inc = ScopeTarget(
        project_id=pid,
        target_type=TargetType.URL,
        target_value="https://internal.example.com",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=sched_users["lead"].id,
    )
    # Add explicit exclusion for sensitive path
    exc = ScopeExclusion(
        project_id=pid,
        target_type=TargetType.URL,
        target_value="https://internal.example.com/sensitive-db",
        reason="Sensitive internal database",
        created_by_id=sched_users["lead"].id,
    )
    db.add_all([inc, exc])
    db.commit()

    req = QueueItemCreate(target_input=target)
    with pytest.raises(ValidationError) as err:
        SchedulingService.enqueue_assessment(db, pid, sched_users["tester"].id, req)

    assert "explicitly excluded scope rule" in str(err.value)


# ---------------------------------------------------------------------------
# Test 5: Preflight Eligibility Revocation Blocks Dispatch
# ---------------------------------------------------------------------------
def test_preflight_eligibility_revocation_blocks_dispatch(db, sched_project, sched_users):
    pid = sched_project.id
    target = "https://temp-allowed.example.com"

    inc = ScopeTarget(
        project_id=pid,
        target_type=TargetType.URL,
        target_value=target,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=sched_users["lead"].id,
    )
    db.add(inc)
    db.commit()

    # Enqueue when eligible
    item = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=target)
    )
    assert item.status == QueueItemStatus.SCHEDULED

    # Scope is revoked before execution! Authorization status is now REVOKED
    inc.authorization_status = AuthorizationStatus.REVOKED
    db.commit()

    # Dispatcher re-validates eligibility immediately before claiming
    dispatched, msg, dispatched_item, job_id = SchedulingService.dispatch_next_eligible(db, pid)

    assert dispatched is False
    assert "rejected at preflight" in msg

    # Item is marked FAILED with PREFLIGHT_ELIGIBILITY_REVOKED
    db.refresh(item)
    assert item.status == QueueItemStatus.FAILED
    assert item.last_error_category == "PREFLIGHT_ELIGIBILITY_REVOKED"


# ---------------------------------------------------------------------------
# Test 6: Deduplication of Identical Active Requests
# ---------------------------------------------------------------------------
def test_deduplication_of_identical_active_requests(db, sched_project, sched_users):
    pid = sched_project.id
    target = "https://dedup-test.example.com"

    inc = ScopeTarget(
        project_id=pid,
        target_type=TargetType.URL,
        target_value=target,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=sched_users["lead"].id,
    )
    db.add(inc)
    db.commit()

    # Enqueue first time
    item1 = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=target)
    )

    # Enqueue identical request
    item2 = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=target)
    )

    assert item1.id == item2.id

    # Verify decision logged as DEDUPLICATE
    dedup_decision = db.query(SchedulerDecisionRecord).filter(
        SchedulerDecisionRecord.project_id == pid,
        SchedulerDecisionRecord.decision_type == SchedulerDecisionType.DEDUPLICATE,
    ).first()
    assert dedup_decision is not None
    assert dedup_decision.queue_item_id == item1.id


# ---------------------------------------------------------------------------
# Test 7: Concurrency Control and Worker Leases
# ---------------------------------------------------------------------------
def test_concurrency_control_and_worker_leases(db, sched_project, sched_users):
    pid = sched_project.id
    target = "https://worker-lease.example.com"

    inc = ScopeTarget(
        project_id=pid,
        target_type=TargetType.URL,
        target_value=target,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=sched_users["lead"].id,
    )
    db.add(inc)
    db.commit()

    item = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=target)
    )

    dispatched, msg, claimed_item, job_id = SchedulingService.dispatch_next_eligible(
        db, pid, worker_id="worker-01"
    )

    assert dispatched is True
    assert claimed_item is not None
    assert claimed_item.status == QueueItemStatus.DISPATCHED
    assert claimed_item.worker_claim_id == "worker-01"
    assert claimed_item.claimed_at is not None
    assert claimed_item.lease_expires_at is not None
    assert claimed_item.job_id == job_id

    # Underlying AssessmentJob must be in RUNNING status
    job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
    assert job is not None
    assert job.status == AssessmentStatus.RUNNING


# ---------------------------------------------------------------------------
# Test 8: Stale Lease Recovery and Bounded Backoff
# ---------------------------------------------------------------------------
def test_stale_lease_recovery_and_bounded_backoff(db, sched_project, sched_users):
    pid = sched_project.id
    target = "https://stale-lease.example.com"

    inc = ScopeTarget(
        project_id=pid,
        target_type=TargetType.URL,
        target_value=target,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=sched_users["lead"].id,
    )
    db.add(inc)
    db.commit()

    item = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=target)
    )
    SchedulingService.dispatch_next_eligible(db, pid, worker_id="worker-crashed")

    # Simulate worker crash: lease expired 10 seconds ago
    db.refresh(item)
    item.lease_expires_at = utc_now() - timedelta(seconds=10)
    db.commit()

    # Run recovery
    rec = SchedulingService.recover_stale_leases(db, pid)
    assert rec.recovered_count == 1
    assert item.id in rec.recovered_ids

    # Item re-queued with backoff
    db.refresh(item)
    assert item.status == QueueItemStatus.SCHEDULED
    assert item.worker_claim_id is None
    assert item.retry_count == 1
    assert item.last_error_category == "LEASE_TIMEOUT_RECOVERED"


# ---------------------------------------------------------------------------
# Test 9: Dead-Lettering When Max Retries Exceeded
# ---------------------------------------------------------------------------
def test_dead_letter_max_retries_exceeded(db, sched_project, sched_users):
    pid = sched_project.id
    target = "https://dead-letter.example.com"

    inc = ScopeTarget(
        project_id=pid,
        target_type=TargetType.URL,
        target_value=target,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=sched_users["lead"].id,
    )
    db.add(inc)
    db.commit()

    item = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=target)
    )
    SchedulingService.dispatch_next_eligible(db, pid, worker_id="worker-crash-loop")

    db.refresh(item)
    # Set retries to maximum
    item.retry_count = item.max_retries
    item.lease_expires_at = utc_now() - timedelta(seconds=10)
    db.commit()

    rec = SchedulingService.recover_stale_leases(db, pid)
    assert rec.dead_letter_count == 1
    assert item.id in rec.dead_letter_ids

    db.refresh(item)
    assert item.status == QueueItemStatus.FAILED
    assert item.last_error_category == "DEAD_LETTER_MAX_RETRIES_EXCEEDED"


# ---------------------------------------------------------------------------
# Test 10: Anti-Starvation Aging Fairness
# ---------------------------------------------------------------------------
def test_anti_starvation_aging_fairness(db, sched_project, sched_users):
    pid = sched_project.id

    # Create two scope targets
    t1 = "https://old-low-priority.example.com"
    t2 = "https://new-high-priority.example.com"
    db.add_all([
        ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=t1, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id),
        ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=t2, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id),
    ])
    db.commit()

    # Item 1: Base priority 30, but created 15 hours ago (Aging: +30.0 effective boost at 2.0/hr -> 60.0)
    item_old = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=t1)
    )
    item_old.priority_score = 30.0
    item_old.created_at = utc_now() - timedelta(hours=15)
    db.commit()

    # Item 2: Fresh item with priority score 45.0, created right now (effective = 45.0)
    item_new = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=t2)
    )
    item_new.priority_score = 45.0
    item_new.created_at = utc_now()
    db.commit()

    # Dispatcher should choose item_old because its aging boosted its effective priority above item_new
    dispatched, msg, claimed, job_id = SchedulingService.dispatch_next_eligible(db, pid)
    assert dispatched is True
    assert claimed.id == item_old.id


# ---------------------------------------------------------------------------
# Test 11: Per-Target Concurrency Limit
# ---------------------------------------------------------------------------
def test_per_target_concurrency_limit(db, sched_project, sched_users):
    pid = sched_project.id
    target1 = "https://target-busy.example.com"
    target2 = "https://target-idle.example.com"

    db.add_all([
        ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=target1, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id),
        ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=target2, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id),
    ])
    db.commit()

    # Policy max_per_target_concurrency is 1
    # Enqueue target 1 and dispatch it
    item1 = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=target1)
    )
    SchedulingService.dispatch_next_eligible(db, pid)

    # Enqueue another job for target 1 (different adapter so not deduped)
    item1_second = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=target1, adapter_name="ssl_tls_analyzer")
    )
    item1_second.priority_score = 99.0  # Very high priority!
    db.commit()

    # Enqueue target 2 (lower priority)
    item2 = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=target2)
    )
    item2.priority_score = 40.0
    db.commit()

    # Next dispatch must skip item1_second because target1 is already running an assessment!
    dispatched, msg, claimed, job_id = SchedulingService.dispatch_next_eligible(db, pid)
    assert dispatched is True
    assert claimed.id == item2.id  # target 2 selected!


# ---------------------------------------------------------------------------
# Test 12: Observable Cancellation State
# ---------------------------------------------------------------------------
def test_observable_cancellation_state(db, sched_project, sched_users):
    pid = sched_project.id
    target = "https://cancel-test.example.com"

    db.add(ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=target, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id))
    db.commit()

    item = SchedulingService.enqueue_assessment(
        db, pid, sched_users["tester"].id, QueueItemCreate(target_input=target)
    )

    cancelled = SchedulingService.request_cancellation(
        db, pid, item.id, sched_users["tester"].id, reason="Testing cancellation flow"
    )

    assert cancelled.status == QueueItemStatus.CANCELLED
    assert cancelled.cancellation_requested_at is not None
    assert cancelled.cancelled_at is not None
    assert cancelled.cancellation_reason == "Testing cancellation flow"

    # Audit ledger records cancellation
    cancel_dec = db.query(SchedulerDecisionRecord).filter(
        SchedulerDecisionRecord.project_id == pid,
        SchedulerDecisionRecord.decision_type == SchedulerDecisionType.CANCEL,
    ).first()
    assert cancel_dec is not None


# ---------------------------------------------------------------------------
# Test 13: Reassessment Trigger Cooldown Deduplication
# ---------------------------------------------------------------------------
def test_reassessment_trigger_cooldown(db, sched_project, sched_users):
    pid = sched_project.id
    target = "https://cooldown-test.example.com"

    db.add(ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=target, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id))
    db.commit()

    # Trigger 1: Exposure drift detected
    item1 = SchedulingService.handle_reassessment_trigger(
        db, pid, sched_users["tester"].id, TriggerSourceType.DRIFT_DETECTED, target
    )
    assert item1.status == QueueItemStatus.SCHEDULED

    # Trigger 2: Another drift event immediately fired for same target within cooldown
    item2 = SchedulingService.handle_reassessment_trigger(
        db, pid, sched_users["tester"].id, TriggerSourceType.DRIFT_DETECTED, target
    )

    assert item1.id == item2.id

    # Verify decision logged as DEDUPLICATE within cooldown
    cooldown_dec = db.query(SchedulerDecisionRecord).filter(
        SchedulerDecisionRecord.project_id == pid,
        SchedulerDecisionRecord.decision_type == SchedulerDecisionType.DEDUPLICATE,
        SchedulerDecisionRecord.trigger_source == TriggerSourceType.DRIFT_DETECTED.value,
    ).first()
    assert cooldown_dec is not None


# ---------------------------------------------------------------------------
# Test 14: REST API Integration & RBAC Enforcement
# ---------------------------------------------------------------------------
def test_api_scheduling_endpoints(client: TestClient, db, sched_project, sched_users):
    pid = sched_project.id
    target = "https://api-sched.example.com"

    db.add(ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=target, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id))
    db.commit()

    headers_tester = auth_header_for_user(sched_users["tester"])
    headers_viewer = auth_header_for_user(sched_users["viewer"])
    headers_outsider = auth_header_for_user(sched_users["outsider"])

    # 1. Outsider cannot access project scheduling (404 defense)
    res_out = client.get(f"/api/v1/projects/{pid}/scheduling/queue", headers=headers_outsider)
    assert res_out.status_code == status.HTTP_404_NOT_FOUND

    # 2. Viewer can list queue and preview
    res_list = client.get(f"/api/v1/projects/{pid}/scheduling/queue", headers=headers_viewer)
    assert res_list.status_code == status.HTTP_200_OK

    res_prev = client.post(
        f"/api/v1/projects/{pid}/scheduling/preview",
        headers=headers_viewer,
        json={"target_input": target, "adapter_name": "local_fixture_adapter"},
    )
    assert res_prev.status_code == status.HTTP_200_OK
    assert res_prev.json()["is_eligible"] is True

    # 3. Viewer cannot enqueue (requires TESTER)
    res_enq_fail = client.post(
        f"/api/v1/projects/{pid}/scheduling/enqueue",
        headers=headers_viewer,
        json={"target_input": target},
    )
    assert res_enq_fail.status_code == status.HTTP_403_FORBIDDEN

    # 4. Tester can enqueue
    res_enq = client.post(
        f"/api/v1/projects/{pid}/scheduling/enqueue",
        headers=headers_tester,
        json={"target_input": target, "schedule_name": "API Enqueue Test"},
    )
    assert res_enq.status_code == status.HTTP_201_CREATED
    queue_id = res_enq.json()["id"]

    # 5. Capacity endpoint reflects queue item
    res_cap = client.get(f"/api/v1/projects/{pid}/scheduling/capacity", headers=headers_viewer)
    assert res_cap.status_code == status.HTTP_200_OK
    assert res_cap.json()["total_queued_items"] >= 1

    # 6. Dispatch Next Job via API
    res_disp = client.post(
        f"/api/v1/projects/{pid}/scheduling/dispatch-next?worker_id=worker-test-api",
        headers=headers_tester,
    )
    assert res_disp.status_code == status.HTTP_200_OK
    assert res_disp.json()["dispatched"] is True

    # 7. Cancel queue item
    res_cancel = client.post(
        f"/api/v1/projects/{pid}/scheduling/queue/{queue_id}/cancel",
        headers=headers_tester,
    )
    assert res_cancel.status_code == status.HTTP_200_OK
    assert res_cancel.json()["status"] == "CANCELLED"

    # 8. List Decisions
    res_dec = client.get(f"/api/v1/projects/{pid}/scheduling/decisions", headers=headers_viewer)
    assert res_dec.status_code == status.HTTP_200_OK
    assert len(res_dec.json()) >= 1


# ---------------------------------------------------------------------------
# Test 15: Global Concurrency Limit Deferral
# ---------------------------------------------------------------------------
def test_global_concurrency_limit_deferral(db, sched_project, sched_users):
    pid = sched_project.id
    policy = SchedulingService.get_or_create_policy(db, pid)
    policy.max_concurrent_assessments = 2
    db.commit()

    # Enqueue 3 items
    for i in range(3):
        t = f"https://limit-{i}.example.com"
        db.add(ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=t, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id))
        db.commit()
        SchedulingService.enqueue_assessment(db, pid, sched_users["tester"].id, QueueItemCreate(target_input=t))

    # Dispatch 1
    d1, _, _, _ = SchedulingService.dispatch_next_eligible(db, pid, worker_id="w-1")
    assert d1 is True
    # Dispatch 2
    d2, _, _, _ = SchedulingService.dispatch_next_eligible(db, pid, worker_id="w-2")
    assert d2 is True
    # Dispatch 3 must be deferred due to max_concurrent_assessments=2!
    d3, msg, _, _ = SchedulingService.dispatch_next_eligible(db, pid, worker_id="w-3")
    assert d3 is False
    assert "Global concurrent assessment limit" in msg


# ---------------------------------------------------------------------------
# Test 16: Per-Adapter Concurrency Limit
# ---------------------------------------------------------------------------
def test_per_adapter_concurrency_limit(db, sched_project, sched_users):
    pid = sched_project.id
    policy = SchedulingService.get_or_create_policy(db, pid)
    policy.max_per_adapter_concurrency = 1
    policy.max_concurrent_assessments = 5
    db.commit()

    t1 = "https://adapter-slot-1.example.com"
    t2 = "https://adapter-slot-2.example.com"
    db.add_all([
        ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=t1, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id),
        ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=t2, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id),
    ])
    db.commit()

    # Enqueue two items with the SAME adapter "local_fixture_adapter"
    SchedulingService.enqueue_assessment(db, pid, sched_users["tester"].id, QueueItemCreate(target_input=t1, adapter_name="local_fixture_adapter"))
    SchedulingService.enqueue_assessment(db, pid, sched_users["tester"].id, QueueItemCreate(target_input=t2, adapter_name="local_fixture_adapter"))

    # First dispatches
    d1, _, _, _ = SchedulingService.dispatch_next_eligible(db, pid)
    assert d1 is True

    # Second must be deferred because max_per_adapter_concurrency=1 is saturated
    d2, msg, _, _ = SchedulingService.dispatch_next_eligible(db, pid)
    assert d2 is False
    assert "deferred due to per-target or per-adapter concurrency limits" in msg


# ---------------------------------------------------------------------------
# Test 17: Queue Capacity Limit Rejection
# ---------------------------------------------------------------------------
def test_queue_capacity_limit_rejection(db, sched_project, sched_users):
    pid = sched_project.id
    policy = SchedulingService.get_or_create_policy(db, pid)
    policy.max_queued_jobs = 1
    db.commit()

    t1 = "https://q-cap-1.example.com"
    t2 = "https://q-cap-2.example.com"
    db.add_all([
        ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=t1, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id),
        ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=t2, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id),
    ])
    db.commit()

    SchedulingService.enqueue_assessment(db, pid, sched_users["tester"].id, QueueItemCreate(target_input=t1))

    # Second enqueue must fail with capacity exceeded
    with pytest.raises(ValidationError) as exc:
        SchedulingService.enqueue_assessment(db, pid, sched_users["tester"].id, QueueItemCreate(target_input=t2))
    assert "Maximum queued assessments capacity" in str(exc.value)


# ---------------------------------------------------------------------------
# Test 18: Update Scheduling Policy Governance
# ---------------------------------------------------------------------------
def test_update_scheduling_policy_governance(client: TestClient, db, sched_project, sched_users):
    pid = sched_project.id
    headers_lead = auth_header_for_user(sched_users["lead"])
    headers_tester = auth_header_for_user(sched_users["tester"])

    # Tester cannot update policy (requires LEAD)
    res_fail = client.put(
        f"/api/v1/projects/{pid}/scheduling/policy",
        headers=headers_tester,
        json={"max_concurrent_assessments": 10},
    )
    assert res_fail.status_code == status.HTTP_403_FORBIDDEN

    # Lead can update policy
    res_ok = client.put(
        f"/api/v1/projects/{pid}/scheduling/policy",
        headers=headers_lead,
        json={"max_concurrent_assessments": 8, "aging_factor_per_hour": 3.5},
    )
    assert res_ok.status_code == status.HTTP_200_OK
    assert res_ok.json()["max_concurrent_assessments"] == 8
    assert res_ok.json()["aging_factor_per_hour"] == 3.5


# ---------------------------------------------------------------------------
# Test 19: Disruptive Scanning Boundary Enforcement
# ---------------------------------------------------------------------------
def test_disruptive_scanning_boundary_enforcement(db, sched_project, sched_users):
    pid = sched_project.id
    disruptive_target = "https://example.com/exploit/payload?--flood=true"

    db.add(ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value="https://example.com", authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id))
    db.commit()

    # Reject non-defensive scanning commands
    with pytest.raises(ValidationError) as exc:
        SchedulingService.enqueue_assessment(
            db, pid, sched_users["tester"].id, QueueItemCreate(target_input=disruptive_target)
        )
    assert "disruptive or non-defensive" in str(exc.value)


# ---------------------------------------------------------------------------
# Test 20: Preview Does Not Reserve Capacity or Persist State
# ---------------------------------------------------------------------------
def test_preview_does_not_reserve_capacity_or_persist(db, sched_project, sched_users):
    pid = sched_project.id
    target = "https://preview-only.example.com"
    db.add(ScopeTarget(project_id=pid, target_type=TargetType.URL, target_value=target, authorization_status=AuthorizationStatus.AUTHORIZED, created_by_id=sched_users["lead"].id))
    db.commit()

    count_before = db.query(AssessmentQueueItem).filter(AssessmentQueueItem.project_id == pid).count()

    prev = SchedulingService.preview_assessment(db, pid, target, "local_fixture_adapter")
    assert prev.is_eligible is True
    assert prev.computed_priority >= 20.0

    count_after = db.query(AssessmentQueueItem).filter(AssessmentQueueItem.project_id == pid).count()
    assert count_before == count_after

