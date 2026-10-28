import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.models.project import Project, ProjectRole
from app.models.user import User
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.monitoring import (
    MonitoringSchedule,
    MonitoringRun,
    ScheduleFrequency,
    ScheduleStatus,
)
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.services.continuous_monitoring_service import ContinuousMonitoringService
from app.schemas.monitoring import ScheduleCreate
from scripts.run_background_worker import run_worker_loop


def test_continuous_monitoring_schedule_creation_and_scope_validation(
    client: TestClient,
    test_project: Project,
    lead_user: User,
    lead_headers: dict,
    tester_headers: dict,
    db,
):
    # 1. Attempt creating schedule for unauthorized target fails
    unauth_payload = {
        "name": "Unauthorized Daily Scan",
        "target_input": "unauthorized.internal.bank",
        "adapter_name": "local_fixture_adapter",
        "fixture_profile": "WEB_APPLICATION_BASELINE",
        "frequency": "DAILY",
        "interval_seconds": 86400,
    }
    res_unauth = client.post(
        f"/api/v1/projects/{test_project.id}/monitoring/schedules",
        json=unauth_payload,
        headers=lead_headers,
    )
    assert res_unauth.status_code == 400
    assert "not authorized in scope" in res_unauth.json()["detail"]

    # 2. Authorize target
    scope_target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="monitoring.internal.bank",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-MONITOR-2026",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(scope_target)
    db.commit()

    # 3. Create schedule as LEAD succeeds
    auth_payload = {
        "name": "Authorized Daily Scan",
        "target_input": "monitoring.internal.bank",
        "adapter_name": "local_fixture_adapter",
        "fixture_profile": "WEB_APPLICATION_BASELINE",
        "frequency": "DAILY",
        "interval_seconds": 86400,
    }
    res_auth = client.post(
        f"/api/v1/projects/{test_project.id}/monitoring/schedules",
        json=auth_payload,
        headers=lead_headers,
    )
    assert res_auth.status_code == 201
    sched = res_auth.json()
    assert sched["status"] == "ACTIVE"
    assert sched["target_input"] == "monitoring.internal.bank"
    assert sched["run_count"] == 0


def test_continuous_monitoring_execution_and_change_detection(
    db,
    test_project: Project,
    lead_user: User,
):
    # 1. Authorize target
    scope_target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="change-detect.internal.bank",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-CHANGE-2026",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(scope_target)
    db.commit()

    # 2. Create schedule
    sched_in = ScheduleCreate(
        name="Change Detection Pipeline",
        target_input="change-detect.internal.bank",
        adapter_name="local_fixture_adapter",
        fixture_profile="WEB_APPLICATION_BASELINE",
        frequency=ScheduleFrequency.DAILY,
        interval_seconds=86400,
    )
    schedule = ContinuousMonitoringService.create_schedule(
        project_id=test_project.id,
        schedule_in=sched_in,
        creator=lead_user,
        creator_role=ProjectRole.LEAD,
        db=db,
    )

    # 3. Execute first monitoring run (Baseline run)
    run1 = ContinuousMonitoringService.execute_schedule_run(
        schedule_id=schedule.id,
        db=db,
    )
    assert run1.status == "SUCCESS"
    assert run1.new_findings_count >= 2
    assert run1.recurring_findings_count == 0

    db.refresh(schedule)
    assert schedule.run_count == 1
    assert schedule.last_status == "SUCCESS"
    next_run = schedule.next_run_at if schedule.next_run_at.tzinfo else schedule.next_run_at.replace(tzinfo=timezone.utc)
    assert next_run > datetime.now(timezone.utc)

    # 4. Execute second monitoring run -> Change detection flags recurring findings
    run2 = ContinuousMonitoringService.execute_schedule_run(
        schedule_id=schedule.id,
        db=db,
    )
    assert run2.status == "SUCCESS"
    assert run2.recurring_findings_count >= 2
    db.refresh(schedule)
    assert schedule.run_count == 2


def test_continuous_monitoring_duplicate_prevention_and_scope_expiration(
    db,
    test_project: Project,
    lead_user: User,
):
    # 1. Authorize target with an expiration date in the past
    now = datetime.now(timezone.utc)
    expired_target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="expired.target.bank",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-EXPIRED-TEST",
        authorized_by_id=lead_user.id,
        authorized_at=now - timedelta(days=10),
        expires_at=now - timedelta(days=1),  # Expired yesterday
        created_by_id=lead_user.id,
    )
    db.add(expired_target)
    db.commit()

    # Create schedule directly in DB
    sched = MonitoringSchedule(
        project_id=test_project.id,
        name="Expired Target Schedule",
        target_input="expired.target.bank",
        adapter_name="local_fixture_adapter",
        fixture_profile="WEB_APPLICATION_BASELINE",
        frequency=ScheduleFrequency.DAILY,
        interval_seconds=86400,
        status=ScheduleStatus.ACTIVE,
        next_run_at=now,
        created_by_id=lead_user.id,
    )
    db.add(sched)
    db.commit()

    # Execute schedule -> Must fail closed and transition to EXPIRED
    run = ContinuousMonitoringService.execute_schedule_run(schedule_id=sched.id, db=db, now=now)
    assert run.status == "SCOPE_EXPIRED"

    db.refresh(sched)
    assert sched.status == ScheduleStatus.EXPIRED
    assert sched.last_status == "SCOPE_EXPIRED"

    # 2. Test Duplicate Prevention on active jobs
    # Authorize valid target
    valid_target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="active-job.target.bank",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-VALID-ACTIVE",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add(valid_target)
    db.commit()

    active_job = AssessmentJob(
        project_id=test_project.id,
        target_input="active-job.target.bank",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.RUNNING,
        created_by_id=lead_user.id,
    )
    db.add(active_job)
    db.commit()

    sched_active = MonitoringSchedule(
        project_id=test_project.id,
        name="Active Job Schedule",
        target_input="active-job.target.bank",
        adapter_name="local_fixture_adapter",
        status=ScheduleStatus.ACTIVE,
        last_job_id=active_job.id,
        next_run_at=now,
        created_by_id=lead_user.id,
    )
    db.add(sched_active)
    db.commit()

    run_dup = ContinuousMonitoringService.execute_schedule_run(schedule_id=sched_active.id, db=db, now=now)
    assert run_dup.status == "SKIPPED_DUPLICATE"
    assert "active assessment job" in run_dup.summary_notes


def test_monitoring_api_lifecycle_and_overview(
    client: TestClient,
    test_project: Project,
    lead_user: User,
    lead_headers: dict,
    db,
):
    # Authorize target
    scope_target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="api-overview.bank",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-API-OVERVIEW",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(scope_target)
    db.commit()

    # 1. Create schedule
    res = client.post(
        f"/api/v1/projects/{test_project.id}/monitoring/schedules",
        json={
            "name": "API Overview Test",
            "target_input": "api-overview.bank",
            "adapter_name": "local_fixture_adapter",
            "fixture_profile": "WEB_APPLICATION_BASELINE",
            "frequency": "DAILY",
            "interval_seconds": 86400,
        },
        headers=lead_headers,
    )
    assert res.status_code == 201
    sched_id = res.json()["id"]

    # 2. Trigger on-demand run
    res_run = client.post(
        f"/api/v1/projects/{test_project.id}/monitoring/schedules/{sched_id}/run-now",
        headers=lead_headers,
    )
    assert res_run.status_code == 200
    assert res_run.json()["status"] == "SUCCESS"

    # 3. Pause and Resume schedule
    res_pause = client.post(
        f"/api/v1/projects/{test_project.id}/monitoring/schedules/{sched_id}/pause",
        headers=lead_headers,
    )
    assert res_pause.status_code == 200
    assert res_pause.json()["status"] == "PAUSED"

    res_resume = client.post(
        f"/api/v1/projects/{test_project.id}/monitoring/schedules/{sched_id}/resume",
        headers=lead_headers,
    )
    assert res_resume.status_code == 200
    assert res_resume.json()["status"] == "ACTIVE"

    # 4. Check Overview metrics
    res_overview = client.get(
        f"/api/v1/projects/{test_project.id}/monitoring/overview",
        headers=lead_headers,
    )
    assert res_overview.status_code == 200
    overview = res_overview.json()
    assert overview["total_schedules"] >= 1
    assert overview["total_runs_executed"] >= 1
    assert len(overview["recent_runs"]) >= 1
