import hashlib
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from app.models.project import Project
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.user import User
from app.services.assessment_engine import AssessmentExecutionEngine


def test_assessment_job_lifecycle_and_evidence_provenance(
    client: TestClient,
    test_project: Project,
    lead_user: User,
    tester_headers: dict,
    lead_headers: dict,
    db,
):
    # 1. Register and Authorize target
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="api.internal-bank.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-SEC-2026-BANK",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # 2. Launch assessment using deterministic web fixture
    payload = {
        "target_input": "api.internal-bank.corp",
        "adapter_name": "local_fixture_adapter",
        "fixture_profile": "WEB_APPLICATION_BASELINE",
        "timeout_seconds": 120,
        "idempotency_key": "idemp-bank-001",
    }
    response = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json=payload,
        headers=tester_headers,
    )
    assert response.status_code == 201
    job = response.json()
    job_id = job["id"]

    assert job["status"] == "COMPLETED"
    assert job["is_simulated"] is True
    assert job["progress_pct"] == 100
    assert job["summary_stats"]["findings_count"] >= 2

    # 3. Verify Idempotency: repeating identical request returns existing job without duplicates
    res_repeat = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json=payload,
        headers=tester_headers,
    )
    assert res_repeat.status_code == 201
    assert res_repeat.json()["id"] == job_id

    # 4. Fetch Findings
    res_findings = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/{job_id}/findings",
        headers=tester_headers,
    )
    assert res_findings.status_code == 200
    findings = res_findings.json()
    assert len(findings) >= 2

    first_finding = findings[0]
    assert first_finding["is_simulated"] is True
    assert len(first_finding["evidence_items"]) > 0

    # 5. Cryptographic Evidence Provenance Check
    evidence = first_finding["evidence_items"][0]
    raw_payload = evidence["payload"]
    expected_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
    assert evidence["sha256_hash"] == expected_hash


def test_unauthorized_and_excluded_targets_denied(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    lead_user: User,
    db,
):
    # Attempting to launch assessment against unapproved target fails closed
    unauth_payload = {
        "target_input": "99.99.99.99",
        "adapter_name": "local_fixture_adapter",
    }
    res_unauth = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json=unauth_payload,
        headers=tester_headers,
    )
    assert res_unauth.status_code == 403
    assert "not authorized" in res_unauth.json()["detail"]

    # Register an authorized subnet 10.50.0.0/16, but exclude 10.50.1.1
    net_target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.CIDR,
        target_value="10.50.0.0/16",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-50-NET",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    exclusion = ScopeExclusion(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="10.50.1.1",
        reason="Core switch gateway",
        created_by_id=lead_user.id,
    )
    db.add_all([net_target, exclusion])
    db.commit()

    # Assessing excluded host must fail
    res_excl = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json={"target_input": "10.50.1.1"},
        headers=tester_headers,
    )
    assert res_excl.status_code == 403
    assert "strictly excluded" in res_excl.json()["detail"].lower()


def test_execution_boundary_revalidates_and_fails_closed(
    client: TestClient,
    test_project: Project,
    lead_user: User,
    tester_headers: dict,
    db,
):
    # 1. Authorize target
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="ephemeral.corp.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-EPHEMERAL",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # 2. Create job in QUEUED status without immediate execution (auto_execute=False)
    res_queue = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={"target_input": "ephemeral.corp.local"},
        headers=tester_headers,
    )
    assert res_queue.status_code == 201
    job_id = res_queue.json()["id"]
    assert res_queue.json()["status"] == "QUEUED"

    # 3. Simulate operational revocation of the target before the worker runs
    target.authorization_status = AuthorizationStatus.REVOKED
    target.revocation_reason = "Emergency revocation before scan"
    db.commit()

    # 4. Worker boundary executes job: must fail closed because target was revoked!
    executed_job = AssessmentExecutionEngine.execute_job(db=db, job_id=job_id)
    assert executed_job.status.value == "FAILED"
    assert "Execution boundary scope denial" in executed_job.error_message


def test_cross_project_isolation(
    client: TestClient,
    test_project: Project,
    outsider_headers: dict,
    tester_headers: dict,
    lead_user: User,
    db,
):
    # Register and authorize target
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="classified.project.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-CLASSIFIED",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # Tester creates assessment
    res_create = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json={"target_input": "classified.project.local"},
        headers=tester_headers,
    )
    assert res_create.status_code == 201
    job_id = res_create.json()["id"]

    # Outsider cannot list assessments in this project (404 fail-closed)
    res_list = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/",
        headers=outsider_headers,
    )
    assert res_list.status_code == 404

    # Outsider cannot get job detail
    res_get = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/{job_id}",
        headers=outsider_headers,
    )
    assert res_get.status_code == 404

    # Outsider cannot cancel job
    res_cancel = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job_id}/cancel",
        headers=outsider_headers,
    )
    assert res_cancel.status_code == 404


def test_partial_failure_profile_handling(
    client: TestClient,
    test_project: Project,
    lead_user: User,
    tester_headers: dict,
    db,
):
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="partial-test.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-PARTIAL",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # Launch with PARTIAL_FAILURE_PROFILE
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json={
            "target_input": "partial-test.local",
            "fixture_profile": "PARTIAL_FAILURE_PROFILE",
        },
        headers=tester_headers,
    )
    assert res.status_code == 201
    job = res.json()
    assert job["status"] == "PARTIAL"
    assert "Partial failure" in job["error_message"]
    assert job["summary_stats"]["errors_count"] > 0
    assert job["summary_stats"]["findings_count"] > 0
