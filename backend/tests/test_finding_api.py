from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.user import User, SystemRole
from app.models.finding import FindingLifecycleStatus, VulnerabilityFinding
from app.core.security import hash_password, create_access_token


def test_finding_ingestion_and_query_endpoints(
    client: TestClient,
    test_project: Project,
    lead_user: User,
    tester_headers: dict,
    lead_headers: dict,
    db,
):
    # 1. Authorize target
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="sec-app.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="AUTH-DOC-2026",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # 2. Run assessment to generate findings
    job_payload = {
        "target_input": "sec-app.local",
        "adapter_name": "local_fixture_adapter",
        "fixture_profile": "WEB_APPLICATION_BASELINE",
        "timeout_seconds": 60,
    }
    res_job = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json=job_payload,
        headers=tester_headers,
    )
    assert res_job.status_code == 201

    # 3. Query /projects/{project_id}/findings
    res_findings = client.get(
        f"/api/v1/projects/{test_project.id}/findings",
        headers=tester_headers,
    )
    assert res_findings.status_code == 200
    findings = res_findings.json()
    assert len(findings) >= 2

    first_finding = findings[0]
    assert "id" in first_finding
    assert "status" in first_finding
    assert first_finding["occurrence_count"] >= 1

    # 4. Filter by severity
    res_filter = client.get(
        f"/api/v1/projects/{test_project.id}/findings?severity={first_finding['severity']}",
        headers=tester_headers,
    )
    assert res_filter.status_code == 200
    assert all(f["severity"] == first_finding["severity"] for f in res_filter.json())

    # 5. Query stats endpoint
    res_stats = client.get(
        f"/api/v1/projects/{test_project.id}/findings/stats",
        headers=tester_headers,
    )
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert stats["total"] >= 2
    assert stats["unresolved_count"] >= 2
    assert "by_status" in stats
    assert "by_severity" in stats

    # 6. Query detail endpoint
    res_detail = client.get(
        f"/api/v1/projects/{test_project.id}/findings/{first_finding['id']}",
        headers=tester_headers,
    )
    assert res_detail.status_code == 200
    detail = res_detail.json()
    assert len(detail["transitions"]) >= 1
    assert len(detail["observation_job_ids"]) >= 1


def test_finding_disposition_endpoints(
    client: TestClient,
    test_project: Project,
    lead_user: User,
    tester_headers: dict,
    lead_headers: dict,
    db,
):
    # Setup target and run assessment
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="portal.corp.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-CORP-01",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json={
            "target_input": "portal.corp.local",
            "fixture_profile": "WEB_APPLICATION_BASELINE",
        },
        headers=tester_headers,
    )

    findings = client.get(
        f"/api/v1/projects/{test_project.id}/findings",
        headers=tester_headers,
    ).json()
    assert len(findings) >= 2
    finding_id = findings[0]["id"]

    # 1. Tester attempts to accept risk -> denied (requires LEAD)
    res_tester_accept = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding_id}/accept-risk",
        json={
            "reason": "Business operational requirement to keep running.",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=60)).isoformat(),
            "compensating_controls": "Strict firewall segmentation",
        },
        headers=tester_headers,
    )
    assert res_tester_accept.status_code == 403

    # 2. Lead accepts risk -> succeeds
    future_date = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
    res_lead_accept = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding_id}/accept-risk",
        json={
            "reason": "Approved by Architecture Review Board pending Q4 redesign.",
            "expires_at": future_date,
            "compensating_controls": "WAF rate limiting rule #44 and mutual TLS.",
        },
        headers=lead_headers,
    )
    assert res_lead_accept.status_code == 200
    accepted = res_lead_accept.json()
    assert accepted["status"] == "ACCEPTED_RISK"
    assert accepted["risk_accepted_reason"] == "Approved by Architecture Review Board pending Q4 redesign."

    # 3. Second finding: Lead marks FALSE_POSITIVE
    finding2_id = findings[1]["id"]
    res_fp = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding2_id}/false-positive",
        json={"reason": "Tested with manual cURL command; endpoint properly validates anti-CSRF tokens."},
        headers=lead_headers,
    )
    assert res_fp.status_code == 200
    fp_finding = res_fp.json()
    assert fp_finding["status"] == "FALSE_POSITIVE"
    assert fp_finding["false_positive_reason"] is not None


def test_finding_cross_project_isolation(
    client: TestClient,
    test_project: Project,
    lead_user: User,
    lead_headers: dict,
    outsider_headers: dict,
    db,
):
    # Create finding in project A
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="isolated-fp-1",
        target_value="10.10.10.10",
        title="Project A Confidential Vulnerability",
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add(finding)
    db.commit()

    # Outsider querying project A findings -> 404 (fails closed)
    res_list = client.get(
        f"/api/v1/projects/{test_project.id}/findings",
        headers=outsider_headers,
    )
    assert res_list.status_code == 404

    # Outsider attempting transition on project A finding -> 404
    res_trans = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/transition",
        json={"to_status": "CONFIRMED", "reason": "Unauthorized tampering attempt"},
        headers=outsider_headers,
    )
    assert res_trans.status_code == 404
