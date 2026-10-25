from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app.models.project import Project


def test_full_scope_lifecycle_via_api(
    client: TestClient,
    test_project: Project,
    lead_headers: dict,
    tester_headers: dict,
):
    # 1. Tester registers a target
    reg_payload = {
        "target_value": "172.16.50.0/24",
        "description": "Internal test staging servers"
    }
    res_reg = client.post(
        f"/api/v1/projects/{test_project.id}/targets",
        json=reg_payload,
        headers=tester_headers,
    )
    assert res_reg.status_code == 201
    target = res_reg.json()
    target_id = target["id"]
    assert target["authorization_status"] == "PENDING"

    # 2. Scope validation while PENDING must be DENIED
    val_payload = {"target": "172.16.50.15"}
    res_val1 = client.post(
        f"/api/v1/projects/{test_project.id}/validate",
        json=val_payload,
        headers=tester_headers,
    )
    assert res_val1.status_code == 200
    val_data1 = res_val1.json()
    assert val_data1["is_authorized"] is False
    assert val_data1["status"] == "PENDING_APPROVAL"

    # 3. Lead authorizes the target with evidence and future expiration
    future_exp = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    auth_payload = {
        "evidence": "ROE-2026-ENGAGEMENT-TICKET-992",
        "expires_at": future_exp,
    }
    res_auth = client.post(
        f"/api/v1/projects/{test_project.id}/targets/{target_id}/authorize",
        json=auth_payload,
        headers=lead_headers,
    )
    assert res_auth.status_code == 200
    auth_target = res_auth.json()
    assert auth_target["authorization_status"] == "AUTHORIZED"
    assert auth_target["authorization_evidence"] == "ROE-2026-ENGAGEMENT-TICKET-992"

    # 4. Scope validation is now AUTHORIZED
    res_val2 = client.post(
        f"/api/v1/projects/{test_project.id}/validate",
        json=val_payload,
        headers=tester_headers,
    )
    assert res_val2.status_code == 200
    val_data2 = res_val2.json()
    assert val_data2["is_authorized"] is True
    assert val_data2["status"] == "AUTHORIZED"
    assert val_data2["matched_rule"]["target_value"] == "172.16.50.0/24"

    # 5. Add an exclusion inside that subnet: 172.16.50.1
    excl_payload = {
        "target_value": "172.16.50.1",
        "reason": "Gateway / Out of Scope",
    }
    res_excl = client.post(
        f"/api/v1/projects/{test_project.id}/exclusions",
        json=excl_payload,
        headers=tester_headers,
    )
    assert res_excl.status_code == 201

    # 6. Validate excluded target -> DENIED with EXCLUDED status
    res_val_excl = client.post(
        f"/api/v1/projects/{test_project.id}/validate",
        json={"target": "172.16.50.1"},
        headers=tester_headers,
    )
    assert res_val_excl.status_code == 200
    assert res_val_excl.json()["is_authorized"] is False
    assert res_val_excl.json()["status"] == "EXCLUDED"

    # 7. Lead revokes the entire CIDR target
    revoke_payload = {"reason": "Assessment completed ahead of schedule"}
    res_revoke = client.post(
        f"/api/v1/projects/{test_project.id}/targets/{target_id}/revoke",
        json=revoke_payload,
        headers=lead_headers,
    )
    assert res_revoke.status_code == 200
    assert res_revoke.json()["authorization_status"] == "REVOKED"

    # 8. Scope validation is now REVOKED
    res_val3 = client.post(
        f"/api/v1/projects/{test_project.id}/validate",
        json={"target": "172.16.50.15"},
        headers=tester_headers,
    )
    assert res_val3.status_code == 200
    assert res_val3.json()["is_authorized"] is False
    assert res_val3.json()["status"] == "REVOKED"
