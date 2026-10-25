from fastapi.testclient import TestClient
from app.models.project import Project
from app.models.audit import AuditEvent


def test_audit_event_generation_and_scrubbing(
    client: TestClient,
    test_project: Project,
    lead_headers: dict,
    auditor_headers: dict,
    outsider_headers: dict,
    db,
):
    # Perform an audited operation: register a scope target
    target_payload = {
        "target_value": "10.200.1.0/24",
        "description": "Critical enclave"
    }
    res_reg = client.post(
        f"/api/v1/projects/{test_project.id}/targets",
        json=target_payload,
        headers=lead_headers,
    )
    assert res_reg.status_code == 201

    # Auditor retrieves audit ledger
    res_audit = client.get(
        f"/api/v1/audit/?project_id={test_project.id}&action=SCOPE_TARGET_REGISTER",
        headers=auditor_headers,
    )
    assert res_audit.status_code == 200
    ledger = res_audit.json()
    assert ledger["total"] >= 1
    recent_event = ledger["items"][0]
    assert recent_event["action"] == "SCOPE_TARGET_REGISTER"
    assert recent_event["outcome"] == "SUCCESS"
    assert recent_event["project_id"] == test_project.id

    # Verify no passwords or tokens in DB audit records
    events = db.query(AuditEvent).all()
    for ev in events:
        details_str = str(ev.details)
        assert "password" not in details_str.lower() or "[REDACTED]" in details_str
        assert "token" not in details_str.lower() or "[REDACTED]" in details_str

    # Outsider trying to query audit events of unauthorized project
    res_outsider = client.get(
        f"/api/v1/audit/?project_id={test_project.id}",
        headers=outsider_headers,
    )
    assert res_outsider.status_code == 200
    assert res_outsider.json()["total"] == 0
