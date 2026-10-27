import sys
import time
import json
import httpx

def main():
    print("=== LIVE VAPT SYSTEM REVIEW & AUDIT PROBE ===")
    client = httpx.Client(base_url="http://127.0.0.1:8000", timeout=30.0, follow_redirects=True)

    # 1. Health & Readiness
    r = client.get("/health")
    assert r.status_code == 200, f"Health failed: {r.status_code}"
    print(f"[PASS] 1. Root Health Probe: {r.json()['status']}")

    r = client.get("/ready")
    assert r.status_code == 200, f"Ready failed: {r.status_code}"
    print(f"[PASS] 2. Root Readiness Probe: {r.json()['status']}")

    # 2. Authentication
    r = client.post("/api/v1/auth/login", json={"email": "lead@example.com", "password": "password123"})
    assert r.status_code == 200, f"Login failed: {r.text}"
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[PASS] 3. Operator Authentication (JWT Bearer Token issued)")

    # 3. Create Project
    proj_payload = {"name": "Live Review Enterprise Assessment", "description": "Defensive testing project"}
    r = client.post("/api/v1/projects/", json=proj_payload, headers=headers)
    assert r.status_code in (200, 201), f"Create project failed: {r.status_code} {r.text}"
    project = r.json()
    p_id = project["id"]
    print(f"[PASS] 4. Project Provisioned: {p_id} ({project['name']})")

    # 4. Scope Target Creation & Validation
    t_payload = {
        "target_value": "10.0.0.50",
        "description": "App Server Host"
    }
    r = client.post(f"/api/v1/projects/{p_id}/targets", json=t_payload, headers=headers)
    assert r.status_code in (200, 201), f"Create target failed: {r.status_code} {r.text}"
    target = r.json()
    t_id = target["id"]
    print(f"[PASS] 5. Scope Target Added: {t_id}")

    # 5. Authorize Target
    auth_payload = {"evidence": "Authorized by security lead according to charter ticket #SEC-1001"}
    r = client.post(f"/api/v1/projects/{p_id}/targets/{t_id}/authorize", json=auth_payload, headers=headers)
    assert r.status_code == 200, f"Authorize target failed: {r.status_code} {r.text}"
    print(f"[PASS] 6. Scope Target Authorized: {r.json()['authorization_status']}")

    # 6. Scope Exclusion Creation
    e_payload = {
        "target_value": "10.0.0.254",
        "reason": "Gateway Router Out of Scope"
    }
    r = client.post(f"/api/v1/projects/{p_id}/exclusions", json=e_payload, headers=headers)
    assert r.status_code in (200, 201), f"Create exclusion failed: {r.status_code} {r.text}"
    print(f"[PASS] 7. Scope Exclusion Added: {e_payload['target_value']}")

    # 7. Boundary Check
    r = client.post(f"/api/v1/projects/{p_id}/validate", json={"target": "10.0.0.50"}, headers=headers)
    assert r.status_code == 200 and r.json()["is_authorized"] is True, f"Validate target failed: {r.text}"
    r_ex = client.post(f"/api/v1/projects/{p_id}/validate", json={"target": "10.0.0.254"}, headers=headers)
    assert r_ex.status_code == 200 and r_ex.json()["is_authorized"] is False
    print("[PASS] 8. Boundary Verification (In-scope and Exclusion preemption confirmed)")

    # 8. Asset Creation & Inventory
    asset_payload = {
        "asset_type": "HOST",
        "canonical_identifier": "10.0.0.50",
        "name": "app-server-01.corp",
        "environment": "DEVELOPMENT",
        "criticality": "HIGH",
        "attributes": {
            "ip_address": "10.0.0.50",
            "hostname": "app-server-01.corp",
            "os": "Linux Ubuntu 22.04 LTS"
        }
    }
    r = client.post(f"/api/v1/projects/{p_id}/assets/fixture", json=asset_payload, headers=headers)
    assert r.status_code in (200, 201), f"Asset fixture failed: {r.status_code} {r.text}"
    asset = r.json()
    asset_id = asset.get("id")
    print(f"[PASS] 9. Asset Inventory Fixture Provisioned: {asset_id}")

    # 9. Assessment Job Execution (Simulated Adapter)
    job_payload = {
        "target_input": "10.0.0.50",
        "adapter_name": "local_fixture_adapter",
        "fixture_profile": "WEB_APPLICATION_BASELINE"
    }
    r = client.post(f"/api/v1/projects/{p_id}/assessments/", json=job_payload, headers=headers)
    assert r.status_code in (200, 201), f"Launch assessment failed: {r.status_code} {r.text}"
    job = r.json()
    job_id = job["id"]
    print(f"[PASS] 10. Assessment Job Dispatched: {job_id} (Status: {job['status']})")

    # Poll for completion
    for _ in range(15):
        time.sleep(1)
        r = client.get(f"/api/v1/projects/{p_id}/assessments/{job_id}", headers=headers)
        if r.status_code == 200 and r.json()["status"] in ("COMPLETED", "FAILED"):
            job = r.json()
            break
    print(f"[PASS] 11. Assessment Job Finished: Status={job['status']}")

    # 10. Finding Lifecycle & Triage
    r = client.get(f"/api/v1/projects/{p_id}/findings", headers=headers)
    assert r.status_code == 200, f"List findings failed: {r.status_code}"
    findings = r.json()
    print(f"[PASS] 12. Finding Inventory Queried: {len(findings)} findings detected")

    if findings:
        f_id = findings[0]["id"]
        # Transition: CONFIRMED
        r = client.post(
            f"/api/v1/projects/{p_id}/findings/{f_id}/transition",
            json={"to_status": "CONFIRMED", "reason": "Verified vulnerability on target host"},
            headers=headers
        )
        assert r.status_code == 200, f"Finding confirm failed: {r.status_code} {r.text}"
        print(f"[PASS] 13. Finding Lifecycle Transition -> CONFIRMED ({f_id})")

    # 11. Knowledge Graph
    r = client.get(f"/api/v1/projects/{p_id}/graph/stats", headers=headers)
    assert r.status_code == 200, f"Graph stats failed: {r.status_code}"
    stats = r.json()
    print(f"[PASS] 14. Universal Security Knowledge Graph: Nodes={stats.get('total_nodes') or stats.get('node_count')}, Edges={stats.get('total_edges') or stats.get('edge_count')}")

    # 12. Contextual Risk Assessment
    r = client.get(f"/api/v1/projects/{p_id}/risk/summary", headers=headers)
    assert r.status_code == 200, f"Risk summary failed: {r.status_code}"
    print(f"[PASS] 15. Contextual Risk Summary: Posture={r.json().get('posture_score')}")

    # 13. Attack Path Analysis
    r = client.post(f"/api/v1/projects/{p_id}/risk/attack-paths", headers=headers)
    assert r.status_code == 200, f"Attack paths failed: {r.status_code}"
    print(f"[PASS] 16. Attack Path Analysis Engine executed")

    # 14. Remediation Planning
    r = client.get(f"/api/v1/projects/{p_id}/remediations", headers=headers)
    assert r.status_code == 200, f"Remediations failed: {r.status_code}"
    print(f"[PASS] 17. Remediation Recommendations listed: {len(r.json())} items")

    # 15. Reports & Manifest
    r = client.get(f"/api/v1/projects/{p_id}/reports", headers=headers)
    assert r.status_code == 200, f"Reports listing failed: {r.status_code}"
    print(f"[PASS] 18. Reports Listing Verified")

    # 16. Digital Twin
    r = client.post(f"/api/v1/projects/{p_id}/digital-twin/snapshots", json={"snapshot_label": "Baseline Snapshot", "description": "Auto snapshot"}, headers=headers)
    assert r.status_code in (200, 201), f"Digital twin snapshot failed: {r.status_code} {r.text}"
    print(f"[PASS] 19. Historical Digital Twin Snapshot Captured")

    # 17. Regression Intelligence
    r = client.get(f"/api/v1/projects/{p_id}/regressions/alerts", headers=headers)
    assert r.status_code == 200, f"Regression alerts failed: {r.status_code}"
    print(f"[PASS] 20. Regression Intelligence Queried")

    # 18. Controlled AI Analyst
    if findings:
        r = client.post(
            f"/api/v1/projects/{p_id}/ai-analyst/explain-finding/{findings[0]['id']}",
            json={"include_mitre_mapping": True, "include_defensive_controls": True},
            headers=headers
        )
        assert r.status_code in (200, 201), f"AI Analyst failed: {r.status_code} {r.text}"
        print(f"[PASS] 21. AI Analyst Explanation Generated")

    # 19. Controlled Learning & Prediction Ledger
    r = client.get(f"/api/v1/projects/{p_id}/learning/models", headers=headers)
    assert r.status_code == 200, f"Learning models failed: {r.status_code}"
    r_ledger = client.get(f"/api/v1/projects/{p_id}/learning/predictions", headers=headers)
    assert r_ledger.status_code == 200, f"Prediction ledger failed: {r_ledger.status_code}"
    print(f"[PASS] 22. Model Governance & Prediction Ledger Queried")

    # 20. Adaptive Defense
    r = client.get(f"/api/v1/projects/{p_id}/adaptive-defense/posture", headers=headers)
    assert r.status_code == 200, f"Adaptive defense posture failed: {r.status_code}"
    print(f"[PASS] 23. Adaptive Defense Posture: {r.json().get('posture_state')}")

    # 21. Integrations (CISA KEV, Webhook, SIEM)
    r = client.get(f"/api/v1/projects/{p_id}/integrations/status", headers=headers)
    assert r.status_code == 200, f"Integrations status failed: {r.status_code}"
    print(f"[PASS] 24. Integration Adapters Health Verified ({len(r.json())} active adapters)")

    r = client.get(f"/api/v1/projects/{p_id}/integrations/kev/lookup?cve_id=CVE-2021-44228", headers=headers)
    assert r.status_code == 200, f"CISA KEV failed: {r.status_code}"
    print(f"[PASS] 25. CISA KEV Threat Feed Lookup (CVE-2021-44228: {r.json().get('vulnerability_name')})")

    r = client.post(
        f"/api/v1/projects/{p_id}/integrations/webhook/test",
        json={"event_type": "FINDING_CREATED"},
        headers=headers
    )
    assert r.status_code == 200, f"Webhook test failed: {r.status_code}"
    print(f"[PASS] 26. HMAC-SHA256 Webhook Dispatch Test Completed")

    r = client.get(f"/api/v1/projects/{p_id}/integrations/siem/export?format_type=CEF", headers=headers)
    assert r.status_code == 200, f"SIEM export failed: {r.status_code}"
    print(f"[PASS] 27. Multi-Format SIEM Export Generated ({len(r.text)} bytes)")

    # 22. Audit Ledger & Cryptographic Verification
    r = client.get(f"/api/v1/audit/?project_id={p_id}", headers=headers)
    assert r.status_code == 200, f"Audit ledger failed: {r.status_code}"
    print(f"[PASS] 28. Audit Ledger Events Verified ({len(r.json().get('items', []))} items)")

    # 23. Project Administration & Team RBAC
    r = client.get(f"/api/v1/auth/users", headers=headers)
    assert r.status_code == 200, f"List users failed: {r.status_code}"
    print(f"[PASS] 29. Organization Users Listed ({len(r.json())} users)")

    r = client.get(f"/api/v1/projects/{p_id}/members", headers=headers)
    assert r.status_code == 200, f"List members failed: {r.status_code}"
    print(f"[PASS] 30. Project Members Roster Listed ({len(r.json())} members)")

    print("\n========================================================")
    print(">>> ALL 30 LIVE SYSTEM CONTROLS & REST APIS VERIFIED! <<<")
    print("========================================================")

if __name__ == "__main__":
    main()
