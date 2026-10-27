import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.user import User
from app.models.audit import AuditEvent
from app.services.integrations import (
    CisaKevFeedAdapter,
    WebhookNotifierAdapter,
    SiemExporterAdapter,
    IntegrationType,
    IntegrationStatus,
)


def test_cisa_kev_feed_adapter_baseline_and_enrichment():
    """Verify CISA KEV adapter looks up CVEs, enriches findings, and detects ransomware risk."""
    adapter = CisaKevFeedAdapter()
    health = adapter.health_check()
    assert health["status"] == "CONFIGURED"
    assert health["total_catalog_entries"] >= 6

    # 1. Look up known Log4j CVE
    log4j = adapter.enrich_cve("CVE-2021-44228")
    assert log4j is not None
    assert log4j["product"] == "Log4j"
    assert log4j["vendor_project"] == "Apache"
    assert log4j["known_ransomware_campaign_use"] is True

    # 2. Look up unknown CVE
    unknown = adapter.enrich_cve("CVE-1999-00001")
    assert unknown is None

    # 3. Query catalog by keyword
    results = adapter.query_catalog(query="exchange")
    assert len(results) >= 1
    assert any("26855" in r["cve_id"] for r in results)

    # 4. Enrich finding dictionary
    raw_finding = {
        "title": "Remote Code Execution via Log4j",
        "description": "Target component vulnerable to CVE-2021-44228 JNDI injection.",
        "severity": "CRITICAL",
    }
    enriched = adapter.enrich_finding(raw_finding)
    assert enriched["is_known_exploited"] is True
    assert enriched["known_ransomware_use"] is True
    assert enriched["active_threat_indicator"] == "CISA_KEV_LISTED"
    assert enriched["cisa_kev_details"]["cve_id"] == "CVE-2021-44228"

    # 5. Finding without CVE
    safe_finding = {
        "title": "Missing Referrer-Policy Header",
        "description": "Informational header warning.",
    }
    safe_enriched = adapter.enrich_finding(safe_finding)
    assert safe_enriched["is_known_exploited"] is False
    assert safe_enriched["cisa_kev_details"] is None


def test_webhook_notifier_adapter_signing_and_sanitization():
    """Verify webhook notifier generates HMAC-SHA256 signatures and sanitizes sensitive tokens."""
    adapter = WebhookNotifierAdapter(config={
        "webhook_url": "https://alerts.corp.internal/vapt-webhook",
        "secret_token": "super_secret_webhook_signing_key_32chars!",
        "max_retries": 3,
    })

    valid, err = adapter.validate_configuration()
    assert valid is True
    assert err is None

    # 1. Dispatch event with sensitive data
    raw_data = {
        "finding_id": "find-001",
        "target": "https://admin:supersecret@10.0.0.1",
        "auth_token": "bearer xyz123456",
        "password_hash": "$2b$12$e...",
        "cve": "CVE-2021-44228",
    }

    delivery = adapter.dispatch_event(
        event_type="FINDING_CRITICAL_DISCOVERED",
        project_id="proj-uuid-001",
        data=raw_data,
        simulate_success=True,
    )

    assert delivery["delivered"] is True
    assert delivery["signature"].startswith("sha256=")
    assert len(delivery["signature"]) == 71  # "sha256=" + 64 hex chars

    # Verify sensitive data was redacted
    payload_data = delivery["payload"]["data"]
    assert payload_data["auth_token"] == "[REDACTED]"
    assert payload_data["password_hash"] == "[REDACTED]"
    assert payload_data["cve"] == "CVE-2021-44228"

    # 2. Re-verify signature independently
    import hmac
    import hashlib
    import json
    timestamp = delivery["timestamp"]
    payload_bytes = json.dumps(delivery["payload"], sort_keys=True).encode("utf-8")
    expected_sig = "sha256=" + hmac.new(
        b"super_secret_webhook_signing_key_32chars!",
        f"{timestamp}.".encode("utf-8") + payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    assert delivery["signature"] == expected_sig


def test_siem_exporter_adapter_formats():
    """Verify SIEM exporter formats events into CEF, Syslog RFC 5424, and JSON stream."""
    adapter = SiemExporterAdapter(config={
        "device_vendor": "VAPT_Platform",
        "device_product": "VAPT_System",
    })

    sample_event = {
        "action": "CRITICAL_FINDING_CONFIRMED",
        "description": "Apache Log4j RCE confirmed on prod cluster",
        "severity": "CRITICAL",
        "project_id": "proj-uuid-100",
        "actor_id": "analyst-uuid-200",
        "client_ip": "192.168.1.100",
        "event_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "target_resource": "finding:find-100",
        "details": {"cve": "CVE-2021-44228", "auth_token": "bearer secret123"},
    }

    # 1. CEF format
    cef_str = adapter.format_event_cef(sample_event)
    assert cef_str.startswith("CEF:0|VAPT_Platform|VAPT_System|1.0.0|CRITICAL_FINDING_CONFIRMED|")
    assert "sev=10" in cef_str or "|10|" in cef_str
    assert "cs1Label=Project cs1=proj-uuid-100" in cef_str
    assert "secret123" not in cef_str  # Sanitized

    # 2. Syslog format
    syslog_str = adapter.format_event_syslog(sample_event)
    assert syslog_str.startswith("<85>1 ")
    assert "VAPT_System" in syslog_str
    assert "CEF:0" in syslog_str

    # 3. Batch export
    stream = adapter.export_audit_stream([sample_event, sample_event], format_type="CEF")
    assert len(stream) == 2
    assert stream[0].startswith("CEF:0")


def test_integrations_api_endpoints(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    lead_headers: dict,
    db: Session,
):
    """Verify REST API endpoints for integration status, KEV lookup, webhook tests, and SIEM exports."""
    # 1. Integration status
    status_res = client.get(
        f"/api/v1/projects/{test_project.id}/integrations/status",
        headers=tester_headers,
    )
    assert status_res.status_code == 200
    adapters = status_res.json()
    assert len(adapters) == 3
    adapter_names = [a["name"] for a in adapters]
    assert "CISA KEV Feed Adapter" in adapter_names
    assert "Webhook Notifier Adapter" in adapter_names
    assert "SIEM Audit Exporter Adapter" in adapter_names

    # 2. KEV CVE lookup
    kev_res = client.get(
        f"/api/v1/projects/{test_project.id}/integrations/kev/lookup?cve_id=CVE-2021-44228",
        headers=tester_headers,
    )
    assert kev_res.status_code == 200
    cve_data = kev_res.json()
    assert cve_data["product"] == "Log4j"
    assert cve_data["known_ransomware_campaign_use"] is True

    # Unknown CVE returns 404
    not_found_res = client.get(
        f"/api/v1/projects/{test_project.id}/integrations/kev/lookup?cve_id=CVE-1999-99999",
        headers=tester_headers,
    )
    assert not_found_res.status_code == 404

    # 3. Search KEV catalog
    catalog_res = client.get(
        f"/api/v1/projects/{test_project.id}/integrations/kev/catalog?query=Fortinet",
        headers=tester_headers,
    )
    assert catalog_res.status_code == 200
    assert len(catalog_res.json()) >= 1

    # 4. Webhook test dispatch (requires Lead role)
    webhook_res = client.post(
        f"/api/v1/projects/{test_project.id}/integrations/webhook/test",
        headers=lead_headers,
        json={"event_type": "FINDING_CRITICAL_DISCOVERED"},
    )
    assert webhook_res.status_code == 200
    delivery = webhook_res.json()
    assert delivery["delivered"] is True
    assert delivery["signature"].startswith("sha256=")

    # 5. Webhook delivery history
    hist_res = client.get(
        f"/api/v1/projects/{test_project.id}/integrations/webhook/history",
        headers=tester_headers,
    )
    assert hist_res.status_code == 200
    assert len(hist_res.json()) >= 1

    # 6. Seed an audit event and export SIEM stream
    audit_ev = AuditEvent(
        project_id=test_project.id,
        action="SCAN_EXECUTION_LAUNCHED",
        actor_id="test-actor",
        target_type="project",
        target_id=test_project.id,
        ip_address="127.0.0.1",
        outcome="SUCCESS",
        details={"mode": "defensive_simulated"},
    )
    db.add(audit_ev)
    db.commit()

    siem_cef_res = client.get(
        f"/api/v1/projects/{test_project.id}/integrations/siem/export?format_type=CEF",
        headers=tester_headers,
    )
    assert siem_cef_res.status_code == 200
    cef_data = siem_cef_res.json()
    assert cef_data["format"] == "CEF"
    assert cef_data["total_events"] >= 1
    assert any("CEF:0" in line for line in cef_data["stream"])

    siem_syslog_res = client.get(
        f"/api/v1/projects/{test_project.id}/integrations/siem/export?format_type=SYSLOG",
        headers=tester_headers,
    )
    assert siem_syslog_res.status_code == 200
    assert any("<85>1" in line for line in siem_syslog_res.json()["stream"])

    # 7. Cross-project isolation
    iso_res = client.get(
        "/api/v1/projects/00000000-0000-0000-0000-000000000000/integrations/status",
        headers=tester_headers,
    )
    assert iso_res.status_code == 404
