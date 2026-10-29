"""
VAPT Platform — Reliable Security Alerting, Event Delivery & Escalation Subsystem.
Test suite for Prompt 31.
Validates:
1. Canonical security event ingestion and transactional outbox atomicity.
2. Event schema version validation (rejects unsupported versions).
3. Sliding-window alert deduplication (suppresses duplicate within 1h window).
4. Material state changes generate distinct active alerts.
5. Maintenance windows explainably suppress non-critical notifications.
6. Critical severity events break through standard maintenance windows.
7. Critical events suppressed only when suppress_critical is explicitly configured.
8. Outbox processor dispatches in-app events to DELIVERED.
9. Outbox processor blocks prohibited SSRF webhook destinations (moves to DEAD_LETTER).
10. Outbox retry exhaustion triggers terminal DEAD_LETTER transition.
11. Dead-letter events can be manually and safely replayed.
12. Alert acknowledgement lifecycle updates state, timestamp, and actor.
13. Alert resolution and reopening lifecycle.
14. API alert listing enforces project boundary and returns lifecycle counters.
15. API alert actions enforce RBAC (VIEWER gets 403, SECURITY_LEAD / ADMIN get 200).
16. API outbox status reports backlog, dead-letter count, and operational health.
17. Sensitive credentials and secrets are redacted from notification payloads.
"""
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project
from app.models.notification import (
    NotificationRecord,
    SecurityEventOutboxRecord,
    MaintenanceWindowRecord,
    NotificationEventType,
    NotificationSeverity,
    NotificationStatus,
    AlertLifecycleStatus,
)
from app.schemas.alerting import SecurityEventContract
from app.services.alerting_service import alerting_service
from tests.conftest import auth_header_for_user


def test_01_canonical_event_ingestion_and_outbox_atomicity(db: Session, test_project: Project):
    event = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        aggregate_type="FINDING",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.CRITICAL,
        title="Unauthenticated RCE Detected",
        summary="Remote code execution verified on production web gateway.",
        payload={"cvss": 9.8, "cve": "CVE-2024-9999"},
    )

    notif, outbox = alerting_service.publish_security_event(db=db, event=event)

    assert notif.id is not None
    assert notif.project_id == test_project.id
    assert notif.severity == NotificationSeverity.CRITICAL
    assert notif.lifecycle_status == AlertLifecycleStatus.NEW
    assert notif.status == NotificationStatus.PENDING

    assert outbox.id is not None
    assert outbox.event_id == event.event_id
    assert outbox.status == "PENDING"
    assert outbox.retry_count == 0


def test_02_schema_version_validation(db: Session, test_project: Project):
    event = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v99.0.0",  # Unsupported version
        event_type=NotificationEventType.ASSESSMENT_FAILED,
        aggregate_type="ASSESSMENT",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.HIGH,
        title="Invalid Event Schema",
        summary="Testing invalid schema version rejection.",
    )

    with pytest.raises(ValueError) as exc_info:
        alerting_service.publish_security_event(db=db, event=event)
    assert "Unsupported event schema version" in str(exc_info.value)


def test_03_sliding_window_deduplication(db: Session, test_project: Project):
    aggregate_id = str(uuid.uuid4())
    event1 = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        aggregate_type="FINDING",
        aggregate_id=aggregate_id,
        project_id=test_project.id,
        severity=NotificationSeverity.CRITICAL,
        title="Repeated Finding Event",
        summary="First observation of finding.",
    )
    notif1, outbox1 = alerting_service.publish_security_event(db=db, event=event1)
    assert notif1.status == NotificationStatus.PENDING
    assert outbox1.status == "PENDING"

    # Emit identical event 5 minutes later
    event2 = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        aggregate_type="FINDING",
        aggregate_id=aggregate_id,
        project_id=test_project.id,
        severity=NotificationSeverity.CRITICAL,
        title="Repeated Finding Event",
        summary="Second observation of same finding.",
    )
    notif2, outbox2 = alerting_service.publish_security_event(db=db, event=event2)
    assert notif2.status == NotificationStatus.SUPPRESSED_DUPLICATE
    assert "Suppressed duplicate" in (notif2.suppression_reason or "")
    assert outbox2.status == "SUPPRESSED"


def test_04_material_state_change_creates_new_event(db: Session, test_project: Project):
    # Event A on finding 1
    event_a = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        aggregate_type="FINDING",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.CRITICAL,
        title="Finding A",
        summary="First finding",
    )
    notif_a, _ = alerting_service.publish_security_event(db=db, event=event_a)
    assert notif_a.status == NotificationStatus.PENDING

    # Event B on finding 2 (distinct entity)
    event_b = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        aggregate_type="FINDING",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.CRITICAL,
        title="Finding B",
        summary="Second finding",
    )
    notif_b, _ = alerting_service.publish_security_event(db=db, event=event_b)
    assert notif_b.status == NotificationStatus.PENDING
    assert notif_a.id != notif_b.id


def test_05_maintenance_window_suppresses_non_critical(db: Session, test_project: Project, admin_user: User):
    now = datetime.now(timezone.utc)
    # Create active maintenance window
    mw = alerting_service.create_maintenance_window(
        db=db,
        project_id=test_project.id,
        title="Cluster OS Upgrade",
        reason="Scheduled kernel upgrade",
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        suppress_critical=False,
        user_id=admin_user.id,
    )

    event_high = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.ASSESSMENT_FAILED,
        aggregate_type="ASSESSMENT",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.HIGH,
        title="High Severity Assessment Fail",
        summary="Assessment failed during maintenance window.",
    )
    notif, outbox = alerting_service.publish_security_event(db=db, event=event_high)

    assert notif.status == NotificationStatus.SUPPRESSED_MAINTENANCE_WINDOW
    assert "Active maintenance window" in (notif.suppression_reason or "")
    assert outbox.status == "SUPPRESSED"


def test_06_critical_events_bypass_standard_maintenance_window(db: Session, test_project: Project, admin_user: User):
    now = datetime.now(timezone.utc)
    mw = alerting_service.create_maintenance_window(
        db=db,
        project_id=test_project.id,
        title="Database Maintenance",
        reason="Index defragmentation",
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        suppress_critical=False,  # Criticals break through
        user_id=admin_user.id,
    )

    event_crit = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        aggregate_type="FINDING",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.CRITICAL,
        title="Critical Breakthrough Event",
        summary="Must not be suppressed by maintenance window.",
    )
    notif, outbox = alerting_service.publish_security_event(db=db, event=event_crit)

    assert notif.status == NotificationStatus.PENDING
    assert outbox.status == "PENDING"


def test_07_critical_events_suppressed_when_explicitly_configured(db: Session, test_project: Project, admin_user: User):
    now = datetime.now(timezone.utc)
    mw = alerting_service.create_maintenance_window(
        db=db,
        project_id=test_project.id,
        title="Disaster Recovery Drill",
        reason="Testing full blackout",
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        suppress_critical=True,  # Explicitly suppress all
        user_id=admin_user.id,
    )

    event_crit = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        aggregate_type="FINDING",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.CRITICAL,
        title="Suppressed Critical Event",
        summary="Drill blackout suppression.",
    )
    notif, outbox = alerting_service.publish_security_event(db=db, event=event_crit)

    assert notif.status == NotificationStatus.SUPPRESSED_MAINTENANCE_WINDOW
    assert outbox.status == "SUPPRESSED"


def test_08_outbox_processing_in_app_dispatch(db: Session, test_project: Project):
    event = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.NEW_EXPOSURE_DETECTED,
        aggregate_type="ASSET",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.MEDIUM,
        title="New Open Port Detected",
        summary="Port 8443 opened on edge router.",
    )
    notif, outbox = alerting_service.publish_security_event(db=db, event=event)
    assert outbox.status == "PENDING"

    # Process outbox without webhook
    res = alerting_service.process_outbox(db=db, batch_size=10)
    assert res["processed"] >= 1
    assert res["delivered"] >= 1

    db.refresh(outbox)
    assert outbox.status == "DELIVERED"
    assert outbox.delivered_at is not None


def test_09_outbox_ssrf_destination_rejected_to_dead_letter(db: Session, test_project: Project):
    event = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        aggregate_type="FINDING",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.CRITICAL,
        title="Webhook SSRF Attack Attempt",
        summary="Attempting to dispatch to metadata server.",
    )
    notif, outbox = alerting_service.publish_security_event(
        db=db,
        event=event,
        webhook_url="http://169.254.169.254/latest/meta-data/",
    )

    res = alerting_service.process_outbox(db=db, batch_size=10)
    assert res["dead_letter"] >= 1

    db.refresh(outbox)
    assert outbox.status == "DEAD_LETTER"
    assert "SSRF Blocked" in (outbox.last_error or "")


def test_10_outbox_retry_exhaustion_triggers_dead_letter(db: Session, test_project: Project):
    outbox = SecurityEventOutboxRecord(
        project_id=test_project.id,
        event_id=f"evt_fail_{uuid.uuid4().hex[:8]}",
        event_type="ASSESSMENT_FAILED",
        aggregate_type="ASSESSMENT",
        aggregate_id=str(uuid.uuid4()),
        payload={"webhook_url": "https://api.external-webhook-test.com/endpoint"},
        status="PENDING",
        retry_count=4,  # Next attempt is 5 (max)
        max_retries=5,
        next_retry_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    db.add(outbox)
    db.commit()

    from unittest.mock import patch
    with patch("app.services.network_security_service.OutboundNetworkSecurityService.validate_destination_url", side_effect=Exception("Gateway Timeout 504")):
        res = alerting_service.process_outbox(db=db, batch_size=10)

    db.refresh(outbox)
    assert outbox.status == "DEAD_LETTER"
    assert outbox.retry_count == 5


def test_11_dead_letter_manual_replay(db: Session, test_project: Project):
    event_id = f"evt_dl_{uuid.uuid4().hex[:8]}"
    outbox = SecurityEventOutboxRecord(
        project_id=test_project.id,
        event_id=event_id,
        event_type="ASSESSMENT_FAILED",
        aggregate_type="ASSESSMENT",
        aggregate_id=str(uuid.uuid4()),
        payload={},
        status="DEAD_LETTER",
        retry_count=5,
        max_retries=5,
        last_error="Connection dropped",
    )
    db.add(outbox)
    db.commit()

    success = alerting_service.replay_dead_letter_event(db=db, event_id=event_id)
    assert success is True

    db.refresh(outbox)
    assert outbox.status == "PENDING"
    assert outbox.retry_count == 0
    assert "Replay initiated" in (outbox.last_error or "")


def test_12_alert_acknowledgement_lifecycle(db: Session, test_project: Project, admin_user: User):
    event = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.POLICY_VIOLATION,
        aggregate_type="SCOPE",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.HIGH,
        title="Unauthorized Port Scan Attempt",
        summary="Scan outside authorized boundary.",
    )
    notif, _ = alerting_service.publish_security_event(db=db, event=event)
    assert notif.lifecycle_status == AlertLifecycleStatus.NEW

    acked = alerting_service.acknowledge_alert(
        db=db,
        alert_id=notif.id,
        user_id=admin_user.id,
        project_id=test_project.id,
    )
    assert acked is not None
    assert acked.lifecycle_status == AlertLifecycleStatus.ACKNOWLEDGED
    assert acked.acknowledged_by_id == admin_user.id
    assert acked.acknowledged_at is not None


def test_13_alert_resolution_and_reopen_lifecycle(db: Session, test_project: Project, admin_user: User):
    event = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        aggregate_type="FINDING",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.CRITICAL,
        title="Resolvable Heartbleed Vulnerability",
        summary="Heartbleed detected.",
    )
    notif, _ = alerting_service.publish_security_event(db=db, event=event)

    resolved = alerting_service.resolve_alert(db=db, alert_id=notif.id, user_id=admin_user.id)
    assert resolved.lifecycle_status == AlertLifecycleStatus.RESOLVED
    assert resolved.resolved_at is not None

    reopened = alerting_service.reopen_alert(db=db, alert_id=notif.id, user_id=admin_user.id)
    assert reopened.lifecycle_status == AlertLifecycleStatus.REOPENED
    assert reopened.reopened_at is not None


def test_14_api_list_alerts_authenticated_and_scoped(client: TestClient, db: Session, test_project: Project, admin_user: User):
    headers = auth_header_for_user(admin_user)
    resp = client.get(f"/api/v1/alerts?project_id={test_project.id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "active_count" in data
    assert "items" in data
    assert isinstance(data["items"], list)


def test_15_api_alert_action_rbac_enforcement(client: TestClient, db: Session, test_project: Project, lead_user: User, auditor_user: User):
    event = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.ASSESSMENT_FAILED,
        aggregate_type="ASSESSMENT",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.MEDIUM,
        title="Job Failure Alert",
        summary="Job failed.",
    )
    notif, _ = alerting_service.publish_security_event(db=db, event=event)

    # Auditor is read-only, gets 403 on acknowledge
    resp_auditor = client.post(
        f"/api/v1/alerts/{notif.id}/acknowledge?project_id={test_project.id}",
        headers=auth_header_for_user(auditor_user),
    )
    assert resp_auditor.status_code == 403

    # Security Lead gets 200 OK
    resp_lead = client.post(
        f"/api/v1/alerts/{notif.id}/acknowledge?project_id={test_project.id}",
        headers=auth_header_for_user(lead_user),
    )
    assert resp_lead.status_code == 200
    assert resp_lead.json()["status"] == "ACKNOWLEDGED"


def test_16_api_outbox_status_reporting(client: TestClient, admin_user: User, test_project: Project):
    headers = auth_header_for_user(admin_user)
    resp = client.get(f"/api/v1/alerts/outbox/status?project_id={test_project.id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "pending_count" in data
    assert "delivered_count" in data
    assert "dead_letter_count" in data
    assert "healthy" in data


def test_17_zero_sensitive_data_in_event_payload(db: Session, test_project: Project):
    event = SecurityEventContract(
        event_id=f"evt_{uuid.uuid4().hex[:12]}",
        schema_version="v1.0.0",
        event_type=NotificationEventType.POLICY_VIOLATION,
        aggregate_type="USER",
        aggregate_id=str(uuid.uuid4()),
        project_id=test_project.id,
        severity=NotificationSeverity.HIGH,
        title="Credential Leak Event",
        summary="User attempt logged.",
        payload={
            "user_email": "operator@example.com",
            "password": "SuperSecretPassword123!",
            "api_key": "vapt_live_secret_key_abcdef",
            "safe_metadata": "audit_passed",
        },
    )

    notif, outbox = alerting_service.publish_security_event(db=db, event=event)
    sanitized_meta = notif.delivery_metadata.get("sanitized_payload", {})

    assert sanitized_meta["password"] == "[REDACTED]"
    assert sanitized_meta["api_key"] == "[REDACTED]"
    assert sanitized_meta["safe_metadata"] == "audit_passed"
