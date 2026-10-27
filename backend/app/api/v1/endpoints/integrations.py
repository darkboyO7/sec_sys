from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.audit import AuditEvent
from app.api.deps import get_current_user, verify_project_access, get_client_ip
from app.schemas.integrations import (
    IntegrationHealthRead,
    KevEntryRead,
    WebhookTestRequest,
    WebhookDeliveryRead,
    SiemExportResponse,
)
from app.services.integrations import (
    CisaKevFeedAdapter,
    WebhookNotifierAdapter,
    SiemExporterAdapter,
)

router = APIRouter()

# Singletons for adapter instances
_cisa_feed = CisaKevFeedAdapter()
_webhook_notifier = WebhookNotifierAdapter(config={
    "webhook_url": "https://siem-alert.internal.corp/webhook",
    "secret_token": "vapt_webhook_secret_key_prod_secure_2026",
    "max_retries": 3,
    "timeout_seconds": 5.0,
})
_siem_exporter = SiemExporterAdapter()


@router.get(
    "/projects/{project_id}/integrations/status",
    response_model=List[IntegrationHealthRead],
    status_code=status.HTTP_200_OK,
    summary="Get status and health of all configured enterprise integrations",
)
def get_integrations_status(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return [
        IntegrationHealthRead(
            name=_cisa_feed.name,
            version=_cisa_feed.version,
            status=_cisa_feed.status.value,
            details=_cisa_feed.health_check(),
        ),
        IntegrationHealthRead(
            name=_webhook_notifier.name,
            version=_webhook_notifier.version,
            status=_webhook_notifier.status.value,
            details=_webhook_notifier.health_check(),
        ),
        IntegrationHealthRead(
            name=_siem_exporter.name,
            version=_siem_exporter.version,
            status=_siem_exporter.status.value,
            details=_siem_exporter.health_check(),
        ),
    ]


@router.get(
    "/projects/{project_id}/integrations/kev/lookup",
    response_model=Optional[KevEntryRead],
    status_code=status.HTTP_200_OK,
    summary="Look up a CVE in the authoritative CISA KEV catalog",
)
def lookup_cve_kev(
    project_id: str,
    cve_id: str = Query(..., description="CVE identifier, e.g. CVE-2021-44228"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    entry = _cisa_feed.enrich_cve(cve_id)
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE '{cve_id}' not found in CISA KEV catalog.",
        )
    return entry


@router.get(
    "/projects/{project_id}/integrations/kev/catalog",
    response_model=List[KevEntryRead],
    status_code=status.HTTP_200_OK,
    summary="Search CISA KEV catalog by keyword, vendor, or product",
)
def search_kev_catalog(
    project_id: str,
    query: Optional[str] = Query(None, description="Search query keyword"),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return _cisa_feed.query_catalog(query=query, limit=limit)


@router.post(
    "/projects/{project_id}/integrations/webhook/test",
    response_model=WebhookDeliveryRead,
    status_code=status.HTTP_200_OK,
    summary="Dispatch a signed test event to the configured webhook endpoint",
)
def test_webhook_dispatch(
    project_id: str,
    payload: WebhookTestRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )

    data = payload.custom_payload or {
        "finding_id": "test-finding-001",
        "title": "Critical Authentication Bypass (Simulated)",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "initiated_by": current_user.email,
    }

    delivery = _webhook_notifier.dispatch_event(
        event_type=payload.event_type,
        project_id=project_id,
        data=data,
        simulate_success=True,
    )
    return delivery


@router.get(
    "/projects/{project_id}/integrations/webhook/history",
    response_model=List[WebhookDeliveryRead],
    status_code=status.HTTP_200_OK,
    summary="Retrieve delivery history of webhook notifications",
)
def get_webhook_history(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    # Filter history by project
    history = [d for d in _webhook_notifier.dispatch_history if d.get("project_id") == project_id]
    return history[-50:]


@router.get(
    "/projects/{project_id}/integrations/siem/export",
    response_model=SiemExportResponse,
    status_code=status.HTTP_200_OK,
    summary="Export project audit events formatted in CEF, Syslog, or JSON stream",
)
def export_siem_audit_stream(
    project_id: str,
    format_type: str = Query("CEF", description="Export format: CEF, SYSLOG, or JSON"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)

    # Fetch audit events for this project
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.project_id == project_id)
        .order_by(AuditEvent.timestamp.desc())
        .limit(limit)
        .all()
    )

    event_dicts = [
        {
            "action": e.action,
            "description": f"{e.action} on {e.target_type}:{e.target_id}",
            "severity": "INFO",
            "project_id": e.project_id,
            "actor_id": e.actor_id,
            "client_ip": e.ip_address or "127.0.0.1",
            "event_hash": getattr(e, "event_hash", None),
            "sequence_id": getattr(e, "sequence_id", None),
            "target_resource": f"{e.target_type}:{e.target_id}",
            "details": e.details,
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
        }
        for e in events
    ]

    stream = _siem_exporter.export_audit_stream(event_dicts, format_type=format_type)

    return SiemExportResponse(
        project_id=project_id,
        format=format_type.upper(),
        total_events=len(stream),
        stream=stream,
        exported_at=datetime.now(timezone.utc),
    )
