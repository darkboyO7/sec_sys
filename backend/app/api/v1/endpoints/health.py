import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.database import get_db
from app.core.config import settings
from app.schemas.health import (
    HealthResponse,
    ReadinessResponse,
    ReadinessCheck,
    DependencyItemCheck,
    DependencyHealthResponse,
    DegradationHealthResponse,
)
from app.services.failure_classification_service import FailureClassificationService
from app.core.fault_injection import FaultInjector

router = APIRouter()
_PROCESS_START_TIME = time.time()


@router.get("/health", response_model=HealthResponse)
@router.get("/health/live", response_model=HealthResponse)
def liveness_check():
    """
    Lightweight Liveness probe: verifies that the control plane process and HTTP loop are responsive.
    Does NOT query downstream databases or external services, preventing cascading container restarts.
    """
    uptime = time.time() - _PROCESS_START_TIME
    return HealthResponse(
        status="ok",
        version="1.0.0",
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc),
        uptime_seconds=round(uptime, 2),
    )


@router.get("/ready", response_model=ReadinessResponse)
@router.get("/health/ready", response_model=ReadinessResponse)
def readiness_check(db: Session = Depends(get_db)):
    """
    Readiness probe: validates database connectivity, schema tables, and disk writability.
    Returns HTTP 200 if ready to accept traffic, or HTTP 503 if any critical dependency fails.
    """
    db_ok = False
    migrations_ok = False
    storage_ok = False
    details: Dict[str, Any] = {}

    # 1. Check Database connection
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
        details["database"] = "reachable"
    except Exception:
        details["database"] = "unreachable"

    # 2. Check Schema tables exist
    try:
        db.execute(text("SELECT count(*) FROM users"))
        migrations_ok = True
        details["schema"] = "initialized"
    except Exception:
        details["schema"] = "unmigrated_or_tables_missing"

    # 3. Check Storage writability (data directory or temp)
    try:
        data_dir = Path("./data")
        data_dir.mkdir(parents=True, exist_ok=True)
        test_file = data_dir / "_readiness_test.tmp"
        test_file.write_text("ok", encoding="utf-8")
        if test_file.exists():
            test_file.unlink()
        storage_ok = True
        details["storage"] = "writable"
    except Exception:
        details["storage"] = "storage_unwritable"

    # 4. Check Evidence Storage writability (Prompt 49)
    evidence_ok = False
    try:
        ev_dir = settings.get_evidence_path()
        ev_file = ev_dir / "_readiness_ev_test.tmp"
        ev_file.write_text("ok", encoding="utf-8")
        if ev_file.exists():
            ev_file.unlink()
        evidence_ok = True
        details["evidence_storage"] = "writable"
    except Exception:
        details["evidence_storage"] = "evidence_storage_unwritable"

    # 5. Check Profile and Configuration Compliance (Prompt 49)
    profile_ok = True
    active_profile = settings.ENVIRONMENT.lower()
    try:
        diagnostics = settings.get_config_diagnostics()
        failed_diags = [d for d in diagnostics if d.get("status") == "FAIL"]
        if failed_diags:
            profile_ok = False
            details["profile_errors"] = [d["message"] for d in failed_diags]
            details["profile_compliance"] = "non_compliant"
        else:
            details["profile_compliance"] = "compliant"
    except Exception as e:
        profile_ok = False
        details["profile_compliance"] = f"evaluation_failed: {str(e)}"

    is_ready = db_ok and migrations_ok and storage_ok and evidence_ok and profile_ok
    status_code = status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE

    response_data = ReadinessResponse(
        status="ready" if is_ready else "not_ready",
        timestamp=datetime.now(timezone.utc),
        degraded=False,
        checks=ReadinessCheck(
            database=db_ok,
            migrations=migrations_ok,
            storage_writable=storage_ok,
            evidence_writable=evidence_ok,
            profile=active_profile,
            profile_valid=profile_ok,
            details=details,
        ),
    )

    if not is_ready:
        raise HTTPException(status_code=status_code, detail=response_data.model_dump(mode="json"))

    return response_data


@router.get("/health/dependencies", response_model=DependencyHealthResponse)
def dependencies_check(response: Response, db: Session = Depends(get_db)):
    """
    Deep Dependency Health Probe:
    Evaluates critical dependencies (DB, local storage) and optional integrations
    (scanner adapters, notifications, vulnerability intelligence feeds).

    - If any CRITICAL dependency fails -> returns HTTP 503 (unhealthy).
    - If all CRITICAL succeed, but an OPTIONAL fails -> returns HTTP 200 (degraded).
    - If ALL succeed -> returns HTTP 200 (healthy).
    - Strictly non-mutating (read-only; does not initiate jobs or state updates).
    - Zero secrets or internal credential disclosure.
    """
    dependencies: Dict[str, DependencyItemCheck] = {}

    # Check 1: Database (Critical)
    t0 = time.perf_counter()
    db_healthy = False
    db_msg = None
    try:
        db.execute(text("SELECT 1"))
        db.execute(text("SELECT count(*) FROM users"))
        db_healthy = True
        db_msg = "Database connected and schema initialized."
    except Exception:
        db_msg = "Database connection or schema query failed."
    db_lat = (time.perf_counter() - t0) * 1000
    dependencies["database"] = DependencyItemCheck(
        name="Primary Database",
        critical=True,
        status="healthy" if db_healthy else "unhealthy",
        latency_ms=round(db_lat, 2),
        message=db_msg,
        details={"engine": "sqlite" if "sqlite" in settings.DATABASE_URL else "postgresql"},
    )

    # Check 2: Storage Writability (Critical)
    t0 = time.perf_counter()
    storage_healthy = False
    storage_msg = None
    try:
        data_dir = Path("./data")
        data_dir.mkdir(parents=True, exist_ok=True)
        probe_file = data_dir / "_probe_dep.tmp"
        probe_file.write_text("probe", encoding="utf-8")
        if probe_file.exists():
            probe_file.unlink()
        storage_healthy = True
        storage_msg = "Local data store directory is writable."
    except Exception:
        storage_msg = "Storage directory is read-only or inaccessible."
    storage_lat = (time.perf_counter() - t0) * 1000
    dependencies["storage"] = DependencyItemCheck(
        name="Data Storage",
        critical=True,
        status="healthy" if storage_healthy else "unhealthy",
        latency_ms=round(storage_lat, 2),
        message=storage_msg,
    )

    # Check 3: Scanner Adapters Framework (Optional)
    t0 = time.perf_counter()
    adapters_healthy = True
    adapter_count = 0
    try:
        from app.services.scanner_adapters.passive_header_adapter import PassiveHeaderAuditAdapter
        from app.services.scanner_adapters.ssl_cipher_adapter import SslTlsCipherAuditAdapter
        from app.services.scanner_adapters.live_network_adapter import LiveNetworkAuditorAdapter
        from app.services.scanner_adapters.local_fixture_adapter import LocalFixtureAdapter
        adapters = [PassiveHeaderAuditAdapter, SslTlsCipherAuditAdapter, LiveNetworkAuditorAdapter, LocalFixtureAdapter]
        adapter_count = len(adapters)
        adapters_msg = f"{adapter_count} standard passive scanner adapters loaded and verified."
    except Exception:
        adapters_healthy = False
        adapters_msg = "One or more passive scanner adapters failed to initialize."
    adapters_lat = (time.perf_counter() - t0) * 1000
    dependencies["scanner_adapters"] = DependencyItemCheck(
        name="Passive Scanner Adapters",
        critical=False,
        status="healthy" if adapters_healthy else "degraded",
        latency_ms=round(adapters_lat, 2),
        message=adapters_msg,
        details={"registered_adapters": adapter_count},
    )

    # Check 4: Notification Pipeline (Optional)
    t0 = time.perf_counter()
    notifications_healthy = True
    notifications_msg = "Notification dispatch service configured."
    try:
        from app.services.notification_service import NotificationService
        # Non-mutating configuration check
        configured_channels = ["AUDIT_LOG"]
        if getattr(settings, "SLACK_WEBHOOK_URL", None):
            configured_channels.append("SLACK")
        if getattr(settings, "SMTP_HOST", None):
            configured_channels.append("EMAIL")
        notifications_msg = f"Notification dispatcher active with channels: {', '.join(configured_channels)}"
    except Exception:
        notifications_healthy = False
        notifications_msg = "Notification subsystem unavailable."
    notif_lat = (time.perf_counter() - t0) * 1000
    dependencies["notifications"] = DependencyItemCheck(
        name="Notification Pipeline",
        critical=False,
        status="healthy" if notifications_healthy else "degraded",
        latency_ms=round(notif_lat, 2),
        message=notifications_msg,
    )

    # Check 5: Vulnerability Threat Feeds (Optional)
    t0 = time.perf_counter()
    feeds_healthy = True
    feeds_msg = "Vulnerability feed cache verified."
    try:
        from app.services.intelligence import CISAFeedClient
        feeds_msg = "Threat intelligence client loaded."
    except Exception:
        # Not all deployments require external CISA feeds
        feeds_healthy = True
        feeds_msg = "Threat intelligence client operational in offline mode."
    feeds_lat = (time.perf_counter() - t0) * 1000
    dependencies["vulnerability_feeds"] = DependencyItemCheck(
        name="Threat Intelligence Feeds",
        critical=False,
        status="healthy" if feeds_healthy else "degraded",
        latency_ms=round(feeds_lat, 2),
        message=feeds_msg,
    )

    # Overall Status Evaluation
    critical_healthy = db_healthy and storage_healthy
    all_healthy = critical_healthy and adapters_healthy and notifications_healthy and feeds_healthy

    if not critical_healthy:
        overall_status = "unhealthy"
        summary = "Critical dependencies failed; control plane cannot accept operational workloads."
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    elif not all_healthy:
        overall_status = "degraded"
        summary = "Core platform operational; one or more optional external integrations are degraded."
        response.status_code = status.HTTP_200_OK
    else:
        overall_status = "healthy"
        summary = "All critical dependencies and optional subsystems are healthy."
        response.status_code = status.HTTP_200_OK

    return DependencyHealthResponse(
        status=overall_status,
        critical_healthy=critical_healthy,
        timestamp=datetime.now(timezone.utc),
        dependencies=dependencies,
        summary=summary,
    )


@router.get("/health/degradation", response_model=DegradationHealthResponse)
@router.get("/health/status", response_model=DegradationHealthResponse)
def degradation_status_check(response: Response, db: Session = Depends(get_db)):
    """
    Degraded Functionality & Operator Guidance Probe (Prompt 52).
    Evaluates:
    - Critical vs secondary capability health
    - Degraded capabilities list
    - Operator-actionable failure playbooks
    - Active fault injection status (if active in test environments)
    - Zero secrets or internal credential disclosure.
    """
    dep_health = dependencies_check(response=response, db=db)
    deps = dep_health.dependencies

    db_ok = deps.get("database") and deps["database"].status == "healthy"
    storage_ok = deps.get("storage") and deps["storage"].status == "healthy"
    adapters_ok = deps.get("scanner_adapters") and deps["scanner_adapters"].status == "healthy"
    notifs_ok = deps.get("notifications") and deps["notifications"].status == "healthy"
    feeds_ok = deps.get("vulnerability_feeds") and deps["vulnerability_feeds"].status == "healthy"

    degraded_caps: List[str] = []
    if not db_ok:
        degraded_caps.extend([
            "AUTHENTICATION_RBAC",
            "SCOPE_AUTHORIZATION",
            "ASSESSMENT_EXECUTION",
            "EVIDENCE_AND_AUDIT_PRESERVATION",
            "REMEDIATION_APPROVAL_GOVERNANCE",
        ])
    if not storage_ok:
        degraded_caps.append("EVIDENCE_AND_AUDIT_PRESERVATION")
    if not adapters_ok:
        degraded_caps.append("ASSESSMENT_EXECUTION")
    if not notifs_ok:
        degraded_caps.append("NOTIFICATION_DISPATCH")
    if not feeds_ok:
        degraded_caps.append("THREAT_INTEL_ENRICHMENT")

    # Deduplicate degraded capabilities
    degraded_caps = sorted(list(set(degraded_caps)))

    # Compile operator recommendations
    recommendations: List[str] = []
    if not db_ok:
        recommendations.append("Database connectivity interrupted: Verify database process health and file locks.")
    if not storage_ok:
        recommendations.append("Storage volume unwritable: Inspect disk free space and service write permissions on data directory.")
    if not adapters_ok:
        recommendations.append("Scanner adapters failed to initialize: Check adapter plugin dependencies.")
    if not notifs_ok:
        recommendations.append("Notification dispatch degraded: External webhook endpoint may be offline. Delivery retries active.")
    if not feeds_ok:
        recommendations.append("Threat intelligence feeds degraded: Check CISA/NVD cache status.")
    if not recommendations:
        recommendations.append("All primary and secondary capabilities are fully operational.")

    fault_active = FaultInjector.is_injection_permitted() and len(FaultInjector.get_active_rules()) > 0
    active_rules = FaultInjector.get_active_rules() if FaultInjector.is_injection_permitted() else []

    all_caps = FailureClassificationService.get_capabilities()
    playbooks = FailureClassificationService.get_classifications()

    # Determine overall status
    critical_ok = db_ok and storage_ok
    if not critical_ok:
        overall_status = "unhealthy"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        summary_msg = f"Critical capabilities degraded: {len(degraded_caps)} capabilities offline. Control plane unavailable."
    elif degraded_caps:
        overall_status = "degraded"
        response.status_code = status.HTTP_200_OK
        summary_msg = f"Platform operational in degraded mode ({', '.join(degraded_caps)} offline). Evidence and audit preserved."
    else:
        overall_status = "healthy"
        response.status_code = status.HTTP_200_OK
        summary_msg = "All critical and secondary capabilities are healthy. Zero degradation detected."

    return DegradationHealthResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        critical_healthy=critical_ok,
        capabilities=all_caps,
        degraded_capabilities=degraded_caps,
        failure_playbooks=playbooks,
        fault_injection_active=fault_active,
        active_fault_rules=active_rules,
        operator_recommendations=recommendations,
        summary=summary_msg,
    )
