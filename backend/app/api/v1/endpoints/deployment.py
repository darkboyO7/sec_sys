"""
VAPT Platform — Secure Windows Deployment & Configuration Governance Endpoints (Prompt 28).
Provides administrative visibility into startup preflight health, redacted configuration,
and schema upgrade readiness.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.deps import get_current_user, require_system_roles
from app.models.user import User, SystemRole
from app.schemas.deployment import (
    PreflightReport,
    RedactedConfigResponse,
    UpgradePrecheckResponse,
    ConfigDiagnosticResponse,
)
from app.services.startup_preflight_service import startup_preflight_service

router = APIRouter()


@router.get("/preflight", response_model=PreflightReport, summary="Execute Startup Preflight Inspection")
def run_preflight(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.AUDITOR,
        ])
    ),
):
    """
    Executes deep startup preflight inspection validating:
    - Cryptographic key strength and production defaults
    - Database engine connectivity and SQLite WAL / FK pragmas
    - Designated storage directory writability (data, evidence, backups, logs)
    - CORS origins and debug mode guardrails
    """
    return startup_preflight_service.run_preflight_checks(db=db)


@router.get("/config", response_model=RedactedConfigResponse, summary="Inspect Redacted Runtime Configuration")
def get_redacted_config(
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.AUDITOR,
        ])
    ),
):
    """
    Returns effective non-secret configuration settings with sensitive credentials,
    tokens, and database connection strings safely redacted.
    """
    return startup_preflight_service.get_redacted_config()


@router.get("/config/diagnostic", response_model=ConfigDiagnosticResponse, summary="Inspect Configuration Diagnostics and Cryptographic Health")
def get_config_diagnostics(
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.AUDITOR,
        ])
    ),
):
    """
    Evaluates individual configuration settings and verifies cryptographic strength
    and missing/insecure parameters without exposing raw secrets.
    """
    return startup_preflight_service.get_config_diagnostics()


@router.post("/upgrade-check", response_model=UpgradePrecheckResponse, summary="Verify Schema Upgrade Readiness")
def check_upgrade_readiness(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """
    Evaluates current Alembic schema revision against repository migration head,
    verifying if pending migrations exist and whether a pre-upgrade backup is required.
    """
    return startup_preflight_service.check_upgrade_readiness(db=db)
