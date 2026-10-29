"""
Identity Security, Authorization Consistency & Privileged-Action Governance Endpoints (Prompt 36).
REST APIs for permission matrix discovery, attributable access denial auditing,
and object-level tenancy verification.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.authorization import AccessDenialAuditRecord
from app.schemas.authorization import (
    DetailedPermissionMatrixResponse,
    AccessDenialAuditResponse,
)
from app.services.authorization_service import AuthorizationService
from app.api.deps import get_current_user, verify_project_access, require_system_roles

router = APIRouter()


# ---------------------------------------------------------------------------
# Permission Matrix Endpoints
# ---------------------------------------------------------------------------

@router.get("/system/permissions/matrix", response_model=DetailedPermissionMatrixResponse, tags=["Identity & Authorization"])
def get_permission_matrix(
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve authoritative permission catalog and role-to-permission mapping.
    """
    matrix = AuthorizationService.get_permission_matrix()
    return DetailedPermissionMatrixResponse(**matrix)


# ---------------------------------------------------------------------------
# Access Denial Ledger Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/projects/{project_id}/governance/access-denials",
    response_model=List[AccessDenialAuditResponse],
    tags=["Identity & Authorization"],
)
def list_project_access_denials(
    project_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve attributable access denial audit records for the specified project.
    Requires LEAD role in project or platform ADMIN.
    """
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD])

    records = (
        db.query(AccessDenialAuditRecord)
        .filter(AccessDenialAuditRecord.project_id == project_id)
        .order_by(desc(AccessDenialAuditRecord.denied_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return records


@router.get(
    "/system/governance/access-denials",
    response_model=List[AccessDenialAuditResponse],
    tags=["Identity & Authorization"],
)
def list_global_access_denials(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.AUDITOR])),
):
    """
    Retrieve platform-wide access denial audit ledger across all tenants.
    Requires ADMIN or AUDITOR role.
    """
    records = (
        db.query(AccessDenialAuditRecord)
        .order_by(desc(AccessDenialAuditRecord.denied_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return records
