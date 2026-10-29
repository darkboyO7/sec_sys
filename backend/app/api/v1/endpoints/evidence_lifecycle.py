"""
VAPT Platform — Evidence Lifecycle Governance & Data Retention Endpoints (Prompt 29).
Provides endpoints for:
1. Retention policy catalog and management.
2. Legal & investigation hold creation, release, and inspection.
3. Retention preview with deterministic dry-run state hashing.
4. Bounded, auditable retention execution with cryptographic suppression tombstones.
5. In-line evidence secret detection and payload redaction.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.deps import get_current_user, require_system_roles
from app.models.user import User, SystemRole
from app.schemas.evidence_lifecycle import (
    RetentionPolicyModel,
    LegalHoldModel,
    LegalHoldCreate,
    DeletionTombstoneModel,
    RetentionPreviewReport,
    RetentionExecutionRequest,
    RetentionExecutionResult,
    EvidenceRedactionRequest,
    EvidenceRedactionResult,
)
from app.services.evidence_lifecycle_service import evidence_lifecycle_service

router = APIRouter()


@router.get("/policies", response_model=List[RetentionPolicyModel], summary="List Configured Retention Policies")
def list_retention_policies(
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.AUDITOR,
        ])
    ),
):
    """Returns the authoritative data classification retention policies."""
    return evidence_lifecycle_service.get_policies()


@router.put("/policies/{policy_id}", response_model=RetentionPolicyModel, summary="Update Retention Policy")
def update_retention_policy(
    policy_id: str,
    policy_update: RetentionPolicyModel,
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
        ])
    ),
):
    """Updates retention policy parameters. Enforces ADMIN role privilege."""
    if policy_id != policy_update.policy_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Policy ID mismatch.")
    return evidence_lifecycle_service.update_policy(policy_update)


@router.get("/holds", response_model=List[LegalHoldModel], summary="List Active Legal & Investigation Holds")
def list_legal_holds(
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.AUDITOR,
        ])
    ),
):
    """Returns all active legal and investigation holds."""
    return evidence_lifecycle_service.list_holds()


@router.post("/holds", response_model=LegalHoldModel, summary="Place Legal or Investigation Hold")
def create_legal_hold(
    create: LegalHoldCreate,
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """Places a binding legal or investigation hold on a project, finding, or evidence item."""
    return evidence_lifecycle_service.create_hold(create=create, placed_by_id=current_user.id)


@router.delete("/holds/{hold_id}", response_model=LegalHoldModel, summary="Release Legal Hold")
def release_legal_hold(
    hold_id: str,
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """Releases an active hold, allowing normal retention policies to resume."""
    hold = evidence_lifecycle_service.release_hold(hold_id=hold_id, released_by_id=current_user.id)
    if not hold:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Hold {hold_id} not found.")
    return hold


@router.get("/preview", response_model=RetentionPreviewReport, summary="Generate Retention Preview")
def get_retention_preview(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """
    Scans persistent evidence records and generates a dry-run preview report,
    accounting for active legal holds, dependencies, and applicable policies.
    """
    return evidence_lifecycle_service.generate_retention_preview(db=db)


@router.post("/execute", response_model=RetentionExecutionResult, summary="Execute Retention Actions")
def execute_retention(
    req: RetentionExecutionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """
    Executes destructive or archiving retention actions against a verified preview.
    Requires explicit Security Lead confirmation and dry-run state hash consistency.
    """
    try:
        return evidence_lifecycle_service.execute_retention(
            req=req,
            db=db,
            executed_by_id=current_user.id,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.get("/tombstones", response_model=List[DeletionTombstoneModel], summary="List Deletion Suppression Tombstones")
def list_deletion_tombstones(
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.AUDITOR,
        ])
    ),
):
    """Returns cryptographic deletion suppression tombstones preventing restoration resurrection."""
    return evidence_lifecycle_service.list_tombstones()


@router.post("/redact-evidence", response_model=EvidenceRedactionResult, summary="Redact Sensitive Evidence Payload")
def redact_evidence_record(
    req: EvidenceRedactionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """Sanitizes sensitive tokens and credentials from an active evidence record."""
    try:
        return evidence_lifecycle_service.redact_evidence_record(
            evidence_id=req.evidence_id,
            db=db,
            reason=req.redaction_reason,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
