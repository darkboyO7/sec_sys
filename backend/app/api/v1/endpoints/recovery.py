from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.api.deps import get_current_user
from app.services.backup_service import BackupRecoveryService
from app.services.rate_limit_service import rate_limiter
from app.schemas.recovery import (
    DisasterRecoveryBundleResponse,
    BackupVerificationResultResponse,
    RestoreDrillResponse,
    LiveRestoreRequest,
    LiveRestoreResponse,
    RotationRequest,
    RotationResponse,
    RecoveryStatusResponse,
)

router = APIRouter(prefix="/recovery", tags=["Disaster Recovery & Data Integrity"])


def require_admin(current_user: User) -> None:
    if current_user.system_role != SystemRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Disaster recovery administration requires System Administrator privileges.",
        )


@router.post("/bundles", response_model=Dict[str, Any])
def create_bundle(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Creates a point-in-time disaster recovery bundle using SQLite online backup API
    with atomic staging and cryptographic manifest generation (Admin only).
    """
    require_admin(current_user)
    allowed, remaining, retry_after = rate_limiter.is_allowed(key=current_user.id, bucket="RECOVERY_LIVE")
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for disaster recovery operations. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )
    try:
        bundle = BackupRecoveryService.create_disaster_recovery_bundle(
            db=db,
            actor_id=current_user.id,
        )
        return bundle
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/bundles", response_model=List[Dict[str, Any]])
def list_bundles(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Lists all available disaster recovery backup bundles with status, table counts,
    and cryptographic integrity digests.
    """
    bundles = BackupRecoveryService.list_disaster_recovery_bundles(db=db)
    return bundles


@router.get("/bundles/{bundle_id}", response_model=Dict[str, Any])
def get_bundle(
    bundle_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves complete manifest, catalog, and verification drill history for a specific bundle.
    """
    try:
        details = BackupRecoveryService.get_bundle_details(bundle_id=bundle_id, db=db)
        return details
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/bundles/{bundle_id}/verify", response_model=BackupVerificationResultResponse)
def verify_bundle(
    bundle_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes independent, non-destructive verification of bundle integrity:
    manifest signature, file digests, SQLite PRAGMA integrity, foreign keys, and audit chain.
    """
    require_admin(current_user)
    allowed, remaining, retry_after = rate_limiter.is_allowed(key=current_user.id, bucket="RECOVERY_LIVE")
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for disaster recovery operations. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )
    try:
        result = BackupRecoveryService.verify_disaster_recovery_bundle(
            bundle_path_or_id=bundle_id,
            db=db,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/bundles/{bundle_id}/restore-drill", response_model=RestoreDrillResponse)
def run_restore_drill(
    bundle_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes an isolated restoration drill in a disposable sandbox:
    restores schema, reconciles in-flight jobs to INTERRUPTED, verifies invariants,
    and cleans up without touching the active database (Admin only).
    """
    require_admin(current_user)
    allowed, remaining, retry_after = rate_limiter.is_allowed(key=current_user.id, bucket="RECOVERY_LIVE")
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for disaster recovery operations. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )
    try:
        result = BackupRecoveryService.restore_and_verify_isolated(
            bundle_path_or_id=bundle_id,
            db=db,
            actor_id=current_user.id,
            preserve_scratch=False,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/bundles/{bundle_id}/live-restore", response_model=LiveRestoreResponse)
def live_restore(
    bundle_id: str,
    req: LiveRestoreRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes a governed live database restoration:
    requires confirmation phrase, creates automatic pre-restore rollback,
    reconciles in-flight jobs, and performs atomic swap with rollback on failure (Admin only).
    """
    require_admin(current_user)
    allowed, remaining, retry_after = rate_limiter.is_allowed(key=current_user.id, bucket="RECOVERY_LIVE")
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for disaster recovery operations. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )
    try:
        result = BackupRecoveryService.live_restore_with_governance(
            db=db,
            bundle_path_or_id=bundle_id,
            authorizer_id=current_user.id,
            confirmation_phrase=req.confirmation_phrase,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/rotate", response_model=RotationResponse)
def rotate_backups(
    req: RotationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Safely prunes surplus backups according to retention policy while preserving
    the last-known-good verified backup and cleaning up stale incomplete markers (Admin only).
    """
    require_admin(current_user)
    res = BackupRecoveryService.rotate_backup_bundles(
        db=db,
        max_retained=req.max_retained,
        preserve_last_known_good=req.preserve_last_known_good,
    )
    return res


@router.get("/status", response_model=RecoveryStatusResponse)
def get_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns disaster recovery posture, last verified backup, last restore drill,
    last-known-good bundle, and storage utilization.
    """
    status_data = BackupRecoveryService.get_recovery_status(db=db)
    return status_data
