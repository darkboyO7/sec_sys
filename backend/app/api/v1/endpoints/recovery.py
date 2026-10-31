from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.api.deps import get_current_user
from app.services.backup_service import BackupRecoveryService
from app.services.backup_scheduler_service import BackupSchedulerService
from app.services.rate_limit_service import rate_limiter
from app.services.data_portability_service import data_portability_service
from app.schemas.recovery import (
    DisasterRecoveryBundleResponse,
    BackupVerificationResultResponse,
    RestoreDrillResponse,
    LiveRestoreRequest,
    LiveRestoreResponse,
    RotationRequest,
    RotationResponse,
    RecoveryStatusResponse,
    BackupScheduleCreate,
    BackupScheduleUpdate,
    BackupScheduleResponse,
    BackupScheduleRunResponse,
    DiskSpaceStatusResponse,
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


# ------------------------------------------------------------------------------
# Prompt 42: Automated Backup Scheduling, Storage Checks & Failure Handling
# ------------------------------------------------------------------------------

@router.get("/disk-space", response_model=DiskSpaceStatusResponse)
def get_disk_space_status(
    storage_path: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Inspects storage capacity and remaining disk space for backup destination (Prompt 42, Req 12).
    """
    return BackupSchedulerService.check_disk_space(storage_path)


@router.get("/schedules", response_model=List[BackupScheduleResponse])
def list_backup_schedules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Lists all configured automated backup schedules and their execution status (Prompt 42).
    """
    return BackupSchedulerService.list_schedules(db)


@router.post("/schedules", response_model=BackupScheduleResponse, status_code=status.HTTP_201_CREATED)
def create_backup_schedule(
    req: BackupScheduleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Creates a new periodic automated backup schedule with configurable retention and verification (Admin only).
    """
    require_admin(current_user)
    return BackupSchedulerService.create_schedule(db=db, data=req, actor_id=current_user.id)


@router.get("/schedules/{schedule_id}", response_model=BackupScheduleResponse)
def get_backup_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves details and execution metrics for a specific backup schedule.
    """
    schedule = BackupSchedulerService.get_schedule(db=db, schedule_id=schedule_id)
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Backup schedule not found.")
    return schedule


@router.put("/schedules/{schedule_id}", response_model=BackupScheduleResponse)
def update_backup_schedule(
    schedule_id: str,
    req: BackupScheduleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Modifies frequency, retention limits, or execution flags for a backup schedule (Admin only).
    """
    require_admin(current_user)
    try:
        return BackupSchedulerService.update_schedule(db=db, schedule_id=schedule_id, data=req, actor_id=current_user.id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_backup_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Deletes an automated backup schedule (Admin only).
    """
    require_admin(current_user)
    deleted = BackupSchedulerService.delete_schedule(db=db, schedule_id=schedule_id, actor_id=current_user.id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Backup schedule not found.")
    return None


@router.post("/schedules/{schedule_id}/trigger", response_model=BackupScheduleRunResponse)
def trigger_backup_schedule(
    schedule_id: str,
    force: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Triggers immediate execution of a backup schedule, enforcing storage checks and retention (Admin only).
    """
    require_admin(current_user)
    try:
        result = BackupSchedulerService.execute_schedule(
            db=db,
            schedule_id=schedule_id,
            actor_id=current_user.id,
            force=force,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/schedules/poll-due", response_model=List[BackupScheduleRunResponse])
def poll_due_schedules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes all active schedules that are currently due for execution (Admin only).
    """
    require_admin(current_user)
    return BackupSchedulerService.run_due_schedules(db)


@router.get("/readiness", response_model=Dict[str, Any])
def get_recovery_readiness(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns comprehensive Disaster Recovery readiness, RPO/RTO adherence metrics,
    storage Object Lock/WORM compliance, active legal holds, and runbooks (Prompt 58-62).
    """
    return BackupRecoveryService.get_recovery_readiness(db=db)


@router.post("/drill", response_model=Dict[str, Any])
def trigger_recovery_drill(
    bundle_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Triggers an isolated disaster recovery drill in a sandbox environment without
    touching live production data, and verifies post-recovery Merkle custody chains (Admin only).
    """
    require_admin(current_user)
    if not bundle_id:
        # Use latest verified bundle or last known good
        readiness = BackupRecoveryService.get_recovery_readiness(db=db)
        bundle_id = readiness["metrics"].get("last_known_good_id") or readiness["metrics"].get("latest_backup_id")
        if not bundle_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No backup bundles available for recovery drill.")

    try:
        drill_result = BackupRecoveryService.restore_disaster_recovery_bundle(
            bundle_path_or_id=bundle_id,
            is_drill=True,
            db=db,
            authorizer_id=current_user.id,
            preserve_scratch=False,
        )
        return drill_result
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Recovery drill failed: {str(e)}")


@router.post("/export", response_model=Dict[str, Any])
def export_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generates a cryptographically signed, safe project portability archive
    preserving UUIDs, timestamps, findings, evidence payloads, and custody ledgers.
    """
    require_admin(current_user)
    try:
        return data_portability_service.export_project_archive(
            db=db,
            project_id=project_id,
            actor_id=current_user.id,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Export failed: {str(e)}")


@router.post("/import", response_model=Dict[str, Any])
def import_project(
    archive_path: str,
    target_project_id: Optional[str] = None,
    dry_run: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Validates and imports a project archive, enforcing Zip Slip protection,
    manifest digital signature attestation, and atomic transaction commit.
    """
    require_admin(current_user)
    try:
        return data_portability_service.import_project_archive(
            db=db,
            archive_path=archive_path,
            target_project_id=target_project_id,
            actor_id=current_user.id,
            dry_run=dry_run,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Import failed: {str(e)}")

