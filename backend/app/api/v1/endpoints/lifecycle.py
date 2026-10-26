from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.api.deps import get_current_user, verify_project_access
from app.services.backup_service import BackupRecoveryService

router = APIRouter()


class ProjectPurgeRequest(BaseModel):
    confirmation_phrase: str


class RetentionPolicyRequest(BaseModel):
    retention_days: int = 180


class BackupVerifyRequest(BaseModel):
    backup_file_path: str
    expected_sha256: str


@router.get("/projects/{project_id}/lifecycle/export")
def export_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate and return a cryptographic export manifest of all project data."""
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    try:
        manifest = BackupRecoveryService.export_project_manifest(db, project_id, actor_id=current_user.id)
        return manifest
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/projects/{project_id}/lifecycle/purge")
def purge_project(
    project_id: str,
    req: ProjectPurgeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Permanently delete project and all dependent assessment data (Lead/Admin only)."""
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    try:
        res = BackupRecoveryService.purge_project_data(
            db=db,
            project_id=project_id,
            actor_id=current_user.id,
            confirmation_phrase=req.confirmation_phrase,
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/projects/{project_id}/lifecycle/retention")
def apply_retention(
    project_id: str,
    req: RetentionPolicyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Prune raw evidence older than specified retention days."""
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    res = BackupRecoveryService.apply_evidence_retention_policy(
        db=db,
        project_id=project_id,
        retention_days=req.retention_days,
        actor_id=current_user.id,
    )
    return res


@router.post("/admin/backup")
def create_backup(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a point-in-time database backup (Admin only)."""
    if current_user.system_role != SystemRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required for system backups.")
    meta = BackupRecoveryService.create_database_backup(db, actor_id=current_user.id)
    return meta.to_dict()


@router.post("/admin/backup/verify")
def verify_backup(
    req: BackupVerifyRequest,
    current_user: User = Depends(get_current_user),
):
    """Cryptographically verify and test restore a backup in a sandbox (Admin only)."""
    if current_user.system_role != SystemRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required for backup verification.")
    try:
        res = BackupRecoveryService.verify_and_test_restore(
            backup_file_path=req.backup_file_path,
            expected_sha256=req.expected_sha256,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
