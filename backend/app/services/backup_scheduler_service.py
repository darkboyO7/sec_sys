"""
Automated Backup Scheduling, Failure Handling & Restoration Assurance Service (Prompt 42).
Manages configurable periodic backup jobs, pre-flight storage capacity checks,
automated cryptographic verifications, retention rotation, and failure tracking.
"""
import os
import shutil
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.recovery import (
    BackupScheduleRecord,
    ScheduleRunStatus,
    DisasterRecoveryBundleRecord,
    RecoveryBundleStatus,
)
from app.models.base import utc_now
from app.schemas.recovery import BackupScheduleCreate, BackupScheduleUpdate
from app.services.backup_service import BackupRecoveryService
from app.services.audit_service import AuditService


class InsufficientDiskSpaceError(Exception):
    """Raised when destination storage volume does not have sufficient free space for backups."""
    pass


class BackupSchedulerService:
    """
    Orchestrates policy-driven automated backups, non-destructive restoration drills,
    and storage capacity governance.
    """

    @classmethod
    def check_disk_space(
        cls,
        storage_path: Optional[str] = None,
        minimum_required_bytes: int = 50 * 1024 * 1024,  # 50 MB default safety margin
    ) -> Dict[str, Any]:
        """
        Inspects available disk storage at designated backup destination (Prompt 42, Req 12).
        Fails closed if remaining space is below safety threshold.
        """
        target = Path(storage_path or "./data/backups").resolve()

        try:
            target.mkdir(parents=True, exist_ok=True)
            usage = shutil.disk_usage(str(target))
            total_bytes = usage.total
            used_bytes = usage.used
            free_bytes = usage.free
        except Exception as e:
            # Storage path inaccessible or non-writable: fail closed
            return {
                "storage_path": str(target),
                "total_bytes": 0,
                "free_bytes": 0,
                "used_bytes": 0,
                "free_gb": 0.0,
                "total_gb": 0.0,
                "is_sufficient_for_backup": False,
                "minimum_required_bytes": minimum_required_bytes,
                "message": f"Storage volume inaccessible: {e}",
            }

        is_sufficient = free_bytes >= minimum_required_bytes
        free_gb = round(free_bytes / (1024 ** 3), 2)
        total_gb = round(total_bytes / (1024 ** 3), 2)

        return {
            "storage_path": str(target),
            "total_bytes": total_bytes,
            "free_bytes": free_bytes,
            "used_bytes": used_bytes,
            "free_gb": free_gb,
            "total_gb": total_gb,
            "is_sufficient_for_backup": is_sufficient,
            "minimum_required_bytes": minimum_required_bytes,
            "message": (
                f"Sufficient storage available ({free_gb} GB free)"
                if is_sufficient
                else f"Insufficient storage volume: {free_bytes} bytes free, requires at least {minimum_required_bytes} bytes"
            ),
        }

    @classmethod
    def create_schedule(
        cls,
        db: Session,
        data: BackupScheduleCreate,
        actor_id: Optional[str] = None,
    ) -> BackupScheduleRecord:
        """Creates a new automated backup schedule and calculates initial execution window."""
        now = utc_now()
        next_run = now + timedelta(hours=data.interval_hours)

        schedule = BackupScheduleRecord(
            name=data.name,
            interval_hours=data.interval_hours,
            retention_days=data.retention_days,
            max_bundles_to_keep=data.max_bundles_to_keep,
            storage_location=data.storage_location,
            include_evidence=data.include_evidence,
            auto_verify_after_backup=data.auto_verify_after_backup,
            auto_drill_after_backup=data.auto_drill_after_backup,
            is_active=data.is_active,
            last_run_at=None,
            last_run_status=None,
            consecutive_failures=0,
            next_run_at=next_run if data.is_active else None,
            created_by_id=actor_id,
        )
        db.add(schedule)
        db.commit()
        db.refresh(schedule)

        AuditService.record_event(
            db=db,
            action="BACKUP_SCHEDULE_CREATED",
            target_type="BackupSchedule",
            outcome="SUCCESS",
            target_id=schedule.id,
            actor_id=actor_id,
            details={
                "schedule_name": schedule.name,
                "interval_hours": schedule.interval_hours,
                "storage_location": schedule.storage_location,
                "next_run_at": next_run.isoformat() if data.is_active else None,
            },
        )
        return schedule

    @classmethod
    def update_schedule(
        cls,
        db: Session,
        schedule_id: str,
        data: BackupScheduleUpdate,
        actor_id: Optional[str] = None,
    ) -> BackupScheduleRecord:
        """Modifies an existing backup schedule, adjusting next execution window accordingly."""
        schedule = db.query(BackupScheduleRecord).filter(BackupScheduleRecord.id == schedule_id).first()
        if not schedule:
            raise ValueError(f"Backup schedule with ID {schedule_id} not found.")

        update_dict = data.model_dump(exclude_unset=True)
        for key, val in update_dict.items():
            setattr(schedule, key, val)

        if "interval_hours" in update_dict or "is_active" in update_dict:
            if schedule.is_active:
                schedule.next_run_at = utc_now() + timedelta(hours=schedule.interval_hours)
            else:
                schedule.next_run_at = None

        db.commit()
        db.refresh(schedule)

        AuditService.record_event(
            db=db,
            action="BACKUP_SCHEDULE_UPDATED",
            target_type="BackupSchedule",
            outcome="SUCCESS",
            target_id=schedule.id,
            actor_id=actor_id,
            details={"updated_fields": list(update_dict.keys())},
        )
        return schedule

    @classmethod
    def delete_schedule(
        cls,
        db: Session,
        schedule_id: str,
        actor_id: Optional[str] = None,
    ) -> bool:
        """Deletes a backup schedule definition."""
        schedule = db.query(BackupScheduleRecord).filter(BackupScheduleRecord.id == schedule_id).first()
        if not schedule:
            return False

        db.delete(schedule)
        db.commit()

        AuditService.record_event(
            db=db,
            action="BACKUP_SCHEDULE_DELETED",
            target_type="BackupSchedule",
            outcome="SUCCESS",
            target_id=schedule_id,
            actor_id=actor_id,
            details={"schedule_id": schedule_id},
        )
        return True

    @classmethod
    def list_schedules(cls, db: Session) -> List[BackupScheduleRecord]:
        """Lists all configured backup schedules."""
        return db.query(BackupScheduleRecord).order_by(BackupScheduleRecord.created_at.desc()).all()

    @classmethod
    def get_schedule(cls, db: Session, schedule_id: str) -> Optional[BackupScheduleRecord]:
        """Retrieves a specific backup schedule by ID."""
        return db.query(BackupScheduleRecord).filter(BackupScheduleRecord.id == schedule_id).first()

    @classmethod
    def execute_schedule(
        cls,
        db: Session,
        schedule_id: str,
        actor_id: Optional[str] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes a scheduled backup according to its policy definition:
        1. Pre-flight disk space safety verification.
        2. SQLite online backup bundle generation with SHA-256 digests.
        3. Automated cryptographic verification (if enabled).
        4. Non-destructive isolated restoration drill (if enabled).
        5. Pruning / retention rotation.
        6. Structured audit recording and next_run_at computation.
        """
        schedule = db.query(BackupScheduleRecord).filter(BackupScheduleRecord.id == schedule_id).first()
        if not schedule:
            raise ValueError(f"Backup schedule with ID {schedule_id} not found.")

        if not schedule.is_active and not force:
            raise ValueError(f"Schedule '{schedule.name}' is inactive. Enable schedule or use force execution.")

        now = utc_now()
        result: Dict[str, Any] = {
            "schedule_id": schedule.id,
            "executed_at": now.isoformat(),
            "status": "RUNNING",
            "bundle_id": None,
            "verification_status": None,
            "drill_status": None,
            "error": None,
        }

        # 1. Pre-flight storage check
        disk_check = cls.check_disk_space(schedule.storage_location)
        if not disk_check["is_sufficient_for_backup"]:
            schedule.last_run_at = now
            schedule.last_run_status = ScheduleRunStatus.SKIPPED_DISK_LOW
            schedule.last_run_error = disk_check["message"]
            schedule.consecutive_failures += 1
            if schedule.is_active:
                schedule.next_run_at = now + timedelta(hours=schedule.interval_hours)
            db.commit()

            AuditService.record_event(
                db=db,
                action="BACKUP_SCHEDULE_SKIPPED_DISK_LOW",
                target_type="BackupSchedule",
                outcome="FAILURE",
                target_id=schedule.id,
                actor_id=actor_id,
                details=disk_check,
            )
            result["status"] = "SKIPPED_DISK_LOW"
            result["error"] = disk_check["message"]
            return result

        try:
            # 2. Generate Disaster Recovery Bundle
            bundle = BackupRecoveryService.create_disaster_recovery_bundle(
                db=db,
                backup_root=schedule.storage_location,
                actor_id=actor_id or schedule.created_by_id,
            )
            bundle_id = bundle["bundle_id"]
            result["bundle_id"] = bundle_id

            # 3. Automated Post-Backup Verification
            if schedule.auto_verify_after_backup:
                v_res = BackupRecoveryService.verify_disaster_recovery_bundle(
                    bundle_path_or_id=bundle_id,
                    db=db,
                    backup_root=schedule.storage_location,
                )
                result["verification_status"] = v_res.get("status")
                if v_res.get("status") != "PASSED":
                    raise RuntimeError(f"Automated post-backup verification failed: {v_res.get('errors')}")

            # 4. Automated Restoration Drill (if enabled)
            if schedule.auto_drill_after_backup:
                d_res = BackupRecoveryService.restore_and_verify_isolated(
                    bundle_path_or_id=bundle_id,
                    backup_root=schedule.storage_location,
                    actor_id=actor_id,
                    db=db,
                )
                result["drill_status"] = d_res.get("status")
                if d_res.get("status") != "SUCCESS":
                    raise RuntimeError(f"Automated isolated restore drill failed: {d_res.get('message')}")

            # 5. Retention Pruning
            if schedule.max_bundles_to_keep > 0:
                BackupRecoveryService.rotate_backup_bundles(
                    db=db,
                    backup_root=schedule.storage_location,
                    max_retained=schedule.max_bundles_to_keep,
                    preserve_last_known_good=True,
                )

            # Success updates
            schedule.last_run_at = now
            schedule.last_run_status = ScheduleRunStatus.SUCCESS
            schedule.last_run_error = None
            schedule.last_bundle_id = bundle_id
            schedule.consecutive_failures = 0
            if schedule.is_active:
                schedule.next_run_at = now + timedelta(hours=schedule.interval_hours)
            db.commit()

            result["status"] = "SUCCESS"
            AuditService.record_event(
                db=db,
                action="BACKUP_SCHEDULE_EXECUTED",
                target_type="BackupSchedule",
                outcome="SUCCESS",
                target_id=schedule.id,
                actor_id=actor_id,
                details={
                    "bundle_id": bundle_id,
                    "storage_location": schedule.storage_location,
                    "auto_verified": schedule.auto_verify_after_backup,
                    "auto_drilled": schedule.auto_drill_after_backup,
                },
            )
            return result

        except Exception as e:
            db.rollback()
            err_msg = str(e)
            schedule.last_run_at = now
            schedule.last_run_status = ScheduleRunStatus.FAILED
            schedule.last_run_error = err_msg
            schedule.consecutive_failures += 1
            if schedule.is_active:
                schedule.next_run_at = now + timedelta(hours=schedule.interval_hours)
            db.commit()

            result["status"] = "FAILED"
            result["error"] = err_msg
            AuditService.record_event(
                db=db,
                action="BACKUP_SCHEDULE_FAILED",
                target_type="BackupSchedule",
                outcome="FAILURE",
                target_id=schedule.id,
                actor_id=actor_id,
                details={"error": err_msg, "consecutive_failures": schedule.consecutive_failures},
            )
            return result

    @classmethod
    def run_due_schedules(cls, db: Session) -> List[Dict[str, Any]]:
        """
        Polls and executes all active schedules whose next execution time is due.
        Called by background workers or maintenance dispatchers.
        """
        now = utc_now()
        due_schedules = (
            db.query(BackupScheduleRecord)
            .filter(
                BackupScheduleRecord.is_active == True,
                BackupScheduleRecord.next_run_at <= now,
            )
            .all()
        )

        results = []
        for sched in due_schedules:
            res = cls.execute_schedule(db=db, schedule_id=sched.id, force=False)
            results.append(res)
        return results
