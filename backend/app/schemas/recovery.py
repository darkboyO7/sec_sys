from typing import Optional, Dict, Any, List, Union
from datetime import datetime
from pydantic import BaseModel, Field


class DisasterRecoveryBundleResponse(BaseModel):
    bundle_id: str
    bundle_path: str
    created_at: str
    created_by_id: Optional[str] = None
    manifest_sha256: str
    database_sha256: str
    size_bytes: int
    status: str
    last_verified_at: Optional[str] = None
    verification_report: Optional[Dict[str, Any]] = None
    last_restore_drill_at: Optional[str] = None
    restore_drill_report: Optional[Dict[str, Any]] = None
    is_last_known_good: bool
    table_counts: Optional[Dict[str, int]] = None
    schema_revision: Optional[str] = None


class CheckDetail(BaseModel):
    passed: bool
    detail: str


class BackupVerificationResultResponse(BaseModel):
    bundle_id: str
    status: str  # PASSED or FAILED
    verified_at: str
    checks: Dict[str, Any]
    errors: List[str]


class RestoreDrillResponse(BaseModel):
    status: str  # SUCCESS or FAILED
    bundle_id: str
    drill_type: str
    sandbox_path: str
    jobs_reconciled: List[Dict[str, Any]]
    tables_verified: int
    audit_events_count: int
    sandbox_cleaned: bool
    duration_ms: float
    message: str


class LiveRestoreRequest(BaseModel):
    confirmation_phrase: str = Field(
        ...,
        description="Explicit confirmation phrase: 'CONFIRM DISASTER RESTORE <bundle_id>'",
    )


class LiveRestoreResponse(BaseModel):
    status: str  # RESTORED
    bundle_id: str
    live_db_path: str
    rollback_path: str
    tables_restored: int
    jobs_reconciled_count: int
    audit_events_count: int
    integrity_check: str
    restored_at: str


class RotationRequest(BaseModel):
    max_retained: int = 5
    preserve_last_known_good: bool = True


class RotationResponse(BaseModel):
    bundles_scanned: int
    bundles_retained: int
    bundles_pruned: int
    incomplete_cleaned: int
    last_known_good_preserved: Optional[str] = None
    details: List[str]


class RecoveryStatusResponse(BaseModel):
    total_bundles: int
    incomplete_bundles: int
    last_attempt_at: Optional[str] = None
    last_verified_bundle_id: Optional[str] = None
    last_verified_at: Optional[str] = None
    last_restore_drill_bundle_id: Optional[str] = None
    last_restore_drill_at: Optional[str] = None
    last_known_good_bundle_id: Optional[str] = None
    total_storage_bytes: int
    recovery_readiness: str  # READY, ATTENTION_REQUIRED, DEGRADED


# Prompt 42: Automated Backup Scheduling & Restoration Assurance Schemas
class BackupScheduleCreate(BaseModel):
    name: str = Field(..., max_length=128, description="Human-readable schedule label")
    interval_hours: int = Field(24, ge=1, le=720, description="Backup interval frequency in hours")
    retention_days: int = Field(30, ge=1, le=365, description="Retention limit in days")
    max_bundles_to_keep: int = Field(10, ge=1, le=100, description="Maximum backup bundles to retain")
    storage_location: str = Field("./data/backups", description="Designated backup storage destination")
    include_evidence: bool = Field(True, description="Whether to bundle raw evidence artifacts")
    auto_verify_after_backup: bool = Field(True, description="Automatically run cryptographic verification")
    auto_drill_after_backup: bool = Field(False, description="Automatically run non-destructive restore drill")
    is_active: bool = Field(True, description="Whether schedule is currently active")


class BackupScheduleUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=128)
    interval_hours: Optional[int] = Field(None, ge=1, le=720)
    retention_days: Optional[int] = Field(None, ge=1, le=365)
    max_bundles_to_keep: Optional[int] = Field(None, ge=1, le=100)
    storage_location: Optional[str] = None
    include_evidence: Optional[bool] = None
    auto_verify_after_backup: Optional[bool] = None
    auto_drill_after_backup: Optional[bool] = None
    is_active: Optional[bool] = None


class BackupScheduleResponse(BaseModel):
    id: str
    name: str
    interval_hours: int
    retention_days: int
    max_bundles_to_keep: int
    storage_location: str
    include_evidence: bool
    auto_verify_after_backup: bool
    auto_drill_after_backup: bool
    is_active: bool
    last_run_at: Optional[Union[datetime, str]] = None
    last_run_status: Optional[str] = None
    last_run_error: Optional[str] = None
    last_bundle_id: Optional[str] = None
    consecutive_failures: int
    next_run_at: Optional[Union[datetime, str]] = None
    created_at: Union[datetime, str]

    class Config:
        from_attributes = True


class BackupScheduleRunResponse(BaseModel):
    schedule_id: str
    status: str
    bundle_id: Optional[str] = None
    verification_status: Optional[str] = None
    drill_status: Optional[str] = None
    executed_at: str
    error: Optional[str] = None


class DiskSpaceStatusResponse(BaseModel):
    storage_path: str
    total_bytes: int
    free_bytes: int
    used_bytes: int
    free_gb: float
    total_gb: float
    is_sufficient_for_backup: bool
    minimum_required_bytes: int
    message: str
