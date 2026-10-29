from typing import Optional, Dict, Any, List
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
