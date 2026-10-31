"""
Comprehensive Deterministic Test Suite for Prompt 42:
Automated Backup Scheduling, Failure Handling & Restoration Assurance.

Covers:
1. Disk space pre-flight validation (sufficient vs below safety margin threshold).
2. Automated Backup Schedule CRUD lifecycle, audit tracking, and execution window calculation.
3. Automated schedule execution triggering full online backup, 7-point cryptographic verification,
   isolated restoration drill, and retention rotation.
4. Polling and batch execution of due backup schedules.
5. Error handling, consecutive failure tracking, and audit recording on execution failures.
6. Comprehensive state inventory: manifest captures database, evidence catalog, model artifacts, and config references.
7. Isolated restore drill verifies database integrity and reconciles in-flight jobs without modifying live database.
8. Detection and rejection of tampered backup archives.
9. RBAC enforcement: non-administrator users are forbidden (403) from mutating backup schedules or triggering backups.
"""

import os
import shutil
import json
import sqlite3
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token
from app.models.user import User, SystemRole
from app.models.project import Project
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.recovery import (
    RecoveryBundleStatus,
    DisasterRecoveryBundleRecord,
    BackupScheduleRecord,
    ScheduleRunStatus,
)
from app.schemas.recovery import BackupScheduleCreate, BackupScheduleUpdate
from app.services.backup_service import (
    BackupRecoveryService,
    compute_sha256,
)
from app.services.backup_scheduler_service import BackupSchedulerService
from app.services.audit_service import AuditService


def _auth_header(user: User) -> dict:
    token = create_access_token(subject=user.id, claims={"email": user.email, "role": user.system_role.value})
    return {"Authorization": f"Bearer {token}"}


def test_01_disk_space_preflight_check(db: Session, client: TestClient, tester_user: User, tmp_path: Path):
    """Verifies storage volume capacity calculation and pre-flight threshold safety."""
    backup_root = tmp_path / "disk_test"
    backup_root.mkdir(parents=True, exist_ok=True)

    # 1. Normal check
    check = BackupSchedulerService.check_disk_space(str(backup_root), minimum_required_bytes=1024 * 1024)
    assert check["is_sufficient_for_backup"] is True
    assert check["free_bytes"] > 0
    assert "Sufficient storage available" in check["message"]

    # 2. Insufficient check (safety threshold exceeds free space)
    unreasonable_margin = 10**18  # Exabyte
    insufficient_check = BackupSchedulerService.check_disk_space(str(backup_root), minimum_required_bytes=unreasonable_margin)
    assert insufficient_check["is_sufficient_for_backup"] is False
    assert "Insufficient storage volume" in insufficient_check["message"]

    # 3. Via REST API
    resp = client.get("/api/v1/recovery/disk-space", headers=_auth_header(tester_user))
    assert resp.status_code == 200
    data = resp.json()
    assert "free_bytes" in data
    assert "is_sufficient_for_backup" in data


def test_02_backup_schedule_crud_lifecycle(db: Session, client: TestClient, admin_user: User, tmp_path: Path):
    """Tests creating, reading, updating, and deleting backup schedules via API."""
    admin_headers = _auth_header(admin_user)
    backup_root = str(tmp_path / "crud_backups")

    # 1. Create schedule
    payload = {
        "name": "Hourly Disaster Assurance",
        "interval_hours": 1,
        "retention_days": 7,
        "max_bundles_to_keep": 5,
        "storage_location": backup_root,
        "include_evidence": True,
        "auto_verify_after_backup": True,
        "auto_drill_after_backup": True,
        "is_active": True,
    }
    create_res = client.post("/api/v1/recovery/schedules", json=payload, headers=admin_headers)
    assert create_res.status_code == 201, create_res.text
    sched_data = create_res.json()
    schedule_id = sched_data["id"]
    assert sched_data["name"] == "Hourly Disaster Assurance"
    assert sched_data["is_active"] is True
    assert sched_data["next_run_at"] is not None

    # 2. Get schedule by ID
    get_res = client.get(f"/api/v1/recovery/schedules/{schedule_id}", headers=admin_headers)
    assert get_res.status_code == 200
    assert get_res.json()["id"] == schedule_id

    # 3. List schedules
    list_res = client.get("/api/v1/recovery/schedules", headers=admin_headers)
    assert list_res.status_code == 200
    assert any(s["id"] == schedule_id for s in list_res.json())

    # 4. Update schedule
    update_res = client.put(
        f"/api/v1/recovery/schedules/{schedule_id}",
        json={"interval_hours": 6, "retention_days": 14},
        headers=admin_headers,
    )
    assert update_res.status_code == 200
    assert update_res.json()["interval_hours"] == 6
    assert update_res.json()["retention_days"] == 14

    # 5. Delete schedule
    del_res = client.delete(f"/api/v1/recovery/schedules/{schedule_id}", headers=admin_headers)
    assert del_res.status_code == 204


def test_03_backup_schedule_execution_with_assurance(db: Session, client: TestClient, admin_user: User, tmp_path: Path):
    """
    Tests triggered execution of a backup schedule:
    Generates online backup bundle, executes 7-point verification, runs isolated drill,
    and updates schedule run status to SUCCESS.
    """
    admin_headers = _auth_header(admin_user)
    backup_root = str(tmp_path / "exec_backups")

    # Create schedule with auto-verify and auto-drill enabled
    payload = {
        "name": "Assurance Execution Schedule",
        "interval_hours": 24,
        "retention_days": 30,
        "max_bundles_to_keep": 3,
        "storage_location": backup_root,
        "include_evidence": True,
        "auto_verify_after_backup": True,
        "auto_drill_after_backup": True,
        "is_active": True,
    }
    create_res = client.post("/api/v1/recovery/schedules", json=payload, headers=admin_headers)
    assert create_res.status_code == 201, create_res.text
    schedule_id = create_res.json()["id"]

    # Trigger manual execution
    trigger_res = client.post(f"/api/v1/recovery/schedules/{schedule_id}/trigger?force=true", headers=admin_headers)
    assert trigger_res.status_code == 200, trigger_res.text
    exec_data = trigger_res.json()

    assert exec_data["status"] == "SUCCESS"
    assert exec_data["bundle_id"] is not None
    assert exec_data["verification_status"] == "PASSED"
    assert exec_data["drill_status"] == "SUCCESS"

    # Verify schedule state in DB
    sched_record = db.query(BackupScheduleRecord).filter(BackupScheduleRecord.id == schedule_id).first()
    assert sched_record.last_run_status == ScheduleRunStatus.SUCCESS
    assert sched_record.last_bundle_id == exec_data["bundle_id"]
    assert sched_record.consecutive_failures == 0
    assert sched_record.last_run_at is not None


def test_04_due_schedules_polling_execution(db: Session, client: TestClient, admin_user: User, tmp_path: Path):
    """Tests the automated runner polling for due schedules and executing them."""
    admin_headers = _auth_header(admin_user)
    backup_root = str(tmp_path / "due_backups")

    # Create schedule set with past next_run_at
    past_due = datetime.utcnow() - timedelta(hours=2)
    due_schedule = BackupScheduleRecord(
        name="Overdue Schedule",
        interval_hours=4,
        retention_days=7,
        max_bundles_to_keep=2,
        storage_location=backup_root,
        include_evidence=False,
        auto_verify_after_backup=True,
        auto_drill_after_backup=False,
        is_active=True,
        next_run_at=past_due,
        created_by_id=admin_user.id,
    )
    db.add(due_schedule)
    db.commit()
    db.refresh(due_schedule)

    # Poll due schedules via REST API
    poll_res = client.post("/api/v1/recovery/schedules/poll-due", headers=admin_headers)
    assert poll_res.status_code == 200, poll_res.text
    results = poll_res.json()

    # The due schedule must be among executed results
    matching = [r for r in results if r["schedule_id"] == due_schedule.id]
    assert len(matching) == 1
    assert matching[0]["status"] == "SUCCESS"

    db.refresh(due_schedule)
    assert due_schedule.last_run_status == ScheduleRunStatus.SUCCESS
    # Ensure next_run_at is updated into the future
    assert due_schedule.next_run_at.replace(tzinfo=None) > datetime.utcnow() - timedelta(minutes=5)


def test_05_schedule_failure_handling_and_tracking(db: Session, admin_user: User):
    """Verifies that execution failures increment consecutive_failures and log failure audit events."""
    # Schedule pointing to a Windows drive path that does not exist
    sched = BackupScheduleRecord(
        name="Faulty Location Schedule",
        interval_hours=12,
        retention_days=1,
        max_bundles_to_keep=1,
        storage_location="Z:\\nonexistent_p42_drive_12345\\backups",
        include_evidence=False,
        auto_verify_after_backup=False,
        auto_drill_after_backup=False,
        is_active=True,
        consecutive_failures=0,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)

    # Execute
    res = BackupSchedulerService.execute_schedule(db=db, schedule_id=sched.id, force=True)
    assert res["status"] in ("FAILED", "SKIPPED_DISK_LOW")

    db.refresh(sched)
    assert sched.consecutive_failures >= 1
    assert sched.last_run_status in (ScheduleRunStatus.FAILED, ScheduleRunStatus.SKIPPED_DISK_LOW)
    assert sched.last_run_error is not None


def test_06_state_inventory_manifest_includes_models_and_config(db: Session, admin_user: User, tmp_path: Path):
    """
    Verifies that the generated DR bundle manifest captures the extended state inventory:
    active SQLite DB, evidence, model artifacts, and configuration reference.
    """
    backup_root = str(tmp_path / "inv_backups")

    # Create dummy model file in ./data/models
    models_dir = Path("./data/models")
    models_dir.mkdir(parents=True, exist_ok=True)
    dummy_model = models_dir / "p42_assurance_model.bin"
    dummy_model.write_bytes(b"DUMMY_MODEL_WEIGHTS_FOR_P42_VERIFICATION")

    try:
        bundle_meta = BackupRecoveryService.create_disaster_recovery_bundle(
            db=db,
            backup_root=backup_root,
            actor_id=admin_user.id,
        )
        bundle_path = Path(bundle_meta["bundle_path"])
        manifest_path = bundle_path / "backup_manifest.json"
        assert manifest_path.exists()

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        # Validate inventory components
        assert "database" in manifest
        assert manifest["database"]["filename"] == "database.db"
        assert manifest["database"]["sha256"] != ""
        assert "evidence_files" in manifest
        assert "model_files" in manifest
        assert any("p42_assurance_model.bin" in m["path"] for m in manifest["model_files"])
        assert "config_reference" in manifest
        assert (bundle_path / "config_reference.json").exists()
    finally:
        if dummy_model.exists():
            dummy_model.unlink()


def test_07_isolated_restoration_drill_reconciles_inflight_jobs(db: Session, admin_user: User, test_project: Project, tmp_path: Path):
    """
    Verifies that non-destructive isolated restore drills reconcile in-flight jobs to INTERRUPTED
    in the sandbox without modifying the active live database.
    """
    from app.services.backup_service import compute_manifest_sha256
    backup_root = str(tmp_path / "drill_backups")

    # 1. Create bundle
    bundle_meta = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=backup_root,
        actor_id=admin_user.id,
    )
    bundle_id = bundle_meta["bundle_id"]
    bundle_path = Path(bundle_meta["bundle_path"])
    db_file = bundle_path / "database.db"

    # 2. Inject an in-flight job into the bundle's database snapshot using SQLAlchemy
    job_id = "job_drill_inflight_99"
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.models.organization import Organization
    bundle_engine = create_engine(f"sqlite:///{db_file.as_posix()}", connect_args={"check_same_thread": False})
    BundleSession = sessionmaker(bind=bundle_engine)
    b_session = BundleSession()

    b_org = Organization(name="Drill Org", slug=f"drill-org-{int(time.time())}", is_active=True)
    b_session.add(b_org)
    b_session.flush()

    b_user = User(email="drill_user@vapt.test", hashed_password="pw", full_name="Drill User", system_role=SystemRole.ADMIN, is_active=True)
    b_session.add(b_user)
    b_session.flush()

    b_proj = Project(name="Drill Project", organization_id=b_org.id, is_active=True)
    b_session.add(b_proj)
    b_session.flush()

    b_job = AssessmentJob(
        id=job_id,
        project_id=b_proj.id,
        target_input="192.168.1.150",
        created_by_id=b_user.id,
        status=AssessmentStatus.RUNNING,
    )
    b_session.add(b_job)
    b_session.commit()
    b_session.close()
    bundle_engine.dispose()

    # Update bundle checksums to reflect the injected record for valid drill
    new_db_sha = compute_sha256(db_file)
    manifest_file = bundle_path / "backup_manifest.json"
    m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    m_data["database"]["sha256"] = new_db_sha
    if "manifest_signature" in m_data:
        from app.services.origin_attestation_service import attestation_service
        clean_body = json.dumps(
            {k: v for k, v in m_data.items() if k not in ("manifest_sha256", "manifest_signature", "manifest_sig")},
            sort_keys=True,
            separators=(",", ":")
        )
        sig, _, _ = attestation_service.sign_manifest(clean_body)
        m_data["manifest_signature"] = sig
        (bundle_path / "manifest.sig").write_text(sig, encoding="utf-8")
    m_data["manifest_sha256"] = compute_manifest_sha256(m_data)
    manifest_file.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

    # 3. Run isolated restore drill
    drill_res = BackupRecoveryService.restore_and_verify_isolated(
        bundle_path_or_id=bundle_id,
        backup_root=backup_root,
        actor_id=admin_user.id,
        db=db,
    )
    assert drill_res["status"] == "SUCCESS"
    assert drill_res["tables_verified"] > 0
    assert drill_res["drill_type"] == "ISOLATED_SANDBOX"

    # Verify that in-flight job was reconciled in drill report
    reconciled_ids = [j["job_id"] for j in drill_res["jobs_reconciled"]]
    assert job_id in reconciled_ids


def test_08_corrupted_archive_tamper_rejection(db: Session, admin_user: User, tmp_path: Path):
    """Verifies that tampered or corrupted backup archives fail 7-point cryptographic verification."""
    backup_root = tmp_path / "tamper_backups"

    bundle_meta = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )
    bundle_dir = Path(bundle_meta["bundle_path"])
    db_file = bundle_dir / "database.db"
    assert db_file.exists()

    # Tamper with the database bytes in the bundle
    with open(db_file, "r+b") as f:
        f.seek(120)
        f.write(b"CORRUPTED_BYTES_INJECTED_FOR_TAMPER_TESTING")

    # Run verification - must fail cryptographic checksum check
    verify_res = BackupRecoveryService.verify_disaster_recovery_bundle(
        bundle_path_or_id=bundle_meta["bundle_id"],
        db=db,
        backup_root=str(backup_root),
    )
    assert verify_res["status"] == "FAILED"
    assert any("SHA-256 digest mismatch" in err or "database" in err.lower() for err in verify_res["errors"])


def test_09_rbac_non_admin_forbidden_on_schedule_management(client: TestClient, tester_user: User):
    """Enforces that non-administrative roles cannot manage or trigger backup schedules."""
    tester_headers = _auth_header(tester_user)

    # 1. Tester attempting to create schedule -> 403
    create_res = client.post(
        "/api/v1/recovery/schedules",
        json={"name": "Unauthorized Schedule", "interval_hours": 12, "retention_days": 7, "max_bundles_to_keep": 5},
        headers=tester_headers,
    )
    assert create_res.status_code == 403

    # 2. Tester attempting to trigger schedule -> 403
    trigger_res = client.post("/api/v1/recovery/schedules/some-id/trigger", headers=tester_headers)
    assert trigger_res.status_code == 403

    # 3. Tester attempting to poll due -> 403
    poll_res = client.post("/api/v1/recovery/schedules/poll-due", headers=tester_headers)
    assert poll_res.status_code == 403
