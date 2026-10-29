"""
Comprehensive Deterministic Test Suite for Prompt 23:
VAPT System Disaster Recovery, Verified Restoration & Data Integrity.

Covers:
1. Consistent SQLite WAL online backup creation and atomic staging (.incomplete marker removal).
2. Atomic staging marker prevents use of partial/interrupted backup.
3. Independent non-destructive backup verification passes for healthy bundle across all 7 checks.
4. Detection of tampered database file (SHA-256 digest mismatch).
5. Detection of tampered manifest signature (signature mismatch).
6. Detection of corrupted SQLite internal pages (PRAGMA integrity_check failure).
7. Detection of broken foreign keys (PRAGMA foreign_key_check failure).
8. Detection of broken audit chain continuity.
9. Detection of missing cataloged evidence files.
10. Isolated sandbox restore drill reconciles in-flight jobs (RUNNING/PREFLIGHT -> INTERRUPTED).
11. Governance and Separation of Duties preserved on restored state (revoked/pending approvals stay unexecuted).
12. Isolated restore drill preserves active database and cleans up sandbox directory.
13. Live restore requires exact confirmation phrase and creates pre-restore rollback snapshot.
14. Live restore safety rollback reverts if post-swap integrity check fails.
15. Backup retention rotation prunes surplus backups while preserving last-known-good verified bundle.
16. RBAC enforcement: non-administrators denied (403 Forbidden) on destructive/recovery operations.
17. Recovery posture and readiness status reporting.
"""

import os
import shutil
import json
import sqlite3
import time
from pathlib import Path
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.security import create_access_token
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.governance import (
    ApprovalWorkflowType,
    GovernanceApprovalStatus,
    ApprovalRequestRecord,
)
from app.models.recovery import RecoveryBundleStatus, DisasterRecoveryBundleRecord
from app.services.backup_service import (
    BackupRecoveryService,
    compute_sha256,
    compute_manifest_sha256,
)
from app.services.audit_service import AuditService


def _auth_header(user: User) -> dict:
    token = create_access_token(subject=user.id, claims={"email": user.email, "role": user.system_role.value})
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Test 1: Consistent WAL Online Backup Creation & Staging
# ---------------------------------------------------------------------------

def test_01_consistent_wal_online_backup_creation(db: Session, admin_user: User, test_project: Project, tmp_path: Path):
    """
    Creates a disaster recovery bundle using SQLite online backup API.
    Verifies atomic staging, absence of .incomplete marker, manifest digests, and table counts.
    """
    db.commit()
    backup_root = tmp_path / "dr_backups"

    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    bundle_path = Path(bundle["bundle_path"])
    assert bundle_path.exists(), "Bundle directory must exist on disk"
    assert not bundle_path.name.endswith(".incomplete"), "Completed bundle must not end with .incomplete"

    # Verify database.db exists and matches sha256
    db_file = bundle_path / "database.db"
    assert db_file.exists()
    assert compute_sha256(db_file) == bundle["database_sha256"]

    # Verify backup_manifest.json
    manifest_file = bundle_path / "backup_manifest.json"
    assert manifest_file.exists()
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    assert manifest_data["manifest_version"] == "2.0"
    assert manifest_data["bundle_id"] == bundle["bundle_id"]
    assert manifest_data["engine"] == "sqlite"
    assert manifest_data["manifest_sha256"] == compute_manifest_sha256(manifest_data)
    assert "projects" in manifest_data["record_counts"]
    assert manifest_data["database"]["size_bytes"] > 0


# ---------------------------------------------------------------------------
# Test 2: Atomic Staging Marker Prevents Partial Backup Use
# ---------------------------------------------------------------------------

def test_02_atomic_staging_marker_prevents_partial_backup(db: Session, admin_user: User, tmp_path: Path):
    """
    Verifies that a bundle carrying the .incomplete staging marker fails verification early.
    """
    backup_root = tmp_path / "dr_backups"
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    orig_path = Path(bundle["bundle_path"])
    incomplete_path = orig_path.parent / f"{orig_path.name}.incomplete"
    orig_path.rename(incomplete_path)

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(
        bundle_path_or_id=str(incomplete_path),
        db=db,
        backup_root=str(backup_root),
    )

    assert v_res["status"] == "FAILED"
    assert v_res["checks"]["staging_complete"]["passed"] is False
    assert any("incomplete marker" in err.lower() for err in v_res["errors"])


# ---------------------------------------------------------------------------
# Test 3: Independent Verification of Healthy Bundle
# ---------------------------------------------------------------------------

def test_03_independent_verification_healthy_bundle(db: Session, admin_user: User, tmp_path: Path):
    """
    Independent verification checks:
    staging_complete, manifest_integrity, file_checksums, sqlite_integrity,
    foreign_keys, schema_revision, and audit_chain_continuity.
    """
    backup_root = tmp_path / "dr_backups"
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(
        bundle_path_or_id=bundle["bundle_id"],
        db=db,
        backup_root=str(backup_root),
    )

    assert v_res["status"] == "PASSED", f"Expected PASSED, got {v_res}"
    assert len(v_res["errors"]) == 0
    checks = v_res["checks"]
    assert checks["staging_complete"]["passed"] is True
    assert checks["manifest_integrity"]["passed"] is True
    assert checks["file_checksums"]["passed"] is True
    assert checks["sqlite_integrity"]["passed"] is True
    assert checks["foreign_keys"]["passed"] is True
    assert checks["schema_revision"]["passed"] is True
    assert checks["audit_chain_continuity"]["passed"] is True


# ---------------------------------------------------------------------------
# Test 4: Detection of Tampered Database File
# ---------------------------------------------------------------------------

def test_04_tampered_database_file_detected(db: Session, admin_user: User, tmp_path: Path):
    """
    Modifying any byte in database.db must trigger a SHA-256 digest failure.
    """
    backup_root = tmp_path / "dr_backups"
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    bundle_path = Path(bundle["bundle_path"])
    db_file = bundle_path / "database.db"

    # Append corruption bytes
    with open(db_file, "ab") as f:
        f.write(b"CORRUPTED_BYTES_INJECTION")

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(
        bundle_path_or_id=bundle["bundle_id"],
        db=db,
        backup_root=str(backup_root),
    )

    assert v_res["status"] == "FAILED"
    assert v_res["checks"]["file_checksums"]["passed"] is False
    assert any("SHA-256 mismatch" in err for err in v_res["errors"])


# ---------------------------------------------------------------------------
# Test 5: Detection of Tampered Manifest Signature
# ---------------------------------------------------------------------------

def test_05_tampered_manifest_signature_detected(db: Session, admin_user: User, tmp_path: Path):
    """
    Modifying manifest contents without recalculating the canonical hash must fail verification.
    """
    backup_root = tmp_path / "dr_backups"
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    bundle_path = Path(bundle["bundle_path"])
    manifest_file = bundle_path / "backup_manifest.json"
    data = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Tamper with record count without altering manifest_sha256
    data["record_counts"]["projects"] = 9999
    manifest_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(
        bundle_path_or_id=bundle["bundle_id"],
        db=db,
        backup_root=str(backup_root),
    )

    assert v_res["status"] == "FAILED"
    assert v_res["checks"]["manifest_integrity"]["passed"] is False
    assert any("Manifest signature mismatch" in err for err in v_res["errors"])


# ---------------------------------------------------------------------------
# Test 6: Detection of Corrupted SQLite Pages
# ---------------------------------------------------------------------------

def test_06_corrupted_sqlite_pages_detected(db: Session, admin_user: User, tmp_path: Path):
    """
    Corrupting SQLite page bytes while updating manifest checksums must fail PRAGMA integrity_check.
    """
    backup_root = tmp_path / "dr_backups"
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    bundle_path = Path(bundle["bundle_path"])
    db_file = bundle_path / "database.db"

    # Corrupt internal database bytes
    with open(db_file, "r+b") as f:
        f.seek(100)
        f.write(b"\x00" * 256)

    # Update manifest to match new file sha256 so checksum check passes but SQLite integrity fails
    new_db_sha = compute_sha256(db_file)
    manifest_file = bundle_path / "backup_manifest.json"
    m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    m_data["database"]["sha256"] = new_db_sha
    m_data["manifest_sha256"] = compute_manifest_sha256(m_data)
    manifest_file.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(
        bundle_path_or_id=bundle["bundle_id"],
        db=db,
        backup_root=str(backup_root),
    )

    assert v_res["status"] == "FAILED"
    assert v_res["checks"]["sqlite_integrity"]["passed"] is False


# ---------------------------------------------------------------------------
# Test 7: Detection of Broken Foreign Keys
# ---------------------------------------------------------------------------

def test_07_broken_foreign_keys_detected(db: Session, admin_user: User, tmp_path: Path):
    """
    Violations of foreign key constraints must fail PRAGMA foreign_key_check.
    """
    backup_root = tmp_path / "dr_backups"
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    bundle_path = Path(bundle["bundle_path"])
    db_file = bundle_path / "database.db"

    # Insert a foreign key violation row (assessment_findings.job_id -> assessment_jobs.id)
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = OFF")
    cur.execute(
        "INSERT INTO assessment_findings (id, project_id, job_id, target_value, title, description, severity, confidence, is_simulated, reproduction_steps, created_at) "
        "VALUES ('bad_finding_id', 'non_existent_project_id', 'non_existent_job_id', '10.0.0.1', 'Bad Finding', 'Description text', 'HIGH', 'FIRM', 1, '', '2026-10-29T00:00:00')"
    )
    conn.commit()
    conn.close()

    # Update checksums
    new_db_sha = compute_sha256(db_file)
    manifest_file = bundle_path / "backup_manifest.json"
    m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    m_data["database"]["sha256"] = new_db_sha
    m_data["manifest_sha256"] = compute_manifest_sha256(m_data)
    manifest_file.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(
        bundle_path_or_id=bundle["bundle_id"],
        db=db,
        backup_root=str(backup_root),
    )

    assert v_res["status"] == "FAILED"
    assert v_res["checks"]["foreign_keys"]["passed"] is False


# ---------------------------------------------------------------------------
# Test 8: Detection of Broken Audit Chain
# ---------------------------------------------------------------------------

def test_08_broken_audit_chain_detected(db: Session, admin_user: User, tmp_path: Path):
    """
    Tampering with prev_event_hash or audit chain records must fail audit chain verification.
    """
    backup_root = tmp_path / "dr_backups"

    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    bundle_path = Path(bundle["bundle_path"])
    db_file = bundle_path / "database.db"

    # Insert two audit events with a deliberate break in the hash chain
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_events (id, timestamp, action, target_type, outcome, details, prev_event_hash, event_hash) "
        "VALUES ('ev_1', '2026-10-29T00:00:00', 'EVENT_1', 'System', 'SUCCESS', '{}', NULL, 'hash_first_event')"
    )
    cur.execute(
        "INSERT INTO audit_events (id, timestamp, action, target_type, outcome, details, prev_event_hash, event_hash) "
        "VALUES ('ev_2', '2026-10-29T00:00:01', 'EVENT_2', 'System', 'SUCCESS', '{}', 'BROKEN_PREV_HASH', 'hash_second_event')"
    )
    conn.commit()
    conn.close()

    # Recompute file and manifest digests
    new_db_sha = compute_sha256(db_file)
    manifest_file = bundle_path / "backup_manifest.json"
    m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    m_data["database"]["sha256"] = new_db_sha
    m_data["audit_chain_head"] = {"event_id": "ev_2", "event_hash": "hash_second_event"}
    m_data["manifest_sha256"] = compute_manifest_sha256(m_data)
    manifest_file.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(
        bundle_path_or_id=bundle["bundle_id"],
        db=db,
        backup_root=str(backup_root),
    )

    assert v_res["status"] == "FAILED"
    assert v_res["checks"]["audit_chain_continuity"]["passed"] is False


# ---------------------------------------------------------------------------
# Test 9: Detection of Missing Evidence Files
# ---------------------------------------------------------------------------

def test_09_missing_evidence_files_detected(db: Session, admin_user: User, tmp_path: Path):
    """
    Cataloged evidence files missing from bundle directory must fail file checksum verification.
    """
    backup_root = tmp_path / "dr_backups"
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    bundle_path = Path(bundle["bundle_path"])
    manifest_file = bundle_path / "backup_manifest.json"
    m_data = json.loads(manifest_file.read_text(encoding="utf-8"))

    # Add missing evidence file to manifest
    m_data["evidence_files"].append({
        "path": "evidence/missing_artifact.bin",
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "size_bytes": 1024,
    })
    m_data["manifest_sha256"] = compute_manifest_sha256(m_data)
    manifest_file.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(
        bundle_path_or_id=bundle["bundle_id"],
        db=db,
        backup_root=str(backup_root),
    )

    assert v_res["status"] == "FAILED"
    assert v_res["checks"]["file_checksums"]["passed"] is False
    assert any("missing" in err for err in v_res["errors"])


# ---------------------------------------------------------------------------
# Test 10: Isolated Restore Drill Reconciles In-Flight Jobs
# ---------------------------------------------------------------------------

def test_10_isolated_restore_drill_reconciles_inflight_jobs(
    db: Session,
    admin_user: User,
    test_project: Project,
    tmp_path: Path,
):
    """
    When restoring, in-flight jobs (RUNNING, PREFLIGHT) must be safely reconciled
    to INTERRUPTED so that automated scanners do not execute with stale leases.
    The active live database must remain untouched.
    """
    backup_root = tmp_path / "dr_backups"

    # Create bundle
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    bundle_path = Path(bundle["bundle_path"])
    db_file = bundle_path / "database.db"

    # Insert in-flight jobs into the bundle database using SQLAlchemy session
    bundle_engine = create_engine(f"sqlite:///{db_file.as_posix()}", connect_args={"check_same_thread": False})
    BundleSession = sessionmaker(bind=bundle_engine)
    b_session = BundleSession()

    org = Organization(id="org_dr_1", name="DR Org", slug="dr-org", is_active=True)
    b_session.add(org)
    b_session.flush()

    usr = User(id="user_dr_1", email="dr_jobs@vapt.local", hashed_password="hash", full_name="DR Job User", system_role=SystemRole.ADMIN, is_active=True)
    b_session.add(usr)
    b_session.flush()

    proj = Project(id="proj_dr_1", organization_id=org.id, name="DR Project", is_active=True)
    b_session.add(proj)
    b_session.flush()

    job_run_id = "job_test_running_1"
    job_pre_id = "job_test_preflight_1"

    job1 = AssessmentJob(
        id=job_run_id,
        project_id=proj.id,
        target_input="192.168.1.100",
        status=AssessmentStatus.RUNNING,
        adapter_name="test",
        adapter_version="1.0",
        policy_version="v1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        created_by_id=usr.id,
    )
    job2 = AssessmentJob(
        id=job_pre_id,
        project_id=proj.id,
        target_input="192.168.1.101",
        status=AssessmentStatus.PREFLIGHT,
        adapter_name="test",
        adapter_version="1.0",
        policy_version="v1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        created_by_id=usr.id,
    )
    b_session.add_all([job1, job2])
    b_session.commit()
    b_session.close()
    bundle_engine.dispose()

    # Update bundle checksums
    new_db_sha = compute_sha256(db_file)
    manifest_file = bundle_path / "backup_manifest.json"
    m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    m_data["database"]["sha256"] = new_db_sha
    m_data["manifest_sha256"] = compute_manifest_sha256(m_data)
    manifest_file.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

    sandbox_dir = tmp_path / "test_sandbox"
    drill_res = BackupRecoveryService.restore_and_verify_isolated(
        bundle_path_or_id=bundle["bundle_id"],
        scratch_dir=str(sandbox_dir),
        backup_root=str(backup_root),
        preserve_scratch=True,
        db=db,
        actor_id=admin_user.id,
    )

    assert drill_res["status"] == "SUCCESS"
    reconciled_ids = [j["job_id"] for j in drill_res["jobs_reconciled"]]
    assert job_run_id in reconciled_ids
    assert job_pre_id in reconciled_ids

    # Verify state inside the restored sandbox database
    restored_db = sandbox_dir / "database.db"
    conn = sqlite3.connect(str(restored_db))
    cur = conn.cursor()
    cur.execute("SELECT id, status, error_message FROM assessment_jobs WHERE id IN (?, ?)", (job_run_id, job_pre_id))
    rows = cur.fetchall()
    conn.close()

    assert len(rows) == 2
    for row in rows:
        assert row[1] == "INTERRUPTED"
        assert "disaster recovery backup bundle" in row[2]

    shutil.rmtree(sandbox_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 11: Governance & SoD Invariants Preserved on Restored State
# ---------------------------------------------------------------------------

def test_11_governance_and_sod_preserved_on_restoration(
    db: Session,
    admin_user: User,
    test_project: Project,
    tmp_path: Path,
):
    """
    Approvals in PENDING or REVOKED state must not be automatically promoted
    or executed during restoration.
    """
    backup_root = tmp_path / "dr_backups"

    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    bundle_path = Path(bundle["bundle_path"])
    db_file = bundle_path / "database.db"

    revoked_id = "req_revoked_test_1"
    pending_id = "req_pending_test_1"

    # Insert governance records into the bundle database using SQLAlchemy session
    bundle_engine = create_engine(f"sqlite:///{db_file.as_posix()}", connect_args={"check_same_thread": False})
    BundleSession = sessionmaker(bind=bundle_engine)
    b_session = BundleSession()

    org = Organization(id="org_dr_gov_1", name="DR Gov Org", slug="dr-gov-org", is_active=True)
    b_session.add(org)
    b_session.flush()

    usr = User(id="user_dr_gov_1", email="dr_gov@vapt.local", hashed_password="hash", full_name="DR Gov User", system_role=SystemRole.ADMIN, is_active=True)
    b_session.add(usr)
    b_session.flush()

    proj = Project(id="proj_dr_gov_1", organization_id=org.id, name="DR Gov Project", is_active=True)
    b_session.add(proj)
    b_session.flush()

    app1 = ApprovalRequestRecord(
        id=revoked_id,
        project_id=proj.id,
        workflow_type=ApprovalWorkflowType.REMEDIATION_CHANGE,
        resource_type="RemediationProposal",
        resource_id="patch-123",
        title="Emergency Patch 123",
        parameter_hash="hash1",
        parameters_snapshot={},
        requester_id=usr.id,
        status=GovernanceApprovalStatus.REVOKED,
    )
    app2 = ApprovalRequestRecord(
        id=pending_id,
        project_id=proj.id,
        workflow_type=ApprovalWorkflowType.SECURITY_DECISION,
        resource_type="SecurityDecision",
        resource_id="decision-456",
        title="Decision 456 Review",
        parameter_hash="hash2",
        parameters_snapshot={},
        requester_id=usr.id,
        status=GovernanceApprovalStatus.PENDING,
    )
    b_session.add_all([app1, app2])
    b_session.commit()
    b_session.close()
    bundle_engine.dispose()

    new_db_sha = compute_sha256(db_file)
    manifest_file = bundle_path / "backup_manifest.json"
    m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    m_data["database"]["sha256"] = new_db_sha
    m_data["manifest_sha256"] = compute_manifest_sha256(m_data)
    manifest_file.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

    sandbox_dir = tmp_path / "gov_sandbox"
    drill_res = BackupRecoveryService.restore_and_verify_isolated(
        bundle_path_or_id=bundle["bundle_id"],
        scratch_dir=str(sandbox_dir),
        backup_root=str(backup_root),
        preserve_scratch=True,
        db=db,
        actor_id=admin_user.id,
    )
    assert drill_res["status"] == "SUCCESS"

    # Verify in restored DB
    restored_db = sandbox_dir / "database.db"
    conn = sqlite3.connect(str(restored_db))
    cur = conn.cursor()
    cur.execute("SELECT id, status FROM approval_request_records WHERE id = ?", (revoked_id,))
    assert cur.fetchone()[1] == "REVOKED"
    cur.execute("SELECT id, status FROM approval_request_records WHERE id = ?", (pending_id,))
    assert cur.fetchone()[1] == "PENDING"
    conn.close()

    shutil.rmtree(sandbox_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 12: Isolated Restore Cleans Sandbox Automatically
# ---------------------------------------------------------------------------

def test_12_isolated_restore_cleans_sandbox_automatically(
    db: Session,
    admin_user: User,
    tmp_path: Path,
):
    """
    By default (preserve_scratch=False), the isolated restoration drill
    removes the sandbox directory upon completion.
    """
    backup_root = tmp_path / "dr_backups"
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    sandbox_dir = tmp_path / "auto_cleaned_sandbox"
    drill_res = BackupRecoveryService.restore_and_verify_isolated(
        bundle_path_or_id=bundle["bundle_id"],
        scratch_dir=str(sandbox_dir),
        backup_root=str(backup_root),
        preserve_scratch=False,
        db=db,
    )

    assert drill_res["status"] == "SUCCESS"
    assert drill_res["sandbox_cleaned"] is True
    assert not sandbox_dir.exists(), "Sandbox directory must be cleaned up automatically"


# ---------------------------------------------------------------------------
# Test 13: Live Restore with Governance & Rollback Creation
# ---------------------------------------------------------------------------

def test_13_live_restore_with_governance_and_rollback(
    db: Session,
    admin_user: User,
    tmp_path: Path,
):
    """
    Live restore requires exact confirmation phrase, creates a pre-restore
    rollback snapshot, and restores database successfully.
    """
    backup_root = tmp_path / "dr_backups"
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    # 1. Reject incorrect confirmation phrase
    with pytest.raises(ValueError, match="Confirmation phrase mismatch"):
        BackupRecoveryService.live_restore_with_governance(
            db=db,
            bundle_path_or_id=bundle["bundle_id"],
            authorizer_id=admin_user.id,
            confirmation_phrase="WRONG PHRASE",
            backup_root=str(backup_root),
        )

    # 2. Simulate target live db
    simulated_live = tmp_path / "simulated_live.db"
    shutil.copy2(Path(bundle["bundle_path"]) / "database.db", simulated_live)

    phrase = f"CONFIRM DISASTER RESTORE {bundle['bundle_id']}"
    res = BackupRecoveryService.live_restore_with_governance(
        db=db,
        bundle_path_or_id=bundle["bundle_id"],
        authorizer_id=admin_user.id,
        confirmation_phrase=phrase,
        backup_root=str(backup_root),
        live_db_path=str(simulated_live),
    )

    assert res["status"] == "RESTORED"
    assert Path(res["rollback_path"]).exists(), "Pre-restore rollback snapshot must exist"
    assert res["integrity_check"] == "ok"


# ---------------------------------------------------------------------------
# Test 14: Live Restore Rolls Back on Post-Swap Integrity Failure
# ---------------------------------------------------------------------------

def test_14_live_restore_rolls_back_on_integrity_failure(
    db: Session,
    admin_user: User,
    tmp_path: Path,
):
    """
    If post-swap live database integrity check fails, live restore must revert
    to pre-restore rollback snapshot.
    """
    backup_root = tmp_path / "dr_backups"
    bundle = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db,
        backup_root=str(backup_root),
        actor_id=admin_user.id,
    )

    simulated_live = tmp_path / "simulated_live_broken.db"
    # Write initial state
    simulated_live.write_bytes(b"INITIAL_ACTIVE_DATABASE_BYTES")

    # Corrupt bundle database so post-swap integrity fails
    b_db = Path(bundle["bundle_path"]) / "database.db"
    with open(b_db, "r+b") as f:
        f.seek(50)
        f.write(b"\x00" * 200)

    # Bypass verify check by patching sha in manifest
    new_sha = compute_sha256(b_db)
    m_file = Path(bundle["bundle_path"]) / "backup_manifest.json"
    m_data = json.loads(m_file.read_text(encoding="utf-8"))
    m_data["database"]["sha256"] = new_sha
    m_data["manifest_sha256"] = compute_manifest_sha256(m_data)
    m_file.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

    phrase = f"CONFIRM DISASTER RESTORE {bundle['bundle_id']}"
    with pytest.raises(Exception):
        BackupRecoveryService.live_restore_with_governance(
            db=db,
            bundle_path_or_id=bundle["bundle_id"],
            authorizer_id=admin_user.id,
            confirmation_phrase=phrase,
            backup_root=str(backup_root),
            live_db_path=str(simulated_live),
        )

    # Assert active database was restored to initial active state
    assert simulated_live.read_bytes() == b"INITIAL_ACTIVE_DATABASE_BYTES"


# ---------------------------------------------------------------------------
# Test 15: Backup Retention Rotation Preserves Last-Known-Good
# ---------------------------------------------------------------------------

def test_15_backup_rotation_preserves_last_known_good(
    db: Session,
    admin_user: User,
    tmp_path: Path,
):
    """
    Rotation policy prunes surplus bundles down to max_retained, but MUST preserve
    the bundle marked as last-known-good even if it exceeds retention limits.
    """
    backup_root = tmp_path / "dr_backups_rotation"
    backup_root.mkdir(parents=True, exist_ok=True)

    # Create 4 bundles
    bundles = []
    for i in range(4):
        b = BackupRecoveryService.create_disaster_recovery_bundle(
            db=db,
            backup_root=str(backup_root),
            actor_id=admin_user.id,
        )
        bundles.append(b)
        time.sleep(0.01)

    # Mark the oldest bundle as last-known-good in DB
    oldest_id = bundles[0]["bundle_id"]
    db.query(DisasterRecoveryBundleRecord).filter(
        DisasterRecoveryBundleRecord.bundle_id == oldest_id
    ).update({"is_last_known_good": True})
    db.commit()

    # Rotate with max_retained = 2
    rot_res = BackupRecoveryService.rotate_backup_bundles(
        db=db,
        backup_root=str(backup_root),
        max_retained=2,
        preserve_last_known_good=True,
    )

    assert rot_res["bundles_scanned"] == 4
    # Retained should include the top 2 newest PLUS the oldest last-known-good (total 3)
    assert rot_res["bundles_retained"] == 3
    assert (backup_root / oldest_id).exists(), "Oldest bundle must be preserved as last-known-good"


# ---------------------------------------------------------------------------
# Test 16: RBAC Enforcement on Recovery REST API Endpoints
# ---------------------------------------------------------------------------

def test_16_rbac_enforcement_on_recovery_endpoints(
    client: TestClient,
    admin_user: User,
    tester_user: User,
    tmp_path: Path,
):
    """
    Non-admin users (e.g. Tester/Analyst) must receive 403 Forbidden on
    disaster recovery operations (create bundle, verify, restore drill, live restore, rotate).
    """
    tester_headers = _auth_header(tester_user)
    admin_headers = _auth_header(admin_user)

    # 1. Create bundle
    resp = client.post("/api/v1/recovery/bundles", headers=tester_headers)
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"

    # 2. Verify bundle
    resp = client.post("/api/v1/recovery/bundles/fake-id/verify", headers=tester_headers)
    assert resp.status_code == 403

    # 3. Restore drill
    resp = client.post("/api/v1/recovery/bundles/fake-id/restore-drill", headers=tester_headers)
    assert resp.status_code == 403

    # 4. Live restore
    resp = client.post(
        "/api/v1/recovery/bundles/fake-id/live-restore",
        headers=tester_headers,
        json={"confirmation_phrase": "CONFIRM DISASTER RESTORE fake-id"},
    )
    assert resp.status_code == 403

    # 5. Rotate
    resp = client.post("/api/v1/recovery/rotate", headers=tester_headers, json={"max_retained": 5})
    assert resp.status_code == 403

    # Admin access succeeds
    resp_admin = client.post("/api/v1/recovery/bundles", headers=admin_headers)
    assert resp_admin.status_code in (200, 201), f"Expected 200, got {resp_admin.status_code}: {resp_admin.text}"


# ---------------------------------------------------------------------------
# Test 17: Recovery Posture and Readiness Status Reporting
# ---------------------------------------------------------------------------

def test_17_recovery_status_summary(
    client: TestClient,
    admin_user: User,
    db: Session,
):
    """
    GET /api/v1/recovery/status provides central visibility into backup count,
    last verified bundle, last restore drill, and overall readiness.
    """
    admin_headers = _auth_header(admin_user)
    resp = client.get("/api/v1/recovery/status", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "total_bundles" in data
    assert "recovery_readiness" in data
    assert data["recovery_readiness"] in ("READY", "ATTENTION_REQUIRED", "DEGRADED")
    assert "total_storage_bytes" in data
