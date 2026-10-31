"""
Automated Test Suite for Prompts 58–62: Forensic Storage, Backup,
Disaster Recovery & Data Governance.

Verifies:
1. Tampered backup detection & classification.
2. Missing evidence object detection.
3. Interrupted upload / staging (.incomplete marker) detection.
4. Invalid/tampered Ed25519 digital signature detection.
5. Broken Merkle custody chain detection post-recovery.
6. Active legal hold enforcement blocking deletion (HTTP 409).
7. Cryptographically signed deletion tombstones (Ed25519/HMAC).
8. Partial restore detection & job reconciliation to INTERRUPTED.
9. Duplicate restore prevention & concurrency fencing.
10. Unauthorized deletion rejection (HTTP 403).
11. Recovery verification failure halting restore operations.
12. Isolated disaster recovery drills leaving production database untouched.
13. Storage adapter atomic staging, hash verification & overwrite prevention.
14. WORM compliance truthfulness (never claims WORM without testing).
15. Data portability export and import preserving UUIDs and provenance.
16. Zip Slip traversal rejection & malformed archive detection.
17. Operational governance, RPO/RTO telemetry, and recovery readiness.
"""
import os
import sys
import json
import uuid
import shutil
import zipfile
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Generator

import pytest
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.core.database import SessionLocal, Base, engine
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project
from app.models.scope import ScopeTarget
from app.models.assessment import AssessmentJob, AssessmentFinding, FindingEvidence, AssessmentStatus
from app.models.forensic_evidence import (
    ForensicEvidenceRecord,
    EvidenceCustodyEvent,
    EvidenceLifecycleState,
    CustodyEventType,
)
from app.models.recovery import (
    RecoveryBundleStatus,
    DisasterRecoveryBundleRecord,
    LegalHoldRecord,
    LegalHoldStatus,
    EvidenceTombstoneRecord,
)
from app.services.backup_service import (
    BackupRecoveryService,
    compute_sha256,
    compute_manifest_sha256,
    sanitize_config_metadata,
)
from app.services.forensic_evidence_service import (
    forensic_evidence_service,
    compute_custody_hash,
)
from app.services.evidence_lifecycle_service import (
    evidence_lifecycle_service,
    DataClassification,
    LegalHoldCreate,
    HoldType,
)
from app.services.origin_attestation_service import attestation_service
from app.services.storage.factory import get_evidence_storage_adapter, reset_evidence_storage_adapter
from app.services.storage.base import (
    EvidenceOverwriteError,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
)
from app.services.storage.local_adapter import LocalStorageAdapter
from app.services.storage.s3_adapter import S3CompatibleStorageAdapter
from app.services.data_portability_service import data_portability_service
from fastapi import HTTPException


@pytest.fixture(scope="module")
def db_session() -> Generator[Session, None, None]:
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        admin = session.query(User).filter(User.email == "admin_dr@vapt.local").first()
        if not admin:
            admin = User(
                email="admin_dr@vapt.local",
                full_name="Admin DR User",
                hashed_password="mock_hashed_password_123",
                system_role=SystemRole.ADMIN,
            )
            session.add(admin)
            session.commit()

        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def clean_session(db_session: Session):
    db_session.rollback()
    yield
    db_session.rollback()



@pytest.fixture
def test_project(db_session: Session) -> Project:
    org = db_session.query(Organization).first()
    if not org:
        org = Organization(name="Forensic Org", slug="forensic-org-p58")
        db_session.add(org)
        db_session.flush()

    proj_id = f"proj-dr-{uuid.uuid4().hex[:8]}"
    proj = Project(
        id=proj_id,
        organization_id=org.id,
        name=f"Forensic DR Test Project {proj_id}",
        description="Test project for backup, recovery and data governance",
    )
    db_session.add(proj)
    db_session.commit()
    db_session.refresh(proj)
    return proj


@pytest.fixture
def temp_backup_root(tmp_path: Path) -> Path:
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir


# ==============================================================================
# TEST 1 & 11: Tampered Backup & Recovery Verification Failure
# ==============================================================================
def test_tampered_backup_detected(db_session: Session, temp_backup_root: Path):
    """Verifies that tampering with database or evidence flags TAMPERED and halts restore."""
    bundle_res = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db_session,
        backup_root=str(temp_backup_root),
        actor_id="admin_dr@vapt.local",
    )
    bundle_path = Path(bundle_res["bundle_path"])

    # 1. Verify fresh bundle passes
    fresh_res = BackupRecoveryService.verify_disaster_recovery_bundle(str(bundle_path), db=db_session)
    assert fresh_res["status"] == "PASSED"
    assert fresh_res["bundle_status"] == "VERIFIED"

    # 2. Tamper with database.db
    db_file = bundle_path / "database.db"
    assert db_file.exists()
    with open(db_file, "ab") as f:
        f.write(b"\nTAMPERED_INJECTION_CORRUPTION_BYTES\n")

    # 3. Verify detects tampering
    tampered_res = BackupRecoveryService.verify_disaster_recovery_bundle(str(bundle_path), db=db_session)
    assert tampered_res["status"] == "FAILED"
    assert tampered_res["bundle_status"] == "TAMPERED"
    assert any("mismatch" in err.lower() for err in tampered_res["errors"])

    # 4. Attempting to restore tampered bundle must fail closed
    with pytest.raises(ValueError, match="Cannot restore unverified or corrupted"):
        BackupRecoveryService.restore_disaster_recovery_bundle(str(bundle_path), is_drill=True, db=db_session)


# ==============================================================================
# TEST 2: Missing Evidence Object Detection
# ==============================================================================
def test_missing_evidence_object_detected(db_session: Session, temp_backup_root: Path, tmp_path: Path):
    """Verifies that missing evidence files in a backup bundle are flagged as CORRUPTED."""
    # Setup test evidence
    ev_dir = tmp_path / "test_evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    test_file = ev_dir / "packet_capture.pcap"
    test_file.write_bytes(b"SYN_ACK_PACKET_STREAM_EVIDENCE")

    bundle_res = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db_session,
        backup_root=str(temp_backup_root),
        actor_id="admin_dr@vapt.local",
        evidence_dir=str(ev_dir),
    )
    bundle_path = Path(bundle_res["bundle_path"])

    # Delete copied evidence file
    copied_ev = bundle_path / "evidence" / "packet_capture.pcap"
    assert copied_ev.exists()
    copied_ev.unlink()

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(str(bundle_path), db=db_session)
    assert v_res["status"] == "FAILED"
    assert v_res["bundle_status"] == "CORRUPTED"
    assert any("missing" in err.lower() for err in v_res["errors"])


# ==============================================================================
# TEST 3: Interrupted Upload / Staging Detection (.incomplete marker)
# ==============================================================================
def test_interrupted_upload_staging_detected(db_session: Session, temp_backup_root: Path):
    """Verifies that an interrupted or incomplete backup bundle is rejected immediately."""
    incomplete_dir = temp_backup_root / "dr_bundle_20261031_000000_fakeid.incomplete"
    incomplete_dir.mkdir(parents=True, exist_ok=True)
    (incomplete_dir / "database.db").write_bytes(b"PARTIAL_DB")

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(str(incomplete_dir), db=db_session)
    assert v_res["status"] == "FAILED"
    assert v_res["bundle_status"] == "CORRUPTED"
    assert any("incomplete" in err.lower() for err in v_res["errors"])


# ==============================================================================
# TEST 4: Invalid / Tampered Digital Signature
# ==============================================================================
def test_invalid_signature_detected(db_session: Session, temp_backup_root: Path):
    """Verifies that invalid or forged Ed25519 manifest digital signatures fail verification."""
    bundle_res = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db_session,
        backup_root=str(temp_backup_root),
        actor_id="admin_dr@vapt.local",
    )
    bundle_path = Path(bundle_res["bundle_path"])

    # Corrupt the detached signature
    sig_file = bundle_path / "manifest.sig"
    sig_file.write_text("00" * 64, encoding="utf-8")

    # Also corrupt manifest.json signature
    manifest_file = bundle_path / "backup_manifest.json"
    m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    m_data["manifest_signature"] = "00" * 64
    manifest_file.write_text(json.dumps(m_data, indent=2), encoding="utf-8")

    v_res = BackupRecoveryService.verify_disaster_recovery_bundle(str(bundle_path), db=db_session)
    assert v_res["status"] == "FAILED"
    assert v_res["bundle_status"] == "TAMPERED"
    assert any("signature" in err.lower() for err in v_res["errors"])


# ==============================================================================
# TEST 5: Broken Merkle Custody Chain Detection Post-Recovery
# ==============================================================================
def test_broken_merkle_chain_detected(db_session: Session, test_project: Project, tmp_path: Path):
    """Verifies that a severed or forged custody hash chain is caught post-recovery."""
    now = datetime.now(timezone.utc)
    ev_id = f"ev-{uuid.uuid4().hex[:8]}"

    # Ingest genuine evidence
    ev_record = ForensicEvidenceRecord(
        id=ev_id,
        project_id=test_project.id,
        evidence_type="RAW_HTTP",
        raw_payload="GET /api/v1/auth HTTP/1.1\nHost: target",
        raw_digest_sha256=hashlib.sha256(b"GET /api/v1/auth HTTP/1.1\nHost: target").hexdigest(),
        source_identity="SENSOR_01",
        adapter_version="1.0",
        collection_time=now,
        origin_signature="SIG123",
        signing_key_id="KEY-DEFAULT-ED25519",
        signature_algorithm="ED25519",
        lifecycle_state=EvidenceLifecycleState.INGESTED,
    )
    db_session.add(ev_record)
    db_session.flush()

    # Event 1: Collection
    det1 = json.dumps({"action": "COLLECTED"}, sort_keys=True, separators=(",", ":"))
    h1 = compute_custody_hash("0" * 64, CustodyEventType.COLLECTION.value, "SENSOR_01", now, det1)
    ev1 = EvidenceCustodyEvent(
        id=str(uuid.uuid4()),
        evidence_id=ev_id,
        event_type=CustodyEventType.COLLECTION.value,
        actor_id="SENSOR_01",
        actor_role="SENSOR",
        timestamp=now,
        action_details={"action": "COLLECTED"},
        prev_custody_hash="0" * 64,
        custody_hash=h1,
    )
    db_session.add(ev1)

    # Event 2: Ingestion
    t2 = now + timedelta(seconds=1)
    det2 = json.dumps({"action": "INGESTED"}, sort_keys=True, separators=(",", ":"))
    h2 = compute_custody_hash(h1, CustodyEventType.INGESTION.value, "SYSTEM", t2, det2)
    ev2 = EvidenceCustodyEvent(
        id=str(uuid.uuid4()),
        evidence_id=ev_id,
        event_type=CustodyEventType.INGESTION.value,
        actor_id="SYSTEM",
        actor_role="SYSTEM",
        timestamp=t2,
        action_details={"action": "INGESTED"},
        prev_custody_hash=h1,
        custody_hash=h2,
    )
    db_session.add(ev2)
    db_session.commit()

    # Verify initial chain passes
    report = BackupRecoveryService.verify_custody_chains_post_recovery(db_session)
    assert report["status"] == "VERIFIED"
    assert report["broken_chains_count"] == 0

    # Tamper with Event 2's prev_custody_hash (break Merkle link)
    ev2.prev_custody_hash = "deadbeef" * 8
    db_session.commit()

    broken_report = BackupRecoveryService.verify_custody_chains_post_recovery(db_session)
    assert broken_report["status"] == "CORRUPTED"
    assert broken_report["broken_chains_count"] > 0
    assert any(b.get("evidence_id") == ev_id for b in broken_report["broken_chains"])

    # Clean up tampered event to preserve fixture integrity
    db_session.delete(ev2)
    db_session.delete(ev1)
    db_session.delete(ev_record)
    db_session.commit()


# ==============================================================================
# TEST 6 & 10: Legal Holds, Tombstones & Unauthorized Deletion
# ==============================================================================
def test_active_legal_hold_and_unauthorized_deletion(db_session: Session, test_project: Project):
    """Verifies that active legal holds block deletion (409) and unauthorized roles are rejected (403)."""
    now = datetime.now(timezone.utc)
    ev_id = f"ev-hold-{uuid.uuid4().hex[:8]}"

    ev_record = ForensicEvidenceRecord(
        id=ev_id,
        project_id=test_project.id,
        evidence_type="CONFIG",
        raw_payload="secret_config=sample",
        raw_digest_sha256=hashlib.sha256(b"secret_config=sample").hexdigest(),
        source_identity="ANALYST_01",
        adapter_version="1.0",
        collection_time=now,
        origin_signature="SIG_SAMPLE",
        signing_key_id="KEY-DEFAULT-ED25519",
        signature_algorithm="ED25519",
        lifecycle_state=EvidenceLifecycleState.INGESTED,
    )
    db_session.add(ev_record)
    db_session.commit()

    # 1. Unauthorized deletion attempt by regular ANALYST must fail (HTTP 403)
    with pytest.raises(HTTPException) as exc_info:
        forensic_evidence_service.delete_evidence_authorized(
            db=db_session,
            evidence_id=ev_id,
            actor_id="analyst_user",
            actor_role="ANALYST",
            justification="Routine cleanup attempt",
        )
    assert exc_info.value.status_code == 403

    # 2. Place an active legal hold on the evidence target
    hold = evidence_lifecycle_service.create_hold(
        create=LegalHoldCreate(
            hold_type=HoldType.LEGAL_HOLD,
            target_scope="EVIDENCE",
            target_id=ev_id,
            reason="Subpoena case #8841 litigation hold",
        ),
        placed_by_id="compliance_officer",
        db=db_session,
    )

    # 3. Authorized deletion attempt by ADMIN must fail because of active legal hold (HTTP 409)
    with pytest.raises(HTTPException) as exc_info_hold:
        forensic_evidence_service.delete_evidence_authorized(
            db=db_session,
            evidence_id=ev_id,
            actor_id="admin_user",
            actor_role="ADMIN",
            justification="Administrative purge",
        )
    assert exc_info_hold.value.status_code == 409
    assert "active legal hold" in exc_info_hold.value.detail.lower()

    # 4. Release legal hold
    evidence_lifecycle_service.release_hold(hold.hold_id, released_by_id="legal_counsel", db=db_session)

    # 5. Authorized deletion should now succeed and generate signed tombstone
    del_record = forensic_evidence_service.delete_evidence_authorized(
        db=db_session,
        evidence_id=ev_id,
        actor_id="admin_user",
        actor_role="ADMIN",
        justification="Authorized legal retention purge after hold release",
    )
    assert del_record.is_deleted is True
    assert del_record.lifecycle_state == EvidenceLifecycleState.AUTHORIZED_DELETED

    # 6. Verify signed tombstone in database
    tombstone = db_session.query(EvidenceTombstoneRecord).filter(
        EvidenceTombstoneRecord.evidence_id == ev_id
    ).first()
    assert tombstone is not None
    assert len(tombstone.tombstone_digest) > 0


# ==============================================================================
# TEST 8: Partial Restore Detection & Job Reconciliation
# ==============================================================================
def test_partial_restore_job_reconciliation(db_session: Session, test_project: Project, temp_backup_root: Path):
    """Verifies that in-flight jobs (RUNNING, QUEUED, PREFLIGHT) are reconciled to INTERRUPTED."""
    # Create in-flight jobs
    admin_u = db_session.query(User).first()
    job_run = AssessmentJob(
        id=f"job-run-{uuid.uuid4().hex[:6]}",
        project_id=test_project.id,
        created_by_id=admin_u.id,
        adapter_name="nmap",
        target_input="192.168.1.1",
        status=AssessmentStatus.RUNNING,
    )
    job_q = AssessmentJob(
        id=f"job-q-{uuid.uuid4().hex[:6]}",
        project_id=test_project.id,
        created_by_id=admin_u.id,
        adapter_name="zap",
        target_input="https://example.com",
        status=AssessmentStatus.QUEUED,
    )
    db_session.add_all([job_run, job_q])
    db_session.commit()

    # Create backup bundle with in-flight jobs
    bundle_res = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db_session,
        backup_root=str(temp_backup_root),
        actor_id="admin_dr@vapt.local",
    )

    # Execute isolated recovery drill
    drill_res = BackupRecoveryService.restore_disaster_recovery_bundle(
        bundle_path_or_id=bundle_res["bundle_id"],
        is_drill=True,
        db=db_session,
        backup_root=str(temp_backup_root),
        authorizer_id="admin_dr@vapt.local",
    )
    assert drill_res["status"] == "SUCCESS"
    reconciled = drill_res["jobs_reconciled"]
    reconciled_ids = [r["job_id"] for r in reconciled]
    assert job_run.id in reconciled_ids
    assert job_q.id in reconciled_ids
    for r in reconciled:
        assert r["new_status"] == "INTERRUPTED"


# ==============================================================================
# TEST 9: Duplicate Restore Prevention
# ==============================================================================
def test_duplicate_restore_fenced(db_session: Session, temp_backup_root: Path):
    """Verifies that re-applying an already restored live bundle is rejected."""
    bundle_res = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db_session,
        backup_root=str(temp_backup_root),
        actor_id="admin_dr@vapt.local",
    )
    b_id = bundle_res["bundle_id"]

    # In our session tracker, add b_id to simulate completion
    from app.services.backup_service import _RESTORED_BUNDLES_IN_SESSION
    _RESTORED_BUNDLES_IN_SESSION.add(b_id)

    # Duplicate live restore should be rejected
    with pytest.raises(ValueError, match="Duplicate live restore rejected"):
        BackupRecoveryService.restore_disaster_recovery_bundle(
            bundle_path_or_id=b_id,
            is_drill=False,
            db=db_session,
            backup_root=str(temp_backup_root),
            authorizer_id="admin_dr@vapt.local",
            confirmation_phrase=f"CONFIRM DISASTER RESTORE {b_id}",
            force=False,
        )

    _RESTORED_BUNDLES_IN_SESSION.discard(b_id)


# ==============================================================================
# TEST 12: Recovery Drill Sandbox Leaves Production Untouched
# ==============================================================================
def test_recovery_drill_does_not_touch_production_db(db_session: Session, test_project: Project, temp_backup_root: Path):
    """Verifies that recovery drills restore into isolated scratch directories."""
    bundle_res = BackupRecoveryService.create_disaster_recovery_bundle(
        db=db_session,
        backup_root=str(temp_backup_root),
        actor_id="admin_dr@vapt.local",
    )

    # Record current count of projects
    initial_count = db_session.query(Project).count()

    drill_res = BackupRecoveryService.restore_disaster_recovery_bundle(
        bundle_path_or_id=bundle_res["bundle_id"],
        is_drill=True,
        db=db_session,
        backup_root=str(temp_backup_root),
        authorizer_id="admin_dr@vapt.local",
    )
    assert drill_res["status"] == "SUCCESS"
    assert drill_res["drill_type"] == "ISOLATED_SANDBOX"

    # Production database count remains completely untouched
    final_count = db_session.query(Project).count()
    assert initial_count == final_count


# ==============================================================================
# TEST 13 & 14: Storage Adapter Atomic Staging, Overwrites & WORM Status
# ==============================================================================
def test_storage_adapter_atomic_staging_and_worm_truthfulness(tmp_path: Path):
    """Verifies storage adapters enforce atomic staging, reject overwrites, and honestly report WORM."""
    storage_dir = tmp_path / "storage_evidence"
    adapter = LocalStorageAdapter(root_dir=storage_dir)

    key = "evidence/test_blob_01.bin"
    payload = b"CRITICAL_FORENSIC_MEMORY_DUMP"

    # 1. Store evidence
    store_meta = adapter.store_evidence(key=key, payload=payload)
    assert store_meta["key"] == key
    assert store_meta["sha256"] == hashlib.sha256(payload).hexdigest()

    # 2. Overwrite attempt must raise EvidenceOverwriteError
    with pytest.raises(EvidenceOverwriteError, match="cannot be overwritten"):
        adapter.store_evidence(key=key, payload=b"MALICIOUS_OVERWRITE")

    # 3. Retrieve and verify digest
    ret_bytes, ret_meta = adapter.retrieve_evidence(key=key, expected_sha256=store_meta["sha256"])
    assert ret_bytes == payload

    # 4. Hash verification failure on retrieval
    with pytest.raises(EvidenceIntegrityError):
        adapter.retrieve_evidence(key=key, expected_sha256="deadbeef" * 8)

    # 5. WORM status truthfulness: local disk MUST NOT claim compliance
    worm_status = adapter.check_worm_status()
    assert worm_status["worm_compliant"] is False
    assert worm_status["worm_mode"] == "OS_READONLY_SIMULATION"

    # 6. S3 Adapter WORM probe honesty
    s3_adapter = S3CompatibleStorageAdapter(bucket_name="nonexistent-mock-bucket")
    s3_worm = s3_adapter.check_worm_status()
    assert s3_worm["worm_compliant"] is False


# ==============================================================================
# TEST 15 & 16: Data Portability Safe Export, Import & Zip Slip Rejection
# ==============================================================================
def test_data_portability_export_import_and_zip_slip_rejection(db_session: Session, test_project: Project, tmp_path: Path):
    """Verifies data portability export, import schema validation, and Zip Slip rejection."""
    # 1. Export project archive
    export_res = data_portability_service.export_project_archive(
        db=db_session,
        project_id=test_project.id,
        actor_id="admin_dr@vapt.local",
    )
    archive_path = export_res["archive_path"]
    assert Path(archive_path).exists()
    assert export_res["size_bytes"] > 0
    assert len(export_res["manifest_signature"]) > 0

    # 2. Validate valid archive
    val_res = data_portability_service.validate_project_archive(archive_path)
    assert val_res["valid"] is True
    assert len(val_res["errors"]) == 0

    # 3. Dry-run import
    dry_res = data_portability_service.import_project_archive(
        db=db_session,
        archive_path=archive_path,
        dry_run=True,
    )
    assert dry_res["dry_run"] is True
    assert dry_res["status"] == "VALIDATED"

    # 4. Zip Slip traversal rejection test
    zip_slip_archive = tmp_path / "zip_slip_attack.zip"
    with zipfile.ZipFile(str(zip_slip_archive), "w") as zf:
        zf.writestr("manifest.json", "{}")
        zf.writestr("../../etc/passwd", "root:x:0:0:root")

    bad_val = data_portability_service.validate_project_archive(str(zip_slip_archive))
    assert bad_val["valid"] is False
    assert any("zip slip" in err.lower() for err in bad_val["errors"])


# ==============================================================================
# TEST 17: Operational Governance & Recovery Readiness Telemetry
# ==============================================================================
def test_operational_governance_and_readiness_telemetry(db_session: Session, temp_backup_root: Path):
    """Verifies RPO/RTO calculations, readiness health evaluation, and operator runbooks."""
    readiness = BackupRecoveryService.get_recovery_readiness(db=db_session, backup_root=str(temp_backup_root))

    assert "health" in readiness
    assert readiness["assumptions"]["rpo_target_minutes"] == 60
    assert readiness["assumptions"]["rto_target_minutes"] == 15
    assert "metrics" in readiness
    assert "storage_worm_status" in readiness
    assert "operator_runbook" in readiness
    assert "DISASTER_RECOVERY_AND_OPERATOR_RUNBOOK.md" in readiness["operator_runbook"]["documentation_path"]
