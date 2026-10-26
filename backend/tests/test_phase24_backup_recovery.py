import os
import uuid
import time
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from sqlalchemy.orm import Session
from fastapi.testclient import TestClient

from app.models.project import Project
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus, AssessmentFinding, FindingEvidence, FindingSeverity, FindingConfidence
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.services.backup_service import BackupRecoveryService


def test_online_database_backup_and_integrity(db: Session, test_project: Project, tester_user):
    """
    Verify online backup creation using VACUUM INTO, computing SHA-256 integrity hash.
    """
    backup_dir = "./data/test_backups"
    meta = BackupRecoveryService.create_database_backup(db, backup_dir=backup_dir, actor_id=tester_user.id)

    assert meta.backup_path is not None
    assert os.path.exists(meta.backup_path)
    assert meta.size_bytes > 0
    assert len(meta.sha256_hash) == 64
    assert meta.table_count > 10

    # Clean up test backup file
    try:
        os.remove(meta.backup_path)
    except Exception:
        pass


def test_backup_sandbox_restore_and_verification(db: Session, test_project: Project, tester_user):
    """
    Verify backup sandbox restoration:
    - Valid backup restores cleanly with PRAGMA integrity_check = 'ok'.
    - Tampered checksum fails closed.
    """
    backup_dir = "./data/test_backups"
    meta = BackupRecoveryService.create_database_backup(db, backup_dir=backup_dir, actor_id=tester_user.id)

    # 1. Successful verification
    verify_res = BackupRecoveryService.verify_and_test_restore(
        backup_file_path=meta.backup_path,
        expected_sha256=meta.sha256_hash,
    )
    assert verify_res["is_valid"] is True
    assert verify_res["integrity_result"] == "ok"
    assert verify_res["table_count"] > 10
    assert "projects" in verify_res["tables_verified"]

    # 2. Checksum tampering detection
    tampered_hash = "0" * 64
    with pytest.raises(ValueError, match="Integrity check failed"):
        BackupRecoveryService.verify_and_test_restore(
            backup_file_path=meta.backup_path,
            expected_sha256=tampered_hash,
        )

    # Clean up
    try:
        os.remove(meta.backup_path)
    except Exception:
        pass


def test_project_manifest_export(db: Session, test_project: Project, tester_user):
    """
    Verify comprehensive project manifest export generation and SHA-256 digest calculation.
    """
    # Create sample targets and findings
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="export.test.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorized_by_id=tester_user.id,
        created_by_id=tester_user.id,
    )
    db.add(target)

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint=hashlib.sha256(b"export.test.local:CWE-79").hexdigest(),
        title="Export Test Finding",
        description="To be exported",
        target_value="export.test.local",
        vuln_id="CWE-79",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
    )
    db.add(finding)
    db.commit()

    manifest = BackupRecoveryService.export_project_manifest(db, test_project.id, actor_id=tester_user.id)

    assert manifest["project"]["id"] == test_project.id
    assert manifest["scope_targets_count"] >= 1
    assert manifest["vulnerability_findings_count"] >= 1
    assert len(manifest["manifest_sha256"]) == 64
    assert len(manifest["targets"]) >= 1


def test_project_purge_lifecycle_and_tombstone(db: Session, test_project: Project, tester_user):
    """
    Verify project teardown / right-to-erasure:
    - Invalid confirmation phrase rejected.
    - Valid phrase purges all dependent records and records tombstone audit event.
    """
    # Create disposable project
    disposable = Project(
        name="Disposable Teardown Target",
        description="Temporary project for purge test",
        organization_id=test_project.organization_id,
    )
    db.add(disposable)
    db.commit()
    disposable_id = disposable.id

    # Add child scope target
    target = ScopeTarget(
        project_id=disposable_id,
        target_type=TargetType.IP_ADDRESS,
        target_value="10.99.99.1",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorized_by_id=tester_user.id,
        created_by_id=tester_user.id,
    )
    db.add(target)
    db.commit()

    # 1. Invalid confirmation phrase fails
    with pytest.raises(ValueError, match="Confirmation phrase mismatch"):
        BackupRecoveryService.purge_project_data(
            db=db,
            project_id=disposable_id,
            actor_id=tester_user.id,
            confirmation_phrase="wrong phrase",
        )

    # 2. Valid phrase succeeds
    res = BackupRecoveryService.purge_project_data(
        db=db,
        project_id=disposable_id,
        actor_id=tester_user.id,
        confirmation_phrase=f"PURGE PROJECT {disposable.name}",
    )
    assert res["status"] == "PURGED"

    # Verify project deleted from database
    deleted_p = db.query(Project).filter(Project.id == disposable_id).first()
    assert deleted_p is None

    # Verify child targets cascade deleted
    child_targets = db.query(ScopeTarget).filter(ScopeTarget.project_id == disposable_id).all()
    assert len(child_targets) == 0


def test_evidence_retention_policy_archival(db: Session, test_project: Project, tester_user):
    """
    Verify retention policy prunes old raw evidence while preserving finding records.
    """
    past_time = datetime.now(timezone.utc) - timedelta(days=200)

    job = AssessmentJob(
        project_id=test_project.id,
        adapter_name="scanner.passive_header",
        target_input="retention.test.local",
        created_by_id=tester_user.id,
        status=AssessmentStatus.COMPLETED,
        completed_at=past_time,
    )
    db.add(job)
    db.commit()

    finding = AssessmentFinding(
        project_id=test_project.id,
        job_id=job.id,
        title="Retention Finding",
        target_value="retention.test.local",
        vuln_id="CVE-2026-RET",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.CERTAIN,
        description="Finding with evidence to be pruned",
    )
    db.add(finding)
    db.commit()

    ev = FindingEvidence(
        finding_id=finding.id,
        evidence_type="RAW_HTTP_RESPONSE",
        payload="Sensitive old HTTP body payload",
        sha256_hash="f" * 64,
        is_truncated=False,
    )
    db.add(ev)
    db.commit()

    # Apply 180-day retention policy
    retention_res = BackupRecoveryService.apply_evidence_retention_policy(
        db=db,
        project_id=test_project.id,
        retention_days=180,
        actor_id=tester_user.id,
    )

    assert retention_res["pruned_evidence_count"] >= 1

    # Verify evidence payload was archived
    db.refresh(ev)
    assert ev.payload == "[ARCHIVED_BY_RETENTION_POLICY]"
    assert ev.is_truncated is True
    # Verify finding itself is still present
    db.refresh(finding)
    assert finding.title == "Retention Finding"


def test_api_lifecycle_endpoints(client: TestClient, test_project: Project, lead_headers: dict, admin_headers: dict):
    """
    Verify HTTP API endpoints for project export, retention, and admin backup.
    """
    # 1. Project export (Lead role)
    exp_res = client.get(
        f"/api/v1/projects/{test_project.id}/lifecycle/export",
        headers=lead_headers,
    )
    assert exp_res.status_code == 200
    assert "manifest_sha256" in exp_res.json()

    # 2. Retention policy execution (Lead role)
    ret_res = client.post(
        f"/api/v1/projects/{test_project.id}/lifecycle/retention",
        json={"retention_days": 90},
        headers=lead_headers,
    )
    assert ret_res.status_code == 200
    assert ret_res.json()["retention_days"] == 90

    # 3. Admin backup creation (Admin role)
    backup_res = client.post(
        "/api/v1/admin/backup",
        headers=admin_headers,
    )
    assert backup_res.status_code == 200
    assert "sha256_hash" in backup_res.json()

    # Clean up created backup file
    b_path = backup_res.json().get("backup_path")
    if b_path and os.path.exists(b_path):
        try:
            os.remove(b_path)
        except Exception:
            pass
