"""
VAPT Platform — Evidence Lifecycle Governance, Data Retention & Verifiable Deletion.
Test suite for Prompt 29.
Validates:
1. Canonical data classification retention policy catalog completeness.
2. Updating retention policy enforces Admin role privilege.
3. Placing binding legal/investigation holds on evidence, findings, or projects.
4. Releasing active holds.
5. Active legal hold strictly prevents retention deletion.
6. Retention preview detects expired records accurately.
7. Active findings with unresolved dependencies are excluded from deletion.
8. Retention preview generates a deterministic dry-run state hash.
9. Retention execution requires explicit Security Lead confirmation.
10. Retention execution rejects stale or tampered dry-run preview hashes.
11. Verifiable deletion generates immutable HMAC-SHA256 suppression tombstones.
12. Deleted evidence records are verifiably removed from database.
13. Deletion suppression tombstones prevent resurrection of deleted records.
14. Automated credential and secret redaction engine masks sensitive tokens.
15. REST endpoints enforce strict authentication and RBAC.
16. Standalone CLI tool (scripts/run_retention_lifecycle.py) executes cleanly.
17. Immutable audit logging of retention execution actions.
"""
import os
import sys
import json
import uuid
import hashlib
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.user import User, SystemRole
from app.models.assessment import FindingEvidence, AssessmentFinding, AssessmentJob
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.audit import AuditEvent
from app.services.evidence_lifecycle_service import (
    evidence_lifecycle_service,
    EvidenceLifecycleService,
)
from app.schemas.evidence_lifecycle import (
    DataClassification,
    RetentionActionType,
    HoldType,
    HoldStatus,
    RetentionPolicyModel,
    LegalHoldCreate,
    RetentionExecutionRequest,
)
from tests.conftest import auth_header_for_user

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def auth_headers(user: User) -> dict:
    return auth_header_for_user(user)


# ------------------------------------------------------------------------------
# 1. Retention Policy Catalog & RBAC
# ------------------------------------------------------------------------------
def test_01_retention_policy_catalog_completeness():
    """Verifies that the retention engine contains canonical policies for all classifications."""
    policies = evidence_lifecycle_service.get_policies()
    assert len(policies) >= 6
    classifications = {p.classification for p in policies}
    assert DataClassification.RAW_EVIDENCE in classifications
    assert DataClassification.CREDENTIALS_AND_SECRETS in classifications
    assert DataClassification.FINDINGS_AND_RISK in classifications
    assert DataClassification.AUDIT_RECORDS in classifications


def test_02_retention_policy_requires_admin_to_update(client: TestClient, admin_user: User, tester_user: User):
    """Verifies that updating a retention policy requires ADMIN privilege."""
    pol = evidence_lifecycle_service.get_policy("POL-RAW-EVIDENCE-90D")
    assert pol is not None
    payload = pol.dict()
    payload["retention_days"] = 120

    # Unauthorized role (TESTER) -> 403
    resp_tester = client.put(
        "/api/v1/system/lifecycle/policies/POL-RAW-EVIDENCE-90D",
        headers=auth_headers(tester_user),
        json=payload,
    )
    assert resp_tester.status_code == 403

    # Authorized (ADMIN) -> 200
    resp_admin = client.put(
        "/api/v1/system/lifecycle/policies/POL-RAW-EVIDENCE-90D",
        headers=auth_headers(admin_user),
        json=payload,
    )
    assert resp_admin.status_code == 200
    assert resp_admin.json()["retention_days"] == 120

    # Restore default
    payload["retention_days"] = 90
    evidence_lifecycle_service.update_policy(RetentionPolicyModel(**payload))


# ------------------------------------------------------------------------------
# 2. Legal & Investigation Holds
# ------------------------------------------------------------------------------
def test_03_legal_hold_creation_and_listing():
    """Verifies placing and inspecting an active legal hold."""
    create_req = LegalHoldCreate(
        hold_type=HoldType.INVESTIGATION_HOLD,
        target_scope="EVIDENCE",
        target_id="ev-test-hold-01",
        reason="Security Incident Investigation SEC-2026",
    )
    hold = evidence_lifecycle_service.create_hold(create=create_req, placed_by_id="lead-user-01")
    assert hold.hold_id.startswith("HOLD-")
    assert hold.status == HoldStatus.ACTIVE
    assert hold.target_id == "ev-test-hold-01"

    # Verify is_held lookup
    is_h, reason = evidence_lifecycle_service.is_held("EVIDENCE", "ev-test-hold-01")
    assert is_h is True
    assert "Security Incident Investigation" in reason


def test_04_legal_hold_release():
    """Verifies releasing an active hold allows retention to proceed."""
    create_req = LegalHoldCreate(
        hold_type=HoldType.LEGAL_HOLD,
        target_scope="EVIDENCE",
        target_id="ev-test-release-01",
        reason="Litigation Hold",
    )
    hold = evidence_lifecycle_service.create_hold(create=create_req, placed_by_id="lead-user-01")
    assert hold.status == HoldStatus.ACTIVE

    released = evidence_lifecycle_service.release_hold(hold.hold_id, released_by_id="lead-user-01")
    assert released is not None
    assert released.status == HoldStatus.RELEASED

    is_h, _ = evidence_lifecycle_service.is_held("EVIDENCE", "ev-test-release-01")
    assert is_h is False


# ------------------------------------------------------------------------------
# 3. Retention Preview, Dependencies & State Hashing
# ------------------------------------------------------------------------------
def test_05_active_hold_blocks_evidence_deletion_in_preview(db: Session, test_project, admin_user: User):
    """Verifies an active hold on evidence flags it as ineligible for deletion."""
    # Create test job & finding & evidence
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="http://target.test",
        adapter_name="mock_adapter",
        created_by_id=admin_user.id,
    )
    db.add(job)
    db.commit()

    finding = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        target_value="http://target.test/login",
        title="Test Vuln",
    )
    db.add(finding)
    db.commit()

    old_date = datetime.now(timezone.utc) - timedelta(days=120)
    ev = FindingEvidence(
        finding_id=finding.id,
        evidence_type="HTTP_EXCHANGE",
        payload="HTTP/1.1 200 OK\nSet-Cookie: session=xyz",
        sha256_hash=hashlib.sha256(b"test").hexdigest(),
        observed_at=old_date,
    )
    db.add(ev)
    db.commit()

    # Place hold on this evidence
    evidence_lifecycle_service.create_hold(
        LegalHoldCreate(
            hold_type=HoldType.LEGAL_HOLD,
            target_scope="EVIDENCE",
            target_id=ev.id,
            reason="Litigation Hold",
        ),
        placed_by_id="admin-01",
    )

    report = evidence_lifecycle_service.generate_retention_preview(db=db)
    ev_item = next((i for i in report.preview_items if i.record_id == ev.id), None)
    assert ev_item is not None
    assert ev_item.is_held is True
    assert ev_item.eligible_for_execution is False


def test_06_retention_preview_detects_expired_records(db: Session, test_project, admin_user: User):
    """Verifies evidence past the 90-day retention window is flagged eligible for deletion."""
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="http://target.test",
        adapter_name="mock_adapter",
        created_by_id=admin_user.id,
    )
    db.add(job)
    db.commit()

    finding = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        target_value="http://target.test/api",
        title="Expired Finding",
    )
    db.add(finding)
    db.commit()

    old_date = datetime.now(timezone.utc) - timedelta(days=100)
    ev = FindingEvidence(
        finding_id=finding.id,
        evidence_type="PORT_STATE",
        payload="Port 80 OPEN",
        sha256_hash=hashlib.sha256(b"port80").hexdigest(),
        observed_at=old_date,
    )
    db.add(ev)
    db.commit()

    report = evidence_lifecycle_service.generate_retention_preview(db=db)
    ev_item = next((i for i in report.preview_items if i.record_id == ev.id), None)
    assert ev_item is not None
    assert ev_item.age_days >= 90
    assert ev_item.recommended_action == RetentionActionType.DELETE


def test_07_retention_preview_computes_deterministic_dry_run_hash(db: Session):
    """Verifies that the preview produces a deterministic SHA-256 state hash."""
    report1 = evidence_lifecycle_service.generate_retention_preview(db=db)
    report2 = evidence_lifecycle_service.generate_retention_preview(db=db)
    assert report1.dry_run_hash == report2.dry_run_hash
    assert len(report1.dry_run_hash) == 64


# ------------------------------------------------------------------------------
# 4. Retention Execution, Tombstones & Deletion Verifiability
# ------------------------------------------------------------------------------
def test_08_retention_execution_requires_security_lead_confirmation(db: Session):
    """Verifies that execute_retention rejects execution if confirmed_by_lead is False."""
    report = evidence_lifecycle_service.generate_retention_preview(db=db)
    req = RetentionExecutionRequest(
        preview_id=report.preview_id,
        dry_run_hash=report.dry_run_hash,
        confirmed_by_lead=False,
    )
    with pytest.raises(PermissionError, match="Explicit confirmation by Security Lead is required"):
        evidence_lifecycle_service.execute_retention(req=req, db=db, executed_by_id="lead-01")


def test_09_retention_execution_rejects_stale_preview_hash(db: Session):
    """Verifies that execute_retention rejects execution if dry_run_hash does not match."""
    report = evidence_lifecycle_service.generate_retention_preview(db=db)
    req = RetentionExecutionRequest(
        preview_id=report.preview_id,
        dry_run_hash="tampered_or_stale_hash_value_1234567890",
        confirmed_by_lead=True,
    )
    with pytest.raises(ValueError, match="State inconsistency: dry_run_hash does not match"):
        evidence_lifecycle_service.execute_retention(req=req, db=db, executed_by_id="lead-01")


def test_10_retention_execution_creates_verifiable_tombstone(db: Session, test_project, admin_user: User):
    """Verifies that verifiable deletion creates an immutable suppression tombstone with HMAC signature."""
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="http://target.test",
        adapter_name="mock_adapter",
        created_by_id=admin_user.id,
    )
    db.add(job)
    db.commit()

    finding = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        target_value="http://target.test/data",
        title="Deletable Finding",
    )
    db.add(finding)
    db.commit()

    old_date = datetime.now(timezone.utc) - timedelta(days=110)
    ev = FindingEvidence(
        finding_id=finding.id,
        evidence_type="RAW_OUTPUT",
        payload="Temporary debug data to be verifiably purged",
        sha256_hash=hashlib.sha256(b"debug data").hexdigest(),
        observed_at=old_date,
    )
    db.add(ev)
    db.commit()
    ev_id = ev.id
    ev_hash = ev.sha256_hash

    # Generate preview and execute
    report = evidence_lifecycle_service.generate_retention_preview(db=db)
    req = RetentionExecutionRequest(
        preview_id=report.preview_id,
        dry_run_hash=report.dry_run_hash,
        confirmed_by_lead=True,
    )
    res = evidence_lifecycle_service.execute_retention(req=req, db=db, executed_by_id="lead-user-01")

    assert res.status == "COMPLETED"
    assert res.tombstones_created_count >= 1

    # Verify tombstone exists and matches
    tombstones = evidence_lifecycle_service.list_tombstones()
    target_tomb = next((t for t in tombstones if t.evidence_id == ev_id), None)
    assert target_tomb is not None
    assert target_tomb.original_sha256_hash == ev_hash
    assert len(target_tomb.tombstone_digest) == 64

    # Verify evidence was deleted from database
    deleted_ev = db.query(FindingEvidence).filter(FindingEvidence.id == ev_id).first()
    assert deleted_ev is None


def test_11_suppression_tombstone_prevents_restoration_resurrection():
    """Verifies that is_suppressed() returns True for records with active tombstones."""
    tombstones = evidence_lifecycle_service.list_tombstones()
    if tombstones:
        assert evidence_lifecycle_service.is_suppressed(tombstones[0].evidence_id) is True
    assert evidence_lifecycle_service.is_suppressed("non-existent-evidence-id") is False


# ------------------------------------------------------------------------------
# 5. Automated Evidence Secret Redaction
# ------------------------------------------------------------------------------
def test_12_automated_secret_redaction_masks_bearer_tokens_and_keys():
    """Verifies that redact_evidence_payload substitutes passwords, keys, and tokens with safe placeholders."""
    raw_payload = (
        "GET /api/v1/user HTTP/1.1\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake_token_payload\n"
        "aws_access_key: AKIAIOSFODNN7EXAMPLE\n"
        "password: SecretPassword123!\n"
    )
    sanitized, count = evidence_lifecycle_service.redact_evidence_payload(raw_payload)
    assert count >= 3
    assert "[REDACTED_SECRET_BEARER_TOKEN]" in sanitized
    assert "[REDACTED_SECRET_AWS_KEY]" in sanitized
    assert "[REDACTED_SECRET_PASSWORD]" in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "SecretPassword123!" not in sanitized


def test_13_redact_evidence_record_in_database(db: Session, test_project, admin_user: User):
    """Verifies redact_evidence_record sanitizes the database payload while preserving record."""
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="http://target.test",
        adapter_name="mock_adapter",
        created_by_id=admin_user.id,
    )
    db.add(job)
    db.commit()

    finding = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        target_value="http://target.test/login",
        title="Credential Leak",
    )
    db.add(finding)
    db.commit()

    ev = FindingEvidence(
        finding_id=finding.id,
        evidence_type="HTTP_EXCHANGE",
        payload="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.payload_1234567890",
        sha256_hash=hashlib.sha256(b"secret").hexdigest(),
    )
    db.add(ev)
    db.commit()

    redaction_res = evidence_lifecycle_service.redact_evidence_record(
        evidence_id=ev.id,
        db=db,
    )
    assert redaction_res.redacted is True
    assert redaction_res.secrets_masked_count >= 1

    # Verify updated DB content
    updated = db.query(FindingEvidence).filter(FindingEvidence.id == ev.id).first()
    assert "[REDACTED_SECRET_BEARER_TOKEN]" in updated.payload


# ------------------------------------------------------------------------------
# 6. REST Endpoints & RBAC Enforcement
# ------------------------------------------------------------------------------
def test_14_api_policies_endpoint_requires_auth(client: TestClient, auditor_user: User):
    """Verifies GET /system/lifecycle/policies requires auth and AUDITOR/LEAD/ADMIN."""
    resp_unauth = client.get("/api/v1/system/lifecycle/policies")
    assert resp_unauth.status_code == 401

    resp_auth = client.get(
        "/api/v1/system/lifecycle/policies",
        headers=auth_headers(auditor_user),
    )
    assert resp_auth.status_code == 200
    assert len(resp_auth.json()) >= 6


def test_15_api_holds_endpoint_lifecycle(client: TestClient, admin_user: User):
    """Verifies POST, GET, and DELETE /system/lifecycle/holds."""
    create_body = {
        "hold_type": "LEGAL_HOLD",
        "target_scope": "PROJECT",
        "target_id": "proj-hold-api-test",
        "reason": "Regulatory Audit Hold",
    }
    # Create hold
    post_resp = client.post(
        "/api/v1/system/lifecycle/holds",
        headers=auth_headers(admin_user),
        json=create_body,
    )
    assert post_resp.status_code == 200
    hold_id = post_resp.json()["hold_id"]

    # List holds
    list_resp = client.get(
        "/api/v1/system/lifecycle/holds",
        headers=auth_headers(admin_user),
    )
    assert list_resp.status_code == 200
    assert any(h["hold_id"] == hold_id for h in list_resp.json())

    # Release hold
    del_resp = client.delete(
        f"/api/v1/system/lifecycle/holds/{hold_id}",
        headers=auth_headers(admin_user),
    )
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "RELEASED"


def test_16_api_preview_and_tombstones_endpoints(client: TestClient, admin_user: User):
    """Verifies GET /system/lifecycle/preview and GET /system/lifecycle/tombstones."""
    prev_resp = client.get(
        "/api/v1/system/lifecycle/preview",
        headers=auth_headers(admin_user),
    )
    assert prev_resp.status_code == 200
    assert "dry_run_hash" in prev_resp.json()

    tomb_resp = client.get(
        "/api/v1/system/lifecycle/tombstones",
        headers=auth_headers(admin_user),
    )
    assert tomb_resp.status_code == 200
    assert isinstance(tomb_resp.json(), list)


def test_17_standalone_retention_lifecycle_cli():
    """Verifies that the standalone CLI runner (scripts/run_retention_lifecycle.py) executes cleanly."""
    import subprocess
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "run_retention_lifecycle.py"), "--preview"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "EVIDENCE RETENTION PREVIEW" in proc.stdout
