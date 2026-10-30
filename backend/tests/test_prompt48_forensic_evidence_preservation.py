"""
VAPT Platform — Forensic Evidence Preservation & Chain of Custody Integration Tests (Prompt 48).
Validates:
1. Documented evidence lifecycle from collection to normalized, verified, archived, and deleted states.
2. Separation of untouched original raw records from derived normalized interpretations.
3. Cryptographic proof of origin (Ed25519 digital signatures) vs payload checksums.
4. Monotonic Merkle custody hash chaining for auditable provenance.
5. Explicit verification outcomes: VERIFIED, FAILED, UNAVAILABLE, NOT_CHECKED.
6. Contradiction preservation that never overwrites historical records.
7. Verifiable export and import round-trips.
8. Server-side authorization and sensitive evidence masking.
9. Safe deletion governance with active legal hold enforcement.
10. Read-only forensic CLI verification tool.
"""
import json
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_access_token
from app.core.database import SessionLocal
from app.main import app
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.forensic_evidence import (
    ForensicEvidenceRecord,
    EvidenceCustodyEvent,
    EvidenceLifecycleState,
    VerificationOutcome,
    ContradictionStatus,
    CustodyEventType,
)
from app.services.forensic_evidence_service import forensic_evidence_service
from app.services.origin_attestation_service import attestation_service
from app.schemas.forensic_evidence import (
    EvidenceIngestRequest,
    EvidenceNormalizeRequest,
    EvidenceContradictionRequest,
    EvidenceVerificationRequest,
    EvidenceImportRequest,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def setup_prompt48_fixtures():
    db: Session = SessionLocal()
    try:
        suffix = uuid.uuid4().hex[:6]
        org = Organization(id=str(uuid.uuid4()), name=f"Forensic Org {suffix}", slug=f"forensic-org-{suffix}")
        db.add(org)

        lead_user = User(
            id=str(uuid.uuid4()),
            email=f"forensic_lead_{suffix}@example.com",
            hashed_password="hashed_pwd_test",
            full_name=f"Forensic Lead {suffix}",
            system_role=SystemRole.SECURITY_LEAD,
            is_active=True,
        )
        analyst_user = User(
            id=str(uuid.uuid4()),
            email=f"forensic_analyst_{suffix}@example.com",
            hashed_password="hashed_pwd_test",
            full_name=f"Forensic Analyst {suffix}",
            system_role=SystemRole.SECURITY_TESTER,
            is_active=True,
        )
        viewer_user = User(
            id=str(uuid.uuid4()),
            email=f"forensic_viewer_{suffix}@example.com",
            hashed_password="hashed_pwd_test",
            full_name=f"Forensic Viewer {suffix}",
            system_role=SystemRole.VIEWER,
            is_active=True,
        )
        admin_user = User(
            id=str(uuid.uuid4()),
            email=f"forensic_admin_{suffix}@example.com",
            hashed_password="hashed_pwd_test",
            full_name=f"Forensic Admin {suffix}",
            system_role=SystemRole.ADMIN,
            is_active=True,
        )
        db.add_all([lead_user, analyst_user, viewer_user, admin_user])

        project = Project(
            id=str(uuid.uuid4()),
            organization_id=org.id,
            name=f"Forensic Project {suffix}",
            is_active=True,
        )
        other_project = Project(
            id=str(uuid.uuid4()),
            organization_id=org.id,
            name=f"Other Project {suffix}",
            is_active=True,
        )
        db.add_all([project, other_project])
        db.flush()

        mem_lead = ProjectMember(project_id=project.id, user_id=lead_user.id, role=ProjectRole.LEAD)
        mem_other_lead = ProjectMember(project_id=other_project.id, user_id=lead_user.id, role=ProjectRole.LEAD)
        mem_analyst = ProjectMember(project_id=project.id, user_id=analyst_user.id, role=ProjectRole.TESTER)
        mem_viewer = ProjectMember(project_id=project.id, user_id=viewer_user.id, role=ProjectRole.VIEWER)
        db.add_all([mem_lead, mem_other_lead, mem_analyst, mem_viewer])
        db.commit()

        client = TestClient(app)

        def make_headers(user: User):
            token = create_access_token(subject=user.id, claims={"role": user.system_role.value})
            return {"Authorization": f"Bearer {token}"}

        yield {
            "db": db,
            "client": client,
            "lead_user": lead_user,
            "analyst_user": analyst_user,
            "viewer_user": viewer_user,
            "admin_user": admin_user,
            "lead_headers": make_headers(lead_user),
            "analyst_headers": make_headers(analyst_user),
            "viewer_headers": make_headers(viewer_user),
            "admin_headers": make_headers(admin_user),
            "project": project,
            "other_project": other_project,
        }
    finally:
        db.close()


def test_01_evidence_lifecycle_and_custody_chain_initialization(setup_prompt48_fixtures):
    """
    1. Ingests raw evidence record.
    2. Verifies lifecycle state defaults to INGESTED.
    3. Verifies last_verification_status defaults to NOT_CHECKED.
    4. Verifies initial custody event with Merkle hash chaining (prev_custody_hash == 0*64).
    """
    f = setup_prompt48_fixtures
    client: TestClient = f["client"]

    payload = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html>Protected</html>"
    req_data = {
        "project_id": f["project"].id,
        "evidence_type": "RAW_HTTP",
        "raw_payload": payload,
        "source_identity": "adapter-zap-active-scanner",
        "adapter_version": "2.14.0",
        "collection_time": datetime.now(timezone.utc).isoformat(),
        "assessment_context": {"target": "https://api.internal.corp", "port": 443},
    }

    resp = client.post("/api/v1/forensic-evidence/records", json=req_data, headers=f["analyst_headers"])
    assert resp.status_code == 201, resp.text
    data = resp.json()

    assert data["lifecycle_state"] == "INGESTED"
    assert data["last_verification_status"] == "NOT_CHECKED"
    assert data["raw_digest_sha256"] == hashlib.sha256(payload.encode("utf-8")).hexdigest()
    assert data["origin_signature"] != ""
    assert data["signature_algorithm"] == "ED25519"
    assert data["contradiction_status"] == "SUPPORTING"

    # Verify custody chain event in database
    db: Session = f["db"]
    events = db.query(EvidenceCustodyEvent).filter(EvidenceCustodyEvent.evidence_id == data["id"]).all()
    assert len(events) == 1
    assert events[0].event_type == "INGESTION"
    assert events[0].prev_custody_hash == "0" * 64
    assert len(events[0].custody_hash) == 64


def test_02_original_raw_evidence_separated_from_normalized_interpretation(setup_prompt48_fixtures):
    """
    1. Normalizes raw evidence.
    2. Verifies raw_payload and raw_digest_sha256 are strictly untouched.
    3. Verifies normalized_payload and normalized_digest_sha256 are populated.
    4. Verifies transformation history logs step, transformer identity, version, reason, actor, and timestamp.
    5. Verifies chained custody event.
    """
    f = setup_prompt48_fixtures
    client: TestClient = f["client"]

    raw_payload = "PORT 22/tcp OPEN ssh OpenSSH 8.2p1 Ubuntu-4ubuntu0.5"
    ingest_resp = client.post(
        "/api/v1/forensic-evidence/records",
        json={
            "project_id": f["project"].id,
            "evidence_type": "BANNER",
            "raw_payload": raw_payload,
            "source_identity": "nmap-scanner-sensor",
            "adapter_version": "7.94",
            "collection_time": datetime.now(timezone.utc).isoformat(),
        },
        headers=f["analyst_headers"],
    )
    assert ingest_resp.status_code == 201
    evidence_id = ingest_resp.json()["id"]
    original_digest = ingest_resp.json()["raw_digest_sha256"]

    norm_data = {
        "normalized_payload": {
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "8.2p1",
            "os": "Ubuntu-4ubuntu0.5",
        },
        "transformer_identity": "service-banner-normalizer",
        "adapter_version": "1.4.2",
        "reason": "Extract structured service tokens for vulnerability matching",
    }
    norm_resp = client.post(
        f"/api/v1/forensic-evidence/records/{evidence_id}/normalize",
        json=norm_data,
        headers=f["analyst_headers"],
    )
    assert norm_resp.status_code == 200
    res = norm_resp.json()

    # Raw payload and digest must be unchanged
    assert res["raw_payload"] == raw_payload
    assert res["raw_digest_sha256"] == original_digest
    assert res["normalized_payload"] == norm_data["normalized_payload"]
    assert res["normalized_digest_sha256"] is not None
    assert res["lifecycle_state"] == "NORMALIZED"

    # Transformation history must be present
    assert len(res["transformation_history"]) == 1
    t_entry = res["transformation_history"][0]
    assert t_entry["step"] == "NORMALIZATION"
    assert t_entry["transformer"] == "service-banner-normalizer"
    assert t_entry["actor"] == f["analyst_user"].email

    # Check custody chain has 2 chained events
    db: Session = f["db"]
    events = (
        db.query(EvidenceCustodyEvent)
        .filter(EvidenceCustodyEvent.evidence_id == evidence_id)
        .order_by(EvidenceCustodyEvent.timestamp.asc())
        .all()
    )
    assert len(events) == 2
    assert events[1].event_type == "NORMALIZATION"
    assert events[1].prev_custody_hash == events[0].custody_hash


def test_03_altered_evidence_detected_and_verification_fails(setup_prompt48_fixtures):
    """
    Directly mutates raw_payload in database to simulate tampering.
    Runs verify_evidence_record and asserts status == FAILED with discrepancy noted.
    """
    f = setup_prompt48_fixtures
    client: TestClient = f["client"]
    db: Session = f["db"]

    raw_payload = "GET /admin/config HTTP/1.1\r\nHost: target.corp\r\n\r\n"
    ingest_resp = client.post(
        "/api/v1/forensic-evidence/records",
        json={
            "project_id": f["project"].id,
            "evidence_type": "RAW_HTTP",
            "raw_payload": raw_payload,
            "source_identity": "zap-tamper-test",
            "adapter_version": "1.0",
            "collection_time": datetime.now(timezone.utc).isoformat(),
        },
        headers=f["analyst_headers"],
    )
    evidence_id = ingest_resp.json()["id"]

    # Deliberately tamper with raw_payload directly in database
    rec = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
    rec.raw_payload = "GET /admin/MALICIOUS_OVERWRITE HTTP/1.1\r\nHost: target.corp\r\n\r\n"
    db.commit()

    # Verify
    verify_resp = client.post(
        f"/api/v1/forensic-evidence/records/{evidence_id}/verify",
        json={"verify_raw_digest": True, "verify_origin_signature": True, "verify_custody_chain": True},
        headers=f["analyst_headers"],
    )
    assert verify_resp.status_code == 200
    v_res = verify_resp.json()

    assert v_res["status"] == "FAILED"
    assert v_res["raw_digest_match"] is False
    assert v_res["signature_valid"] is False
    assert any("Raw payload digest mismatch" in d for d in v_res["discrepancies"])


def test_04_missing_or_empty_raw_payload_handled_as_unavailable(setup_prompt48_fixtures):
    """
    Simulates missing or empty evidence artifact.
    Asserts verification status is UNAVAILABLE and never reports VERIFIED.
    """
    f = setup_prompt48_fixtures
    client: TestClient = f["client"]
    db: Session = f["db"]

    ingest_resp = client.post(
        "/api/v1/forensic-evidence/records",
        json={
            "project_id": f["project"].id,
            "evidence_type": "CONSOLE",
            "raw_payload": "Valid capture before disk loss",
            "source_identity": "external-collector",
            "adapter_version": "1.0",
            "collection_time": datetime.now(timezone.utc).isoformat(),
        },
        headers=f["analyst_headers"],
    )
    evidence_id = ingest_resp.json()["id"]

    # Simulate lost artifact
    rec = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
    rec.raw_payload = ""
    db.commit()

    verify_resp = client.post(
        f"/api/v1/forensic-evidence/records/{evidence_id}/verify",
        headers=f["analyst_headers"],
    )
    assert verify_resp.status_code == 200
    v_res = verify_resp.json()

    assert v_res["status"] == "UNAVAILABLE"
    assert v_res["artifacts_present"] is False
    assert any("missing or empty" in d for d in v_res["discrepancies"])


def test_05_digital_origin_signature_vs_checksum_distinction(setup_prompt48_fixtures):
    """
    Mathematically demonstrates that a checksum is NOT proof of origin:
    - An attacker can recalculate a valid SHA-256 checksum for modified bytes.
    - However, an attacker CANNOT forge an asymmetric Ed25519 origin signature without the private key.
    """
    original_payload = "AUTHENTIC_TELEMETRY_SAMPLE_A"
    tampered_payload = "AUTHENTIC_TELEMETRY_SAMPLE_A_ATTACKER_INJECTED"
    collection_time = datetime.now(timezone.utc)
    source_identity = "sensor-nmap-01"

    # 1. Attest origin with genuine sensor private key
    sig, algo, key_id = attestation_service.sign_evidence_origin(
        raw_payload=original_payload,
        source_identity=source_identity,
        collection_time=collection_time,
        key_id="KEY-SENSOR-NMAP-01",
    )

    # 2. Checksum of tampered payload can be computed by anyone
    tampered_checksum = hashlib.sha256(tampered_payload.encode("utf-8")).hexdigest()
    assert tampered_checksum == hashlib.sha256(tampered_payload.encode("utf-8")).hexdigest()

    # 3. But validating the original signature against tampered payload FAILS cryptographically!
    valid_tampered, reason_tampered = attestation_service.verify_evidence_origin(
        raw_payload=tampered_payload,
        source_identity=source_identity,
        collection_time=collection_time,
        signature_hex=sig,
        key_id=key_id,
        algorithm=algo,
    )
    assert valid_tampered is False
    assert "Cryptographic signature verification failed" in reason_tampered

    # 4. Validating against authentic payload PASSES
    valid_orig, _ = attestation_service.verify_evidence_origin(
        raw_payload=original_payload,
        source_identity=source_identity,
        collection_time=collection_time,
        signature_hex=sig,
        key_id=key_id,
        algorithm=algo,
    )
    assert valid_orig is True


def test_06_unverified_record_reports_not_checked_until_evaluated(setup_prompt48_fixtures):
    """
    Acceptance Criteria: The system must never report integrity as verified
    without performing the relevant check.
    """
    f = setup_prompt48_fixtures
    client: TestClient = f["client"]

    ingest_resp = client.post(
        "/api/v1/forensic-evidence/records",
        json={
            "project_id": f["project"].id,
            "evidence_type": "CONFIG",
            "raw_payload": "kernel.randomize_va_space = 2",
            "source_identity": "os-hardening-audit",
            "adapter_version": "2.0",
            "collection_time": datetime.now(timezone.utc).isoformat(),
        },
        headers=f["analyst_headers"],
    )
    evidence_id = ingest_resp.json()["id"]

    # Fetch record
    get_resp = client.get(f"/api/v1/forensic-evidence/records/{evidence_id}", headers=f["analyst_headers"])
    assert get_resp.status_code == 200
    rec = get_resp.json()

    assert rec["last_verification_status"] == "NOT_CHECKED"
    assert rec["last_verified_at"] is None
    assert rec["last_verified_by"] is None

    # Now run verification
    client.post(f"/api/v1/forensic-evidence/records/{evidence_id}/verify", headers=f["analyst_headers"])

    # Re-fetch: Now and only now is it VERIFIED
    get_resp_after = client.get(f"/api/v1/forensic-evidence/records/{evidence_id}", headers=f["analyst_headers"])
    rec_after = get_resp_after.json()
    assert rec_after["last_verification_status"] == "VERIFIED"
    assert rec_after["last_verified_at"] is not None


def test_07_contradictory_observations_preserved_as_history_never_rewritten(setup_prompt48_fixtures):
    """
    Verifies that divergent target behavior or scanner disagreements create
    distinct linked historical records and never silently rewrite earlier evidence.
    """
    f = setup_prompt48_fixtures
    client: TestClient = f["client"]

    # Initial scan: port open
    orig_resp = client.post(
        "/api/v1/forensic-evidence/records",
        json={
            "project_id": f["project"].id,
            "evidence_type": "PORT_STATE",
            "raw_payload": "PORT 8080/tcp OPEN http Apache Tomcat 9.0.30",
            "source_identity": "scanner-run-001",
            "adapter_version": "1.0",
            "collection_time": datetime.now(timezone.utc).isoformat(),
        },
        headers=f["analyst_headers"],
    )
    orig_id = orig_resp.json()["id"]
    orig_digest = orig_resp.json()["raw_digest_sha256"]

    # Subsequent scan finds port FILTERED / CLOSED
    contra_data = {
        "contradictory_payload": "PORT 8080/tcp FILTERED http-proxy (Connection timed out)",
        "source_identity": "scanner-run-002",
        "adapter_version": "1.0",
        "collection_time": datetime.now(timezone.utc).isoformat(),
        "notes": "Target firewall rule deployed; port no longer answering requests",
        "supersedes_previous": True,
    }
    contra_resp = client.post(
        f"/api/v1/forensic-evidence/records/{orig_id}/contradiction",
        json=contra_data,
        headers=f["analyst_headers"],
    )
    assert contra_resp.status_code == 201
    new_evidence = contra_resp.json()

    assert new_evidence["is_contradictory"] is True
    assert new_evidence["contradiction_status"] == "SUPERSEDED"
    assert new_evidence["prior_evidence_id"] == orig_id

    # Verify original record still exists and its raw payload was NOT overwritten
    orig_check = client.get(f"/api/v1/forensic-evidence/records/{orig_id}", headers=f["analyst_headers"]).json()
    assert orig_check["raw_payload"] == "PORT 8080/tcp OPEN http Apache Tomcat 9.0.30"
    assert orig_check["raw_digest_sha256"] == orig_digest
    assert orig_check["contradiction_status"] == "SUPERSEDED"
    assert orig_check["superseded_by_id"] == new_evidence["id"]


def test_08_evidence_export_and_import_roundtrip_with_signature_and_provenance(setup_prompt48_fixtures):
    """
    Tests verifiable export bundle generation and cross-project import with provenance checks.
    """
    f = setup_prompt48_fixtures
    client: TestClient = f["client"]

    # Ingest record in source project
    client.post(
        "/api/v1/forensic-evidence/records",
        json={
            "project_id": f["project"].id,
            "evidence_type": "RAW_HTTP",
            "raw_payload": "TRACE / HTTP/1.1\r\nHost: app.corp\r\n\r\nHTTP/1.1 200 OK\r\nTrace Enabled",
            "source_identity": "http-methods-scanner",
            "adapter_version": "1.1",
            "collection_time": datetime.now(timezone.utc).isoformat(),
        },
        headers=f["analyst_headers"],
    )

    # Export bundle
    export_resp = client.post(
        f"/api/v1/forensic-evidence/export?project_id={f['project'].id}",
        headers=f["lead_headers"],
    )
    assert export_resp.status_code == 200
    bundle = export_resp.json()

    assert bundle["record_count"] >= 1
    assert bundle["bundle_digest_sha256"] != ""
    assert bundle["bundle_signature"] != ""

    # Import bundle into other_project
    import_resp = client.post(
        "/api/v1/forensic-evidence/import",
        json={"bundle": bundle, "target_project_id": f["other_project"].id},
        headers=f["lead_headers"],
    )
    assert import_resp.status_code == 200
    import_res = import_resp.json()

    assert import_res["verification_passed"] is True
    assert import_res["imported_count"] >= 1
    assert len(import_res["warnings"]) == 0


def test_09_server_side_authorization_restricts_raw_evidence_access(setup_prompt48_fixtures):
    """
    Verifies that VIEWER receives sanitized payloads and unauthorized callers are rejected.
    """
    f = setup_prompt48_fixtures
    client: TestClient = f["client"]

    sensitive_payload = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_token_content"
    ingest_resp = client.post(
        "/api/v1/forensic-evidence/records",
        json={
            "project_id": f["project"].id,
            "evidence_type": "RAW_HTTP",
            "raw_payload": sensitive_payload,
            "source_identity": "auth-header-leak",
            "adapter_version": "1.0",
            "collection_time": datetime.now(timezone.utc).isoformat(),
        },
        headers=f["analyst_headers"],
    )
    evidence_id = ingest_resp.json()["id"]

    # Analyst receives full unsanitized payload
    analyst_resp = client.get(f"/api/v1/forensic-evidence/records/{evidence_id}", headers=f["analyst_headers"])
    assert analyst_resp.status_code == 200
    assert analyst_resp.json()["raw_payload"] == sensitive_payload

    # Viewer receives sanitized payload
    viewer_resp = client.get(f"/api/v1/forensic-evidence/records/{evidence_id}", headers=f["viewer_headers"])
    assert viewer_resp.status_code == 200
    assert "[REDACTED_BEARER_TOKEN]" in viewer_resp.json()["raw_payload"]
    assert "sensitive_token_content" not in viewer_resp.json()["raw_payload"]

    # Unauthenticated receives 401
    unauth_resp = client.get(f"/api/v1/forensic-evidence/records/{evidence_id}")
    assert unauth_resp.status_code == 401


def test_10_sensitive_evidence_sanitization_in_display_and_logs(setup_prompt48_fixtures):
    """
    Verifies that high-entropy secrets and private keys are scrubbed by sanitize_for_display.
    """
    raw_secrets = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0fake...\n-----END RSA PRIVATE KEY-----\n"
        "AKIAIOSFODNN7EXAMPLE\n"
        "postgres://user:super_secret_db_pass@db.corp:5432/production"
    )
    sanitized = forensic_evidence_service.sanitize_for_display(raw_secrets)

    assert "-----BEGIN RSA PRIVATE KEY-----" not in sanitized
    assert "[REDACTED_PRIVATE_KEY]" in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "[REDACTED_AWS_KEY]" in sanitized
    assert "super_secret_db_pass" not in sanitized
    assert "[REDACTED_DATABASE_URL]" in sanitized


def test_11_safe_retention_and_deletion_governance_with_legal_holds(setup_prompt48_fixtures):
    """
    Verifies that active legal holds block deletion, and authorized deletion records tombstones.
    """
    f = setup_prompt48_fixtures
    client: TestClient = f["client"]
    db: Session = f["db"]

    ingest_resp = client.post(
        "/api/v1/forensic-evidence/records",
        json={
            "project_id": f["project"].id,
            "evidence_type": "CONFIG",
            "raw_payload": "confidential_config=true",
            "source_identity": "retention-test",
            "adapter_version": "1.0",
            "collection_time": datetime.now(timezone.utc).isoformat(),
        },
        headers=f["analyst_headers"],
    )
    evidence_id = ingest_resp.json()["id"]

    # Place an active legal hold on the project
    holds_file = REPO_ROOT / "backend" / "data" / "legal_holds.json"
    holds_file.parent.mkdir(parents=True, exist_ok=True)
    hold_id = f"hold-{uuid.uuid4().hex[:6]}"
    holds_data = {
        "holds": [
            {
                "hold_id": hold_id,
                "title": "Investigation Hold",
                "status": "ACTIVE",
                "target_reference": f["project"].id,
                "hold_type": "REGULATORY_INVESTIGATION",
            }
        ]
    }
    with open(holds_file, "w", encoding="utf-8") as file_out:
        json.dump(holds_data, file_out)

    # Attempt deletion with admin headers -> Should fail 409 Conflict
    del_resp = client.delete(
        f"/api/v1/forensic-evidence/records/{evidence_id}?justification=RoutinePurge",
        headers=f["admin_headers"],
    )
    assert del_resp.status_code == 409
    assert "protected under active legal hold" in del_resp.json()["detail"]

    # Release the legal hold
    with open(holds_file, "w", encoding="utf-8") as file_out:
        json.dump({"holds": []}, file_out)

    # Delete again -> Should succeed
    del_resp_ok = client.delete(
        f"/api/v1/forensic-evidence/records/{evidence_id}?justification=AuthorizedInvestigationClosure",
        headers=f["admin_headers"],
    )
    assert del_resp_ok.status_code == 200
    del_data = del_resp_ok.json()
    assert del_data["is_deleted"] is True
    assert del_data["lifecycle_state"] == "AUTHORIZED_DELETED"
    assert del_data["deleted_by"] == f["admin_user"].email


def test_12_forensic_verification_cli_read_only_guarantee(setup_prompt48_fixtures):
    """
    Executes scripts/verify_forensic_evidence.py and verifies that database contents,
    updated_at timestamps, and custody event counts remain 100% untouched.
    """
    f = setup_prompt48_fixtures
    client: TestClient = f["client"]
    db: Session = f["db"]

    ingest_resp = client.post(
        "/api/v1/forensic-evidence/records",
        json={
            "project_id": f["project"].id,
            "evidence_type": "RAW_HTTP",
            "raw_payload": "CLI_VERIFY_SAMPLE_PAYLOAD",
            "source_identity": "cli-test",
            "adapter_version": "1.0",
            "collection_time": datetime.now(timezone.utc).isoformat(),
        },
        headers=f["analyst_headers"],
    )
    evidence_id = ingest_resp.json()["id"]

    # First verify via API so record has valid verification status
    client.post(f"/api/v1/forensic-evidence/records/{evidence_id}/verify", headers=f["analyst_headers"])

    # Snapshot timestamps and custody event count
    db.expire_all()
    rec_before = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
    updated_at_before = rec_before.updated_at
    last_verified_at_before = rec_before.last_verified_at
    custody_count_before = (
        db.query(EvidenceCustodyEvent).filter(EvidenceCustodyEvent.evidence_id == evidence_id).count()
    )

    # Run CLI in subprocess with --evidence-id and --json
    import subprocess
    cli_path = REPO_ROOT / "scripts" / "verify_forensic_evidence.py"
    py_exe = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    proc = subprocess.run(
        [str(py_exe), str(cli_path), "--evidence-id", evidence_id, "--json"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    json_start = proc.stdout.find("{")
    json_end = proc.stdout.rfind("}") + 1
    assert json_start != -1 and json_end != -1, f"No JSON in stdout: {proc.stdout}"
    out = json.loads(proc.stdout[json_start:json_end])
    assert out["all_verified"] is True
    assert out["items"][0]["evidence_id"] == evidence_id
    assert out["items"][0]["status"] == "VERIFIED"

    # Verify that database record was NOT updated and NO new custody events were added
    db.expire_all()
    rec_after = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
    assert rec_after.updated_at == updated_at_before
    assert rec_after.last_verified_at == last_verified_at_before

    custody_count_after = (
        db.query(EvidenceCustodyEvent).filter(EvidenceCustodyEvent.evidence_id == evidence_id).count()
    )
    assert custody_count_after == custody_count_before
