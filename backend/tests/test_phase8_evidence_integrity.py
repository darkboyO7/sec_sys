import hashlib
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.project import Project
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.audit import AuditEvent
from app.models.assessment import AssessmentJob, AssessmentFinding, FindingEvidence
from app.services.integrity_service import (
    MerkleTree,
    IntegrityService,
    ExternalTrustAnchor,
    HMACExternalTrustAnchor,
)
from app.services.audit_service import AuditService, compute_audit_event_hash


# ==============================================================================
# 1. Merkle Tree Construction & Cryptographic Inclusion Proofs
# ==============================================================================

def test_merkle_tree_construction_and_verification():
    """
    Verifies that MerkleTree correctly builds trees of varying sizes (odd and even),
    computes deterministic roots, and produces verifiable inclusion proofs.
    """
    # 1. Empty tree
    empty_tree = MerkleTree([])
    assert empty_tree.root_hash == "0" * 64

    # 2. Single leaf
    leaf_0 = hashlib.sha256(b"leaf_zero").hexdigest()
    single_tree = MerkleTree([leaf_0])
    assert single_tree.root_hash == leaf_0

    # 3. Even and Odd leaves
    leaves = [
        hashlib.sha256(f"evidence_leaf_{i}".encode("utf-8")).hexdigest()
        for i in range(5)  # 5 leaves: tests duplicate-last on odd levels
    ]
    tree = MerkleTree(leaves)
    assert len(tree.root_hash) == 64

    # 4. Verify inclusion proofs for each leaf
    for leaf in leaves:
        proof = tree.get_proof(leaf)
        assert len(proof) > 0
        is_valid = MerkleTree.verify_proof(leaf, proof, tree.root_hash)
        assert is_valid is True, f"Inclusion proof verification failed for {leaf}"

    # 5. Proof fails if root is altered
    tampered_root = hashlib.sha256(b"tampered_root").hexdigest()
    proof_0 = tree.get_proof(leaves[0])
    assert MerkleTree.verify_proof(leaves[0], proof_0, tampered_root) is False

    # 6. Proof fails if leaf hash is altered
    fake_leaf = hashlib.sha256(b"fake_leaf").hexdigest()
    assert MerkleTree.verify_proof(fake_leaf, proof_0, tree.root_hash) is False


# ==============================================================================
# 2. Audit Event Hash Chaining & Tamper Detection
# ==============================================================================

def test_audit_event_hash_chaining_and_tamper_detection(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """
    Verifies that AuditService chains events with cryptographic SHA-256 links
    and that IntegrityService detects unauthorized database tampering.
    """
    # 1. Record a sequence of audit events for the project
    event1 = AuditService.record_event(
        db=db,
        action="SCOPE_TARGET_CREATE",
        target_type="SCOPE_TARGET",
        target_id="target-01",
        project_id=test_project.id,
        actor_id=tester_user.id,
        outcome="SUCCESS",
        details={"target": "api.internal-defense.corp"},
    )
    assert event1.prev_event_hash is None or len(event1.prev_event_hash) == 64
    assert event1.event_hash is not None and len(event1.event_hash) == 64

    event2 = AuditService.record_event(
        db=db,
        action="SCOPE_TARGET_AUTHORIZE",
        target_type="SCOPE_TARGET",
        target_id="target-01",
        project_id=test_project.id,
        actor_id=tester_user.id,
        outcome="SUCCESS",
        details={"evidence": "Signed change order"},
    )
    assert event2.prev_event_hash == event1.event_hash
    assert len(event2.event_hash) == 64

    event3 = AuditService.record_event(
        db=db,
        action="ASSESSMENT_JOB_DISPATCH",
        target_type="ASSESSMENT_JOB",
        target_id="job-01",
        project_id=test_project.id,
        actor_id=tester_user.id,
        outcome="SUCCESS",
        details={"adapter": "passive_header_adapter"},
    )
    assert event3.prev_event_hash == event2.event_hash

    # 2. Verify audit ledger is intact initially
    report = IntegrityService.verify_audit_ledger_integrity(db=db, project_id=test_project.id)
    assert report["is_valid"] is True
    assert len(report["tampered_event_ids"]) == 0
    assert report["total_events_checked"] >= 3
    assert len(report["merkle_root"]) == 64

    # 3. Simulate unauthorized database tampering (modify event2 action directly)
    event2.action = "TAMPERED_ACTION_UNAUTHORIZED"
    db.commit()

    # 4. Re-verify: tampering MUST be detected
    tamper_report = IntegrityService.verify_audit_ledger_integrity(db=db, project_id=test_project.id)
    assert tamper_report["is_valid"] is False
    assert event2.id in tamper_report["tampered_event_ids"]


# ==============================================================================
# 3. Evidence Integrity Verification & Tamper Detection
# ==============================================================================

def test_evidence_integrity_verification_and_tamper_detection(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
):
    """
    Verifies that IntegrityService validates evidence records against their
    persisted SHA-256 hashes and detects payload tampering.
    """
    # 1. Authorize scope target
    st = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="integrity.internal-defense.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="Integrity test authorization",
        created_by_id=tester_user.id,
    )
    db.add(st)
    db.commit()

    # 2. Execute assessment to generate real findings and evidence
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=true",
        headers=tester_headers,
        json={
            "target_input": "integrity.internal-defense.corp",
            "adapter_name": "passive_header_adapter",
            "fixture_profile": "OWASP_SECURE_HEADERS",
        },
    )
    assert res.status_code == 201
    job = res.json()
    job_id = job["id"]

    # 3. Verify evidence integrity
    verify_report = IntegrityService.verify_evidence_integrity(db=db, job_id=job_id)
    assert verify_report["is_valid"] is True
    assert verify_report["total_evidence_checked"] >= 2
    assert len(verify_report["corrupted_evidence_ids"]) == 0
    assert len(verify_report["merkle_root"]) == 64

    # 4. Tamper with an evidence payload directly in the database
    findings = db.query(AssessmentFinding).filter(AssessmentFinding.job_id == job_id).all()
    evidence_to_tamper = (
        db.query(FindingEvidence)
        .filter(FindingEvidence.finding_id == findings[0].id)
        .first()
    )
    assert evidence_to_tamper is not None
    original_payload = evidence_to_tamper.payload

    evidence_to_tamper.payload = original_payload + "\nTAMPERED_MALICIOUS_INJECTION"
    db.commit()

    # 5. Re-verify evidence: must flag corrupted evidence
    tamper_report = IntegrityService.verify_evidence_integrity(db=db, job_id=job_id)
    assert tamper_report["is_valid"] is False
    assert evidence_to_tamper.id in tamper_report["corrupted_evidence_ids"]


# ==============================================================================
# 4. API Endpoints: Audit Verification & Merkle Proofs
# ==============================================================================

def test_api_audit_and_evidence_integrity_endpoints(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
):
    """
    Verifies GET endpoints for audit verification, evidence verification,
    and individual evidence Merkle inclusion proofs.
    """
    # 1. Authorize scope target
    st = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="api-proof.internal-defense.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="API proof authorization",
        created_by_id=tester_user.id,
    )
    db.add(st)
    db.commit()

    # 2. Run assessment job
    res_job = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=true",
        headers=tester_headers,
        json={
            "target_input": "api-proof.internal-defense.corp",
            "adapter_name": "ssl_cipher_adapter",
            "fixture_profile": "LEGACY_DEPRECATION_AUDIT",
        },
    )
    assert res_job.status_code == 201
    job_data = res_job.json()
    job_id = job_data["id"]

    # 3. Test GET /projects/{project_id}/audit/verify
    res_audit_ver = client.get(
        f"/api/v1/projects/{test_project.id}/audit/verify",
        headers=tester_headers,
    )
    assert res_audit_ver.status_code == 200
    audit_data = res_audit_ver.json()
    assert audit_data["project_id"] == test_project.id
    assert audit_data["is_valid"] is True
    assert "merkle_root" in audit_data

    # 4. Test GET /projects/{project_id}/assessments/{job_id}/evidence/verify
    res_ev_ver = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/{job_id}/evidence/verify",
        headers=tester_headers,
    )
    assert res_ev_ver.status_code == 200
    ev_data = res_ev_ver.json()
    assert ev_data["job_id"] == job_id
    assert ev_data["is_valid"] is True
    assert ev_data["total_evidence_checked"] >= 2
    assert len(ev_data["evidence_records"]) >= 2

    # 5. Test GET Merkle inclusion proof for specific evidence record
    first_ev_id = ev_data["evidence_records"][0]["id"]
    res_proof = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/{job_id}/evidence/{first_ev_id}/proof",
        headers=tester_headers,
    )
    assert res_proof.status_code == 200
    proof_data = res_proof.json()
    assert proof_data["evidence_id"] == first_ev_id
    assert proof_data["leaf_hash"] == ev_data["evidence_records"][0]["sha256_hash"]
    assert proof_data["merkle_root"] == ev_data["merkle_root"]
    assert len(proof_data["proof"]) > 0

    # Cryptographically verify the returned proof locally
    is_proof_valid = MerkleTree.verify_proof(
        leaf_hash=proof_data["leaf_hash"],
        proof=proof_data["proof"],
        expected_root=proof_data["merkle_root"],
    )
    assert is_proof_valid is True


# ==============================================================================
# 5. Cross-Project Isolation on Integrity Endpoints
# ==============================================================================

def test_cross_project_integrity_access_rejected(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    outsider_headers: dict,
):
    """
    Verifies that users without project membership cannot verify audit records
    or access evidence proofs from another project.
    """
    # Outsider denied audit verification
    res_audit = client.get(
        f"/api/v1/projects/{test_project.id}/audit/verify",
        headers=outsider_headers,
    )
    assert res_audit.status_code in (403, 404)

    # Outsider denied evidence verification
    res_ev = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/fake-job-id/evidence/verify",
        headers=outsider_headers,
    )
    assert res_ev.status_code in (403, 404)


# ==============================================================================
# 6. Edge Cases: Empty Sets & Missing Identifiers
# ==============================================================================

def test_integrity_edge_cases_and_non_existent_resources(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_headers: dict,
):
    """
    Verifies that verification queries on non-existent jobs or empty audit sets
    fail closed gracefully with appropriate HTTP error codes.
    """
    # 1. Non-existent job evidence verify returns 404
    res = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/non-existent-job-uuid/evidence/verify",
        headers=tester_headers,
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()

    # 2. Non-existent evidence proof returns 404
    res = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/non-existent-job-uuid/evidence/fake-ev-id/proof",
        headers=tester_headers,
    )
    assert res.status_code == 404

    # 3. Merkle verification on 0 audit events
    empty_report = IntegrityService.verify_audit_ledger_integrity(db=db, project_id="empty-project-id")
    assert empty_report["is_valid"] is True
    assert empty_report["total_events_checked"] == 0
    assert empty_report["merkle_root"] == "0" * 64


def test_external_trust_anchor_and_ledger_anchoring(db: Session, test_project: Project, tester_user: User):
    """
    Verifies that audit ledgers can be anchored to an external trust anchor (e.g. HMACExternalTrustAnchor),
    producing a verifiable receipt that fails closed if tampered.
    """
    # 1. Record an event
    AuditService.record_event(
        db=db,
        action="ANCHOR_TEST_EVENT",
        target_type="Project",
        outcome="SUCCESS",
        project_id=test_project.id,
        actor_id=tester_user.id,
    )
    db.commit()

    # 2. Anchor ledger using HMACExternalTrustAnchor
    anchor = HMACExternalTrustAnchor(anchor_secret="test-isolated-anchor-secret-32-chars!!")
    receipt = IntegrityService.anchor_audit_ledger(db=db, project_id=test_project.id, anchor=anchor)

    assert receipt["ledger_verified"] is True
    assert len(receipt["merkle_root"]) == 64
    anchor_receipt = receipt["anchor_receipt"]
    assert anchor_receipt["anchor_type"] == "HMAC_SECRET"
    assert anchor_receipt["root_hash"] == receipt["merkle_root"]
    assert "anchor_token" in anchor_receipt

    # 3. Verify valid anchor payload
    is_valid = IntegrityService.verify_external_anchor(
        root_hash=receipt["merkle_root"],
        anchor_payload=anchor_receipt,
        anchor=anchor,
    )
    assert is_valid is True

    # 4. Tampered anchor token or root hash fails verification
    assert IntegrityService.verify_external_anchor(
        root_hash="f" * 64,
        anchor_payload=anchor_receipt,
        anchor=anchor,
    ) is False

    tampered_payload = dict(anchor_receipt)
    tampered_payload["anchor_token"] = "0" * 64
    assert IntegrityService.verify_external_anchor(
        root_hash=receipt["merkle_root"],
        anchor_payload=tampered_payload,
        anchor=anchor,
    ) is False
