"""
VAPT Platform — Multi-Process Audit Chain Integrity & Tamper Detection Tests (Phase 5).
Validates:
1. Sequential audit events establish monotonic sequence numbers and cryptographic hash links.
2. verify_chain_integrity verifies intact chain links and recomputes hashes.
3. Tampered payload details or broken chain links are detected and flagged.
4. Strict audit mode blocks operations fail-closed when audit persistence fails.
"""
import pytest
from sqlalchemy.orm import Session
from app.models.project import Project
from app.models.audit import AuditEvent
from app.services.audit_service import AuditService, compute_audit_event_hash
from app.core.config import settings


def test_audit_event_monotonic_sequence_and_hash_linking(db: Session, test_project: Project):
    """Ensure audit events receive monotonic sequence numbers and chain prev_event_hash."""
    e1 = AuditService.record_event(
        db=db,
        action="TEST_ACTION_ONE",
        target_type="system",
        outcome="SUCCESS",
        project_id=test_project.id,
        details={"step": 1},
    )
    assert e1 is not None
    assert e1.sequence_number is not None
    seq1 = e1.sequence_number
    hash1 = e1.event_hash

    e2 = AuditService.record_event(
        db=db,
        action="TEST_ACTION_TWO",
        target_type="system",
        outcome="SUCCESS",
        project_id=test_project.id,
        details={"step": 2},
    )
    assert e2 is not None
    assert e2.sequence_number == seq1 + 1
    assert e2.prev_event_hash == hash1

    e3 = AuditService.record_event(
        db=db,
        action="TEST_ACTION_THREE",
        target_type="system",
        outcome="SUCCESS",
        project_id=test_project.id,
        details={"step": 3},
    )
    assert e3 is not None
    assert e3.sequence_number == seq1 + 2
    assert e3.prev_event_hash == e2.event_hash

    # Verify chain integrity check
    res = AuditService.verify_chain_integrity(db, project_id=test_project.id)
    assert res["valid"] is True
    assert res["total_events"] >= 3
    assert res["broken_links"] == 0


def test_audit_chain_tampering_detected(db: Session, test_project: Project):
    """Ensure any modification to an event payload or hash is detected by verify_chain_integrity."""
    e = AuditService.record_event(
        db=db,
        action="TAMPER_TEST_ACTION",
        target_type="evidence",
        outcome="SUCCESS",
        project_id=test_project.id,
        details={"original": "data"},
    )
    assert e is not None

    # Tamper with the details directly in the DB
    e.details = {"tampered": "hacked_data"}
    db.commit()

    # Chain verification MUST fail
    res = AuditService.verify_chain_integrity(db, project_id=test_project.id)
    assert res["valid"] is False
    assert res["broken_links"] > 0
    assert len(res["discrepancies"]) > 0
    assert "integrity failed" in res["discrepancies"][0].lower()


def test_strict_audit_mode_blocks_operations_on_failure(db: Session, monkeypatch):
    """Ensure strict audit mode raises RuntimeError if persistence fails."""
    monkeypatch.setattr(settings, "AUDIT_LOG_STRICT", True)

    def fail_add(*args, **kwargs):
        raise Exception("Database disk full or write failure simulated")

    monkeypatch.setattr(db, "add", fail_add)

    with pytest.raises(RuntimeError) as exc_info:
        AuditService.record_event(
            db=db,
            action="CRITICAL_OPERATION",
            target_type="target",
            outcome="SUCCESS",
            details={"attempt": 1},
        )

    assert "strict security policy" in str(exc_info.value)
