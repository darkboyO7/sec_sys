import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.audit import AuditEvent
from app.models.assessment import AssessmentJob, AssessmentFinding, FindingEvidence
from app.services.scanner_adapters.base import MAX_EVIDENCE_PAYLOAD_BYTES
from app.services.audit_service import compute_audit_event_hash, SENSITIVE_KEYS


class MerkleTree:
    """
    Binary Merkle Tree implementation for tamper-evident cryptographic proofs.
    Implements standard leaf hashing, duplicate-last on odd sets, and inclusion proofs.
    """

    def __init__(self, leaves: List[str]):
        # Ensure all leaves are non-empty strings
        self.leaves = [str(l) for l in leaves if l]
        self.levels: List[List[str]] = []
        self._build_tree()

    def _hash_pair(self, left: str, right: str) -> str:
        return hashlib.sha256(f"{left}{right}".encode("utf-8")).hexdigest()

    def _build_tree(self) -> None:
        if not self.leaves:
            self.root_hash = "0" * 64
            self.levels = [[]]
            return

        current_level = list(self.leaves)
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = self._hash_pair(left, right)
                next_level.append(parent)
            current_level = next_level
            self.levels.append(current_level)

        self.root_hash = current_level[0]

    def get_proof(self, leaf_hash: str) -> List[Dict[str, str]]:
        """
        Generate Merkle audit path (inclusion proof) for a specific leaf hash.
        """
        if not self.leaves or leaf_hash not in self.leaves:
            return []

        index = self.leaves.index(leaf_hash)
        proof = []

        for level_idx in range(len(self.levels) - 1):
            level = self.levels[level_idx]
            is_odd = len(level) % 2 == 1

            if index % 2 == 0:
                # Sibling is to the right
                sibling_idx = index + 1 if index + 1 < len(level) else index
                proof.append({"position": "right", "hash": level[sibling_idx]})
            else:
                # Sibling is to the left
                sibling_idx = index - 1
                proof.append({"position": "left", "hash": level[sibling_idx]})

            index //= 2

        return proof

    @classmethod
    def verify_proof(cls, leaf_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        """
        Cryptographically verify that leaf_hash belongs to a Merkle tree with expected_root.
        """
        if not proof:
            return leaf_hash == expected_root

        current = leaf_hash
        for step in proof:
            sibling = step["hash"]
            if step["position"] == "left":
                current = hashlib.sha256(f"{sibling}{current}".encode("utf-8")).hexdigest()
            else:
                current = hashlib.sha256(f"{current}{sibling}".encode("utf-8")).hexdigest()

        return current == expected_root


class IntegrityService:
    """
    Cryptographic Audit and Evidence Integrity Verification Engine (Phase 8).
    Provides tamper detection, Merkle proof generation, and ledger verification.
    """

    @classmethod
    def verify_evidence_integrity(cls, db: Session, job_id: str) -> Dict[str, Any]:
        """
        Validates all evidence items belonging to an assessment job against their
        cryptographic SHA-256 hashes and builds a Merkle verification tree.
        """
        findings = db.query(AssessmentFinding).filter(AssessmentFinding.job_id == job_id).all()
        finding_ids = [f.id for f in findings]

        evidence_items: List[FindingEvidence] = []
        if finding_ids:
            evidence_items = (
                db.query(FindingEvidence)
                .filter(FindingEvidence.finding_id.in_(finding_ids))
                .order_by(FindingEvidence.observed_at.asc(), FindingEvidence.id.asc())
                .all()
            )

        corrupted_ids: List[str] = []
        evidence_records: List[Dict[str, Any]] = []
        leaf_hashes: List[str] = []

        for ev in evidence_items:
            payload_str = ev.payload or ""
            actual_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
            is_valid = True

            # Check 1: Persisted SHA-256 integrity
            if actual_hash != ev.sha256_hash:
                is_valid = False

            # Check 2: Truncation boundary integrity
            if ev.is_truncated:
                raw_bytes = payload_str.encode("utf-8")
                if len(raw_bytes) > MAX_EVIDENCE_PAYLOAD_BYTES + 50:  # Allow margin for suffix
                    is_valid = False

            if not is_valid:
                corrupted_ids.append(ev.id)

            leaf_hashes.append(ev.sha256_hash)
            evidence_records.append({
                "id": ev.id,
                "finding_id": ev.finding_id,
                "evidence_type": ev.evidence_type,
                "sha256_hash": ev.sha256_hash,
                "raw_sha256_hash": ev.raw_sha256_hash,
                "is_truncated": ev.is_truncated,
                "is_valid": is_valid,
            })

        merkle_tree = MerkleTree(leaf_hashes)

        return {
            "job_id": job_id,
            "total_evidence_checked": len(evidence_items),
            "is_valid": len(corrupted_ids) == 0,
            "corrupted_evidence_ids": corrupted_ids,
            "merkle_root": merkle_tree.root_hash,
            "evidence_records": evidence_records,
            "summary": (
                f"Evidence integrity verified: {len(evidence_items)} records checked, "
                f"{len(corrupted_ids)} corrupted."
            ),
        }

    @classmethod
    def get_evidence_merkle_proof(
        cls,
        db: Session,
        job_id: str,
        evidence_id: str,
    ) -> Dict[str, Any]:
        """
        Generate Merkle audit proof for a single evidence item within a job.
        """
        findings = db.query(AssessmentFinding).filter(AssessmentFinding.job_id == job_id).all()
        finding_ids = [f.id for f in findings]

        evidence_items = (
            db.query(FindingEvidence)
            .filter(FindingEvidence.finding_id.in_(finding_ids))
            .order_by(FindingEvidence.observed_at.asc(), FindingEvidence.id.asc())
            .all()
        )

        target_ev = next((ev for ev in evidence_items if ev.id == evidence_id), None)
        if not target_ev:
            raise ValueError(f"Evidence '{evidence_id}' not found in assessment job '{job_id}'.")

        leaf_hashes = [ev.sha256_hash for ev in evidence_items]
        merkle_tree = MerkleTree(leaf_hashes)
        proof = merkle_tree.get_proof(target_ev.sha256_hash)

        return {
            "job_id": job_id,
            "evidence_id": evidence_id,
            "leaf_hash": target_ev.sha256_hash,
            "merkle_root": merkle_tree.root_hash,
            "proof": proof,
        }

    @classmethod
    def verify_audit_ledger_integrity(cls, db: Session, project_id: str) -> Dict[str, Any]:
        """
        Verifies cryptographic hash chain and Merkle integrity of the audit ledger
        for the specified project.
        """
        events = (
            db.query(AuditEvent)
            .filter(AuditEvent.project_id == project_id)
            .order_by(AuditEvent.timestamp.asc(), AuditEvent.id.asc())
            .all()
        )

        tampered_ids: List[str] = []
        event_hashes: List[str] = []
        prev_hash: Optional[str] = None
        previous_ts = None

        for ev in events:
            # Check 1: Monotonic timestamp
            if previous_ts and ev.timestamp < previous_ts:
                tampered_ids.append(ev.id)
            previous_ts = ev.timestamp

            # Check 2: Cryptographic hash chain (if event has hash assigned)
            if ev.event_hash:
                # Check previous link matches
                if ev.prev_event_hash != prev_hash:
                    tampered_ids.append(ev.id)

                # Recompute expected hash
                expected_hash = compute_audit_event_hash(
                    prev_hash=ev.prev_event_hash,
                    timestamp=ev.timestamp,
                    actor_id=ev.actor_id,
                    action=ev.action,
                    target_type=ev.target_type,
                    target_id=ev.target_id,
                    project_id=ev.project_id,
                    outcome=ev.outcome,
                    details=ev.details,
                )
                if expected_hash != ev.event_hash:
                    if ev.id not in tampered_ids:
                        tampered_ids.append(ev.id)

                prev_hash = ev.event_hash
                event_hashes.append(ev.event_hash)
            else:
                # Fallback for historical events before Phase 8
                synthetic_hash = hashlib.sha256(
                    f"{ev.id}:{ev.timestamp.isoformat()}:{ev.action}".encode("utf-8")
                ).hexdigest()
                event_hashes.append(synthetic_hash)

        merkle_tree = MerkleTree(event_hashes)

        return {
            "project_id": project_id,
            "total_events_checked": len(events),
            "is_valid": len(tampered_ids) == 0,
            "tampered_event_ids": tampered_ids,
            "merkle_root": merkle_tree.root_hash,
            "timestamp_range": {
                "earliest": events[0].timestamp.isoformat() if events else None,
                "latest": events[-1].timestamp.isoformat() if events else None,
            },
            "summary": (
                f"Audit ledger integrity verified: {len(events)} events checked, "
                f"{len(tampered_ids)} tampered records detected."
            ),
        }
