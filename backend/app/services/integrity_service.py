import json
import hashlib
import hmac
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
from sqlalchemy.orm import Session

from app.models.audit import AuditEvent
from app.models.assessment import AssessmentJob, AssessmentFinding, FindingEvidence
from app.services.scanner_adapters.base import MAX_EVIDENCE_PAYLOAD_BYTES
from app.services.audit_service import compute_audit_event_hash, SENSITIVE_KEYS


class ExternalTrustAnchor(ABC):
    """
    Abstract interface for out-of-band external trust anchoring (e.g. RFC 3161 Time-Stamp Protocol,
    cloud WORM storage commit, or public bulletin ledger).
    Enables cryptographic binding of internal Merkle roots to an external trust boundary.
    """
    @abstractmethod
    def anchor_merkle_root(self, root_hash: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Submits a Merkle root to the external trust anchor.
        Returns anchor token or confirmation payload with signature/timestamp.
        """
        pass

    @abstractmethod
    def verify_anchor(self, root_hash: str, anchor_payload: Dict[str, Any]) -> bool:
        """
        Verifies that an external anchor payload attests to root_hash.
        """
        pass


class HMACExternalTrustAnchor(ExternalTrustAnchor):
    """
    Default hardened cryptographic anchor using an isolated system HMAC secret key.
    Provides verifiable cryptographic binding without requiring an external network roundtrip.
    """
    def __init__(self, anchor_secret: str, anchor_identifier: str = "vapt-internal-vault-v1"):
        self.secret = anchor_secret.encode("utf-8") if isinstance(anchor_secret, str) else anchor_secret
        self.anchor_identifier = anchor_identifier

    def anchor_merkle_root(self, root_hash: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        timestamp = datetime.now(timezone.utc).isoformat()
        message = f"{self.anchor_identifier}:{root_hash}:{timestamp}".encode("utf-8")
        signature = hmac.new(self.secret, message, hashlib.sha256).hexdigest()
        return {
            "anchor_type": "HMAC_SECRET",
            "anchor_identifier": self.anchor_identifier,
            "root_hash": root_hash,
            "timestamp": timestamp,
            "anchor_token": signature,
            "context": context or {},
        }

    def verify_anchor(self, root_hash: str, anchor_payload: Dict[str, Any]) -> bool:
        if not anchor_payload or anchor_payload.get("root_hash") != root_hash:
            return False
        timestamp = anchor_payload.get("timestamp")
        token = anchor_payload.get("anchor_token")
        identifier = anchor_payload.get("anchor_identifier", self.anchor_identifier)
        if not timestamp or not token:
            return False
        message = f"{identifier}:{root_hash}:{timestamp}".encode("utf-8")
        expected_sig = hmac.new(self.secret, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, token)


class AppendOnlyArchiveTrustAnchor(ExternalTrustAnchor):
    """
    Independent append-only archive trust anchor that persists cryptographic
    receipts to an external append-only log file outside the database.
    Supports strictly monotonic sequence numbers, cryptographic chaining between
    receipts, key rotation via key identifiers, and whole-database rollback detection.
    """

    def __init__(
        self,
        archive_path: Union[Path, str],
        anchor_identifier: str = "vapt-independent-archive-v1",
        keys: Optional[Dict[str, str]] = None,
        active_key_id: str = "key-2026-v1",
    ):
        self.archive_path = Path(archive_path)
        self.anchor_identifier = anchor_identifier
        self.keys = keys or {active_key_id: "default-independent-anchor-secret-32-chars!!"}
        self.active_key_id = active_key_id
        if self.active_key_id not in self.keys:
            raise ValueError(f"Active key ID '{self.active_key_id}' not found in provided keys dictionary.")
        self.archive_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_latest_entry(self) -> Optional[Dict[str, Any]]:
        if not self.archive_path.exists() or self.archive_path.stat().st_size == 0:
            return None
        last_line = ""
        with open(self.archive_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if not last_line:
            return None
        try:
            return json.loads(last_line)
        except json.JSONDecodeError:
            return None

    def anchor_merkle_root(self, root_hash: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        latest = self._get_latest_entry()
        prev_entry_hash = latest["entry_hash"] if latest else "0" * 64
        sequence = (latest["sequence_number"] + 1) if latest else 1

        # Idempotency check: if last anchored root matches current root, return existing receipt
        if latest and latest.get("root_hash") == root_hash:
            return latest

        timestamp = datetime.now(timezone.utc).isoformat()
        raw_message = f"{self.anchor_identifier}:{sequence}:{prev_entry_hash}:{root_hash}:{timestamp}"
        entry_hash = hashlib.sha256(raw_message.encode("utf-8")).hexdigest()

        secret = self.keys[self.active_key_id].encode("utf-8")
        signature = hmac.new(secret, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

        entry = {
            "anchor_type": "APPEND_ONLY_ARCHIVE",
            "anchor_identifier": self.anchor_identifier,
            "sequence_number": sequence,
            "prev_entry_hash": prev_entry_hash,
            "root_hash": root_hash,
            "timestamp": timestamp,
            "key_id": self.active_key_id,
            "entry_hash": entry_hash,
            "anchor_token": signature,
            "context": context or {},
        }

        # Atomic append to file
        with open(self.archive_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

        return entry

    def verify_anchor(self, root_hash: str, anchor_payload: Dict[str, Any]) -> bool:
        if not anchor_payload or anchor_payload.get("root_hash") != root_hash:
            return False

        key_id = anchor_payload.get("key_id", self.active_key_id)
        if key_id not in self.keys:
            return False

        sequence = anchor_payload.get("sequence_number")
        prev_entry_hash = anchor_payload.get("prev_entry_hash")
        timestamp = anchor_payload.get("timestamp")
        identifier = anchor_payload.get("anchor_identifier", self.anchor_identifier)
        token = anchor_payload.get("anchor_token")
        entry_hash = anchor_payload.get("entry_hash")

        if not all([sequence, prev_entry_hash, timestamp, token, entry_hash]):
            return False

        # Verify entry hash computation
        raw_message = f"{identifier}:{sequence}:{prev_entry_hash}:{root_hash}:{timestamp}"
        expected_entry_hash = hashlib.sha256(raw_message.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(expected_entry_hash, entry_hash):
            return False

        # Verify signature with corresponding key (supporting historical keys)
        secret = self.keys[key_id].encode("utf-8")
        expected_sig = hmac.new(secret, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, token):
            return False

        return True

    def check_for_database_rollback(self, db_last_anchored_sequence: int) -> Dict[str, Any]:
        """
        Detects if database has been rolled back relative to external trust archive.
        If the external archive has advanced past the database's reported sequence,
        a rollback or snapshot replay has occurred.
        """
        latest = self._get_latest_entry()
        if not latest:
            return {"rollback_detected": False, "archive_sequence": 0, "db_sequence": db_last_anchored_sequence}
        archive_seq = latest["sequence_number"]
        is_rollback = db_last_anchored_sequence < archive_seq
        return {
            "rollback_detected": is_rollback,
            "archive_sequence": archive_seq,
            "db_sequence": db_last_anchored_sequence,
            "difference": archive_seq - db_last_anchored_sequence if is_rollback else 0,
            "reason": "Database sequence lags external append-only archive" if is_rollback else "Sequence aligned",
        }


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

        if not events:
            chain_status = "EMPTY"
        elif len(tampered_ids) > 0:
            chain_status = "TAMPERED"
        elif any(ev.event_hash is None for ev in events):
            chain_status = "LEGACY_UNVERIFIED"
        else:
            chain_status = "VALID"

        return {
            "project_id": project_id,
            "total_events_checked": len(events),
            "is_valid": len(tampered_ids) == 0,
            "chain_status": chain_status,
            "tampered_event_ids": tampered_ids,
            "merkle_root": merkle_tree.root_hash,
            "timestamp_range": {
                "earliest": events[0].timestamp.isoformat() if events else None,
                "latest": events[-1].timestamp.isoformat() if events else None,
            },
            "summary": (
                f"Audit ledger integrity verified ({chain_status}): {len(events)} events checked, "
                f"{len(tampered_ids)} tampered records detected."
            ),
        }

    @classmethod
    def anchor_audit_ledger(
        cls,
        db: Session,
        project_id: str,
        anchor: Optional[ExternalTrustAnchor] = None,
    ) -> Dict[str, Any]:
        """
        Verifies the project audit ledger and anchors its Merkle root to an external trust boundary.
        If no anchor is provided, uses HMACExternalTrustAnchor with the application SECRET_KEY.
        """
        from app.core.config import settings

        verification = cls.verify_audit_ledger_integrity(db, project_id)
        if not verification["is_valid"]:
            raise ValueError(f"Cannot anchor corrupted audit ledger for project '{project_id}': tampered events detected.")

        merkle_root = verification["merkle_root"]
        active_anchor = anchor or HMACExternalTrustAnchor(anchor_secret=settings.SECRET_KEY)
        anchor_receipt = active_anchor.anchor_merkle_root(
            root_hash=merkle_root,
            context={"project_id": project_id, "total_events": verification["total_events_checked"]},
        )
        return {
            "project_id": project_id,
            "merkle_root": merkle_root,
            "anchor_receipt": anchor_receipt,
            "ledger_verified": True,
        }

    @classmethod
    def verify_external_anchor(
        cls,
        root_hash: str,
        anchor_payload: Dict[str, Any],
        anchor: Optional[ExternalTrustAnchor] = None,
    ) -> bool:
        """
        Verifies an external anchor payload against a target Merkle root.
        """
        from app.core.config import settings

        active_anchor = anchor or HMACExternalTrustAnchor(anchor_secret=settings.SECRET_KEY)
        return active_anchor.verify_anchor(root_hash, anchor_payload)

    @classmethod
    def verify_platform_entity_integrity(cls, db: Session, project_id: str) -> Dict[str, Any]:
        """
        Comprehensive cross-table integrity verification for assessment records,
        vulnerability findings, evidence items, assets, remediation actions,
        and verification results within a project boundary.
        """
        from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
        from app.models.asset import Asset, AssetObservation
        from app.models.risk import RemediationRecommendation, RecommendationStatus
        from app.models.verification import RemediationVerification, VerificationOutcome
        from app.services.scanner_adapters.base import PERMITTED_EVIDENCE_TYPES

        # 1. Assessment Records
        jobs = db.query(AssessmentJob).filter(AssessmentJob.project_id == project_id).all()
        corrupted_jobs = []
        for job in jobs:
            if job.timeout_seconds <= 0 or job.attempt_count < 1:
                corrupted_jobs.append(job.id)
                continue
            if job.scope_snapshot and job.scope_snapshot_digest:
                canonical = json.dumps(job.scope_snapshot, sort_keys=True, separators=(",", ":"))
                digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                if digest != job.scope_snapshot_digest:
                    corrupted_jobs.append(job.id)

        # 2. Vulnerability Findings
        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()
        corrupted_findings = []
        for f in findings:
            if not f.fingerprint or len(f.fingerprint) != 64:
                corrupted_findings.append(f.id)
                continue
            if not f.title or not f.severity:
                corrupted_findings.append(f.id)

        # 3. Evidence Items (linked to project's findings)
        job_ids = [j.id for j in jobs]
        corrupted_evidence = []
        evidence_count = 0
        if job_ids:
            assessment_findings = db.query(AssessmentFinding).filter(AssessmentFinding.job_id.in_(job_ids)).all()
            af_ids = [af.id for af in assessment_findings]
            if af_ids:
                evidence_items = db.query(FindingEvidence).filter(FindingEvidence.finding_id.in_(af_ids)).all()
                evidence_count = len(evidence_items)
                for ev in evidence_items:
                    payload = ev.payload or ""
                    expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                    if expected_hash != ev.sha256_hash:
                        corrupted_evidence.append(ev.id)
                        continue
                    if ev.evidence_type and ev.evidence_type.upper() not in PERMITTED_EVIDENCE_TYPES:
                        corrupted_evidence.append(ev.id)

        # 4. Assets & Observations
        assets = db.query(Asset).filter(Asset.project_id == project_id).all()
        corrupted_assets = []
        for a in assets:
            if not a.canonical_identifier:
                corrupted_assets.append(a.id)
                continue
            for obs in (a.observations or []):
                if obs.confidence < 0.0 or obs.confidence > 1.0:
                    corrupted_assets.append(a.id)
                    break

        # 5. Remediation Recommendations
        remeds = db.query(RemediationRecommendation).filter(RemediationRecommendation.project_id == project_id).all()
        corrupted_remeds = []
        for r in remeds:
            if not r.title or not r.status:
                corrupted_remeds.append(r.id)

        # 6. Verification Records
        verifications = db.query(RemediationVerification).filter(RemediationVerification.project_id == project_id).all()
        corrupted_verifs = []
        for v in verifications:
            if not v.outcome or not v.verifier_id or not v.finding_id:
                corrupted_verifs.append(v.id)

        all_valid = (
            len(corrupted_jobs) == 0
            and len(corrupted_findings) == 0
            and len(corrupted_evidence) == 0
            and len(corrupted_assets) == 0
            and len(corrupted_remeds) == 0
            and len(corrupted_verifs) == 0
        )

        return {
            "project_id": project_id,
            "is_valid": all_valid,
            "assessment_records": {
                "checked": len(jobs),
                "valid": len(jobs) - len(corrupted_jobs),
                "corrupted_ids": corrupted_jobs,
            },
            "findings": {
                "checked": len(findings),
                "valid": len(findings) - len(corrupted_findings),
                "corrupted_ids": corrupted_findings,
            },
            "evidence_items": {
                "checked": evidence_count,
                "valid": evidence_count - len(corrupted_evidence),
                "corrupted_ids": corrupted_evidence,
            },
            "assets": {
                "checked": len(assets),
                "valid": len(assets) - len(corrupted_assets),
                "corrupted_ids": corrupted_assets,
            },
            "remediations": {
                "checked": len(remeds),
                "valid": len(remeds) - len(corrupted_remeds),
                "corrupted_ids": corrupted_remeds,
            },
            "verifications": {
                "checked": len(verifications),
                "valid": len(verifications) - len(corrupted_verifs),
                "corrupted_ids": corrupted_verifs,
            },
            "summary": (
                f"Platform entity integrity {'verified completely' if all_valid else 'detected discrepancies'}: "
                f"{len(jobs)} jobs, {len(findings)} findings, {evidence_count} evidence items, {len(assets)} assets checked."
            ),
        }
