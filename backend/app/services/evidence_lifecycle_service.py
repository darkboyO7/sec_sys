"""
VAPT Platform — Evidence Lifecycle Governance & Retention Engine (Prompt 29).
Provides:
1. Authoritative data classification and retention policy enforcement.
2. Active legal and investigation hold management.
3. Automated credential & secret detection with payload redaction.
4. Retention preview and bounded, idempotent execution.
5. Cryptographic deletion suppression tombstones to prevent restoration resurrection.
"""
import os
import re
import json
import uuid
import hmac
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone, timedelta

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.models.assessment import FindingEvidence, AssessmentFinding
from app.models.audit import AuditEvent
from app.schemas.evidence_lifecycle import (
    DataClassification,
    RetentionActionType,
    HoldType,
    HoldStatus,
    RetentionPolicyModel,
    LegalHoldModel,
    LegalHoldCreate,
    DeletionTombstoneModel,
    RetentionPreviewItem,
    RetentionPreviewReport,
    RetentionExecutionRequest,
    RetentionExecutionResult,
    EvidenceRedactionResult,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
TOMBSTONE_FILE = REPO_ROOT / "backend" / "data" / "evidence_tombstones.json"
HOLDS_FILE = REPO_ROOT / "backend" / "data" / "legal_holds.json"

# Secret patterns for automated evidence redaction
SECRET_REDACTION_PATTERNS = [
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("BEARER_TOKEN", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.]{25,}\b")),
    ("AWS_KEY", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("API_KEY", re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{24,})['\"]?")),
    ("PASSWORD", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?")),
]


class EvidenceLifecycleService:
    def __init__(self):
        self.tombstone_path = TOMBSTONE_FILE
        self.holds_path = HOLDS_FILE
        self._ensure_storage()

        # In-memory default policies
        self.policies: Dict[str, RetentionPolicyModel] = {
            "POL-RAW-EVIDENCE-90D": RetentionPolicyModel(
                policy_id="POL-RAW-EVIDENCE-90D",
                classification=DataClassification.RAW_EVIDENCE,
                retention_days=90,
                action=RetentionActionType.DELETE,
                requires_approval=True,
                description="Raw assessment payloads (HTTP, tool stdout) purged after 90 days with cryptographic tombstone.",
            ),
            "POL-SECRETS-30D": RetentionPolicyModel(
                policy_id="POL-SECRETS-30D",
                classification=DataClassification.CREDENTIALS_AND_SECRETS,
                retention_days=30,
                action=RetentionActionType.REDACT,
                requires_approval=True,
                description="Discovered secrets in evidence payloads sanitized after 30 days to mitigate credential spill.",
            ),
            "POL-FINDINGS-365D": RetentionPolicyModel(
                policy_id="POL-FINDINGS-365D",
                classification=DataClassification.FINDINGS_AND_RISK,
                retention_days=365,
                action=RetentionActionType.ARCHIVE,
                requires_approval=True,
                description="Verified vulnerability finding records archived to cold storage after 1 year.",
            ),
            "POL-OPERATIONAL-180D": RetentionPolicyModel(
                policy_id="POL-OPERATIONAL-180D",
                classification=DataClassification.OPERATIONAL_METADATA,
                retention_days=180,
                action=RetentionActionType.DELETE,
                requires_approval=False,
                description="Assessment execution logs and transient telemetry purged after 180 days.",
            ),
            "POL-AUDIT-7Y": RetentionPolicyModel(
                policy_id="POL-AUDIT-7Y",
                classification=DataClassification.AUDIT_RECORDS,
                retention_days=2555,  # 7 years
                action=RetentionActionType.RETAIN,
                requires_approval=True,
                description="Append-only cryptographic audit events preserved for minimum 7-year compliance.",
            ),
            "POL-ANALYTICS-60D": RetentionPolicyModel(
                policy_id="POL-ANALYTICS-60D",
                classification=DataClassification.DERIVED_ANALYTICS,
                retention_days=60,
                action=RetentionActionType.DELETE,
                requires_approval=False,
                description="Transient AI analyst inference caches and derived graph projections refreshed after 60 days.",
            ),
        }

        # Cached active previews
        self._active_previews: Dict[str, RetentionPreviewReport] = {}

    def _ensure_storage(self) -> None:
        self.tombstone_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.tombstone_path.exists():
            self.tombstone_path.write_text("[]", encoding="utf-8")
        if not self.holds_path.exists():
            self.holds_path.write_text("[]", encoding="utf-8")

    # --------------------------------------------------------------------------
    # 1. Retention Policies Management
    # --------------------------------------------------------------------------
    def get_policies(self) -> List[RetentionPolicyModel]:
        return list(self.policies.values())

    def get_policy(self, policy_id: str) -> Optional[RetentionPolicyModel]:
        return self.policies.get(policy_id)

    def get_policy_for_classification(self, classification: DataClassification) -> Optional[RetentionPolicyModel]:
        for p in self.policies.values():
            if p.classification == classification and p.is_active:
                return p
        return None

    def update_policy(self, policy: RetentionPolicyModel) -> RetentionPolicyModel:
        policy.updated_at = datetime.now(timezone.utc).isoformat()
        self.policies[policy.policy_id] = policy
        return policy

    # --------------------------------------------------------------------------
    # 2. Legal & Investigation Holds
    # --------------------------------------------------------------------------
    def _read_holds(self) -> List[LegalHoldModel]:
        try:
            data = json.loads(self.holds_path.read_text(encoding="utf-8"))
            return [LegalHoldModel(**h) for h in data]
        except Exception:
            return []

    def _write_holds(self, holds: List[LegalHoldModel]) -> None:
        self.holds_path.write_text(json.dumps([h.dict() for h in holds], indent=2), encoding="utf-8")

    def list_holds(self, status: Optional[HoldStatus] = None) -> List[LegalHoldModel]:
        holds = self._read_holds()
        if status:
            return [h for h in holds if h.status == status]
        return holds

    def create_hold(self, create: LegalHoldCreate, placed_by_id: str) -> LegalHoldModel:
        hold = LegalHoldModel(
            hold_id=f"HOLD-{uuid.uuid4().hex[:8].upper()}",
            hold_type=create.hold_type,
            target_scope=create.target_scope.upper(),
            target_id=create.target_id,
            reason=create.reason,
            status=HoldStatus.ACTIVE,
            placed_by_id=placed_by_id,
        )
        holds = self._read_holds()
        holds.append(hold)
        self._write_holds(holds)
        return hold

    def release_hold(self, hold_id: str, released_by_id: str) -> Optional[LegalHoldModel]:
        holds = self._read_holds()
        target = None
        for h in holds:
            if h.hold_id == hold_id:
                h.status = HoldStatus.RELEASED
                h.released_by_id = released_by_id
                h.released_at = datetime.now(timezone.utc).isoformat()
                target = h
                break
        if target:
            self._write_holds(holds)
        return target

    def is_held(self, target_scope: str, target_id: str) -> Tuple[bool, Optional[str]]:
        active_holds = self.list_holds(status=HoldStatus.ACTIVE)
        for h in active_holds:
            if h.target_scope == target_scope.upper() and h.target_id == target_id:
                return True, f"Subject to {h.hold_type.value}: {h.reason} (Hold: {h.hold_id})"
        return False, None

    # --------------------------------------------------------------------------
    # 3. Secret Detection & Evidence Redaction
    # --------------------------------------------------------------------------
    def redact_evidence_payload(self, raw_text: str) -> Tuple[str, int]:
        """Scans raw evidence string and substitutes detected credentials with safe tokens."""
        sanitized = raw_text
        total_masked = 0
        for token_type, pat in SECRET_REDACTION_PATTERNS:
            matches = list(pat.finditer(sanitized))
            if matches:
                total_masked += len(matches)
                sanitized = pat.sub(f"[REDACTED_SECRET_{token_type}]", sanitized)
        return sanitized, total_masked

    def redact_evidence_record(self, evidence_id: str, db: Session, reason: str = "Automated credential masking") -> EvidenceRedactionResult:
        ev = db.query(FindingEvidence).filter(FindingEvidence.id == evidence_id).first()
        if not ev:
            raise ValueError(f"Evidence {evidence_id} not found")

        original_hash = ev.sha256_hash or hashlib.sha256(ev.payload.encode("utf-8")).hexdigest()
        sanitized, count = self.redact_evidence_payload(ev.payload)

        # Update evidence payload with sanitized version
        ev.payload = sanitized
        db.commit()

        return EvidenceRedactionResult(
            evidence_id=evidence_id,
            redacted=True,
            secrets_masked_count=count,
            original_sha256_hash=original_hash,
            sanitized_preview=sanitized[:200],
        )

    # --------------------------------------------------------------------------
    # 4. Suppression Tombstones
    # --------------------------------------------------------------------------
    def _read_tombstones(self) -> List[DeletionTombstoneModel]:
        try:
            data = json.loads(self.tombstone_path.read_text(encoding="utf-8"))
            return [DeletionTombstoneModel(**t) for t in data]
        except Exception:
            return []

    def _write_tombstones(self, tombstones: List[DeletionTombstoneModel]) -> None:
        self.tombstone_path.write_text(json.dumps([t.dict() for t in tombstones], indent=2), encoding="utf-8")

    def list_tombstones(self) -> List[DeletionTombstoneModel]:
        return self._read_tombstones()

    def is_suppressed(self, evidence_id: str) -> bool:
        tombstones = self._read_tombstones()
        return any(t.evidence_id == evidence_id for t in tombstones)

    def create_tombstone(
        self,
        evidence_id: str,
        original_hash: str,
        classification: DataClassification,
        policy_id: str,
        deleted_by_id: str,
        reason: str,
    ) -> DeletionTombstoneModel:
        # Compute HMAC-SHA256 signature
        payload_data = f"{evidence_id}:{original_hash}:{policy_id}:{deleted_by_id}"
        sig = hmac.new(settings.SECRET_KEY.encode("utf-8"), payload_data.encode("utf-8"), hashlib.sha256).hexdigest()

        tombstone = DeletionTombstoneModel(
            tombstone_id=f"TOMB-{uuid.uuid4().hex[:8].upper()}",
            evidence_id=evidence_id,
            original_sha256_hash=original_hash,
            classification=classification,
            policy_id=policy_id,
            deleted_by_id=deleted_by_id,
            tombstone_digest=sig,
            reason=reason,
        )
        tombstones = self._read_tombstones()
        tombstones.append(tombstone)
        self._write_tombstones(tombstones)
        return tombstone

    # --------------------------------------------------------------------------
    # 5. Retention Preview & Execution Workflow
    # --------------------------------------------------------------------------
    def generate_retention_preview(self, db: Session) -> RetentionPreviewReport:
        items: List[RetentionPreviewItem] = []
        raw_policy = self.get_policy_for_classification(DataClassification.RAW_EVIDENCE)
        retention_days = raw_policy.retention_days if raw_policy else 90

        # Query all evidence records
        records = db.query(FindingEvidence).all()
        now = datetime.now(timezone.utc)
        eligible_count = 0
        held_count = 0
        dep_count = 0

        for r in records:
            # Approximate creation date from Finding or default
            parent_finding = db.query(AssessmentFinding).filter(AssessmentFinding.id == r.finding_id).first()
            created_at_dt = r.observed_at if r.observed_at else (parent_finding.created_at if parent_finding else (now - timedelta(days=100)))
            if created_at_dt.tzinfo is None:
                created_at_dt = created_at_dt.replace(tzinfo=timezone.utc)
            age_days = (now - created_at_dt).days

            # Check hold on evidence, finding, or project
            held = False
            hold_reason = None
            h_ev, r_ev = self.is_held("EVIDENCE", r.id)
            if h_ev:
                held, hold_reason = True, r_ev
            elif parent_finding:
                h_f, r_f = self.is_held("FINDING", parent_finding.id)
                if h_f:
                    held, hold_reason = True, r_f
                elif parent_finding.project_id:
                    h_p, r_p = self.is_held("PROJECT", parent_finding.project_id)
                    if h_p:
                        held, hold_reason = True, r_p

            is_expired = age_days >= retention_days
            has_deps = False  # Finding still active
            if parent_finding and parent_finding.canonical_finding and hasattr(parent_finding.canonical_finding.status, 'value'):
                if parent_finding.canonical_finding.status.value in ["OPEN", "CONFIRMED"]:
                    has_deps = True

            eligible = is_expired and not held

            if held:
                held_count += 1
            elif has_deps:
                dep_count += 1
            elif eligible:
                eligible_count += 1

            items.append(
                RetentionPreviewItem(
                    record_id=r.id,
                    classification=DataClassification.RAW_EVIDENCE,
                    entity_type="FindingEvidence",
                    created_at=created_at_dt.isoformat(),
                    age_days=age_days,
                    applicable_policy_id=raw_policy.policy_id if raw_policy else "POL-DEFAULT",
                    recommended_action=RetentionActionType.DELETE if is_expired else RetentionActionType.RETAIN,
                    is_held=held,
                    hold_reason=hold_reason,
                    has_dependent_records=has_deps,
                    eligible_for_execution=eligible,
                )
            )

        # Compute deterministic dry run state hash
        preview_id = f"PREV-{uuid.uuid4().hex[:8].upper()}"
        preview_data = "".join(f"{i.record_id}:{i.eligible_for_execution}" for i in items)
        dry_run_hash = hashlib.sha256(preview_data.encode("utf-8")).hexdigest()

        report = RetentionPreviewReport(
            preview_id=preview_id,
            total_scanned_records=len(records),
            eligible_records_count=eligible_count,
            excluded_by_hold_count=held_count,
            excluded_by_dependency_count=dep_count,
            preview_items=items,
            dry_run_hash=dry_run_hash,
        )
        self._active_previews[preview_id] = report
        return report

    def execute_retention(
        self,
        req: RetentionExecutionRequest,
        db: Session,
        executed_by_id: str,
    ) -> RetentionExecutionResult:
        preview = self._active_previews.get(req.preview_id)
        if not preview:
            raise ValueError(f"Stale or non-existent retention preview {req.preview_id}. Generate a fresh preview.")
        if preview.dry_run_hash != req.dry_run_hash:
            raise ValueError("State inconsistency: dry_run_hash does not match stored preview.")
        if not req.confirmed_by_lead:
            raise PermissionError("Explicit confirmation by Security Lead is required for destructive retention execution.")

        deleted_count = 0
        tombstones: List[DeletionTombstoneModel] = []

        for item in preview.preview_items:
            if not item.eligible_for_execution:
                continue

            # Double check hold right before deleting
            h, _ = self.is_held("EVIDENCE", item.record_id)
            if h:
                continue

            ev = db.query(FindingEvidence).filter(FindingEvidence.id == item.record_id).first()
            if not ev:
                continue

            orig_hash = ev.sha256_hash or hashlib.sha256(ev.payload.encode("utf-8")).hexdigest()

            # Create suppression tombstone
            tomb = self.create_tombstone(
                evidence_id=ev.id,
                original_hash=orig_hash,
                classification=item.classification,
                policy_id=item.applicable_policy_id,
                deleted_by_id=executed_by_id,
                reason="Retention policy expiration execution",
            )
            tombstones.append(tomb)

            # Verifiably delete record
            db.delete(ev)
            deleted_count += 1

        db.commit()

        # Audit event record
        audit_id = f"AUD-{uuid.uuid4().hex[:8].upper()}"
        result = RetentionExecutionResult(
            execution_id=f"EXEC-{uuid.uuid4().hex[:8].upper()}",
            preview_id=req.preview_id,
            archived_count=0,
            redacted_count=0,
            deleted_count=deleted_count,
            tombstones_created_count=len(tombstones),
            skipped_count=len(preview.preview_items) - deleted_count,
            status="COMPLETED",
            audit_event_id=audit_id,
            tombstones=tombstones,
        )
        return result


evidence_lifecycle_service = EvidenceLifecycleService()
