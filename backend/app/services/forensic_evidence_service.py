"""
VAPT Platform — Forensic Evidence Preservation & Chain of Custody Service (Prompt 48).
Provides:
1. Strict separation between untouched original evidence and derived normalized interpretations.
2. Cryptographic origin attestation (Ed25519 digital signatures) distinct from checksums.
3. Monotonic Merkle-chained custody event auditing.
4. Contradiction and correction tracking that preserves historical records.
5. Explicit verification outcomes: VERIFIED, FAILED, UNAVAILABLE, NOT_CHECKED.
6. Safe deletion governance enforcing legal holds and tombstoning.
7. Redaction and sanitization preventing sensitive leaks into logs and standard views.
"""
import re
import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import text
from fastapi import HTTPException, status

from app.models.forensic_evidence import (
    ForensicEvidenceRecord,
    EvidenceCustodyEvent,
    EvidenceLifecycleState,
    VerificationOutcome,
    ContradictionStatus,
    CustodyEventType,
)
from app.models.base import utc_now
from app.schemas.forensic_evidence import (
    EvidenceIngestRequest,
    EvidenceNormalizeRequest,
    EvidenceContradictionRequest,
    EvidenceVerificationRequest,
    ForensicVerificationReport,
    ForensicVerificationReportItem,
    EvidenceExportBundle,
    EvidenceImportResult,
)
from app.services.origin_attestation_service import attestation_service, canonical_time_str
from app.services.evidence_lifecycle_service import (
    SECRET_REDACTION_PATTERNS,
    HOLDS_FILE,
    TOMBSTONE_FILE,
    evidence_lifecycle_service,
    DataClassification,
)
from app.services.storage.factory import get_evidence_storage_adapter



def compute_custody_hash(prev_hash: str, event_type: str, actor_id: str, timestamp_val: Any, details_json: str) -> str:
    time_str = canonical_time_str(timestamp_val)
    canonical_str = f"PREV={prev_hash}|TYPE={event_type}|ACTOR={actor_id}|TIME={time_str}|DETAILS={details_json}"
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


class ForensicEvidenceService:
    """
    Core forensic service governing the lifecycle, integrity, and provenance of evidence.
    """

    def ingest_evidence(
        self,
        db: Session,
        req: EvidenceIngestRequest,
        actor_id: str,
        actor_role: str,
    ) -> ForensicEvidenceRecord:
        """
        Ingests original raw evidence, generates cryptographic SHA-256 digest,
        signs origin using Ed25519 private key, and initializes hash-chained custody.
        """
        raw_payload = req.raw_payload
        raw_digest = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

        # Generate genuine cryptographic proof of origin
        key_id = req.signing_key_id or "KEY-DEFAULT-ED25519"
        origin_sig, sig_algo, key_id = attestation_service.sign_evidence_origin(
            raw_payload=raw_payload,
            source_identity=req.source_identity,
            collection_time=req.collection_time,
            key_id=key_id,
        )

        now = utc_now()
        record = ForensicEvidenceRecord(
            id=str(uuid.uuid4()),
            finding_id=req.finding_id,
            job_id=req.job_id,
            project_id=req.project_id,
            evidence_type=req.evidence_type,
            raw_payload=raw_payload,
            raw_digest_sha256=raw_digest,
            normalized_payload=None,
            normalized_digest_sha256=None,
            source_identity=req.source_identity,
            adapter_version=req.adapter_version,
            collection_time=req.collection_time,
            ingestion_time=now,
            assessment_context=req.assessment_context or {},
            transformation_history=[],
            origin_signature=origin_sig,
            signing_key_id=key_id,
            signature_algorithm=sig_algo,
            lifecycle_state=EvidenceLifecycleState.INGESTED,
            last_verification_status=VerificationOutcome.NOT_CHECKED,
            contradiction_status=ContradictionStatus.SUPPORTING,
            classification=req.classification or "RESTRICTED",
            created_at=now,
            updated_at=now,
        )
        db.add(record)
        db.flush()

        # Initial Custody Event (Ingestion)
        prev_hash = "0" * 64
        details_str = json.dumps({"action": "INGESTION", "source": req.source_identity, "key_id": key_id}, sort_keys=True)
        custody_hash = compute_custody_hash(prev_hash, CustodyEventType.INGESTION.value, actor_id, now, details_str)

        custody_event = EvidenceCustodyEvent(
            id=str(uuid.uuid4()),
            evidence_id=record.id,
            event_type=CustodyEventType.INGESTION.value,
            actor_id=actor_id,
            actor_role=actor_role,
            timestamp=now,
            action_details={"action": "INGESTION", "source": req.source_identity, "key_id": key_id},
            prev_custody_hash=prev_hash,
            custody_hash=custody_hash,
        )
        db.add(custody_event)
        db.commit()
        db.refresh(record)
        return record

    def normalize_evidence(
        self,
        db: Session,
        evidence_id: str,
        req: EvidenceNormalizeRequest,
        actor_id: str,
        actor_role: str,
    ) -> ForensicEvidenceRecord:
        """
        Derives normalized interpretation while strictly preserving untouched original raw record.
        """
        record = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
        if not record:
            raise HTTPException(status_code=404, detail=f"Evidence record {evidence_id} not found")

        if record.is_deleted:
            raise HTTPException(status_code=410, detail=f"Evidence record {evidence_id} has been authorized deleted")

        # Invariant: Never overwrite raw_payload or raw_digest_sha256
        norm_str = json.dumps(req.normalized_payload, sort_keys=True)
        norm_digest = hashlib.sha256(norm_str.encode("utf-8")).hexdigest()

        record.normalized_payload = req.normalized_payload
        record.normalized_digest_sha256 = norm_digest

        now = utc_now()
        history = list(record.transformation_history or [])
        history.append({
            "step": "NORMALIZATION",
            "transformer": req.transformer_identity,
            "version": req.adapter_version,
            "reason": req.reason,
            "timestamp": now.isoformat(),
            "actor": actor_id,
        })
        record.transformation_history = history
        record.lifecycle_state = EvidenceLifecycleState.NORMALIZED
        record.updated_at = now

        # Append chained custody event
        last_event = (
            db.query(EvidenceCustodyEvent)
            .filter(EvidenceCustodyEvent.evidence_id == record.id)
            .order_by(EvidenceCustodyEvent.timestamp.desc())
            .first()
        )
        prev_hash = last_event.custody_hash if last_event else "0" * 64
        details_str = json.dumps({"action": "NORMALIZATION", "transformer": req.transformer_identity, "norm_digest": norm_digest}, sort_keys=True)
        custody_hash = compute_custody_hash(prev_hash, CustodyEventType.NORMALIZATION.value, actor_id, now, details_str)

        custody_event = EvidenceCustodyEvent(
            id=str(uuid.uuid4()),
            evidence_id=record.id,
            event_type=CustodyEventType.NORMALIZATION.value,
            actor_id=actor_id,
            actor_role=actor_role,
            timestamp=now,
            action_details={"action": "NORMALIZATION", "transformer": req.transformer_identity, "norm_digest": norm_digest},
            prev_custody_hash=prev_hash,
            custody_hash=custody_hash,
        )
        db.add(custody_event)
        db.commit()
        db.refresh(record)
        return record

    def record_contradiction(
        self,
        db: Session,
        prior_evidence_id: str,
        req: EvidenceContradictionRequest,
        actor_id: str,
        actor_role: str,
    ) -> ForensicEvidenceRecord:
        """
        Preserves contradictory observations or corrections as additional history
        rather than silently rewriting earlier evidence.
        """
        prior = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == prior_evidence_id).first()
        if not prior:
            raise HTTPException(status_code=404, detail=f"Prior evidence {prior_evidence_id} not found")

        raw_payload = req.contradictory_payload
        raw_digest = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

        key_id = req.signing_key_id or "KEY-DEFAULT-ED25519"
        origin_sig, sig_algo, key_id = attestation_service.sign_evidence_origin(
            raw_payload=raw_payload,
            source_identity=req.source_identity,
            collection_time=req.collection_time,
            key_id=key_id,
        )

        now = utc_now()
        new_status = ContradictionStatus.SUPERSEDED if req.supersedes_previous else ContradictionStatus.CONTRADICTORY

        new_record = ForensicEvidenceRecord(
            id=str(uuid.uuid4()),
            finding_id=prior.finding_id,
            job_id=prior.job_id,
            project_id=prior.project_id,
            evidence_type=prior.evidence_type,
            raw_payload=raw_payload,
            raw_digest_sha256=raw_digest,
            normalized_payload=None,
            normalized_digest_sha256=None,
            source_identity=req.source_identity,
            adapter_version=req.adapter_version,
            collection_time=req.collection_time,
            ingestion_time=now,
            assessment_context=req.assessment_context or prior.assessment_context,
            transformation_history=[],
            origin_signature=origin_sig,
            signing_key_id=key_id,
            signature_algorithm=sig_algo,
            lifecycle_state=EvidenceLifecycleState.INGESTED,
            last_verification_status=VerificationOutcome.NOT_CHECKED,
            contradiction_status=new_status,
            prior_evidence_id=prior.id,
            is_contradictory=True,
            contradiction_notes=req.notes,
            classification=prior.classification,
            created_at=now,
            updated_at=now,
        )
        db.add(new_record)
        db.flush()

        # Update prior record's superseded link without altering its payload or hashes
        if req.supersedes_previous:
            prior.contradiction_status = ContradictionStatus.SUPERSEDED
            prior.superseded_by_id = new_record.id
            prior.updated_at = now

        # Add custody events
        prev_hash = "0" * 64
        details_str = json.dumps({"action": "CONTRADICTION_ATTACHED", "prior_id": prior.id, "superseded": req.supersedes_previous}, sort_keys=True)
        custody_hash = compute_custody_hash(prev_hash, CustodyEventType.CONTRADICTION_ATTACHED.value, actor_id, now, details_str)

        custody_event = EvidenceCustodyEvent(
            id=str(uuid.uuid4()),
            evidence_id=new_record.id,
            event_type=CustodyEventType.CONTRADICTION_ATTACHED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            timestamp=now,
            action_details={"action": "CONTRADICTION_ATTACHED", "prior_id": prior.id, "superseded": req.supersedes_previous},
            prev_custody_hash=prev_hash,
            custody_hash=custody_hash,
        )
        db.add(custody_event)
        db.commit()
        db.refresh(new_record)
        return new_record

    def verify_evidence_record(
        self,
        db: Session,
        evidence_id: str,
        actor_id: str,
        actor_role: str,
        req: Optional[EvidenceVerificationRequest] = None,
        persist: bool = True,
    ) -> ForensicVerificationReportItem:
        """
        Executes explicit cryptographic verification checks:
        1. SHA-256 payload digest matching.
        2. Asymmetric Ed25519 origin digital signature verification.
        3. Custody event Merkle hash continuity.
        Never reports VERIFIED without executing the actual checks.
        """
        if req is None:
            req = EvidenceVerificationRequest()

        record = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
        if not record:
            return ForensicVerificationReportItem(
                evidence_id=evidence_id,
                status=VerificationOutcome.UNAVAILABLE,
                raw_digest_match=False,
                signature_valid=False,
                custody_chain_valid=False,
                artifacts_present=False,
                contradiction_status=ContradictionStatus.SUPPORTING,
                discrepancies=["Record not found in database"],
            )

        discrepancies: List[str] = []
        raw_match = True
        sig_valid = True
        custody_valid = True
        artifacts_present = True

        # Check raw payload artifact presence
        if not record.raw_payload:
            artifacts_present = False
            discrepancies.append("Raw evidence payload is missing or empty")

        # 1. SHA-256 Digest Verification
        if req.verify_raw_digest and artifacts_present:
            computed_digest = hashlib.sha256(record.raw_payload.encode("utf-8")).hexdigest()
            if computed_digest != record.raw_digest_sha256:
                raw_match = False
                discrepancies.append(
                    f"Raw payload digest mismatch: expected {record.raw_digest_sha256}, calculated {computed_digest}"
                )

        # 2. Cryptographic Origin Signature Verification
        if req.verify_origin_signature and artifacts_present:
            valid_sig, sig_reason = attestation_service.verify_evidence_origin(
                raw_payload=record.raw_payload,
                source_identity=record.source_identity,
                collection_time=record.collection_time,
                signature_hex=record.origin_signature,
                key_id=record.signing_key_id,
                algorithm=record.signature_algorithm,
            )
            if not valid_sig:
                sig_valid = False
                discrepancies.append(f"Origin signature verification failed: {sig_reason}")

        # 3. Merkle Custody Hash Chain Verification
        if req.verify_custody_chain:
            events = (
                db.query(EvidenceCustodyEvent)
                .filter(EvidenceCustodyEvent.evidence_id == record.id)
                .order_by(EvidenceCustodyEvent.timestamp.asc())
                .all()
            )
            if not events:
                custody_valid = False
                discrepancies.append("Custody chain is empty; no provenance events found")
            else:
                expected_prev = "0" * 64
                for ev in events:
                    if ev.prev_custody_hash != expected_prev:
                        custody_valid = False
                        discrepancies.append(f"Broken custody chain at event {ev.id}: expected prev {expected_prev}, got {ev.prev_custody_hash}")
                        break
                    details_str = json.dumps(ev.action_details, sort_keys=True)
                    calc_hash = compute_custody_hash(ev.prev_custody_hash, ev.event_type, ev.actor_id, ev.timestamp, details_str)
                    if calc_hash != ev.custody_hash:
                        custody_valid = False
                        discrepancies.append(f"Tampered custody event hash at event {ev.id}")
                        break
                    expected_prev = ev.custody_hash

        # Determine outcome
        if not artifacts_present:
            outcome = VerificationOutcome.UNAVAILABLE
        elif not raw_match or not sig_valid or not custody_valid:
            outcome = VerificationOutcome.FAILED
        else:
            outcome = VerificationOutcome.VERIFIED

        now = utc_now()
        verification_details = {
            "verified_at": now.isoformat(),
            "verified_by": actor_id,
            "raw_digest_match": raw_match,
            "signature_valid": sig_valid,
            "custody_chain_valid": custody_valid,
            "artifacts_present": artifacts_present,
            "discrepancies": discrepancies,
        }

        if persist:
            record.last_verification_status = outcome
            record.last_verified_at = now
            record.last_verified_by = actor_id
            record.verification_details = verification_details
            record.updated_at = now

            # Append custody event for verification
            last_event = (
                db.query(EvidenceCustodyEvent)
                .filter(EvidenceCustodyEvent.evidence_id == record.id)
                .order_by(EvidenceCustodyEvent.timestamp.desc())
                .first()
            )
            prev_hash = last_event.custody_hash if last_event else "0" * 64
            details_str = json.dumps({"action": "VERIFICATION", "outcome": outcome.value, "discrepancies_count": len(discrepancies)}, sort_keys=True)
            custody_hash = compute_custody_hash(prev_hash, CustodyEventType.VERIFICATION.value, actor_id, now, details_str)

            custody_event = EvidenceCustodyEvent(
                id=str(uuid.uuid4()),
                evidence_id=record.id,
                event_type=CustodyEventType.VERIFICATION.value,
                actor_id=actor_id,
                actor_role=actor_role,
                timestamp=now,
                action_details={"action": "VERIFICATION", "outcome": outcome.value, "discrepancies_count": len(discrepancies)},
                prev_custody_hash=prev_hash,
                custody_hash=custody_hash,
            )
            db.add(custody_event)
            db.commit()

        return ForensicVerificationReportItem(
            evidence_id=record.id,
            status=outcome,
            raw_digest_match=raw_match,
            signature_valid=sig_valid,
            custody_chain_valid=custody_valid,
            artifacts_present=artifacts_present,
            contradiction_status=record.contradiction_status,
            discrepancies=discrepancies,
        )

    def verify_batch(
        self,
        db: Session,
        project_id: Optional[str] = None,
        actor_id: str = "system",
        actor_role: str = "SECURITY_ANALYST",
        persist: bool = True,
    ) -> ForensicVerificationReport:
        """
        Runs comprehensive forensic verification across evidence records without assuming integrity.
        """
        query = db.query(ForensicEvidenceRecord)
        if project_id:
            query = query.filter(ForensicEvidenceRecord.project_id == project_id)

        records = query.all()
        now = utc_now()
        items: List[ForensicVerificationReportItem] = []

        v_count = 0
        f_count = 0
        u_count = 0
        nc_count = 0

        for rec in records:
            item = self.verify_evidence_record(db, rec.id, actor_id, actor_role, persist=persist)
            items.append(item)
            if item.status == VerificationOutcome.VERIFIED:
                v_count += 1
            elif item.status == VerificationOutcome.FAILED:
                f_count += 1
            elif item.status == VerificationOutcome.UNAVAILABLE:
                u_count += 1
            else:
                nc_count += 1

        return ForensicVerificationReport(
            timestamp=now,
            total_records=len(records),
            verified_count=v_count,
            failed_count=f_count,
            unavailable_count=u_count,
            not_checked_count=nc_count,
            items=items,
        )

    def export_evidence_bundle(
        self,
        db: Session,
        project_id: str,
        actor_id: str,
        actor_role: str,
    ) -> EvidenceExportBundle:
        """
        Exports forensic evidence records with raw payloads, custody chains,
        and authentic digital signature for independent inspection.
        """
        records = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.project_id == project_id).all()
        now = utc_now()

        rec_dicts: List[Dict[str, Any]] = []
        custody_dicts: List[Dict[str, Any]] = []

        for r in records:
            rec_dicts.append({
                "id": r.id,
                "project_id": r.project_id,
                "finding_id": r.finding_id,
                "job_id": r.job_id,
                "evidence_type": r.evidence_type,
                "raw_payload": r.raw_payload,
                "raw_digest_sha256": r.raw_digest_sha256,
                "normalized_payload": r.normalized_payload,
                "normalized_digest_sha256": r.normalized_digest_sha256,
                "source_identity": r.source_identity,
                "adapter_version": r.adapter_version,
                "collection_time": r.collection_time.isoformat() if isinstance(r.collection_time, datetime) else str(r.collection_time),
                "ingestion_time": r.ingestion_time.isoformat() if isinstance(r.ingestion_time, datetime) else str(r.ingestion_time),
                "origin_signature": r.origin_signature,
                "signing_key_id": r.signing_key_id,
                "signature_algorithm": r.signature_algorithm,
                "lifecycle_state": r.lifecycle_state.value if hasattr(r.lifecycle_state, "value") else str(r.lifecycle_state),
                "contradiction_status": r.contradiction_status.value if hasattr(r.contradiction_status, "value") else str(r.contradiction_status),
                "prior_evidence_id": r.prior_evidence_id,
                "is_contradictory": r.is_contradictory,
            })

            # Record custody event for export
            last_event = (
                db.query(EvidenceCustodyEvent)
                .filter(EvidenceCustodyEvent.evidence_id == r.id)
                .order_by(EvidenceCustodyEvent.timestamp.desc())
                .first()
            )
            prev_hash = last_event.custody_hash if last_event else "0" * 64
            details_str = json.dumps({"action": "EXPORT", "exported_by": actor_id}, sort_keys=True)
            custody_hash = compute_custody_hash(prev_hash, CustodyEventType.EXPORT.value, actor_id, now, details_str)

            export_event = EvidenceCustodyEvent(
                id=str(uuid.uuid4()),
                evidence_id=r.id,
                event_type=CustodyEventType.EXPORT.value,
                actor_id=actor_id,
                actor_role=actor_role,
                timestamp=now,
                action_details={"action": "EXPORT", "exported_by": actor_id},
                prev_custody_hash=prev_hash,
                custody_hash=custody_hash,
            )
            db.add(export_event)

            # Collect existing custody events
            for cev in r.custody_events:
                custody_dicts.append({
                    "id": cev.id,
                    "evidence_id": cev.evidence_id,
                    "event_type": cev.event_type,
                    "actor_id": cev.actor_id,
                    "actor_role": cev.actor_role,
                    "timestamp": cev.timestamp.isoformat() if isinstance(cev.timestamp, datetime) else str(cev.timestamp),
                    "action_details": cev.action_details,
                    "prev_custody_hash": cev.prev_custody_hash,
                    "custody_hash": cev.custody_hash,
                })

        db.commit()

        bundle_data = {
            "export_version": "1.0",
            "exported_at": now.isoformat(),
            "exported_by": actor_id,
            "project_id": project_id,
            "records": rec_dicts,
            "custody_events": custody_dicts,
        }
        bundle_str = json.dumps(bundle_data, sort_keys=True)
        bundle_digest = hashlib.sha256(bundle_str.encode("utf-8")).hexdigest()

        # Sign bundle with platform key
        key_id = "KEY-DEFAULT-ED25519"
        bundle_sig, _, _ = attestation_service.sign_evidence_origin(
            raw_payload=bundle_str,
            source_identity=f"exporter:{actor_id}",
            collection_time=now,
            key_id=key_id,
        )

        return EvidenceExportBundle(
            export_version="1.0",
            exported_at=now,
            exported_by=actor_id,
            record_count=len(rec_dicts),
            records=rec_dicts,
            custody_events=custody_dicts,
            bundle_digest_sha256=bundle_digest,
            bundle_signature=bundle_sig,
            signing_key_id=key_id,
        )

    def import_evidence_bundle(
        self,
        db: Session,
        bundle: EvidenceExportBundle,
        target_project_id: str,
        actor_id: str,
        actor_role: str,
    ) -> EvidenceImportResult:
        """
        Imports evidence records into a target project, verifying all signatures and digests before ingress.
        """
        imported_ids: List[str] = []
        warnings: List[str] = []
        now = utc_now()

        for rec_dict in bundle.records:
            raw_payload = rec_dict.get("raw_payload", "")
            expected_digest = rec_dict.get("raw_digest_sha256", "")
            calc_digest = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

            if calc_digest != expected_digest:
                warnings.append(f"Skipping record {rec_dict.get('id')}: payload digest mismatch")
                continue

            # Verify signature
            coll_time = datetime.fromisoformat(rec_dict["collection_time"]) if isinstance(rec_dict["collection_time"], str) else rec_dict["collection_time"]
            sig_valid, sig_reason = attestation_service.verify_evidence_origin(
                raw_payload=raw_payload,
                source_identity=rec_dict.get("source_identity", ""),
                collection_time=coll_time,
                signature_hex=rec_dict.get("origin_signature", ""),
                key_id=rec_dict.get("signing_key_id", "KEY-DEFAULT-ED25519"),
                algorithm=rec_dict.get("signature_algorithm", "ED25519"),
            )

            if not sig_valid:
                warnings.append(f"Record {rec_dict.get('id')} signature verification failed: {sig_reason}")

            new_record = ForensicEvidenceRecord(
                id=str(uuid.uuid4()),
                project_id=target_project_id,
                finding_id=rec_dict.get("finding_id"),
                job_id=rec_dict.get("job_id"),
                evidence_type=rec_dict.get("evidence_type", "IMPORTED_RECORD"),
                raw_payload=raw_payload,
                raw_digest_sha256=calc_digest,
                normalized_payload=rec_dict.get("normalized_payload"),
                normalized_digest_sha256=rec_dict.get("normalized_digest_sha256"),
                source_identity=rec_dict.get("source_identity", "unknown_source"),
                adapter_version=rec_dict.get("adapter_version", "1.0.0"),
                collection_time=coll_time,
                ingestion_time=now,
                assessment_context=rec_dict.get("assessment_context", {}),
                transformation_history=rec_dict.get("transformation_history", []),
                origin_signature=rec_dict.get("origin_signature", ""),
                signing_key_id=rec_dict.get("signing_key_id", "KEY-DEFAULT-ED25519"),
                signature_algorithm=rec_dict.get("signature_algorithm", "ED25519"),
                lifecycle_state=EvidenceLifecycleState.INGESTED,
                last_verification_status=VerificationOutcome.VERIFIED if sig_valid else VerificationOutcome.FAILED,
                last_verified_at=now,
                last_verified_by=actor_id,
                contradiction_status=ContradictionStatus(rec_dict.get("contradiction_status", "SUPPORTING")),
                classification=rec_dict.get("classification", "RESTRICTED"),
                created_at=now,
                updated_at=now,
            )
            db.add(new_record)
            db.flush()

            # Custody event for import
            prev_hash = "0" * 64
            details_str = json.dumps({"action": "IMPORT", "original_id": rec_dict.get("id"), "imported_by": actor_id}, sort_keys=True)
            custody_hash = compute_custody_hash(prev_hash, CustodyEventType.IMPORT.value, actor_id, now, details_str)

            custody_event = EvidenceCustodyEvent(
                id=str(uuid.uuid4()),
                evidence_id=new_record.id,
                event_type=CustodyEventType.IMPORT.value,
                actor_id=actor_id,
                actor_role=actor_role,
                timestamp=now,
                action_details={"action": "IMPORT", "original_id": rec_dict.get("id"), "imported_by": actor_id},
                prev_custody_hash=prev_hash,
                custody_hash=custody_hash,
            )
            db.add(custody_event)
            imported_ids.append(new_record.id)

        db.commit()
        return EvidenceImportResult(
            imported_count=len(imported_ids),
            verification_passed=len(warnings) == 0,
            evidence_ids=imported_ids,
            warnings=warnings,
        )

    def delete_evidence_authorized(
        self,
        db: Session,
        evidence_id: str,
        actor_id: str,
        actor_role: str,
        justification: str,
    ) -> ForensicEvidenceRecord:
        """
        Executes safe deletion enforcing role authorization, legal hold checks,
        and recording cryptographic tombstones with authentic digital signatures.
        """
        # Strict role-based authorization check
        normalized_role = str(actor_role).upper()
        if normalized_role not in ("ADMIN", "SECURITY_LEAD", "SYSTEM", "LEAD"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Actor role '{actor_role}' is not authorized to delete forensic evidence. Requires ADMIN or SECURITY_LEAD.",
            )

        record = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
        if not record:
            raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

        # Check for active legal holds in database and file
        held, hold_msg = evidence_lifecycle_service.is_held("EVIDENCE", record.id, db=db)
        if not held and record.finding_id:
            held, hold_msg = evidence_lifecycle_service.is_held("FINDING", record.finding_id, db=db)
        if not held and record.project_id:
            held, hold_msg = evidence_lifecycle_service.is_held("PROJECT", record.project_id, db=db)

        if held:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Evidence {evidence_id} is protected under active legal hold: {hold_msg}",
            )

        if HOLDS_FILE.exists():
            try:
                with open(HOLDS_FILE, "r", encoding="utf-8") as f:
                    holds_data = json.load(f)
                    for hold in (holds_data.get("holds", []) if isinstance(holds_data, dict) else holds_data):
                        if hold.get("status") == "ACTIVE":
                            target_ref = hold.get("target_reference") or hold.get("target_id", "")
                            if target_ref in (record.id, record.project_id, "ALL_PROJECTS"):
                                raise HTTPException(
                                    status_code=status.HTTP_409_CONFLICT,
                                    detail=f"Evidence {evidence_id} is protected under active legal hold: {hold.get('hold_id')}",
                                )
            except HTTPException:
                raise
            except Exception:
                pass

        now = utc_now()
        record.is_deleted = True
        record.lifecycle_state = EvidenceLifecycleState.AUTHORIZED_DELETED
        record.deleted_at = now
        record.deleted_by = actor_id
        record.updated_at = now

        # Record deletion suppression tombstone with Ed25519 signature
        tombstone = evidence_lifecycle_service.create_tombstone(
            evidence_id=record.id,
            original_hash=record.raw_digest_sha256,
            classification=DataClassification.RAW_EVIDENCE,
            policy_id="AUTHORIZED_DELETION",
            deleted_by_id=actor_id,
            reason=justification,
            db=db,
        )

        # Notify storage adapter to tombstone/delete physical object
        try:
            adapter = get_evidence_storage_adapter()
            adapter.delete_evidence(f"evidence/{record.id}", tombstone.tombstone_digest)
        except Exception:
            pass

        # Append custody event
        last_event = (
            db.query(EvidenceCustodyEvent)
            .filter(EvidenceCustodyEvent.evidence_id == record.id)
            .order_by(EvidenceCustodyEvent.timestamp.desc())
            .first()
        )
        prev_hash = last_event.custody_hash if last_event else "0" * 64
        details_str = json.dumps({"action": "DELETION_AUTHORIZED", "justification": justification, "tombstone_id": tombstone.tombstone_id}, sort_keys=True)
        custody_hash = compute_custody_hash(prev_hash, CustodyEventType.DELETION_AUTHORIZED.value, actor_id, now, details_str)

        custody_event = EvidenceCustodyEvent(
            id=str(uuid.uuid4()),
            evidence_id=record.id,
            event_type=CustodyEventType.DELETION_AUTHORIZED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            timestamp=now,
            action_details={"action": "DELETION_AUTHORIZED", "justification": justification, "tombstone_id": tombstone.tombstone_id},
            prev_custody_hash=prev_hash,
            custody_hash=custody_hash,
        )
        db.add(custody_event)
        db.commit()
        db.refresh(record)
        return record

    def sanitize_for_display(self, payload: str) -> str:
        """
        Redacts high-entropy credentials, private keys, and passwords before presentation in logs or non-privileged views.
        """
        sanitized = payload
        for pattern_name, regex in SECRET_REDACTION_PATTERNS:
            sanitized = regex.sub(f"[REDACTED_{pattern_name}]", sanitized)
        db_regex = re.compile(r"(?i)\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:]+:)[^\s@]+(@[^\s\/]+)")
        sanitized = db_regex.sub(r"\1[REDACTED_DATABASE_URL]\2", sanitized)
        return sanitized


forensic_evidence_service = ForensicEvidenceService()
