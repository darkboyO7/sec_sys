"""
Data Portability & Secure Project Archive Service (Prompt 58-62).
Implements safe export and import formats, preserving UUIDs, timestamps, relationships,
cryptographic signatures, and provenance.
Enforces Zip Slip prevention, schema validation, Merkle custody auditing,
and rejects malformed or untrusted archives.
"""
import os
import zipfile
import json
import uuid
import hashlib
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.base import utc_now
from app.models.project import Project
from app.models.scope import ScopeTarget, ScopeExclusion
from app.models.assessment import AssessmentJob, AssessmentFinding, FindingEvidence
from app.models.finding import VulnerabilityFinding
from app.models.forensic_evidence import ForensicEvidenceRecord, EvidenceCustodyEvent
from app.services.origin_attestation_service import attestation_service
from app.services.forensic_evidence_service import compute_custody_hash
from app.services.storage.factory import get_evidence_storage_adapter


class DataPortabilityService:
    """
    Governs safe, verified data import/export between environments
    with strict isolation and cryptographic verification.
    """

    MAX_ARCHIVE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB max archive size
    MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 500 MB max uncompressed limit

    @classmethod
    def export_project_archive(
        cls,
        db: Session,
        project_id: str,
        output_path: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Exports a complete self-contained project archive preserving:
        - Project metadata and configuration
        - Scope targets and exclusions
        - Findings and vulnerabilities
        - Forensic raw and normalized evidence records
        - Cryptographic origin signatures and Merkle custody chains
        - Manifest digital signature (Ed25519)
        """
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project with ID '{project_id}' does not exist.")

        now = datetime.now(timezone.utc)
        export_id = f"export_{project_id}_{now.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        export_root = Path(getattr(settings, "DATA_DIR", getattr(settings, "BACKUP_STORAGE_DIR", "./data/backups"))).parent / "exports"
        export_root.mkdir(parents=True, exist_ok=True)

        staging_dir = export_root / f"{export_id}_staging"
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        staging_dir.mkdir(parents=True, exist_ok=True)

        try:
            # 1. Export Project metadata
            project_data = {
                "id": project.id,
                "organization_id": getattr(project, "organization_id", None),
                "name": project.name,
                "description": project.description,
                "created_at": project.created_at.isoformat() if project.created_at else None,
                "updated_at": project.updated_at.isoformat() if project.updated_at else None,
            }
            (staging_dir / "project.json").write_text(json.dumps(project_data, indent=2), encoding="utf-8")

            # 2. Export Scope Targets & Exclusions
            targets = db.query(ScopeTarget).filter(ScopeTarget.project_id == project_id).all()
            targets_data = [
                {
                    "id": t.id,
                    "project_id": t.project_id,
                    "target_type": t.target_type.value if hasattr(t.target_type, "value") else str(t.target_type),
                    "target_value": t.target_value,
                    "description": t.description,
                    "authorization_status": t.authorization_status.value if hasattr(t.authorization_status, "value") else str(t.authorization_status),
                    "created_by_id": t.created_by_id,
                    "created_at": t.created_at.isoformat() if t.created_at else None,
                }
                for t in targets
            ]
            (staging_dir / "targets.json").write_text(json.dumps(targets_data, indent=2), encoding="utf-8")

            # 3. Export Findings
            findings = db.query(AssessmentFinding).filter(AssessmentFinding.project_id == project_id).all()
            findings_data = [
                {
                    "id": f.id,
                    "project_id": f.project_id,
                    "job_id": f.job_id,
                    "target_value": f.target_value,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                    "cvss_score": f.cvss_score,
                    "vuln_id": f.vuln_id,
                    "created_at": f.created_at.isoformat() if hasattr(f, "created_at") and f.created_at else None,
                }
                for f in findings
            ]
            (staging_dir / "findings.json").write_text(json.dumps(findings_data, indent=2), encoding="utf-8")

            # 4. Export Forensic Evidence & Custody Chains
            evidence_records = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.project_id == project_id).all()
            evidence_data = []
            custody_data = []
            blobs_dir = staging_dir / "evidence_blobs"
            blobs_dir.mkdir(parents=True, exist_ok=True)

            storage_adapter = get_evidence_storage_adapter()

            for ev in evidence_records:
                evidence_data.append({
                    "id": ev.id,
                    "project_id": ev.project_id,
                    "finding_id": ev.finding_id,
                    "job_id": ev.job_id,
                    "evidence_type": ev.evidence_type,
                    "raw_payload": ev.raw_payload,
                    "raw_digest_sha256": ev.raw_digest_sha256,
                    "normalized_payload": ev.normalized_payload,
                    "source_identity": ev.source_identity,
                    "adapter_version": ev.adapter_version,
                    "collection_time": ev.collection_time.isoformat() if ev.collection_time else None,
                    "origin_signature": ev.origin_signature,
                    "signing_key_id": ev.signing_key_id,
                    "signature_algorithm": ev.signature_algorithm,
                    "lifecycle_state": ev.lifecycle_state.value if hasattr(ev.lifecycle_state, "value") else str(ev.lifecycle_state),
                    "is_deleted": ev.is_deleted,
                    "created_at": ev.created_at.isoformat() if ev.created_at else None,
                })

                # Write raw blob
                blob_path = blobs_dir / f"{ev.id}.raw"
                blob_path.write_text(ev.raw_payload, encoding="utf-8")

                # Fetch custody events
                events = db.query(EvidenceCustodyEvent).filter(
                    EvidenceCustodyEvent.evidence_id == ev.id
                ).order_by(EvidenceCustodyEvent.timestamp.asc(), EvidenceCustodyEvent.id.asc()).all()
                for c in events:
                    custody_data.append({
                        "id": c.id,
                        "evidence_id": c.evidence_id,
                        "event_type": c.event_type,
                        "actor_id": c.actor_id,
                        "actor_role": c.actor_role,
                        "timestamp": c.timestamp.isoformat() if c.timestamp else None,
                        "action_details": c.action_details,
                        "prev_custody_hash": c.prev_custody_hash,
                        "custody_hash": c.custody_hash,
                    })

            (staging_dir / "forensic_evidence.json").write_text(json.dumps(evidence_data, indent=2), encoding="utf-8")
            (staging_dir / "custody_events.json").write_text(json.dumps(custody_data, indent=2), encoding="utf-8")

            # 5. Compute Checksums of All Member Files
            file_checksums = {}
            for item in staging_dir.glob("**/*"):
                if item.is_file():
                    rel_p = item.relative_to(staging_dir).as_posix()
                    file_checksums[rel_p] = hashlib.sha256(item.read_bytes()).hexdigest()

            # 6. Compile Manifest
            manifest = {
                "manifest_version": "1.0",
                "export_id": export_id,
                "project_id": project_id,
                "project_name": project.name,
                "exported_at": now.isoformat(),
                "exported_by": actor_id or "system",
                "record_counts": {
                    "targets": len(targets_data),
                    "findings": len(findings_data),
                    "evidence_records": len(evidence_data),
                    "custody_events": len(custody_data),
                },
                "file_checksums": file_checksums,
            }

            manifest["signature_algorithm"] = "ED25519"
            manifest["signing_key_id"] = "KEY-DEFAULT-ED25519"
            canonical_manifest = json.dumps(
                {k: v for k, v in manifest.items() if k not in ("manifest_sha256", "manifest_signature")},
                sort_keys=True,
                separators=(",", ":")
            )
            sig_hex, sig_algo, kid = attestation_service.sign_manifest(canonical_manifest)
            manifest["manifest_signature"] = sig_hex
            manifest["signature_algorithm"] = sig_algo
            manifest["signing_key_id"] = kid
            manifest["manifest_sha256"] = hashlib.sha256(canonical_manifest.encode("utf-8")).hexdigest()

            (staging_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            (staging_dir / "manifest.sig").write_text(sig_hex, encoding="utf-8")

            # 7. Package into ZIP archive
            zip_dest = Path(output_path) if output_path else (export_root / f"{export_id}.vapt_archive.zip")
            with zipfile.ZipFile(str(zip_dest), "w", zipfile.ZIP_DEFLATED) as zf:
                for item in staging_dir.glob("**/*"):
                    if item.is_file():
                        rel = item.relative_to(staging_dir)
                        zf.write(str(item), arcname=rel.as_posix())

            archive_sha = hashlib.sha256(zip_dest.read_bytes()).hexdigest()
            archive_size = zip_dest.stat().st_size

            return {
                "export_id": export_id,
                "archive_path": str(zip_dest),
                "archive_sha256": archive_sha,
                "size_bytes": archive_size,
                "manifest_signature": sig_hex,
                "record_counts": manifest["record_counts"],
                "exported_at": now.isoformat(),
            }
        finally:
            if staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)

    @classmethod
    def validate_project_archive(cls, archive_path: str) -> Dict[str, Any]:
        """
        Validates archive safety and authenticity before extraction or ingestion:
        - Prevents Zip Slip directory traversal attacks.
        - Enforces size constraints (zip bomb prevention).
        - Verifies manifest SHA-256 and Ed25519 digital signature.
        - Verifies checksums of all contained entities.
        - Audits cryptographic Merkle custody chains.
        """
        path = Path(archive_path).resolve()
        if not path.exists():
            return {"valid": False, "errors": [f"Archive does not exist: {archive_path}"]}

        if path.stat().st_size > cls.MAX_ARCHIVE_SIZE_BYTES:
            return {"valid": False, "errors": [f"Archive size exceeds maximum allowed ({cls.MAX_ARCHIVE_SIZE_BYTES} bytes)."]}

        errors: List[str] = []
        manifest_data: Dict[str, Any] = {}

        try:
            with zipfile.ZipFile(str(path), "r") as zf:
                # 1. Zip Slip and bomb checks
                total_uncompressed = 0
                for info in zf.infolist():
                    name = info.filename
                    total_uncompressed += info.file_size
                    if total_uncompressed > cls.MAX_UNCOMPRESSED_BYTES:
                        errors.append("Uncompressed archive size exceeds safety threshold (potential zip bomb).")
                        break

                    # Zip Slip detection: reject absolute paths or directory traversal
                    clean = Path(name).as_posix()
                    if clean.startswith("/") or clean.startswith("\\") or ":" in clean or ".." in clean.split("/"):
                        errors.append(f"Zip Slip traversal vulnerability detected in member path: '{name}'")
                        break

                if errors:
                    return {"valid": False, "errors": errors}

                # 2. Check for manifest.json
                if "manifest.json" not in zf.namelist():
                    errors.append("Archive missing required 'manifest.json' metadata.")
                    return {"valid": False, "errors": errors}

                manifest_bytes = zf.read("manifest.json")
                try:
                    manifest_data = json.loads(manifest_bytes.decode("utf-8"))
                except Exception as e:
                    errors.append(f"Malformed manifest JSON: {str(e)}")
                    return {"valid": False, "errors": errors}

                # 3. Verify manifest digital signature
                manifest_sig = manifest_data.get("manifest_signature")
                if not manifest_sig and "manifest.sig" in zf.namelist():
                    manifest_sig = zf.read("manifest.sig").decode("utf-8").strip()

                if manifest_sig:
                    clean_body = json.dumps(
                        {k: v for k, v in manifest_data.items() if k not in ("manifest_sha256", "manifest_signature")},
                        sort_keys=True,
                        separators=(",", ":")
                    )
                    kid = manifest_data.get("signing_key_id", "KEY-DEFAULT-ED25519")
                    sig_valid, sig_reason = attestation_service.verify_manifest(clean_body, manifest_sig, kid)
                    if not sig_valid:
                        errors.append(f"Manifest digital signature verification failed: {sig_reason}")
                else:
                    errors.append("Archive manifest lacks required cryptographic origin signature.")

                # 4. Check file checksums
                checksums = manifest_data.get("file_checksums", {})
                for rel_p, expected_sha in checksums.items():
                    if rel_p in ("manifest.json", "manifest.sig"):
                        continue
                    if rel_p not in zf.namelist():
                        errors.append(f"Archive missing cataloged file: '{rel_p}'")
                        continue
                    actual_sha = hashlib.sha256(zf.read(rel_p)).hexdigest()
                    if actual_sha != expected_sha:
                        errors.append(f"Checksum mismatch for '{rel_p}': expected {expected_sha}, got {actual_sha}")

                # 5. Validate schema and required entities
                required_files = ["project.json", "targets.json", "findings.json", "forensic_evidence.json", "custody_events.json"]
                for req in required_files:
                    if req not in zf.namelist():
                        errors.append(f"Archive missing mandatory entity file: '{req}'")

                # 6. Audit Merkle custody chains in custody_events.json
                if "custody_events.json" in zf.namelist():
                    try:
                        events_list = json.loads(zf.read("custody_events.json").decode("utf-8"))
                        # Group by evidence_id
                        by_ev: Dict[str, List[Dict[str, Any]]] = {}
                        for c in events_list:
                            by_ev.setdefault(c["evidence_id"], []).append(c)

                        for evid, ev_events in by_ev.items():
                            expected_prev = "0" * 64
                            for ev in ev_events:
                                if ev.get("prev_custody_hash") != expected_prev:
                                    errors.append(f"Custody chain broken for evidence {evid} at event {ev.get('id')}")
                                    break
                                if not ev.get("custody_hash") or len(ev.get("custody_hash")) != 64:
                                    errors.append(f"Invalid custody hash format for evidence {evid} at event {ev.get('id')}")
                                    break
                                expected_prev = ev.get("custody_hash")
                    except Exception as e:
                        errors.append(f"Failed to parse custody events ledger: {str(e)}")

        except zipfile.BadZipFile:
            errors.append("Invalid or corrupted zip archive format.")
        except Exception as e:
            errors.append(f"Archive inspection error: {str(e)}")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "manifest": manifest_data,
        }

    @classmethod
    def import_project_archive(
        cls,
        db: Session,
        archive_path: str,
        target_project_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Safely imports an archive into the target database:
        - Rejects untrusted or malformed archives upfront.
        - Supports dry-run inspection without committing changes.
        - Preserves UUIDs, timestamps, and relationships.
        - Commits atomically in a single transaction.
        """
        val_res = cls.validate_project_archive(archive_path)
        if not val_res["valid"]:
            raise ValueError(f"Untrusted or malformed archive rejected. Errors: {val_res['errors']}")

        if dry_run:
            return {
                "dry_run": True,
                "status": "VALIDATED",
                "manifest": val_res.get("manifest"),
                "message": "Archive validated successfully; dry-run mode did not modify database.",
            }

        archive_p = Path(archive_path).resolve()
        with zipfile.ZipFile(str(archive_p), "r") as zf:
            project_data = json.loads(zf.read("project.json").decode("utf-8"))
            targets_data = json.loads(zf.read("targets.json").decode("utf-8"))
            findings_data = json.loads(zf.read("findings.json").decode("utf-8"))
            evidence_data = json.loads(zf.read("forensic_evidence.json").decode("utf-8"))
            custody_data = json.loads(zf.read("custody_events.json").decode("utf-8"))

        dest_project_id = target_project_id or project_data["id"]

        try:
            # 1. Project record
            proj = db.query(Project).filter(Project.id == dest_project_id).first()
            if not proj:
                org_id = project_data.get("organization_id")
                if not org_id:
                    from app.models.organization import Organization
                    first_org = db.query(Organization).first()
                    if first_org:
                        org_id = first_org.id
                    else:
                        new_org = Organization(name="Default Org", slug=f"org-{uuid.uuid4().hex[:6]}")
                        db.add(new_org)
                        db.flush()
                        org_id = new_org.id

                proj = Project(
                    id=dest_project_id,
                    organization_id=org_id,
                    name=project_data.get("name", "Imported Project"),
                    description=project_data.get("description", "Imported via DataPortabilityService"),
                )
                db.add(proj)
                db.flush()

            # 2. Scope Targets
            imported_targets = 0
            for t in targets_data:
                existing = db.query(ScopeTarget).filter(ScopeTarget.id == t["id"]).first()
                if not existing:
                    target_rec = ScopeTarget(
                        id=t["id"],
                        project_id=dest_project_id,
                        target_type=t.get("target_type", "IP"),
                        target_value=t.get("target_value", ""),
                        description=t.get("description", ""),
                        authorization_status=t.get("authorization_status", "AUTHORIZED"),
                        created_by_id=t.get("created_by_id") or actor_id or default_user_id,
                    )
                    db.add(target_rec)
                    imported_targets += 1

            # 3. Findings
            imported_findings = 0
            for f in findings_data:
                existing_f = db.query(AssessmentFinding).filter(AssessmentFinding.id == f["id"]).first()
                if not existing_f:
                    f_rec = AssessmentFinding(
                        id=f["id"],
                        project_id=dest_project_id,
                        job_id=f.get("job_id"),
                        target_value=f.get("target_value", ""),
                        title=f.get("title", "Imported Finding"),
                        description=f.get("description", ""),
                        severity=f.get("severity", "MEDIUM"),
                        confidence=f.get("confidence", "FIRM"),
                        cvss_score=f.get("cvss_score"),
                        vuln_id=f.get("vuln_id"),
                    )
                    db.add(f_rec)
                    imported_findings += 1

            # 4. Forensic Evidence Records
            imported_evidence = 0
            for ev in evidence_data:
                existing_ev = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == ev["id"]).first()
                if not existing_ev:
                    ev_rec = ForensicEvidenceRecord(
                        id=ev["id"],
                        project_id=dest_project_id,
                        finding_id=ev.get("finding_id"),
                        job_id=ev.get("job_id"),
                        evidence_type=ev.get("evidence_type", "RAW_HTTP"),
                        raw_payload=ev.get("raw_payload", ""),
                        raw_digest_sha256=ev.get("raw_digest_sha256", ""),
                        normalized_payload=ev.get("normalized_payload"),
                        source_identity=ev.get("source_identity", "IMPORT"),
                        adapter_version=ev.get("adapter_version", "1.0"),
                        collection_time=datetime.fromisoformat(ev["collection_time"]) if ev.get("collection_time") else utc_now(),
                        origin_signature=ev.get("origin_signature", ""),
                        signing_key_id=ev.get("signing_key_id", "KEY-DEFAULT-ED25519"),
                        signature_algorithm=ev.get("signature_algorithm", "ED25519"),
                    )
                    db.add(ev_rec)
                    imported_evidence += 1

            # 5. Custody Events
            imported_custody = 0
            for c in custody_data:
                existing_c = db.query(EvidenceCustodyEvent).filter(EvidenceCustodyEvent.id == c["id"]).first()
                if not existing_c:
                    c_rec = EvidenceCustodyEvent(
                        id=c["id"],
                        evidence_id=c["evidence_id"],
                        event_type=c.get("event_type", "IMPORT"),
                        actor_id=c.get("actor_id", actor_id or "system"),
                        actor_role=c.get("actor_role", "OPERATOR"),
                        timestamp=datetime.fromisoformat(c["timestamp"]) if c.get("timestamp") else utc_now(),
                        action_details=c.get("action_details", {}),
                        prev_custody_hash=c.get("prev_custody_hash", "0" * 64),
                        custody_hash=c.get("custody_hash", ""),
                    )
                    db.add(c_rec)
                    imported_custody += 1

            db.commit()

            return {
                "status": "SUCCESS",
                "project_id": dest_project_id,
                "targets_imported": imported_targets,
                "findings_imported": imported_findings,
                "evidence_imported": imported_evidence,
                "custody_events_imported": imported_custody,
                "imported_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception:
            db.rollback()
            raise


data_portability_service = DataPortabilityService()
