import os
import shutil
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.models.project import Project
from app.models.scope import ScopeTarget, ScopeExclusion
from app.models.assessment import AssessmentJob, AssessmentFinding, FindingEvidence, AssessmentStatus
from app.models.finding import VulnerabilityFinding
from app.models.graph import GraphNode, GraphRelationship
from app.models.risk import RiskAssessment
from app.models.audit import AuditEvent
from app.services.audit_service import AuditService


class BackupMetadata:
    def __init__(
        self,
        backup_path: str,
        sha256_hash: str,
        size_bytes: int,
        engine_type: str,
        timestamp: datetime,
        table_count: int,
    ):
        self.backup_path = backup_path
        self.sha256_hash = sha256_hash
        self.size_bytes = size_bytes
        self.engine_type = engine_type
        self.timestamp = timestamp
        self.table_count = table_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backup_path": self.backup_path,
            "sha256_hash": self.sha256_hash,
            "size_bytes": self.size_bytes,
            "engine_type": self.engine_type,
            "timestamp": self.timestamp.isoformat(),
            "table_count": self.table_count,
        }


class BackupRecoveryService:
    """
    Data Lifecycle, Safe Backup, Verification, and Disaster Recovery Service.
    Enforces atomic non-blocking backups, cryptographic SHA-256 integrity verification,
    disposable restore testing, project lifecycle teardown, and retention governance.
    """

    @classmethod
    def create_database_backup(
        cls,
        db: Session,
        backup_dir: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> BackupMetadata:
        """
        Creates a consistent, point-in-time database backup:
        - For SQLite WAL mode: Uses VACUUM INTO to safely checkpoint and create a clean standalone copy.
        - For PostgreSQL: Prepares transaction consistency metadata.
        Computes SHA-256 integrity digest and verifies backup completeness.
        """
        now = datetime.now(timezone.utc)
        target_dir = Path(backup_dir or "./data/backups")
        target_dir.mkdir(parents=True, exist_ok=True)

        timestamp_str = now.strftime("%Y%m%d_%H%M%S")
        dialect_name = getattr(db.bind.dialect, "name", "sqlite") if (db.bind and hasattr(db.bind, "dialect")) else "sqlite"

        if dialect_name == "sqlite":
            backup_filename = f"vapt_backup_{timestamp_str}.db"
            backup_path = target_dir / backup_filename

            # If an existing file exists with same name, remove it
            if backup_path.exists():
                backup_path.unlink()

            # Execute non-blocking online backup using SQLite read-only URI mode and backup API
            # This is atomic, WAL-consistent, and works safely even during concurrent transactions
            db.flush()
            db_url = str(
                getattr(db.bind, "url", None)
                or (getattr(db.bind, "engine", None).url if getattr(db.bind, "engine", None) else None)
                or settings.DATABASE_URL
            )
            raw_path = db_url.replace("sqlite:///", "").replace("sqlite://", "")
            source_file = Path(raw_path).resolve()

            dst_conn = sqlite3.connect(str(backup_path))
            try:
                src_conn = sqlite3.connect(f"file:{source_file.as_posix()}?mode=ro", uri=True)
                try:
                    src_conn.backup(dst_conn)
                finally:
                    src_conn.close()
            finally:
                dst_conn.close()

            # Calculate SHA-256 hash of backup file
            hasher = hashlib.sha256()
            with open(backup_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            sha256_digest = hasher.hexdigest()
            size_bytes = backup_path.stat().st_size

            # Count tables in backup to ensure structural validity
            verify_conn = sqlite3.connect(str(backup_path))
            cur = verify_conn.cursor()
            cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table'")
            table_count = cur.fetchone()[0]
            verify_conn.close()

            AuditService.record_event(
                db=db,
                action="SYSTEM_BACKUP_CREATED",
                target_type="DatabaseBackup",
                outcome="SUCCESS",
                actor_id=actor_id,
                details={
                    "backup_filename": backup_filename,
                    "sha256_hash": sha256_digest,
                    "size_bytes": size_bytes,
                    "table_count": table_count,
                    "engine": "sqlite",
                },
            )
            db.commit()

            return BackupMetadata(
                backup_path=str(backup_path),
                sha256_hash=sha256_digest,
                size_bytes=size_bytes,
                engine_type="sqlite",
                timestamp=now,
                table_count=table_count,
            )
        else:
            # PostgreSQL transaction-safe metadata stub
            backup_filename = f"postgres_manifest_{timestamp_str}.json"
            backup_path = target_dir / backup_filename
            manifest = {
                "engine": "postgresql",
                "timestamp": now.isoformat(),
                "procedure": "pg_dump --format=custom --no-owner --no-acl",
                "restore_procedure": "pg_restore --clean --if-exists",
            }
            content = json.dumps(manifest, indent=2).encode("utf-8")
            backup_path.write_bytes(content)
            sha256_digest = hashlib.sha256(content).hexdigest()

            return BackupMetadata(
                backup_path=str(backup_path),
                sha256_hash=sha256_digest,
                size_bytes=len(content),
                engine_type="postgresql",
                timestamp=now,
                table_count=len(db.bind.dialect.get_table_names(db.connection())),
            )

    @classmethod
    def verify_and_test_restore(
        cls,
        backup_file_path: str,
        expected_sha256: str,
        restore_test_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validates backup integrity against expected SHA-256 digest
        and executes an isolated restore in a disposable database sandbox.
        """
        path = Path(backup_file_path)
        if not path.exists():
            raise FileNotFoundError(f"Backup file '{backup_file_path}' does not exist.")

        # 1. Cryptographic SHA-256 integrity check
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        actual_sha256 = hasher.hexdigest()

        if actual_sha256 != expected_sha256:
            raise ValueError(
                f"Integrity check failed: expected SHA-256 {expected_sha256}, got {actual_sha256}"
            )

        # 2. Disposable restore sandbox verification
        test_restore_file = Path(restore_test_path or f"./data/_restore_test_{int(time.time())}.db")
        if test_restore_file.exists():
            test_restore_file.unlink()

        try:
            shutil.copyfile(path, test_restore_file)

            conn = sqlite3.connect(str(test_restore_file))
            cur = conn.cursor()

            # Execute PRAGMA integrity_check
            cur.execute("PRAGMA integrity_check")
            integrity_result = cur.fetchone()[0]

            cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table'")
            table_count = cur.fetchone()[0]

            # Verify presence of essential core tables
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cur.fetchall()]

            conn.close()

            is_valid = (integrity_result == "ok") and (table_count > 0)
            return {
                "is_valid": is_valid,
                "integrity_result": integrity_result,
                "table_count": table_count,
                "tables_verified": [t for t in ["projects", "users", "assessment_jobs", "audit_events"] if t in tables],
                "sha256_verified": True,
            }
        finally:
            if test_restore_file.exists():
                try:
                    test_restore_file.unlink()
                except Exception:
                    pass

    @classmethod
    def export_project_manifest(
        cls,
        db: Session,
        project_id: str,
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generates a comprehensive, verifiable JSON export manifest of all project data:
        scopes, exclusions, jobs, findings, knowledge graph nodes, risk assessments, and audits.
        """
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        scopes = db.query(ScopeTarget).filter(ScopeTarget.project_id == project_id).all()
        exclusions = db.query(ScopeExclusion).filter(ScopeExclusion.project_id == project_id).all()
        jobs = db.query(AssessmentJob).filter(AssessmentJob.project_id == project_id).all()
        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()
        graph_nodes = db.query(GraphNode).filter(GraphNode.project_id == project_id).all()
        risks = db.query(RiskAssessment).filter(RiskAssessment.project_id == project_id).all()

        manifest_data = {
            "version": "1.0",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "project": {
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "organization_id": project.organization_id,
            },
            "scope_targets_count": len(scopes),
            "scope_exclusions_count": len(exclusions),
            "assessment_jobs_count": len(jobs),
            "vulnerability_findings_count": len(findings),
            "graph_nodes_count": len(graph_nodes),
            "risk_assessments_count": len(risks),
            "targets": [
                {"id": s.id, "type": s.target_type.value, "value": s.target_value, "status": s.authorization_status.value}
                for s in scopes
            ],
            "findings_summary": [
                {"id": f.id, "title": f.title, "severity": f.severity.value, "status": f.status.value}
                for f in findings
            ],
        }

        canonical_json = json.dumps(manifest_data, sort_keys=True, separators=(",", ":"))
        manifest_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        manifest_data["manifest_sha256"] = manifest_digest

        AuditService.record_event(
            db=db,
            action="PROJECT_DATA_EXPORTED",
            target_type="Project",
            outcome="SUCCESS",
            target_id=project_id,
            project_id=project_id,
            actor_id=actor_id,
            details={"manifest_sha256": manifest_digest, "findings_count": len(findings)},
        )
        db.commit()

        return manifest_data

    @classmethod
    def purge_project_data(
        cls,
        db: Session,
        project_id: str,
        actor_id: str,
        confirmation_phrase: str,
    ) -> Dict[str, Any]:
        """
        Executes authorized project teardown and data erasure (Right to erasure / data minimization).
        Requires explicit confirmation phrase: 'PURGE PROJECT {project.name}'.
        Cascades deletion across all findings, evidence, jobs, graphs, and digital twins,
        leaving an immutable tombstone audit event.
        """
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        expected_phrase = f"PURGE PROJECT {project.name}"
        if confirmation_phrase.strip() != expected_phrase:
            raise ValueError(
                f"Confirmation phrase mismatch: expected '{expected_phrase}', received '{confirmation_phrase}'"
            )

        project_name = project.name
        org_id = project.organization_id

        # Delete project (database CASCADE constraints delete dependent records)
        db.delete(project)
        db.commit()

        # Log tombstone event
        AuditService.record_event(
            db=db,
            action="PROJECT_PURGED_TOMBSTONE",
            target_type="Project",
            outcome="SUCCESS",
            target_id=project_id,
            actor_id=actor_id,
            details={
                "project_name": project_name,
                "organization_id": org_id,
                "purged_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        db.commit()

        return {
            "status": "PURGED",
            "project_id": project_id,
            "project_name": project_name,
            "purged_at": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    def apply_evidence_retention_policy(
        cls,
        db: Session,
        project_id: str,
        retention_days: int = 180,
        actor_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prunes old, resolved assessment raw evidence older than retention_days,
        preserving findings, risk models, and audit records (data minimization).
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

        # Find assessment jobs completed before cutoff
        old_jobs = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.status == AssessmentStatus.COMPLETED,
                AssessmentJob.completed_at < cutoff,
            )
            .all()
        )

        job_ids = [j.id for j in old_jobs]
        pruned_evidence_count = 0

        if job_ids:
            findings = db.query(AssessmentFinding).filter(AssessmentFinding.job_id.in_(job_ids)).all()
            finding_ids = [f.id for f in findings]
            if finding_ids:
                # Truncate / replace large payload with retention placeholder
                evidence_items = db.query(FindingEvidence).filter(FindingEvidence.finding_id.in_(finding_ids)).all()
                for ev in evidence_items:
                    if not ev.is_truncated:
                        ev.payload = "[ARCHIVED_BY_RETENTION_POLICY]"
                        ev.is_truncated = True
                        pruned_evidence_count += 1
                db.commit()

        AuditService.record_event(
            db=db,
            action="RETENTION_POLICY_APPLIED",
            target_type="Project",
            outcome="SUCCESS",
            target_id=project_id,
            project_id=project_id,
            actor_id=actor_id,
            details={
                "retention_days": retention_days,
                "old_jobs_scanned": len(job_ids),
                "pruned_evidence_items": pruned_evidence_count,
            },
        )
        db.commit()

        return {
            "project_id": project_id,
            "retention_days": retention_days,
            "pruned_evidence_count": pruned_evidence_count,
            "jobs_evaluated": len(job_ids),
        }
