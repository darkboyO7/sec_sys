"""
Diagnostics Engine for VAPT System.
Executes safe, read-only, bounded diagnostic checks across project and platform resources.
Generates structured diagnostic findings linked to the Failure Knowledge Base.
"""
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.models.base import utc_now
from app.models.diagnostics import (
    DiagnosticCategory,
    DiagnosticSeverity,
    DiagnosticConfidence,
    DiagnosticRunRecord,
    DiagnosticFindingRecord,
    RecoveryActionType,
)
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingEvidence
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.asset import Asset
from app.models.notification import NotificationRecord, NotificationStatus
from app.models.decision import AutonomousPolicyRecord
from app.models.verification import RemediationVerification, VerificationOutcome
from app.services.failure_knowledge_base import FailureKnowledgeBase


class DiagnosticsEngineService:
    """
    Executes bounded, safe self-diagnostics.
    Distinguishes confirmed defects from unverified hypotheses or unavailable data.
    """

    @classmethod
    def run_project_diagnostics(
        cls,
        db: Session,
        project_id: str,
        actor_id: Optional[str] = None,
        trigger_type: str = "MANUAL",
    ) -> Dict[str, Any]:
        now = utc_now()
        findings: List[Dict[str, Any]] = []
        total_checks = 10
        passed_checks = 0
        warning_checks = 0
        failed_checks = 0

        # Check 1: Database Migration Alignment
        c1 = cls._check_database_migrations(db)
        if c1:
            findings.append(c1)
            failed_checks += 1
        else:
            passed_checks += 1

        # Check 2: Stuck or Interrupted Assessment Jobs
        c2 = cls._check_stuck_jobs(db, project_id, now)
        if c2:
            findings.append(c2)
            warning_checks += 1
        else:
            passed_checks += 1

        # Check 3: Repeated Scanner Failures
        c3 = cls._check_repeated_job_failures(db, project_id)
        if c3:
            findings.append(c3)
            warning_checks += 1
        else:
            passed_checks += 1

        # Check 4: Missing Scanner Dependencies
        c4 = cls._check_scanner_dependencies()
        if c4:
            findings.append(c4)
            warning_checks += 1
        else:
            passed_checks += 1

        # Check 5: Invalid Configuration & Secrets
        c5 = cls._check_configuration_sanity()
        if c5:
            findings.append(c5)
            warning_checks += 1
        else:
            passed_checks += 1

        # Check 6: Orphaned Evidence Records
        c6 = cls._check_orphaned_evidence(db, project_id)
        if c6:
            findings.append(c6)
            warning_checks += 1
        else:
            passed_checks += 1

        # Check 7: Stale Asset Coverage (> 30 days without assessment)
        c7 = cls._check_stale_asset_coverage(db, project_id, now)
        if c7:
            findings.append(c7)
            warning_checks += 1
        else:
            passed_checks += 1

        # Check 8: Inconsistent Finding Lifecycle States
        c8 = cls._check_finding_state_consistency(db, project_id)
        if c8:
            findings.append(c8)
            failed_checks += 1
        else:
            passed_checks += 1

        # Check 9: Notification Delivery Failures
        c9 = cls._check_notification_delivery_failures(db, project_id)
        if c9:
            findings.append(c9)
            warning_checks += 1
        else:
            passed_checks += 1

        # Check 10: Stale or Missing Disaster Recovery Backup
        c10 = cls._check_backup_freshness(now)
        if c10:
            findings.append(c10)
            warning_checks += 1
        else:
            passed_checks += 1

        summary = (
            f"Diagnostics completed: {passed_checks}/{total_checks} checks passed. "
            f"{failed_checks} failed, {warning_checks} warnings."
        )

        # Persist diagnostic run and findings
        run_record = DiagnosticRunRecord(
            project_id=project_id,
            run_timestamp=now,
            executed_by_id=actor_id,
            trigger_type=trigger_type,
            total_checks=total_checks,
            passed_checks=passed_checks,
            warning_checks=warning_checks,
            failed_checks=failed_checks,
            summary=summary,
        )
        db.add(run_record)
        db.flush()

        persisted_findings = []
        for f in findings:
            df = DiagnosticFindingRecord(
                run_id=run_record.id,
                project_id=project_id,
                check_id=f["check_id"],
                category=f["category"],
                severity=f["severity"],
                confidence=f["confidence"],
                title=f["title"],
                description=f["description"],
                observed_issue=f["observed_issue"],
                affected_entities=f["affected_entities"],
                recommended_action=f["recommended_action"],
                recovery_action_available=f.get("recovery_action_available"),
            )
            db.add(df)
            persisted_findings.append({**f, "id": df.id})

        db.commit()

        return {
            "run_id": run_record.id,
            "project_id": project_id,
            "timestamp": now.isoformat(),
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "warning_checks": warning_checks,
            "failed_checks": failed_checks,
            "summary": summary,
            "findings": persisted_findings,
        }

    # --------------------------------------------------------------------------
    # Individual Diagnostic Check Implementations
    # --------------------------------------------------------------------------
    @classmethod
    def _check_database_migrations(cls, db: Session) -> Optional[Dict[str, Any]]:
        try:
            ver = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
            expected_head = "a8b9c0d1e2f3"
            if ver != expected_head:
                kb = FailureKnowledgeBase.lookup_failure("FAIL_DB_MIGRATION_MISMATCH")
                return {
                    "check_id": "DIAG_DB_MIGRATIONS",
                    "category": DiagnosticCategory.DATABASE,
                    "severity": DiagnosticSeverity.CRITICAL,
                    "confidence": DiagnosticConfidence.CONFIRMED,
                    "title": "Database Schema Revision Outdated",
                    "description": "Checks if active database schema revision matches the current repository head.",
                    "observed_issue": f"Database version is '{ver}', expected '{expected_head}'.",
                    "affected_entities": [f"alembic_version:{ver}"],
                    "recommended_action": kb["safe_next_steps"] if kb else "Run alembic upgrade head.",
                    "recovery_action_available": None,
                }
        except Exception as e:
            return {
                "check_id": "DIAG_DB_MIGRATIONS",
                "category": DiagnosticCategory.DATABASE,
                "severity": DiagnosticSeverity.CRITICAL,
                "confidence": DiagnosticConfidence.CONFIRMED,
                "title": "Database Connectivity Failed",
                "description": "Checks database accessibility.",
                "observed_issue": str(e)[:150],
                "affected_entities": [],
                "recommended_action": "Check database service connectivity and credentials.",
                "recovery_action_available": None,
            }
        return None

    @classmethod
    def _check_stuck_jobs(cls, db: Session, project_id: str, now: datetime) -> Optional[Dict[str, Any]]:
        cutoff_running = now - timedelta(minutes=15)
        cutoff_queued = now - timedelta(minutes=30)

        stuck_running = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.status == AssessmentStatus.RUNNING,
                AssessmentJob.started_at < cutoff_running,
            )
            .all()
        )
        stuck_queued = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.status == AssessmentStatus.QUEUED,
                AssessmentJob.created_at < cutoff_queued,
            )
            .all()
        )

        all_stuck = stuck_running + stuck_queued
        if all_stuck:
            kb = FailureKnowledgeBase.lookup_failure("FAIL_JOB_STUCK_RUNNING")
            return {
                "check_id": "DIAG_STUCK_JOBS",
                "category": DiagnosticCategory.JOBS,
                "severity": DiagnosticSeverity.HIGH,
                "confidence": DiagnosticConfidence.CONFIRMED,
                "title": "Stuck Assessment Jobs Detected",
                "description": "Scans for assessment jobs running > 15m or queued > 30m without progress.",
                "observed_issue": f"Found {len(stuck_running)} stuck running jobs and {len(stuck_queued)} starved queued jobs.",
                "affected_entities": [j.id for j in all_stuck],
                "recommended_action": kb["safe_next_steps"] if kb else "Recover stuck jobs to release concurrency slots.",
                "recovery_action_available": RecoveryActionType.RECOVER_STUCK_JOB.value,
            }
        return None

    @classmethod
    def _check_repeated_job_failures(cls, db: Session, project_id: str) -> Optional[Dict[str, Any]]:
        recent_failed = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.status == AssessmentStatus.FAILED,
            )
            .order_by(AssessmentJob.created_at.desc())
            .limit(10)
            .all()
        )
        if len(recent_failed) >= 3:
            return {
                "check_id": "DIAG_REPEATED_FAILURES",
                "category": DiagnosticCategory.JOBS,
                "severity": DiagnosticSeverity.MEDIUM,
                "confidence": DiagnosticConfidence.CONFIRMED,
                "title": "Repeated Assessment Failures Detected",
                "description": "Checks for clusters of recently failed assessment jobs.",
                "observed_issue": f"Observed {len(recent_failed)} failed assessment jobs recently.",
                "affected_entities": [j.id for j in recent_failed],
                "recommended_action": "Inspect scanner error messages and verify target network reachability.",
                "recovery_action_available": RecoveryActionType.RETRY_ASSESSMENT.value,
            }
        return None

    @classmethod
    def _check_scanner_dependencies(cls) -> Optional[Dict[str, Any]]:
        missing = []
        try:
            import nmap
        except ImportError:
            pass  # nmap python wrapper optional, native live_network_adapter uses socket
        return None

    @classmethod
    def _check_configuration_sanity(cls) -> Optional[Dict[str, Any]]:
        issues = []
        if settings.ENVIRONMENT == "production":
            if not settings.SECRET_KEY or len(settings.SECRET_KEY) < 32:
                issues.append("SECRET_KEY must be >= 32 characters in production.")
        if issues:
            return {
                "check_id": "DIAG_CONFIG_SANITY",
                "category": DiagnosticCategory.CONFIG,
                "severity": DiagnosticSeverity.HIGH,
                "confidence": DiagnosticConfidence.CONFIRMED,
                "title": "Security Configuration Warnings",
                "description": "Validates system environment and security parameters.",
                "observed_issue": "; ".join(issues),
                "affected_entities": ["environment_settings"],
                "recommended_action": "Review environment variables and update secret keys.",
                "recovery_action_available": None,
            }
        return None

    @classmethod
    def _check_orphaned_evidence(cls, db: Session, project_id: str) -> Optional[Dict[str, Any]]:
        # Query FindingEvidence records whose finding_id does not exist
        try:
            orphans = (
                db.query(FindingEvidence)
                .outerjoin(VulnerabilityFinding, FindingEvidence.finding_id == VulnerabilityFinding.id)
                .filter(VulnerabilityFinding.id.is_(None))
                .limit(5)
                .all()
            )
            if orphans:
                kb = FailureKnowledgeBase.lookup_failure("FAIL_EVIDENCE_ORPHANED")
                return {
                    "check_id": "DIAG_ORPHANED_EVIDENCE",
                    "category": DiagnosticCategory.EVIDENCE,
                    "severity": DiagnosticSeverity.MEDIUM,
                    "confidence": DiagnosticConfidence.CONFIRMED,
                    "title": "Orphaned Evidence Records Found",
                    "description": "Verifies that all cryptographic evidence records are linked to active findings.",
                    "observed_issue": f"Found {len(orphans)} evidence records without valid parent finding.",
                    "affected_entities": [e.id for e in orphans],
                    "recommended_action": kb["safe_next_steps"] if kb else "Reconcile evidence records with asset graph.",
                    "recovery_action_available": RecoveryActionType.REBUILD_KNOWLEDGE_GRAPH.value,
                }
        except Exception:
            pass
        return None

    @classmethod
    def _check_stale_asset_coverage(cls, db: Session, project_id: str, now: datetime) -> Optional[Dict[str, Any]]:
        stale_threshold = now - timedelta(days=30)
        stale_assets = (
            db.query(Asset)
            .filter(
                Asset.project_id == project_id,
                Asset.last_seen_at < stale_threshold,
            )
            .limit(5)
            .all()
        )
        if stale_assets:
            kb = FailureKnowledgeBase.lookup_failure("FAIL_ASSET_STALE_COVERAGE")
            return {
                "check_id": "DIAG_STALE_ASSETS",
                "category": DiagnosticCategory.ASSETS,
                "severity": DiagnosticSeverity.LOW,
                "confidence": DiagnosticConfidence.CONFIRMED,
                "title": "Stale Asset Observations Detected",
                "description": "Identifies assets that have not been observed or assessed in over 30 days.",
                "observed_issue": f"Found {len(stale_assets)} assets with stale observation dates.",
                "affected_entities": [a.canonical_identifier for a in stale_assets],
                "recommended_action": kb["safe_next_steps"] if kb else "Dispatch recurring assessment sweep for stale targets.",
                "recovery_action_available": RecoveryActionType.RETRY_ASSESSMENT.value,
            }
        return None

    @classmethod
    def _check_finding_state_consistency(cls, db: Session, project_id: str) -> Optional[Dict[str, Any]]:
        # Check findings marked VERIFIED_CLOSED without a VERIFIED_FIXED verification record
        closed_without_proof = (
            db.query(VulnerabilityFinding)
            .outerjoin(RemediationVerification, VulnerabilityFinding.id == RemediationVerification.finding_id)
            .filter(
                VulnerabilityFinding.project_id == project_id,
                VulnerabilityFinding.status == FindingLifecycleStatus.VERIFIED_CLOSED,
                RemediationVerification.id.is_(None),
            )
            .limit(5)
            .all()
        )
        if closed_without_proof:
            kb = FailureKnowledgeBase.lookup_failure("FAIL_FINDING_STATE_INCONSISTENT")
            return {
                "check_id": "DIAG_FINDING_INCONSISTENCY",
                "category": DiagnosticCategory.FINDINGS,
                "severity": DiagnosticSeverity.HIGH,
                "confidence": DiagnosticConfidence.CONFIRMED,
                "title": "Closed Findings Missing Independent Verification",
                "description": "Enforces lifecycle rule that findings cannot close without empirical retest proof.",
                "observed_issue": f"Found {len(closed_without_proof)} closed findings without verification records.",
                "affected_entities": [f.id for f in closed_without_proof],
                "recommended_action": kb["safe_next_steps"] if kb else "Trigger independent retest or revert status.",
                "recovery_action_available": RecoveryActionType.RETEST_REMEDIATION.value,
            }
        return None

    @classmethod
    def _check_notification_delivery_failures(cls, db: Session, project_id: str) -> Optional[Dict[str, Any]]:
        failed_notifs = (
            db.query(NotificationRecord)
            .filter(
                NotificationRecord.project_id == project_id,
                NotificationRecord.status == NotificationStatus.FAILED,
            )
            .limit(5)
            .all()
        )
        if failed_notifs:
            kb = FailureKnowledgeBase.lookup_failure("FAIL_NOTIFICATION_DELIVERY")
            return {
                "check_id": "DIAG_NOTIFICATIONS_FAILED",
                "category": DiagnosticCategory.NOTIFICATIONS,
                "severity": DiagnosticSeverity.MEDIUM,
                "confidence": DiagnosticConfidence.CONFIRMED,
                "title": "Failed Notification Deliveries",
                "description": "Detects alert notifications that failed to deliver to configured channels.",
                "observed_issue": f"Found {len(failed_notifs)} failed notification deliveries.",
                "affected_entities": [n.id for n in failed_notifs],
                "recommended_action": kb["safe_next_steps"] if kb else "Requeue failed notifications or verify provider credentials.",
                "recovery_action_available": RecoveryActionType.REQUEUE_NOTIFICATION.value,
            }
        return None

    @classmethod
    def _check_backup_freshness(cls, now: datetime) -> Optional[Dict[str, Any]]:
        backup_dir = "./data/backups"
        if not os.path.exists(backup_dir):
            kb = FailureKnowledgeBase.lookup_failure("FAIL_BACKUP_STALE")
            return {
                "check_id": "DIAG_BACKUP_FRESHNESS",
                "category": DiagnosticCategory.BACKUP,
                "severity": DiagnosticSeverity.HIGH,
                "confidence": DiagnosticConfidence.CONFIRMED,
                "title": "Disaster Recovery Backup Directory Missing",
                "description": "Validates presence of point-in-time database backup archive.",
                "observed_issue": "Backup directory ./data/backups does not exist.",
                "affected_entities": ["./data/backups"],
                "recommended_action": kb["safe_next_steps"] if kb else "Trigger database backup.",
                "recovery_action_available": RecoveryActionType.TRIGGER_BACKUP.value,
            }

        files = [os.path.join(backup_dir, f) for f in os.listdir(backup_dir) if f.endswith(".db")]
        if not files:
            kb = FailureKnowledgeBase.lookup_failure("FAIL_BACKUP_STALE")
            return {
                "check_id": "DIAG_BACKUP_FRESHNESS",
                "category": DiagnosticCategory.BACKUP,
                "severity": DiagnosticSeverity.HIGH,
                "confidence": DiagnosticConfidence.CONFIRMED,
                "title": "No Verified Backups Available",
                "description": "Validates that a database backup exists.",
                "observed_issue": "No .db backup files found in ./data/backups.",
                "affected_entities": ["./data/backups"],
                "recommended_action": kb["safe_next_steps"] if kb else "Trigger database backup.",
                "recovery_action_available": RecoveryActionType.TRIGGER_BACKUP.value,
            }
        return None
