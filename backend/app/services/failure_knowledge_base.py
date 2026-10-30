"""
Failure Knowledge Base for VAPT System.
Provides a structured, deterministic catalog of known operational failure signatures,
detection conditions, causal hypotheses, safe next steps, and validated recovery mappings.
"""
from typing import Dict, Any, List, Optional
from app.models.diagnostics import (
    DiagnosticCategory,
    DiagnosticSeverity,
    DiagnosticConfidence,
    RecoveryActionType,
)


class FailureKnowledgeEntry:
    def __init__(
        self,
        failure_id: str,
        title: str,
        category: DiagnosticCategory,
        severity: DiagnosticSeverity,
        confidence: DiagnosticConfidence,
        detection_condition: str,
        likely_causes: List[str],
        supporting_evidence: str,
        safe_next_steps: str,
        recovery_action: Optional[RecoveryActionType] = None,
        required_role: str = "LEAD",
        verification_procedure: str = "",
    ):
        self.failure_id = failure_id
        self.title = title
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.detection_condition = detection_condition
        self.likely_causes = likely_causes
        self.supporting_evidence = supporting_evidence
        self.safe_next_steps = safe_next_steps
        self.recovery_action = recovery_action
        self.required_role = required_role
        self.verification_procedure = verification_procedure

    def to_dict(self) -> Dict[str, Any]:
        return {
            "failure_id": self.failure_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "detection_condition": self.detection_condition,
            "likely_causes": self.likely_causes,
            "supporting_evidence": self.supporting_evidence,
            "safe_next_steps": self.safe_next_steps,
            "recovery_action": self.recovery_action.value if self.recovery_action else None,
            "required_role": self.required_role,
            "verification_procedure": self.verification_procedure,
        }


FAILURE_CATALOG: Dict[str, FailureKnowledgeEntry] = {
    "FAIL_JOB_STUCK_RUNNING": FailureKnowledgeEntry(
        failure_id="FAIL_JOB_STUCK_RUNNING",
        title="Assessment Job Stuck in Running State",
        category=DiagnosticCategory.JOBS,
        severity=DiagnosticSeverity.HIGH,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="Assessment job has been in RUNNING status for > 15 minutes without progress update.",
        likely_causes=[
            "[Hypothesis] Scanner subprocess hung on network socket read or host TCP timeout.",
            "[Hypothesis] Host machine terminated the worker process unexpectedly (OOM or reboot).",
            "[Hypothesis] Worker crashed without executing database state machine teardown handler.",
        ],
        supporting_evidence="Job ID, target URL/IP, adapter name, elapsed time since started_at.",
        safe_next_steps="Review adapter debug logs. Transition job status to INTERRUPTED and release concurrency slot.",
        recovery_action=RecoveryActionType.RECOVER_STUCK_JOB,
        required_role="LEAD",
        verification_procedure="Verify job status is INTERRUPTED/FAILED and active concurrency count is decremented.",
    ),
    "FAIL_JOB_STUCK_QUEUED": FailureKnowledgeEntry(
        failure_id="FAIL_JOB_STUCK_QUEUED",
        title="Assessment Job Starved in Queued State",
        category=DiagnosticCategory.JOBS,
        severity=DiagnosticSeverity.MEDIUM,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="Assessment job has remained in QUEUED status for > 30 minutes without worker pickup.",
        likely_causes=[
            "[Hypothesis] Background worker queue polling loop is inactive or paused.",
            "[Hypothesis] Project maximum concurrency limit is saturated by longer-running jobs.",
            "[Hypothesis] Worker execution budget has been exhausted for the 24-hour window.",
        ],
        supporting_evidence="Job creation timestamp, project policy concurrency setting, active worker status.",
        safe_next_steps="Check background worker process health, evaluate active jobs, or cancel starved job.",
        recovery_action=RecoveryActionType.RECOVER_STUCK_JOB,
        required_role="LEAD",
        verification_procedure="Verify worker queue processing resumes or job is safely terminated.",
    ),
    "FAIL_NOTIFICATION_DELIVERY": FailureKnowledgeEntry(
        failure_id="FAIL_NOTIFICATION_DELIVERY",
        title="Notification Delivery Failure Accumulated",
        category=DiagnosticCategory.NOTIFICATIONS,
        severity=DiagnosticSeverity.MEDIUM,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="Notification record delivery has failed or delivery attempts have exhausted.",
        likely_causes=[
            "[Hypothesis] External SMTP server connection refused or timed out.",
            "[Hypothesis] Target webhook returned 5xx server error or rate-limited the payload.",
            "[Hypothesis] Notification destination endpoint certificate validation failed.",
        ],
        supporting_evidence="Notification ID, event type, delivery attempts, sanitized error message from provider.",
        safe_next_steps="Verify destination webhook or mail server accessibility. Requeue notification if transient.",
        recovery_action=RecoveryActionType.REQUEUE_NOTIFICATION,
        required_role="LEAD",
        verification_procedure="Verify delivery attempt increments and provider returns delivery acknowledgement.",
    ),
    "FAIL_DB_MIGRATION_MISMATCH": FailureKnowledgeEntry(
        failure_id="FAIL_DB_MIGRATION_MISMATCH",
        title="Database Schema Revision Outdated",
        category=DiagnosticCategory.DATABASE,
        severity=DiagnosticSeverity.CRITICAL,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="Database alembic_version does not match current repository head revision.",
        likely_causes=[
            "[Hypothesis] alembic upgrade head was not executed after pull or deployment.",
            "[Hypothesis] Multi-tenant test runner pointed to an unmigrated temporary database.",
        ],
        supporting_evidence="Active database alembic_version vs. target revision from migrations directory.",
        safe_next_steps="Execute alembic upgrade head from backend environment before dispatching jobs.",
        recovery_action=None,  # Schema migration must be run by system administrator / deployment tooling
        required_role="ADMIN",
        verification_procedure="Check alembic current returns target head revision.",
    ),
    "FAIL_POLICY_KILL_SWITCH_ACTIVE": FailureKnowledgeEntry(
        failure_id="FAIL_POLICY_KILL_SWITCH_ACTIVE",
        title="Autonomous Operations Suspended via Kill Switch",
        category=DiagnosticCategory.SECURITY,
        severity=DiagnosticSeverity.HIGH,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="Project policy has is_suspended=True, halting all assessment and remediation dispatch.",
        likely_causes=[
            "[Hypothesis] Lead operator manually activated emergency suspension kill switch.",
            "[Hypothesis] Automated failure threshold (3 consecutive job failures) triggered auto-suspension.",
        ],
        supporting_evidence="Suspension timestamp, suspending actor ID, suspension reason from AutonomousPolicyRecord.",
        safe_next_steps="Investigate root cause of failures. When safe, submit resumption request with operator notes.",
        recovery_action=None,  # Requires explicit policy resume API
        required_role="LEAD",
        verification_procedure="Verify policy is_suspended is False and decision ledger logs POLICY_RESUME.",
    ),
    "FAIL_EVIDENCE_ORPHANED": FailureKnowledgeEntry(
        failure_id="FAIL_EVIDENCE_ORPHANED",
        title="Finding Evidence Missing Valid Association",
        category=DiagnosticCategory.EVIDENCE,
        severity=DiagnosticSeverity.MEDIUM,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="FindingEvidence records exist whose finding_id does not correspond to an active finding.",
        likely_causes=[
            "[Hypothesis] An interrupted scanner batch committed partial evidence without parent finding.",
            "[Hypothesis] Unsynchronized test fixture cleanups.",
        ],
        supporting_evidence="List of orphaned evidence IDs, hashes, and foreign key references.",
        safe_next_steps="Investigate data integrity. Re-run reconciliation to link evidence or archive artifacts.",
        recovery_action=RecoveryActionType.REBUILD_KNOWLEDGE_GRAPH,
        required_role="ADMIN",
        verification_procedure="Verify evidence records are properly associated with valid finding fingerprints.",
    ),
    "FAIL_BACKUP_STALE": FailureKnowledgeEntry(
        failure_id="FAIL_BACKUP_STALE",
        title="Disaster Recovery Backup Overdue",
        category=DiagnosticCategory.BACKUP,
        severity=DiagnosticSeverity.HIGH,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="No verified database backup exists within the last 24 hours.",
        likely_causes=[
            "[Hypothesis] Scheduled backup task failed or was not configured in the host environment.",
            "[Hypothesis] Storage disk ran out of space during backup generation.",
        ],
        supporting_evidence="Latest backup timestamp, backup directory status, disk space.",
        safe_next_steps="Execute non-blocking database backup and verify SHA-256 integrity check.",
        recovery_action=RecoveryActionType.TRIGGER_BACKUP,
        required_role="LEAD",
        verification_procedure="Verify new backup created with valid SHA-256 and sandbox restore verification passes.",
    ),
    "FAIL_ASSET_STALE_COVERAGE": FailureKnowledgeEntry(
        failure_id="FAIL_ASSET_STALE_COVERAGE",
        title="Asset Inventory Observations Stale",
        category=DiagnosticCategory.ASSETS,
        severity=DiagnosticSeverity.LOW,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="Authorized assets exist that have not received an assessment or observation in > 30 days.",
        likely_causes=[
            "[Hypothesis] Recurring monitoring schedule is not assigned to the asset scope.",
            "[Hypothesis] Target was unreachable during recent scheduled assessment sweeps.",
        ],
        supporting_evidence="Asset canonical IDs, last_seen_at timestamps, scope target IDs.",
        safe_next_steps="Schedule assessment sweep for stale targets or update asset decommissioning status.",
        recovery_action=RecoveryActionType.RETRY_ASSESSMENT,
        required_role="LEAD",
        verification_procedure="Verify target receives fresh assessment and last_seen_at is refreshed.",
    ),
    "FAIL_FINDING_STATE_INCONSISTENT": FailureKnowledgeEntry(
        failure_id="FAIL_FINDING_STATE_INCONSISTENT",
        title="Finding Closed Without Independent Verification",
        category=DiagnosticCategory.FINDINGS,
        severity=DiagnosticSeverity.HIGH,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="Finding marked VERIFIED_CLOSED without an associated VERIFIED_FIXED retest record.",
        likely_causes=[
            "[Hypothesis] Manual database update bypassed lifecycle state machine.",
            "[Hypothesis] Legacy migration artifact prior to verification gate enforcement.",
        ],
        supporting_evidence="Finding IDs, status history, missing RemediationVerification reference.",
        safe_next_steps="Trigger independent retest to validate target posture, or revert status to CONFIRMED.",
        recovery_action=RecoveryActionType.RETEST_REMEDIATION,
        required_role="LEAD",
        verification_procedure="Verify finding has an empirical RemediationVerification record.",
    ),
    "FAIL_RISK_SCORES_STALE": FailureKnowledgeEntry(
        failure_id="FAIL_RISK_SCORES_STALE",
        title="Contextual Risk Scores Outdated",
        category=DiagnosticCategory.SECURITY,
        severity=DiagnosticSeverity.LOW,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="Findings have risk scores computed with an obsolete scoring version or missing records.",
        likely_causes=[
            "[Hypothesis] New risk scoring engine (v2.0.0) deployed after finding detection.",
            "[Hypothesis] Asset criticality updated without cascading risk recalculation.",
        ],
        supporting_evidence="Finding IDs with scoring_version != 'v2.0.0' or score is NULL.",
        safe_next_steps="Recalculate derived risk scores using recorded contextual risk engine version.",
        recovery_action=RecoveryActionType.RECALCULATE_RISK_SCORES,
        required_role="LEAD",
        verification_procedure="Verify all findings have updated v2.0.0 contextual risk scores.",
    ),
    "FAIL_ADAPTER_TIMEOUT": FailureKnowledgeEntry(
        failure_id="FAIL_ADAPTER_TIMEOUT",
        title="Scanner Adapter Execution Deadline Exceeded",
        category=DiagnosticCategory.ADAPTERS,
        severity=DiagnosticSeverity.MEDIUM,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="Adapter subprocess exceeded timeout_seconds deadline without completing inspection.",
        likely_causes=[
            "[Hypothesis] Remote network socket read timeout or host packet dropping.",
            "[Hypothesis] Target IP/port unresponsive or protected by rate-limiting tarpit.",
            "[Hypothesis] Worker thread hung in infinite wait on raw TCP socket.",
        ],
        supporting_evidence="Job ID, target IP/URL, adapter name, configured timeout_seconds.",
        safe_next_steps="Terminate process tree, record TIMED_OUT status, verify target connectivity before retrying.",
        recovery_action=RecoveryActionType.RETRY_ASSESSMENT,
        required_role="TESTER",
        verification_procedure="Verify job status transitions to TIMED_OUT and worker process has exited.",
    ),
    "FAIL_DISK_WRITE_IO": FailureKnowledgeEntry(
        failure_id="FAIL_DISK_WRITE_IO",
        title="Evidence Storage Volume Write Failure",
        category=DiagnosticCategory.EVIDENCE,
        severity=DiagnosticSeverity.CRITICAL,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="Filesystem write operation to data or evidence storage directory failed with I/O error.",
        likely_causes=[
            "[Hypothesis] Storage disk partition is 100% full.",
            "[Hypothesis] Directory permission restrictions prevent service account write access.",
            "[Hypothesis] Host storage mounted read-only due to underlying filesystem error.",
        ],
        supporting_evidence="Mount point path, free disk bytes, OS errno.",
        safe_next_steps="Free disk space, check write permissions, verify /health/ready storage check.",
        recovery_action=None,
        required_role="ADMIN",
        verification_procedure="Verify /health/ready returns storage_writable=True.",
    ),
    "FAIL_CORRUPT_IPC_PAYLOAD": FailureKnowledgeEntry(
        failure_id="FAIL_CORRUPT_IPC_PAYLOAD",
        title="Worker Returned Corrupt or Malformed IPC Payload",
        category=DiagnosticCategory.JOBS,
        severity=DiagnosticSeverity.HIGH,
        confidence=DiagnosticConfidence.CONFIRMED,
        detection_condition="SubprocessWorkerRunner failed to parse JSON IPC stdout payload from worker process.",
        likely_causes=[
            "[Hypothesis] Worker process produced unexpected warning or stacktrace on stdout instead of JSON.",
            "[Hypothesis] Worker process terminated midway through writing JSON stream.",
            "[Hypothesis] Scanner adapter returned non-UTF8 or malformed binary stream.",
        ],
        supporting_evidence="Worker PID, exit code, raw stdout/stderr snippet in job summary_stats.",
        safe_next_steps="Inspect job summary_stats stderr, reject payload, mark job FAILED with CORRUPT_IPC_RESPONSE.",
        recovery_action=None,
        required_role="LEAD",
        verification_procedure="Verify corrupt payload was rejected at execution boundary without database corruption.",
    ),
}


class FailureKnowledgeBase:
    """Service class for querying failure catalog and matching diagnostic symptoms."""

    @classmethod
    def get_catalog(cls) -> Dict[str, Dict[str, Any]]:
        return {k: v.to_dict() for k, v in FAILURE_CATALOG.items()}

    @classmethod
    def lookup_failure(cls, failure_id: str) -> Optional[Dict[str, Any]]:
        entry = FAILURE_CATALOG.get(failure_id)
        return entry.to_dict() if entry else None

    @classmethod
    def find_by_category(cls, category: DiagnosticCategory) -> List[Dict[str, Any]]:
        return [
            entry.to_dict()
            for entry in FAILURE_CATALOG.values()
            if entry.category == category
        ]
