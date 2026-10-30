"""
Failure Classification, Capability Dependency, and Recovery Guidance Service (Prompt 52).

Provides:
1. Formal definitions of critical capabilities and their failure dependencies.
2. Operator-readable failure classifications with root-cause causal hypotheses.
3. Distinction between automated self-healing mechanisms and manual intervention requirements.
4. Actionable operational recovery playbooks for production resilience.
5. Invariant assurance: Critical evidence and audit trails are never discarded during recovery.
"""
import enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class CapabilityType(str, enum.Enum):
    AUTHENTICATION_RBAC = "AUTHENTICATION_RBAC"
    SCOPE_AUTHORIZATION = "SCOPE_AUTHORIZATION"
    ASSESSMENT_EXECUTION = "ASSESSMENT_EXECUTION"
    EVIDENCE_AND_AUDIT_PRESERVATION = "EVIDENCE_AND_AUDIT_PRESERVATION"
    REMEDIATION_APPROVAL_GOVERNANCE = "REMEDIATION_APPROVAL_GOVERNANCE"
    NOTIFICATION_DISPATCH = "NOTIFICATION_DISPATCH"
    THREAT_INTEL_ENRICHMENT = "THREAT_INTEL_ENRICHMENT"
    ANALYTICS_AND_GRAPH = "ANALYTICS_AND_GRAPH"


class CriticalityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"    # System must fail-closed or report 503 if unavailable
    SECONDARY = "SECONDARY"  # System degrades gracefully; primary workflows proceed


class FailureSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SystemCapabilityDefinition(BaseModel):
    capability: CapabilityType
    name: str
    criticality: CriticalityLevel
    dependencies: List[str]
    degradation_behavior: str
    fail_closed: bool
    description: str


class FailureClassification(BaseModel):
    code: str
    name: str
    category: str
    severity: FailureSeverity
    impact_scope: str
    can_auto_recover: bool
    auto_recovery_mechanism: Optional[str] = None
    requires_manual_intervention: bool
    manual_recovery_steps: List[str]
    operator_summary: str
    evidence_preserved: bool = True


# ------------------------------------------------------------------------------
# 1. Critical Capabilities and Failure Dependencies Catalog
# ------------------------------------------------------------------------------
CAPABILITY_CATALOG: Dict[CapabilityType, SystemCapabilityDefinition] = {
    CapabilityType.AUTHENTICATION_RBAC: SystemCapabilityDefinition(
        capability=CapabilityType.AUTHENTICATION_RBAC,
        name="Authentication & Role-Based Access Control",
        criticality=CriticalityLevel.CRITICAL,
        dependencies=["Primary Database (Users table)", "Cryptographic Secret Key"],
        degradation_behavior="Fail-closed (HTTP 401/403/503). Never bypass authentication.",
        fail_closed=True,
        description="Authenticates API clients, verifies user status, and enforces project role boundaries.",
    ),
    CapabilityType.SCOPE_AUTHORIZATION: SystemCapabilityDefinition(
        capability=CapabilityType.SCOPE_AUTHORIZATION,
        name="Scope & Execution Boundary Governance",
        criticality=CriticalityLevel.CRITICAL,
        dependencies=["Primary Database (ScopeTarget & ScopeExclusion tables)"],
        degradation_behavior="Fail-closed. Prohibits any assessment execution if scope cannot be independently verified.",
        fail_closed=True,
        description="Enforces strict CIDR, domain, and exclusion boundaries prior to any network or adapter dispatch.",
    ),
    CapabilityType.ASSESSMENT_EXECUTION: SystemCapabilityDefinition(
        capability=CapabilityType.ASSESSMENT_EXECUTION,
        name="Assessment Job Execution & Worker Supervision",
        criticality=CriticalityLevel.CRITICAL,
        dependencies=["Worker Subprocess Isolation", "Adapter Registry", "Primary Database"],
        degradation_behavior="Bounded execution deadlines. Marks jobs FAILED, TIMED_OUT, or PARTIAL; never claims false 100% completion.",
        fail_closed=True,
        description="Supervises isolated scanner subprocesses, enforces process timeouts, and ingests untrusted scanner output.",
    ),
    CapabilityType.EVIDENCE_AND_AUDIT_PRESERVATION: SystemCapabilityDefinition(
        capability=CapabilityType.EVIDENCE_AND_AUDIT_PRESERVATION,
        name="Forensic Evidence & Audit Trail Preservation",
        criticality=CriticalityLevel.CRITICAL,
        dependencies=["Primary Database", "Local Storage (data/evidence)", "Ed25519 Origin Signer"],
        degradation_behavior="Transactional write protection. Ingestion rolls back corrupt DB transactions without writing bad data; disk I/O errors trigger alert without discarding DB records.",
        fail_closed=True,
        description="Maintains raw payloads, SHA-256 hashes, Ed25519 digital signatures, and Merkle hash-chained custody logs.",
    ),
    CapabilityType.REMEDIATION_APPROVAL_GOVERNANCE: SystemCapabilityDefinition(
        capability=CapabilityType.REMEDIATION_APPROVAL_GOVERNANCE,
        name="Remediation Change Authorization & Separation of Duties",
        criticality=CriticalityLevel.CRITICAL,
        dependencies=["Primary Database", "Project Governance Policy"],
        degradation_behavior="Fail-closed. Automatic recovery cannot authorize changes, self-approve proposals, or bypass Separation of Duties.",
        fail_closed=True,
        description="Enforces dual-operator authorization and human-in-the-loop review for security changes.",
    ),
    CapabilityType.NOTIFICATION_DISPATCH: SystemCapabilityDefinition(
        capability=CapabilityType.NOTIFICATION_DISPATCH,
        name="Outbound Event & Notification Dispatch",
        criticality=CriticalityLevel.SECONDARY,
        dependencies=["External Webhook Endpoints", "SMTP Relay (Optional)"],
        degradation_behavior="Graceful degradation. Failures are recorded as FAILED or PENDING_RETRY with sliding-window dedup. Core findings and evidence remain 100% committed.",
        fail_closed=False,
        description="Dispatches external alerts to Slack, webhooks, or email without blocking finding lifecycle.",
    ),
    CapabilityType.THREAT_INTEL_ENRICHMENT: SystemCapabilityDefinition(
        capability=CapabilityType.THREAT_INTEL_ENRICHMENT,
        name="Threat Intelligence Correlation & CVE Feeds",
        criticality=CriticalityLevel.SECONDARY,
        dependencies=["CISA KEV, NVD CVE, EPSS feeds"],
        degradation_behavior="Graceful degradation. Missing or failed feed syncs mark feed status as ERROR/DEGRADED; existing finding severity and evidence are unaffected.",
        fail_closed=False,
        description="Correlates findings with external CVE feeds and EPSS exploit prediction metrics.",
    ),
    CapabilityType.ANALYTICS_AND_GRAPH: SystemCapabilityDefinition(
        capability=CapabilityType.ANALYTICS_AND_GRAPH,
        name="Knowledge Graph & Asset Inventory Analytics",
        criticality=CriticalityLevel.SECONDARY,
        dependencies=["Background Reconciliation Workers"],
        degradation_behavior="Graceful degradation. Analytical drift warnings logged; does not impede assessment execution.",
        fail_closed=False,
        description="Maintains graph relationship topology and derived asset discovery observations.",
    ),
}


# ------------------------------------------------------------------------------
# 2. Operator-Readable Failure Classifications & Recovery Instructions
# ------------------------------------------------------------------------------
FAILURE_CLASSIFICATIONS: Dict[str, FailureClassification] = {
    "DB_CONNECTION_INTERRUPTED": FailureClassification(
        code="DB_CONNECTION_INTERRUPTED",
        name="Transient Database Interruption",
        category="DATABASE_FAILURE",
        severity=FailureSeverity.CRITICAL,
        impact_scope="CORE_PLATFORM",
        can_auto_recover=True,
        auto_recovery_mechanism="Connection pool reconnect with bounded exponential backoff (max 3 retries, base delay 50ms).",
        requires_manual_intervention=False,
        manual_recovery_steps=[
            "1. Verify database process (SQLite file lock or PostgreSQL server service) is responsive.",
            "2. Check disk I/O and available file descriptors.",
            "3. If PostgreSQL, inspect pg_stat_activity for deadlock or connection pool saturation.",
        ],
        operator_summary="Database connection was temporarily interrupted during transaction execution. In-flight transaction was rolled back safely to prevent corruption.",
        evidence_preserved=True,
    ),
    "WORKER_ABRUPT_TERMINATION": FailureClassification(
        code="WORKER_ABRUPT_TERMINATION",
        name="Worker Subprocess Crashed or Terminated",
        category="WORKER_FAILURE",
        severity=FailureSeverity.HIGH,
        impact_scope="WORKFLOW_EXECUTION",
        can_auto_recover=True,
        auto_recovery_mechanism="Supervisory heartbeat recovery (recover_abandoned_jobs) cleans up stale lease and marks job FAILED with ABANDONED_EXECUTION_RECOVERED.",
        requires_manual_intervention=False,
        manual_recovery_steps=[
            "1. Review system event logs (Windows Event Viewer or dmesg) for out-of-memory (OOM) killer invocations.",
            "2. Check scanner adapter debug logs for segmentation faults or unhandled native library crashes.",
            "3. Re-queue the assessment job once host resource capacity is confirmed.",
        ],
        operator_summary="Scanner worker process exited unexpectedly or was terminated before completing execution. Concurrency slot has been reclaimed.",
        evidence_preserved=True,
    ),
    "ADAPTER_EXECUTION_TIMEOUT": FailureClassification(
        code="ADAPTER_EXECUTION_TIMEOUT",
        name="Scanner Adapter Deadline Exceeded",
        category="ADAPTER_TIMEOUT",
        severity=FailureSeverity.MEDIUM,
        impact_scope="WORKFLOW_EXECUTION",
        can_auto_recover=True,
        auto_recovery_mechanism="SubprocessWorkerRunner terminates process tree via Win32 Job Object / taskkill and transitions job to TIMED_OUT.",
        requires_manual_intervention=False,
        manual_recovery_steps=[
            "1. Verify network latency and target responsiveness to prevent socket read hangs.",
            "2. Adjust job timeout_seconds in assessment policy if target network requires larger inspection window.",
            "3. Check for intermediate firewall tarpits or IDS/IPS packet dropping.",
        ],
        operator_summary="Adapter execution exceeded configured timeout_seconds. Process tree terminated cleanly to avoid resource leakage.",
        evidence_preserved=True,
    ),
    "SECONDARY_WEBHOOK_OUTAGE": FailureClassification(
        code="SECONDARY_WEBHOOK_OUTAGE",
        name="Outbound Notification Webhook Unavailable",
        category="PROVIDER_FAILURE",
        severity=FailureSeverity.LOW,
        impact_scope="SECONDARY_INTEGRATION",
        can_auto_recover=True,
        auto_recovery_mechanism="Delivery record transitioned to FAILED; automatically eligible for bounded requeue (up to 3 attempts with exponential backoff).",
        requires_manual_intervention=False,
        manual_recovery_steps=[
            "1. Verify target webhook endpoint URL and TLS certificate validity.",
            "2. Inspect external receiver HTTP logs for 5xx errors or rate-limiting responses.",
            "3. Trigger retry_failed_notifications endpoint after target endpoint restoration.",
        ],
        operator_summary="External webhook server returned connection error or 5xx outage. Core findings and forensic evidence were committed without delay.",
        evidence_preserved=True,
    ),
    "EVIDENCE_DISK_WRITE_IO_ERROR": FailureClassification(
        code="EVIDENCE_DISK_WRITE_IO_ERROR",
        name="Storage Volume Disk Write Failure",
        category="STORAGE_FAILURE",
        severity=FailureSeverity.CRITICAL,
        impact_scope="EVIDENCE_PRESERVATION",
        can_auto_recover=False,
        auto_recovery_mechanism=None,
        requires_manual_intervention=True,
        manual_recovery_steps=[
            "1. Inspect storage volume free space (df -h or Windows Explorer).",
            "2. Verify filesystem read-write permissions for the backend service account on data/evidence.",
            "3. Expand disk volume or clean up temporary files, then run health readiness check.",
        ],
        operator_summary="Operating system rejected write operation to evidence storage directory. Manual administrator action required to free disk space or repair filesystem.",
        evidence_preserved=True,
    ),
    "MALFORMED_SCANNER_PAYLOAD": FailureClassification(
        code="MALFORMED_SCANNER_PAYLOAD",
        name="Malformed or Corrupt Scanner Response",
        category="MALFORMED_DATA",
        severity=FailureSeverity.HIGH,
        impact_scope="WORKFLOW_EXECUTION",
        can_auto_recover=False,
        auto_recovery_mechanism="Input boundary validation rejects corrupt payload, records schema validation error, and marks job FAILED (CORRUPT_IPC_RESPONSE).",
        requires_manual_intervention=True,
        manual_recovery_steps=[
            "1. Inspect raw IPC stderr snippet recorded in job summary_stats.",
            "2. Check if third-party scanner version changed its CLI or JSON output format.",
            "3. Update scanner adapter parser to support newer payload schema.",
        ],
        operator_summary="Worker returned invalid, truncated, or non-JSON output. Rejected at untrusted execution boundary to prevent database corruption.",
        evidence_preserved=True,
    ),
    "BACKGROUND_BATCH_INTERRUPTED": FailureClassification(
        code="BACKGROUND_BATCH_INTERRUPTED",
        name="Background Batch Operation Interrupted",
        category="TASK_INTERRUPTION",
        severity=FailureSeverity.MEDIUM,
        impact_scope="WORKFLOW_EXECUTION",
        can_auto_recover=True,
        auto_recovery_mechanism="Batch supervisor marks overall job PARTIAL, recording completed targets alongside failed targets honestly.",
        requires_manual_intervention=False,
        manual_recovery_steps=[
            "1. Review job summary_stats for lists of completed_targets vs. failed_targets.",
            "2. Dispatch a follow-up assessment targeting only the remaining incomplete targets.",
        ],
        operator_summary="Multi-target assessment sweep was cancelled or preempted midway. Completed target findings were preserved; incomplete targets reported honestly as PARTIAL.",
        evidence_preserved=True,
    ),
    "GOVERNANCE_SCOPE_DENIAL": FailureClassification(
        code="GOVERNANCE_SCOPE_DENIAL",
        name="Target Outside Authorized Scope",
        category="GOVERNANCE_DENIAL",
        severity=FailureSeverity.HIGH,
        impact_scope="SECURITY_GOVERNANCE",
        can_auto_recover=False,
        auto_recovery_mechanism=None,
        requires_manual_intervention=True,
        manual_recovery_steps=[
            "1. Contact Project Security Lead to review target authorization requirements.",
            "2. If legitimate, add target CIDR or domain to Project Scope Targets with documented authorization evidence.",
            "3. Verify that target does not match any active Scope Exclusions.",
        ],
        operator_summary="Preflight security boundary detected target outside authorized scope. Automatic recovery is strictly prohibited from bypassing scope controls.",
        evidence_preserved=True,
    ),
    "SCHEMA_MIGRATION_MISMATCH": FailureClassification(
        code="SCHEMA_MIGRATION_MISMATCH",
        name="Database Schema Revision Outdated",
        category="DATABASE_FAILURE",
        severity=FailureSeverity.CRITICAL,
        impact_scope="CORE_PLATFORM",
        can_auto_recover=False,
        auto_recovery_mechanism=None,
        requires_manual_intervention=True,
        manual_recovery_steps=[
            "1. Halt active worker dispatches.",
            "2. Execute 'alembic upgrade head' in the backend environment.",
            "3. Verify alembic_version matches current repository head.",
            "4. Run /health/ready probe to confirm schema initialization.",
        ],
        operator_summary="Database schema version is out of sync with application model definitions. Requires manual database migration.",
        evidence_preserved=True,
    ),
}


class FailureClassificationService:
    """
    Operator-facing classification and recovery guidance service.
    """

    @classmethod
    def get_capabilities(cls) -> Dict[str, Dict[str, Any]]:
        return {k.value: v.model_dump() for k, v in CAPABILITY_CATALOG.items()}

    @classmethod
    def get_classifications(cls) -> Dict[str, Dict[str, Any]]:
        return {k: v.model_dump() for k, v in FAILURE_CLASSIFICATIONS.items()}

    @classmethod
    def classify_failure(cls, failure_category_or_code: str) -> FailureClassification:
        normalized = failure_category_or_code.strip().upper()

        # Direct match
        if normalized in FAILURE_CLASSIFICATIONS:
            return FAILURE_CLASSIFICATIONS[normalized]

        # Fuzzy matching based on key terms
        if "DB" in normalized or "DATABASE" in normalized or "SQL" in normalized or "TRANSACTION" in normalized:
            return FAILURE_CLASSIFICATIONS["DB_CONNECTION_INTERRUPTED"]
        if "WORKER" in normalized or "CRASH" in normalized or "ABANDONED" in normalized:
            return FAILURE_CLASSIFICATIONS["WORKER_ABRUPT_TERMINATION"]
        if "TIMEOUT" in normalized or "DEADLINE" in normalized:
            return FAILURE_CLASSIFICATIONS["ADAPTER_EXECUTION_TIMEOUT"]
        if "WEBHOOK" in normalized or "NOTIFICATION" in normalized or "PROVIDER" in normalized:
            return FAILURE_CLASSIFICATIONS["SECONDARY_WEBHOOK_OUTAGE"]
        if "DISK" in normalized or "STORAGE" in normalized or "FILE" in normalized:
            return FAILURE_CLASSIFICATIONS["EVIDENCE_DISK_WRITE_IO_ERROR"]
        if "CORRUPT" in normalized or "MALFORMED" in normalized or "PARSE" in normalized or "SCHEMA" in normalized:
            return FAILURE_CLASSIFICATIONS["MALFORMED_SCANNER_PAYLOAD"]
        if "SCOPE" in normalized or "DENIED" in normalized or "UNAUTHORIZED" in normalized:
            return FAILURE_CLASSIFICATIONS["GOVERNANCE_SCOPE_DENIAL"]

        # Default fallback classification
        return FailureClassification(
            code=normalized,
            name=f"Operational Failure ({normalized})",
            category="GENERAL_OPERATIONAL",
            severity=FailureSeverity.MEDIUM,
            impact_scope="WORKFLOW_EXECUTION",
            can_auto_recover=False,
            requires_manual_intervention=True,
            manual_recovery_steps=[
                f"1. Review system diagnostics for failure category '{normalized}'.",
                "2. Check service logs for full exception traceback.",
                "3. Contact system administrator if problem persists across worker restarts.",
            ],
            operator_summary=f"Encountered operational failure classified as '{normalized}'.",
            evidence_preserved=True,
        )

    @classmethod
    def get_operator_playbook(cls, code: str) -> Dict[str, Any]:
        classification = cls.classify_failure(code)
        return {
            "classification": classification.model_dump(),
            "immediate_actions": classification.manual_recovery_steps if classification.requires_manual_intervention else [
                "Automated self-healing is active. Monitor recovery metrics."
            ],
            "evidence_safety": "All collected evidence and audit logs are preserved in immutable storage.",
        }
