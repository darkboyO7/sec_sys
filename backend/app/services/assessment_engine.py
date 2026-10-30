import logging
import json
import hashlib
import math
import random
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple, List
from sqlalchemy.orm import Session

logger = logging.getLogger("vapt.assessment")
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingEvidence,
)
from app.services.assessment_state_machine import AssessmentStateMachine
from app.services.scope_engine import ScopeEngine
from app.services.scanner_adapters.base import (
    AdapterRegistry,
    PERMITTED_EVIDENCE_TYPES,
)
from app.services.scanner_adapters.local_fixture_adapter import LocalFixtureAdapter
from app.services.audit_service import AuditService
from app.services.finding_deduplication_service import FindingDeduplicationService
from app.core.config import settings
from app.services.subprocess_worker_runner import SubprocessWorkerRunner
from app.worker.ipc_schemas import WorkerIPCRequest


class AssessmentExecutionEngine:
    """
    Execution Boundary Controller for Assessment Jobs.
    Enforces typed, versioned job contracts, preflight re-validation,
    scope snapshot integrity, adapter capability discovery, worker heartbeats,
    and a normalized untrusted evidence boundary.
    """

    SUPPORTED_POLICY_VERSION = "2026.1"

    @classmethod
    def compute_scope_snapshot_and_digest(
        cls,
        scope_eval: Dict[str, Any],
        policy_version: str = "2026.1",
    ) -> Tuple[Dict[str, Any], str]:
        """
        Creates an immutable, canonicalized snapshot of the authorization decision and computes its SHA-256 digest.
        """
        rule = scope_eval.get("matched_rule") or {}
        snapshot = {
            "normalized_target": scope_eval.get("normalized_target"),
            "status": scope_eval.get("status"),
            "matched_rule_id": rule.get("id"),
            "target_type": rule.get("target_type"),
            "target_value": rule.get("target_value"),
            "authorization_evidence": rule.get("evidence"),
            "expires_at": rule.get("expires_at"),
            "policy_version": policy_version,
        }
        canonical_json = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        return snapshot, digest

    @classmethod
    def preflight_and_claim_job(
        cls,
        db: Session,
        job_id: str,
        worker_id: str = "worker-01",
        now: Optional[datetime] = None,
        client_ip: Optional[str] = None,
    ) -> AssessmentJob:
        """
        Executes strict preflight re-validation at the execution boundary before worker execution:
        1. Scope & authorization re-validation against database.
        2. Scope snapshot tampering verification (digest match).
        3. Adapter capability and profile verification.
        4. Policy version verification.
        Fails closed on any discrepancy, transitioning the job to REJECTED.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
        if not job:
            raise ValueError(f"Assessment job '{job_id}' not found.")

        # Concurrency safety: Only QUEUED, READY, or PREFLIGHT (if claimed by this worker) can proceed
        if job.status not in (AssessmentStatus.QUEUED, AssessmentStatus.READY, AssessmentStatus.PREFLIGHT):
            return job

        if job.status == AssessmentStatus.PREFLIGHT and job.claimed_by != worker_id:
            # Claimed by a different worker
            return job

        # 1. State transition to PREFLIGHT using atomic conditional update
        if job.status == AssessmentStatus.QUEUED:
            rows = db.query(AssessmentJob).filter(
                AssessmentJob.id == job_id,
                AssessmentJob.status == AssessmentStatus.QUEUED,
            ).update({
                AssessmentJob.status: AssessmentStatus.PREFLIGHT,
                AssessmentJob.claimed_by: worker_id,
                AssessmentJob.preflight_at: now,
                AssessmentJob.progress_pct: 10,
            }, synchronize_session="fetch")
            db.commit()
            if rows == 0:
                # Concurrently claimed by another worker or state changed
                db.refresh(job)
                return job
            db.refresh(job)

        # ----------------------------------------------------------------------
        # CHECK 0: Tenant & Creator Authorization Validity at Execution Boundary
        # ----------------------------------------------------------------------
        from app.models.project import Project, ProjectMember
        from app.models.user import User, SystemRole

        project = db.query(Project).filter(Project.id == job.project_id).first()
        if not project or not project.is_active:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.REJECTED,
                error_message="Preflight tenant failure: Project workspace is inactive, archived, or does not exist.",
                failure_category="WORKSPACE_INACTIVE",
                now=now,
            )
            db.commit()
            AuditService.record_event(
                db=db,
                action="ASSESSMENT_PREFLIGHT_DENIED_WORKSPACE",
                target_type="assessment_job",
                target_id=job.id,
                project_id=job.project_id,
                actor_id=job.created_by_id,
                outcome="DENIED",
                ip_address=client_ip,
                details={"failure_category": "WORKSPACE_INACTIVE"},
            )
            return job

        creator = db.query(User).filter(User.id == job.created_by_id).first()
        if not creator or not creator.is_active:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.REJECTED,
                error_message="Preflight authorization failure: Job creator account is deactivated or deleted.",
                failure_category="CREATOR_ACCOUNT_INACTIVE",
                now=now,
            )
            db.commit()
            AuditService.record_event(
                db=db,
                action="ASSESSMENT_PREFLIGHT_DENIED_CREATOR",
                target_type="assessment_job",
                target_id=job.id,
                project_id=job.project_id,
                actor_id=job.created_by_id,
                outcome="DENIED",
                ip_address=client_ip,
                details={"failure_category": "CREATOR_ACCOUNT_INACTIVE"},
            )
            return job

        if creator.system_role != SystemRole.ADMIN:
            membership = (
                db.query(ProjectMember)
                .filter(ProjectMember.project_id == job.project_id, ProjectMember.user_id == job.created_by_id)
                .first()
            )
            if not membership:
                AssessmentStateMachine.transition(
                    job=job,
                    new_status=AssessmentStatus.REJECTED,
                    error_message="Preflight authorization failure: Job creator project membership was revoked.",
                    failure_category="CREATOR_MEMBERSHIP_REVOKED",
                    now=now,
                )
                db.commit()
                AuditService.record_event(
                    db=db,
                    action="ASSESSMENT_PREFLIGHT_DENIED_MEMBERSHIP_REVOKED",
                    target_type="assessment_job",
                    target_id=job.id,
                    project_id=job.project_id,
                    actor_id=job.created_by_id,
                    outcome="DENIED",
                    ip_address=client_ip,
                    details={"failure_category": "CREATOR_MEMBERSHIP_REVOKED"},
                )
                return job

        # ----------------------------------------------------------------------
        # CHECK 1: Scope & Authorization Re-validation at Execution Boundary
        # ----------------------------------------------------------------------
        scope_eval = ScopeEngine.validate_target_in_scope(
            db=db,
            project_id=job.project_id,
            target=job.target_input,
            now=now,
        )

        if not scope_eval["is_authorized"]:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.REJECTED,
                error_message=f"Preflight execution boundary denial: {scope_eval['reason']}",
                failure_category="SCOPE_AUTHORIZATION_DENIED",
                now=now,
            )
            job.summary_stats = {
                "decision": "DENIED",
                "scope_status": scope_eval["status"],
                "reason": scope_eval["reason"],
            }
            db.commit()

            AuditService.record_event(
                db=db,
                action="ASSESSMENT_PREFLIGHT_DENIED",
                target_type="assessment_job",
                target_id=job.id,
                project_id=job.project_id,
                actor_id=job.created_by_id,
                outcome="DENIED",
                ip_address=client_ip,
                details={
                    "target_input": job.target_input,
                    "scope_status": scope_eval["status"],
                    "reason": scope_eval["reason"],
                    "failure_category": "SCOPE_AUTHORIZATION_DENIED",
                },
            )
            return job

        # Synchronize scope-authorized private/loopback execution permissions into config
        cfg = dict(job.config or {})
        if scope_eval.get('is_loopback_authorized') or '127.0.0.1' in job.target_input or 'localhost' in job.target_input:
            cfg['allow_loopback'] = True
        if scope_eval.get('is_private_authorized'):
            cfg['allow_private'] = True
        job.config = cfg

        # ----------------------------------------------------------------------
        # CHECK 2: Scope Snapshot Tampering Verification
        # ----------------------------------------------------------------------
        if job.scope_snapshot and job.scope_snapshot_digest:
            canonical_json = json.dumps(job.scope_snapshot, sort_keys=True, separators=(",", ":"))
            computed_digest = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
            if computed_digest != job.scope_snapshot_digest:
                AssessmentStateMachine.transition(
                    job=job,
                    new_status=AssessmentStatus.REJECTED,
                    error_message="Preflight integrity failure: Scope snapshot digest does not match recorded digest.",
                    failure_category="SCOPE_SNAPSHOT_TAMPERING_DETECTED",
                    now=now,
                )
                db.commit()

                AuditService.record_event(
                    db=db,
                    action="ASSESSMENT_PREFLIGHT_INTEGRITY_VIOLATION",
                    target_type="assessment_job",
                    target_id=job.id,
                    project_id=job.project_id,
                    actor_id=job.created_by_id,
                    outcome="DENIED",
                    ip_address=client_ip,
                    details={
                        "failure_category": "SCOPE_SNAPSHOT_TAMPERING_DETECTED",
                        "recorded_digest": job.scope_snapshot_digest,
                        "computed_digest": computed_digest,
                    },
                )
                return job

        # ----------------------------------------------------------------------
        # CHECK 3: Scanner Adapter Approval & Profile Capabilities
        # ----------------------------------------------------------------------
        adapter = AdapterRegistry.get(job.adapter_name)
        if not adapter:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.REJECTED,
                error_message=f"Preflight capability failure: Scanner adapter '{job.adapter_name}' is not registered or approved.",
                failure_category="UNSUPPORTED_ADAPTER",
                now=now,
            )
            db.commit()

            AuditService.record_event(
                db=db,
                action="ASSESSMENT_PREFLIGHT_DENIED",
                target_type="assessment_job",
                target_id=job.id,
                project_id=job.project_id,
                actor_id=job.created_by_id,
                outcome="DENIED",
                ip_address=client_ip,
                details={
                    "adapter_name": job.adapter_name,
                    "failure_category": "UNSUPPORTED_ADAPTER",
                },
            )
            return job

        # Validate adapter configuration and profile support
        config_valid, config_err = adapter.validate_config(job.config)
        if not config_valid:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.REJECTED,
                error_message=f"Preflight configuration failure: {config_err}",
                failure_category="INVALID_ADAPTER_CONFIGURATION",
                now=now,
            )
            db.commit()
            return job

        # ----------------------------------------------------------------------
        # CHECK 4: Policy Version Compatibility
        # ----------------------------------------------------------------------
        if job.policy_version != cls.SUPPORTED_POLICY_VERSION:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.REJECTED,
                error_message=f"Preflight policy failure: Policy version '{job.policy_version}' is incompatible with engine version '{cls.SUPPORTED_POLICY_VERSION}'.",
                failure_category="POLICY_VERSION_MISMATCH",
                now=now,
            )
            db.commit()
            return job

        # Preflight passed -> READY -> RUNNING (Atomic worker claim using conditional update)
        rows_claimed = db.query(AssessmentJob).filter(
            AssessmentJob.id == job.id,
            AssessmentJob.status.in_([AssessmentStatus.PREFLIGHT, AssessmentStatus.READY]),
        ).update({
            AssessmentJob.status: AssessmentStatus.RUNNING,
            AssessmentJob.claimed_by: worker_id,
            AssessmentJob.lock_version: AssessmentJob.lock_version + 1,
            AssessmentJob.started_at: now,
            AssessmentJob.heartbeat_at: now,
            AssessmentJob.progress_pct: 30,
        }, synchronize_session="fetch")
        db.commit()
        db.refresh(job)
        if rows_claimed == 0:
            # Concurrently claimed by another worker or state changed
            return job
        return job

    @classmethod
    def cancel_job(
        cls,
        db: Session,
        job_id: str,
        operator_id: Optional[str] = None,
        reason: str = "Assessment cancelled by operator request.",
        now: Optional[datetime] = None,
    ) -> AssessmentJob:
        """Atomically transitions an assessment job to CANCELLED state and records timestamp."""
        if now is None:
            now = datetime.now(timezone.utc)
        job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
        if not job:
            raise ValueError(f"Assessment job '{job_id}' not found.")
        AssessmentStateMachine.transition(
            job=job,
            new_status=AssessmentStatus.CANCELLED,
            error_message=reason,
            failure_category="CANCELLED_BY_OPERATOR",
            now=now,
        )
        job.cancellation_requested_at = now
        db.commit()
        db.refresh(job)
        return job

    @classmethod
    def execute_job(
        cls,
        db: Session,
        job_id: str,
        worker_id: str = "worker-01",
        now: Optional[datetime] = None,
        client_ip: Optional[str] = None,
        execution_attempt: Optional[int] = None,
    ) -> AssessmentJob:
        if now is None:
            now = datetime.now(timezone.utc)

        job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
        if not job:
            raise ValueError(f"Assessment job '{job_id}' not found.")

        # Check if already in terminal state
        if job.status in (
            AssessmentStatus.COMPLETED,
            AssessmentStatus.FAILED,
            AssessmentStatus.CANCELLED,
            AssessmentStatus.REJECTED,
            AssessmentStatus.TIMED_OUT,
            AssessmentStatus.PARTIAL,
        ):
            return job

        # Fencing token check: Stale worker attempting to execute an obsolete attempt
        if execution_attempt is not None and (
            job.attempt_count != execution_attempt
            or job.status != AssessmentStatus.RUNNING
            or (job.claimed_by and job.claimed_by != worker_id)
        ):
            logger.warning(
                f"Fencing token check rejected worker '{worker_id}' attempt {execution_attempt}: "
                f"Job '{job.id}' status is '{job.status.value}', current attempt is {job.attempt_count}, claimed_by '{job.claimed_by}'."
            )
            return job

        # Step 1: Preflight re-validation and atomic claim
        if job.status in (AssessmentStatus.QUEUED, AssessmentStatus.PREFLIGHT, AssessmentStatus.READY):
            job = cls.preflight_and_claim_job(
                db=db,
                job_id=job.id,
                worker_id=worker_id,
                now=now,
                client_ip=client_ip,
            )
            if job.status in (AssessmentStatus.REJECTED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED):
                return job

        # Step 2: Handle cancellation requested before execution
        if job.status == AssessmentStatus.CANCELLATION_REQUESTED:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.CANCELLED,
                error_message="Assessment cancelled by operator request.",
                failure_category="CANCELLED_BY_OPERATOR",
                now=now,
            )
            db.commit()
            return job

        # Mutual exclusion: Only the worker that owns this execution attempt may execute
        if job.status != AssessmentStatus.RUNNING:
            return job
        if job.claimed_by and job.claimed_by != worker_id:
            return job

        execution_attempt = job.attempt_count

        # Step 3: Resolve Adapter
        adapter = AdapterRegistry.get(job.adapter_name)
        if not adapter:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.FAILED,
                error_message=f"Unknown or unapproved scanner adapter: {job.adapter_name}",
                failure_category="UNSUPPORTED_ADAPTER",
                now=now,
            )
            db.commit()
            return job

        # Step 4: Execute Adapter with Cancellation and Timeout Check
        def check_cancellation() -> bool:
            # Query fresh job status from database
            fresh = db.query(AssessmentJob.status).filter(AssessmentJob.id == job.id).first()
            return fresh is not None and fresh[0] in (
                AssessmentStatus.CANCELLATION_REQUESTED,
                AssessmentStatus.CANCELLED,
                AssessmentStatus.TIMED_OUT,
                AssessmentStatus.FAILED,
            )

        try:
            AssessmentStateMachine.record_heartbeat(job, now=now)

            # Prompt 52: Deterministic Fault Injection Hooks (Test-Only)
            from app.core.fault_injection import (
                FaultInjector,
                AdapterTimeoutError,
                WorkerTerminationError,
                DatabaseInterruptionError,
                MalformedResponseError,
            )
            FaultInjector.maybe_inject("adapter:execute", {"adapter_name": job.adapter_name, "job_id": job.id})
            FaultInjector.maybe_inject("adapter:timeout", {"adapter_name": job.adapter_name, "job_id": job.id})

            # Injected Worker Termination: Simulates abrupt worker crash mid-execution
            # Sets heartbeat back into the past and leaves job in RUNNING state for recovery engine
            if FaultInjector.is_injection_permitted():
                try:
                    FaultInjector.maybe_inject("worker:termination", {"job_id": job.id})
                except WorkerTerminationError as wte:
                    job.heartbeat_at = now - timedelta(seconds=job.timeout_seconds + 60)
                    db.commit()
                    logger.warning(f"Injected worker termination: Job '{job.id}' left in RUNNING status.")
                    raise wte

            if getattr(settings, "EXECUTION_MODE", "SUBPROCESS") == "SUBPROCESS":
                runner = SubprocessWorkerRunner()
                ipc_req = WorkerIPCRequest(
                    job_id=job.id,
                    project_id=job.project_id,
                    worker_id=worker_id,
                    attempt_count=execution_attempt,
                    target_input=job.target_input,
                    adapter_name=job.adapter_name,
                    adapter_version=job.adapter_version,
                    policy_version=job.policy_version,
                    config=job.config or {},
                    timeout_seconds=job.timeout_seconds,
                    auth_context={
                        "authorization_reference": job.authorization_reference,
                        "scope_snapshot_digest": job.scope_snapshot_digest,
                    },
                )

                def on_worker_spawn(pid: int) -> None:
                    job.worker_pid = pid
                    try:
                        db.commit()
                    except Exception:
                        pass

                result = runner.run_job(
                    request=ipc_req,
                    cancellation_check=check_cancellation,
                    on_spawn=on_worker_spawn,
                )
            else:
                result = adapter.execute(
                    target=job.target_input,
                    config=job.config,
                    cancellation_check=check_cancellation,
                )
        except WorkerTerminationError:
            # Return job in RUNNING state to simulate worker crash before status transition
            return job
        except AdapterTimeoutError as te:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.TIMED_OUT,
                error_message=f"Adapter execution deadline exceeded: {str(te)}",
                failure_category="WORKER_PROCESS_TIMEOUT",
                now=now,
            )
            db.commit()
            return job
        except MalformedResponseError as me:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.FAILED,
                error_message=f"Malformed scanner payload rejected at execution boundary: {str(me)}",
                failure_category="CORRUPT_IPC_RESPONSE",
                now=now,
            )
            db.commit()
            return job
        except Exception as e:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.FAILED,
                error_message=f"Adapter execution exception: {str(e)}",
                failure_category="DRIVER_EXCEPTION",
                now=now,
            )
            db.commit()
            return job

        # Step 5: Check if job was cancelled or reassigned during execution
        db.refresh(job)
        if job.status in AssessmentStateMachine.TERMINAL_STATUSES:
            return job

        if job.status == AssessmentStatus.CANCELLATION_REQUESTED:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.CANCELLED,
                error_message="Assessment cancelled by operator request during execution.",
                failure_category="CANCELLED_BY_OPERATOR",
                now=now,
            )
            db.commit()
            return job

        if job.status != AssessmentStatus.RUNNING or job.attempt_count != execution_attempt or (job.claimed_by and job.claimed_by != worker_id):
            # Stale worker execution, attempt count mismatch, or ownership loss: discard execution results safely
            return job

        # ----------------------------------------------------------------------
        # Step 6: Normalized Untrusted Evidence Boundary (Transactional)
        # ----------------------------------------------------------------------
        persisted_findings_count = 0
        persisted_evidence_count = 0
        persisted_findings_list: List[AssessmentFinding] = []
        canonical_findings = []

        # Bound maximum ingested findings to 50
        raw_findings = result.findings[:50]

        try:
            with db.begin_nested():
                # Prompt 52: Injected DB interruption hook
                FaultInjector.maybe_inject("db:commit:findings", {"job_id": job.id})

                for raw_finding in raw_findings:
                    # Validate CVSS numeric sanity (sanitize non-finite/NaN/inf)
                    safe_cvss = raw_finding.cvss_score
                    if safe_cvss is not None:
                        if math.isnan(safe_cvss) or math.isinf(safe_cvss) or safe_cvss < 0.0 or safe_cvss > 10.0:
                            safe_cvss = None

                    finding = AssessmentFinding(
                        job_id=job.id,
                        project_id=job.project_id,
                        target_value=job.target_input,
                        title=raw_finding.title[:255],
                        description=raw_finding.description[:10000],
                        severity=raw_finding.severity,
                        confidence=raw_finding.confidence,
                        vuln_id=raw_finding.vuln_id[:100] if raw_finding.vuln_id else None,
                        cvss_score=safe_cvss,
                        is_simulated=result.is_simulated,
                        reproduction_steps=raw_finding.reproduction_steps[:10000],
                        created_at=now,
                    )
                    db.add(finding)
                    db.flush()  # Acquire finding.id
                    persisted_findings_count += 1
                    persisted_findings_list.append(finding)

                    for raw_ev in raw_finding.evidence_items:
                        # Validate evidence type against permitted set
                        ev_type = raw_ev.evidence_type.strip().upper()
                        if ev_type not in PERMITTED_EVIDENCE_TYPES:
                            ev_type = "CONFIG_AUDIT"

                        authoritative_hash = hashlib.sha256(raw_ev.payload.encode("utf-8")).hexdigest()
                        evidence = FindingEvidence(
                            finding_id=finding.id,
                            evidence_type=ev_type,
                            payload=raw_ev.payload,
                            sha256_hash=authoritative_hash,
                            raw_sha256_hash=raw_ev.raw_sha256_hash or authoritative_hash,
                            is_truncated=raw_ev.is_truncated,
                            observed_at=raw_ev.observed_at,
                        )
                        db.add(evidence)
                        persisted_evidence_count += 1

                # Phase 3: Deduplicate and correlate into canonical VulnerabilityFindings
                # Invariant: Ingestion never auto-closes or marks findings FALSE_POSITIVE or REMEDIATED.
                if persisted_findings_list:
                    canonical_findings = FindingDeduplicationService.ingest_job_findings(
                        job=job,
                        raw_findings=persisted_findings_list,
                        db=db,
                        client_ip=client_ip,
                    )
            db.commit()
        except Exception as e:
            target_job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first() or job
            AssessmentStateMachine.transition(
                job=target_job,
                new_status=AssessmentStatus.FAILED,
                error_message=f"Evidence persistence transaction rollback: {str(e)}",
                failure_category="INGESTION_TRANSACTION_FAILED",
                now=now,
            )
            db.commit()
            return target_job

        # Step 7: Finalize State Machine based on execution outcome
        # Fencing Token & Concurrency Invariant:
        # Verify worker still owns this execution attempt and that the job was not cancelled or reclaimed
        fresh_job = db.query(AssessmentJob).filter(AssessmentJob.id == job.id).first()
        if not fresh_job or fresh_job.status != AssessmentStatus.RUNNING or fresh_job.attempt_count != execution_attempt or (fresh_job.claimed_by and fresh_job.claimed_by != worker_id):
            logger.warning(
                f"Fencing token check failed for worker '{worker_id}' attempt {execution_attempt}: "
                f"Job '{job.id}' status is '{fresh_job.status if fresh_job else 'DELETED'}' "
                f"claimed by '{fresh_job.claimed_by if fresh_job else None}'. Obsolete worker result discarded."
            )
            return fresh_job or job

        job.is_simulated = result.is_simulated
        job.summary_stats = {
            "status_summary": result.status_summary,
            "findings_count": persisted_findings_count,
            "evidence_count": persisted_evidence_count,
            "errors_count": len(result.errors),
            "errors": result.errors,
            "duration_ms": result.execution_duration_ms,
            "is_simulated": result.is_simulated,
            "policy_version": job.policy_version,
            "adapter_name": job.adapter_name,
            "adapter_version": job.adapter_version,
        }

        if not result.success:
            if result.failure_category == "WORKER_PROCESS_TIMEOUT":
                final_status = AssessmentStatus.TIMED_OUT
                error_msg = f"Assessment timed out: {'; '.join(result.errors)}"
                failure_cat = "WORKER_PROCESS_TIMEOUT"
            elif result.failure_category == "CANCELLED_BY_OPERATOR":
                final_status = AssessmentStatus.CANCELLED
                error_msg = f"Assessment cancelled: {'; '.join(result.errors)}"
                failure_cat = "CANCELLED_BY_OPERATOR"
            elif persisted_findings_count > 0:
                final_status = AssessmentStatus.PARTIAL
                error_msg = f"Partial failure: {'; '.join(result.errors)}"
                failure_cat = result.failure_category or "PARTIAL_MODULE_FAILURE"
            else:
                final_status = AssessmentStatus.FAILED
                error_msg = f"Assessment failed: {'; '.join(result.errors)}"
                failure_cat = result.failure_category or "ADAPTER_EXECUTION_FAILURE"
        elif len(result.errors) > 0:
            final_status = AssessmentStatus.PARTIAL
            error_msg = f"Completed with warnings: {'; '.join(result.errors)}"
            failure_cat = "EXECUTION_WARNINGS"
        else:
            final_status = AssessmentStatus.COMPLETED
            error_msg = None
            failure_cat = None

        AssessmentStateMachine.transition(
            job=job,
            new_status=final_status,
            error_message=error_msg,
            failure_category=failure_cat,
            now=now,
        )

        # Step 8: Reconcile Asset Inventory and auto-populate Security Knowledge Graph
        try:
            FaultInjector.maybe_inject("secondary:asset_graph", {"job_id": job.id})
            cls.integrate_assessment_assets_and_graph(
                job=job,
                canonical_findings=canonical_findings,
                db=db,
                client_ip=client_ip,
            )
        except Exception as e:
            import logging
            logging.getLogger("vapt.assessment").warning(
                f"Asset/Graph integration warning for job {job.id}: {e}", exc_info=True
            )
            # Record secondary service degradation without discarding findings or audit logs
            cur_stats = dict(job.summary_stats or {})
            deg_list = list(cur_stats.get("secondary_degradations", []))
            deg_list.append(f"Asset/Graph integration degraded: {str(e)}")
            cur_stats["secondary_degradations"] = deg_list
            job.summary_stats = cur_stats

        db.commit()
        db.refresh(job)

        # Step 9: Record Comprehensive Audit Log
        AuditService.record_event(
            db=db,
            action="ASSESSMENT_EXECUTION_COMPLETE",
            target_type="assessment_job",
            target_id=job.id,
            project_id=job.project_id,
            actor_id=job.created_by_id,
            outcome="SUCCESS" if final_status == AssessmentStatus.COMPLETED else "FAILURE" if final_status == AssessmentStatus.FAILED else "PARTIAL",
            details={
                "target_input": job.target_input,
                "final_status": final_status.value,
                "findings_count": persisted_findings_count,
                "evidence_count": persisted_evidence_count,
                "is_simulated": job.is_simulated,
                "policy_version": job.policy_version,
                "failure_category": job.failure_category,
            },
        )

        return job

    @classmethod
    def recover_abandoned_jobs(
        cls,
        db: Session,
        project_id: Optional[str] = None,
        max_stale_seconds: int = 120,
        now: Optional[datetime] = None,
    ) -> List[AssessmentJob]:
        """
        Recovers abandoned jobs left in non-terminal active states (RUNNING, PREFLIGHT, READY).
        Transitions stale un-heartbeated jobs to FAILED with category ABANDONED_EXECUTION_RECOVERED.
        Prevents hanging jobs across worker crashes or node failures.
        Respects project isolation when project_id is provided.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=max_stale_seconds)

        query = db.query(AssessmentJob).filter(
            AssessmentJob.status.in_([AssessmentStatus.RUNNING, AssessmentStatus.PREFLIGHT, AssessmentStatus.READY]),
        )
        if project_id:
            query = query.filter(AssessmentJob.project_id == project_id)

        candidates = query.all()

        recovered = []
        for job in candidates:
            last_activity = job.heartbeat_at or job.started_at or job.preflight_at or job.queued_at
            if last_activity:
                if last_activity.tzinfo is None:
                    last_activity = last_activity.replace(tzinfo=timezone.utc)
                if last_activity < cutoff:
                    AssessmentStateMachine.transition(
                        job=job,
                        new_status=AssessmentStatus.FAILED,
                        error_message=f"Execution abandoned: no worker activity reported within {max_stale_seconds}s threshold.",
                        failure_category="ABANDONED_EXECUTION_RECOVERED",
                        now=now,
                    )
                    recovered.append(job)
        if recovered:
            db.commit()
        return recovered

    @classmethod
    def calculate_backoff_delay(
        cls,
        attempt: int,
        base_delay: float = 2.0,
        max_delay: float = 60.0,
        jitter: bool = True,
    ) -> float:
        """
        Calculates bounded exponential backoff with full jitter:
        exponential = min(max_delay, base_delay * (2 ** (attempt - 1)))
        delay = random.uniform(0.5 * exponential, exponential) if jitter else exponential
        """
        clamped_attempt = max(1, attempt)
        exponential_delay = min(max_delay, base_delay * (2.0 ** (clamped_attempt - 1)))
        if jitter:
            return round(random.uniform(0.5 * exponential_delay, exponential_delay), 3)
        return round(exponential_delay, 3)

    @classmethod
    def retry_job(
        cls,
        db: Session,
        job_id: str,
        now: Optional[datetime] = None,
    ) -> Tuple[bool, AssessmentJob, str]:
        """
        Re-queues a failed operational job if attempt_count < max_retries.
        Enforces retry limits with bounded exponential backoff and jitter to prevent infinite loops.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job '{job_id}' not found.")

        if job.status != AssessmentStatus.FAILED:
            return False, job, f"Cannot retry job in status '{job.status.value}'. Only FAILED jobs may be retried."

        if job.attempt_count >= job.max_retries:
            return False, job, f"Job has reached maximum allowed execution attempts ({job.max_retries})."

        # Non-retryable governance failures cannot be retried
        NON_RETRYABLE_CATEGORIES = {
            "SCOPE_AUTHORIZATION_DENIED",
            "SCOPE_SNAPSHOT_TAMPERING_DETECTED",
            "POLICY_VERSION_MISMATCH",
            "UNSUPPORTED_ADAPTER",
            "INVALID_ADAPTER_CONFIGURATION",
        }
        if job.failure_category in NON_RETRYABLE_CATEGORIES:
            return False, job, f"Job failed with non-retryable governance failure '{job.failure_category}'."

        # Execution boundary check: Re-verify target is still authorized by scope policy before re-queueing
        from app.services.scope_engine import ScopeEngine
        from app.models.scope import ScopeTarget, ScopeExclusion
        has_scope_records = db.query(ScopeTarget).filter(ScopeTarget.project_id == job.project_id).first() is not None or \
                            db.query(ScopeExclusion).filter(ScopeExclusion.project_id == job.project_id).first() is not None
        if has_scope_records:
            scope_eval = ScopeEngine.validate_target_in_scope(
                db=db,
                project_id=job.project_id,
                target=job.target_input,
            )
            if not scope_eval.get("is_authorized"):
                return False, job, f"Cannot retry job: Target '{job.target_input}' is no longer authorized by scope policy ({scope_eval.get('status')})."

        job.attempt_count += 1
        job.retry_count += 1
        backoff_delay = cls.calculate_backoff_delay(job.attempt_count)
        next_retry_at = now + timedelta(seconds=backoff_delay)

        job.status = AssessmentStatus.QUEUED
        job.claimed_by = None
        job.worker_pid = None
        job.error_message = None
        job.failure_category = None
        job.started_at = None
        job.completed_at = None
        job.progress_pct = 0

        current_stats = dict(job.summary_stats or {})
        current_stats["retry_backoff_seconds"] = backoff_delay
        current_stats["next_retry_at"] = next_retry_at.isoformat()
        job.summary_stats = current_stats

        db.commit()
        db.refresh(job)
        return True, job, f"Job successfully re-queued for retry (attempt {job.attempt_count}, backoff: {backoff_delay:.2f}s)."

    @classmethod
    def integrate_assessment_assets_and_graph(
        cls,
        job: AssessmentJob,
        canonical_findings: Any,
        db: Session,
        client_ip: Optional[str] = None,
    ) -> None:
        """
        Reconciles target assets and auto-populates the Universal Security Knowledge Graph
        from assessment job outcomes and canonical findings.
        """
        from app.models.project import Project
        from app.services.asset_reconciliation_service import AssetReconciliationService
        from app.services.knowledge_graph_service import KnowledgeGraphService
        from app.models.graph import GraphNodeCategory, RelationshipType, RelationshipStatus

        project = db.query(Project).filter(Project.id == job.project_id).first()
        if not project:
            return

        # 1. Classify and reconcile Target Asset
        asset_type, canonical_id, display_name = AssetReconciliationService.classify_and_normalize(job.target_input)
        target_asset = AssetReconciliationService.reconcile_or_create_asset(
            project_id=job.project_id,
            organization_id=project.organization_id,
            asset_type=asset_type,
            canonical_identifier=canonical_id,
            name=display_name,
            source=f"ASSESSMENT_{job.adapter_name.upper()}",
            db=db,
        )

        # Asset Node in Knowledge Graph
        asset_node = KnowledgeGraphService.get_or_create_node(
            project_id=job.project_id,
            category=GraphNodeCategory.ASSET,
            label=target_asset.name,
            entity_id=target_asset.id,
            entity_type="Asset",
            properties={
                "asset_type": target_asset.asset_type.value,
                "canonical_identifier": target_asset.canonical_identifier,
                "criticality": target_asset.criticality.value,
            },
            db=db,
        )

        # Assessment Job Node in Knowledge Graph
        job_node = KnowledgeGraphService.get_or_create_node(
            project_id=job.project_id,
            category=GraphNodeCategory.ASSESSMENT,
            label=f"Scan {job.id[:8]}",
            entity_id=job.id,
            entity_type="AssessmentJob",
            properties={
                "adapter": job.adapter_name,
                "is_simulated": job.is_simulated,
                "status": job.status.value,
            },
            db=db,
        )

        # If the assessment failed completely, we do not record a successful observation
        # or establish verified edges between the failed scan and target asset or findings.
        if job.status == AssessmentStatus.FAILED:
            db.flush()
            return

        # Determine validation status and relationship status based on execution outcome
        is_partial = (job.status == AssessmentStatus.PARTIAL)
        obs_status = "PARTIAL" if is_partial else "VERIFIED"
        rel_status = RelationshipStatus.INFERRED if is_partial else RelationshipStatus.VERIFIED
        rel_confidence = 0.6 if is_partial else 1.0

        # 2. Record historical observation
        AssetReconciliationService.record_observation(
            asset=target_asset,
            project_id=job.project_id,
            assessment_job_id=job.id,
            observation_source=job.adapter_name,
            adapter_version=job.adapter_version,
            observed_attributes={
                "target_input": job.target_input,
                "findings_count": len(canonical_findings or []),
                "is_simulated": job.is_simulated,
            },
            validation_status=obs_status,
            db=db,
        )

        # 3. Link canonical findings to the asset
        for f in (canonical_findings or []):
            if not f.asset_id:
                f.asset_id = target_asset.id

        # 4. Auto-populate Knowledge Graph nodes & edges
        # Edge: Assessment OBSERVED_AT Asset
        KnowledgeGraphService.create_or_update_relationship(
            project_id=job.project_id,
            source_node_id=job_node.id,
            target_node_id=asset_node.id,
            relationship_type=RelationshipType.OBSERVED_AT,
            status=rel_status,
            confidence=rel_confidence,
            provenance=f"ADAPTER_{job.adapter_name}",
            db=db,
        )

        # Link Findings to Asset & Assessment
        for f in (canonical_findings or []):
            finding_node = KnowledgeGraphService.get_or_create_node(
                project_id=job.project_id,
                category=GraphNodeCategory.FINDING,
                label=f.title,
                entity_id=f.id,
                entity_type="VulnerabilityFinding",
                properties={
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "status": f.status.value,
                    "cvss_score": f.cvss_score,
                },
                db=db,
            )

            # Edge: Asset AFFECTED_BY Finding
            KnowledgeGraphService.create_or_update_relationship(
                project_id=job.project_id,
                source_node_id=asset_node.id,
                target_node_id=finding_node.id,
                relationship_type=RelationshipType.AFFECTED_BY,
                status=rel_status,
                confidence=rel_confidence if is_partial else (1.0 if f.confidence.value == "CERTAIN" else 0.8),
                provenance=f"ASSESSMENT_{job.id[:8]}",
                db=db,
            )

            # Edge: Finding VERIFIED_BY Assessment
            KnowledgeGraphService.create_or_update_relationship(
                project_id=job.project_id,
                source_node_id=finding_node.id,
                target_node_id=job_node.id,
                relationship_type=RelationshipType.VERIFIED_BY,
                status=rel_status,
                confidence=rel_confidence,
                provenance=f"ASSESSMENT_{job.id[:8]}",
                db=db,
            )

            # If finding has vuln_id (e.g. CVE-2026-1049), link to Vulnerability Node
            if f.vuln_id:
                vuln_node = KnowledgeGraphService.get_or_create_node(
                    project_id=job.project_id,
                    category=GraphNodeCategory.VULNERABILITY,
                    label=f.vuln_id,
                    entity_id=f.vuln_id,
                    entity_type="VulnerabilityDefinition",
                    properties={"vuln_id": f.vuln_id},
                    db=db,
                )
                # Edge: Finding ASSOCIATED_WITH Vulnerability
                KnowledgeGraphService.create_or_update_relationship(
                    project_id=job.project_id,
                    source_node_id=finding_node.id,
                    target_node_id=vuln_node.id,
                    relationship_type=RelationshipType.ASSOCIATED_WITH,
                    status=rel_status,
                    confidence=rel_confidence,
                    provenance="CVE_CORRELATION",
                    db=db,
                )


        # 5. Connect Contextual Risk Intelligence & Prioritization (Workstream D)
        try:
            from app.services.contextual_risk_service import ContextualRiskService
            ContextualRiskService.recalculate_project_risks(project_id=job.project_id, db=db, client_ip=client_ip)
        except Exception as e:
            import logging
            logging.getLogger('vapt.assessment').warning(f'Project risk recalculation warning for {job.project_id}: {e}')

        # 6. Generate Actionable Remediation Guidance (Workstream E)
        try:
            from app.services.remediation_service import RemediationPrioritizationService
            for f in (canonical_findings or []):
                try:
                    RemediationPrioritizationService.generate_or_get_recommendation(
                        project_id=job.project_id,
                        finding_id=f.id,
                        db=db,
                        client_ip=client_ip,
                    )
                except Exception as e:
                    import logging
                    logging.getLogger('vapt.assessment').warning(f'Remediation guidance warning for finding {f.id}: {e}')
        except Exception as e:
            import logging
            logging.getLogger('vapt.assessment').warning(f'Remediation service warning for {job.project_id}: {e}')

        # 7. Analyze Contextual Attack Paths from the updated Knowledge Graph (Workstream C)
        try:
            from app.services.attack_path_service import AttackPathService
            AttackPathService.analyze_attack_paths(project_id=job.project_id, db=db)
        except Exception as e:
            import logging
            logging.getLogger('vapt.assessment').warning(f'Attack path analysis warning for {job.project_id}: {e}')

        # 8. Evaluate Regression Intelligence against Baseline (Workstream F)
        try:
            from app.services.regression_service import RegressionIntelligenceService
            RegressionIntelligenceService.evaluate_project_regressions(
                project_id=job.project_id, db=db, client_ip=client_ip
            )
        except Exception as e:
            import logging
            logging.getLogger('vapt.assessment').warning(f'Regression evaluation warning for {job.project_id}: {e}')

        # 9. Evaluate Adaptive Defense Posture (Workstream F)
        try:
            from app.services.adaptive_defense_service import AdaptiveDefenseService
            AdaptiveDefenseService.evaluate_adaptive_posture(
                project_id=job.project_id, db=db, client_ip=client_ip
            )
        except Exception as e:
            import logging
            logging.getLogger('vapt.assessment').warning(f'Adaptive defense evaluation warning for {job.project_id}: {e}')

        db.flush()

    @classmethod
    def claim_next_available_job(
        cls,
        db: Session,
        worker_id: str = "worker-01",
        now: Optional[datetime] = None,
    ) -> Optional[AssessmentJob]:
        """
        Atomically claims the next QUEUED assessment job from the global queue.
        Supports PostgreSQL row-locking concurrency (FOR UPDATE SKIP LOCKED)
        and SQLite atomic conditional update.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        dialect_name = getattr(db.bind.dialect, "name", "sqlite") if db.bind else "sqlite"

        if dialect_name == "postgresql":
            job = (
                db.query(AssessmentJob)
                .filter(AssessmentJob.status == AssessmentStatus.QUEUED)
                .order_by(AssessmentJob.created_at.asc())
                .with_for_update(skip_locked=True)
                .first()
            )
            if not job:
                return None
            job.status = AssessmentStatus.PREFLIGHT
            job.claimed_by = worker_id
            job.preflight_at = now
            job.progress_pct = 10
            db.commit()
            db.refresh(job)
            return job
        else:
            # SQLite / Generic atomic conditional update
            candidate = (
                db.query(AssessmentJob)
                .filter(AssessmentJob.status == AssessmentStatus.QUEUED)
                .order_by(AssessmentJob.created_at.asc())
                .first()
            )
            if not candidate:
                return None

            rows = (
                db.query(AssessmentJob)
                .filter(
                    AssessmentJob.id == candidate.id,
                    AssessmentJob.status == AssessmentStatus.QUEUED,
                )
                .update(
                    {
                        AssessmentJob.status: AssessmentStatus.PREFLIGHT,
                        AssessmentJob.claimed_by: worker_id,
                        AssessmentJob.preflight_at: now,
                        AssessmentJob.progress_pct: 10,
                    },
                    synchronize_session="fetch",
                )
            )
            db.commit()
            if rows > 0:
                db.refresh(candidate)
                return candidate
            return None

    @classmethod
    def recover_stale_workers(
        cls,
        db: Session,
        heartbeat_timeout_seconds: int = 120,
        now: Optional[datetime] = None,
    ) -> List[AssessmentJob]:
        """
        Scans for stalled assessment jobs whose worker heartbeat or runtime has elapsed.
        Re-queues recoverable jobs or marks exhausted jobs as FAILED.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        cutoff = now - timedelta(seconds=heartbeat_timeout_seconds)

        # Check active jobs in PREFLIGHT or RUNNING
        active_jobs = (
            db.query(AssessmentJob)
            .filter(AssessmentJob.status.in_([AssessmentStatus.PREFLIGHT, AssessmentStatus.RUNNING]))
            .all()
        )

        recovered: List[AssessmentJob] = []

        for job in active_jobs:
            # Determine last activity timestamp
            last_active = job.heartbeat_at or job.started_at or job.preflight_at or job.created_at
            if last_active:
                if last_active.tzinfo is None:
                    last_active = last_active.replace(tzinfo=timezone.utc)
                if last_active < cutoff:
                    if job.attempt_count < job.max_retries:
                        # Stale worker recovery: re-queue with exponential backoff & jitter
                        backoff_delay = cls.calculate_backoff_delay(job.attempt_count + 1)
                        next_retry_at = now + timedelta(seconds=backoff_delay)
                        job.status = AssessmentStatus.QUEUED
                        job.claimed_by = None
                        job.worker_pid = None
                        job.retry_count = (job.retry_count or 0) + 1
                        job.attempt_count = (job.attempt_count or 1) + 1
                        job.error_message = f"Stale worker recovered: heartbeat absent since {last_active.isoformat()}"
                        current_stats = dict(job.summary_stats or {})
                        current_stats["retry_backoff_seconds"] = backoff_delay
                        current_stats["next_retry_at"] = next_retry_at.isoformat()
                        job.summary_stats = current_stats
                        AuditService.record_event(
                            db=db,
                            action="ASSESSMENT_STALE_WORKER_RECOVERED",
                            target_type="AssessmentJob",
                            outcome="SUCCESS",
                            target_id=job.id,
                            project_id=job.project_id,
                            details={"last_active": last_active.isoformat(), "retry_count": job.retry_count, "backoff_seconds": backoff_delay},
                        )
                    else:
                        # Attempts exhausted: fail closed
                        job.status = AssessmentStatus.FAILED
                        job.claimed_by = None
                        job.worker_pid = None
                        job.completed_at = now
                        job.failure_category = "WORKER_HEARTBEAT_TIMEOUT"
                        job.error_message = (
                            f"Execution aborted: worker heartbeat absent past {heartbeat_timeout_seconds}s limit "
                            f"and maximum retries ({job.max_retries}) exhausted."
                        )
                        AuditService.record_event(
                            db=db,
                            action="ASSESSMENT_STALE_WORKER_FAILED",
                            target_type="AssessmentJob",
                            outcome="FAILURE",
                            target_id=job.id,
                            project_id=job.project_id,
                            details={"last_active": last_active.isoformat(), "attempts": job.attempt_count},
                        )

                    recovered.append(job)

        if recovered:
            db.commit()

        return recovered

    @classmethod
    def execute_batch_assessment(
        cls,
        db: Session,
        job_id: str,
        targets: List[str],
        worker_id: str = "worker-01",
        now: Optional[datetime] = None,
    ) -> AssessmentJob:
        """
        Executes an assessment job against a batch of targets, ensuring truthful partial success reporting (Prompt 52).
        - If any target fails or is interrupted, the overall job status is strictly PARTIAL (never falsely COMPLETED).
        - Explicitly records completed_targets and failed_targets in summary_stats.
        - Supports deterministic fault injection (trigger_point='background:task').
        """
        if now is None:
            now = datetime.now(timezone.utc)

        job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
        if not job:
            raise ValueError(f"Assessment job '{job_id}' not found.")

        job.status = AssessmentStatus.RUNNING
        job.started_at = now
        job.claimed_by = worker_id
        db.commit()

        completed_targets: List[str] = []
        failed_targets: List[Dict[str, Any]] = []
        all_errors: List[str] = []

        from app.core.fault_injection import FaultInjector, InterruptedBackgroundTaskError

        for target in targets:
            # Deterministic interruption hook (Prompt 52 Scenario 7)
            try:
                FaultInjector.maybe_inject("background:task", {"job_id": job.id, "target": target})
            except InterruptedBackgroundTaskError as ite:
                logger.warning(f"Batch execution interrupted on target '{target}': {ite}")
                failed_targets.append({
                    "target": target,
                    "error": str(ite),
                    "failure_category": "BACKGROUND_TASK_INTERRUPTED",
                })
                all_errors.append(f"Interrupted on target '{target}': {str(ite)}")
                break

            # Preflight Scope validation for target
            scope_eval = ScopeEngine.validate_target_in_scope(
                db=db,
                project_id=job.project_id,
                target=target,
                now=now,
            )
            if not scope_eval.get("is_authorized"):
                failed_targets.append({
                    "target": target,
                    "error": f"Target outside authorized scope: {scope_eval.get('reason')}",
                    "failure_category": "SCOPE_AUTHORIZATION_DENIED",
                })
                all_errors.append(f"Target '{target}' denied: {scope_eval.get('reason')}")
                continue

            # Execute adapter for target
            adapter = AdapterRegistry.get(job.adapter_name)
            if not adapter:
                failed_targets.append({
                    "target": target,
                    "error": f"Adapter '{job.adapter_name}' not found",
                    "failure_category": "UNSUPPORTED_ADAPTER",
                })
                all_errors.append(f"Unknown adapter '{job.adapter_name}'")
                continue

            try:
                res = adapter.execute(target=target, config=job.config)
                if res.success:
                    completed_targets.append(target)
                else:
                    failed_targets.append({
                        "target": target,
                        "error": "; ".join(res.errors),
                        "failure_category": res.failure_category or "ADAPTER_EXECUTION_FAILURE",
                    })
                    all_errors.extend(res.errors)
            except Exception as ex:
                failed_targets.append({
                    "target": target,
                    "error": str(ex),
                    "failure_category": "DRIVER_EXCEPTION",
                })
                all_errors.append(f"Execution failed on target '{target}': {str(ex)}")

        # Determine honest final status
        total_count = len(targets)
        completed_count = len(completed_targets)
        failed_count = len(failed_targets)

        if completed_count == total_count and failed_count == 0:
            final_status = AssessmentStatus.COMPLETED
            summary_msg = f"All {total_count} target(s) successfully assessed."
            failure_cat = None
        elif completed_count > 0 and failed_count > 0:
            final_status = AssessmentStatus.PARTIAL
            summary_msg = f"Partial success: {completed_count}/{total_count} targets succeeded; {failed_count} failed or interrupted."
            failure_cat = "PARTIAL_MODULE_FAILURE"
        else:
            final_status = AssessmentStatus.FAILED
            summary_msg = f"Batch assessment failed: 0/{total_count} targets succeeded."
            failure_cat = failed_targets[0]["failure_category"] if failed_targets else "BATCH_EXECUTION_FAILED"

        job.status = final_status
        job.completed_at = datetime.now(timezone.utc)
        job.error_message = "; ".join(all_errors) if all_errors else None
        job.failure_category = failure_cat
        job.summary_stats = {
            "status_summary": summary_msg,
            "total_targets": total_count,
            "completed_targets": completed_targets,
            "failed_targets": failed_targets,
            "completed_count": completed_count,
            "failed_count": failed_count,
            "errors": all_errors,
        }

        db.commit()
        db.refresh(job)
        return job
