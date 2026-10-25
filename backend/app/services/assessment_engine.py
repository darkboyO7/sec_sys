import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingEvidence,
)
from app.services.assessment_state_machine import AssessmentStateMachine
from app.services.scope_engine import ScopeEngine
from app.services.scanner_adapters.local_fixture_adapter import LocalFixtureAdapter
from app.services.audit_service import AuditService
from app.services.finding_deduplication_service import FindingDeduplicationService


class AssessmentExecutionEngine:
    """
    Execution Boundary Controller for Assessment Jobs.
    Enforces independent scope and authorization re-validation before dispatching to adapters.
    Guarantees that all observations and evidence hashes are transactionally recorded.
    """

    ADAPTER_REGISTRY = {
        "local_fixture_adapter": LocalFixtureAdapter(),
    }

    @classmethod
    def execute_job(
        cls,
        db: Session,
        job_id: str,
        now: Optional[datetime] = None,
        client_ip: Optional[str] = None,
    ) -> AssessmentJob:
        if now is None:
            now = datetime.now(timezone.utc)

        job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
        if not job:
            raise ValueError(f"Assessment job '{job_id}' not found.")

        # Check if already cancelled or in terminal state
        if job.status != AssessmentStatus.QUEUED:
            return job

        # ----------------------------------------------------------------------
        # MANDATORY EXECUTION BOUNDARY INVARIANT:
        # Re-validate authorization and scope independently before touching any target
        # ----------------------------------------------------------------------
        scope_eval = ScopeEngine.validate_target_in_scope(
            db=db,
            project_id=job.project_id,
            target=job.target_input,
            now=now,
        )

        if not scope_eval["is_authorized"]:
            # Scope check failed! Immediately fail closed.
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.FAILED,
                error_message=f"Execution boundary scope denial: {scope_eval['reason']}",
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
                action="ASSESSMENT_EXECUTION_DENIED",
                target_type="assessment_job",
                target_id=job.id,
                project_id=job.project_id,
                actor_id=job.created_by_id,
                outcome="DENIED",
                details={
                    "target_input": job.target_input,
                    "scope_status": scope_eval["status"],
                    "reason": scope_eval["reason"],
                },
            )
            return job

        # ----------------------------------------------------------------------
        # Step 2: Transition to RUNNING
        # ----------------------------------------------------------------------
        AssessmentStateMachine.transition(
            job=job,
            new_status=AssessmentStatus.RUNNING,
            now=now,
        )
        db.commit()

        # Step 3: Resolve Adapter
        adapter = cls.ADAPTER_REGISTRY.get(job.adapter_name)
        if not adapter:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.FAILED,
                error_message=f"Unknown or unapproved scanner adapter: {job.adapter_name}",
                now=now,
            )
            db.commit()
            return job

        # Step 4: Execute Adapter
        try:
            result = adapter.execute(target=job.target_input, config=job.config)
        except Exception as e:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.FAILED,
                error_message=f"Adapter execution exception: {str(e)}",
                now=now,
            )
            db.commit()
            return job

        # Step 5: Check if job was cancelled or timed out while running
        db.refresh(job)
        if job.status == AssessmentStatus.CANCELLED:
            return job

        # Step 6: Ingest Findings and Evidence Provenance
        persisted_findings_count = 0
        persisted_evidence_count = 0
        persisted_findings_list = []

        for raw_finding in result.findings:
            finding = AssessmentFinding(
                job_id=job.id,
                project_id=job.project_id,
                target_value=job.target_input,
                title=raw_finding.title,
                description=raw_finding.description,
                severity=raw_finding.severity,
                confidence=raw_finding.confidence,
                vuln_id=raw_finding.vuln_id,
                cvss_score=raw_finding.cvss_score,
                is_simulated=result.is_simulated,
                reproduction_steps=raw_finding.reproduction_steps,
                created_at=now,
            )
            db.add(finding)
            db.flush()  # Acquire finding.id
            persisted_findings_count += 1
            persisted_findings_list.append(finding)

            for raw_ev in raw_finding.evidence_items:
                # Compute SHA-256 digest of payload for cryptographic provenance
                sha256 = hashlib.sha256(raw_ev.payload.encode("utf-8")).hexdigest()
                evidence = FindingEvidence(
                    finding_id=finding.id,
                    evidence_type=raw_ev.evidence_type,
                    payload=raw_ev.payload,
                    sha256_hash=sha256,
                    observed_at=raw_ev.observed_at,
                )
                db.add(evidence)
                persisted_evidence_count += 1

        # Phase 3: Deduplicate and correlate into canonical VulnerabilityFindings
        if persisted_findings_list:
            FindingDeduplicationService.ingest_job_findings(
                job=job,
                raw_findings=persisted_findings_list,
                db=db,
                client_ip=client_ip,
            )

        # Step 7: Finalize State Machine based on execution outcome
        job.summary_stats = {
            "status_summary": result.status_summary,
            "findings_count": persisted_findings_count,
            "evidence_count": persisted_evidence_count,
            "errors_count": len(result.errors),
            "errors": result.errors,
            "duration_ms": result.execution_duration_ms,
        }

        if not result.success:
            if persisted_findings_count > 0:
                final_status = AssessmentStatus.PARTIAL
                error_msg = f"Partial failure: {'; '.join(result.errors)}"
            else:
                final_status = AssessmentStatus.FAILED
                error_msg = f"Assessment failed: {'; '.join(result.errors)}"
        elif len(result.errors) > 0:
            final_status = AssessmentStatus.PARTIAL
            error_msg = f"Completed with warnings: {'; '.join(result.errors)}"
        else:
            final_status = AssessmentStatus.COMPLETED
            error_msg = None

        AssessmentStateMachine.transition(
            job=job,
            new_status=final_status,
            error_message=error_msg,
            now=now,
        )
        db.commit()
        db.refresh(job)

        # Step 8: Record Audit Log
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
            },
        )

        return job
