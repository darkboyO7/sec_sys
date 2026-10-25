import json
import hashlib
import math
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple, List
from sqlalchemy.orm import Session
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

        # Concurrency safety: Only QUEUED or READY jobs can be preflighted and claimed
        if job.status not in (AssessmentStatus.QUEUED, AssessmentStatus.READY):
            return job

        # 1. State transition to PREFLIGHT
        if job.status == AssessmentStatus.QUEUED:
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.PREFLIGHT,
                now=now,
            )
            db.commit()

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

        # Preflight passed -> READY -> RUNNING (Atomic worker claim)
        AssessmentStateMachine.transition(
            job=job,
            new_status=AssessmentStatus.READY,
            now=now,
        )
        AssessmentStateMachine.transition(
            job=job,
            new_status=AssessmentStatus.RUNNING,
            now=now,
        )
        job.started_at = now
        job.heartbeat_at = now
        db.commit()
        db.refresh(job)
        return job

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

        # Step 1: Preflight re-validation and atomic claim
        if job.status in (AssessmentStatus.QUEUED, AssessmentStatus.PREFLIGHT, AssessmentStatus.READY):
            job = cls.preflight_and_claim_job(
                db=db,
                job_id=job.id,
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

        if job.status != AssessmentStatus.RUNNING:
            return job

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

        # Step 4: Execute Adapter with Cancellation Check
        def check_cancellation() -> bool:
            # Query fresh job status from database
            fresh = db.query(AssessmentJob.status).filter(AssessmentJob.id == job.id).first()
            return fresh is not None and fresh[0] in (
                AssessmentStatus.CANCELLATION_REQUESTED,
                AssessmentStatus.CANCELLED,
            )

        try:
            AssessmentStateMachine.record_heartbeat(job, now=now)
            result = adapter.execute(
                target=job.target_input,
                config=job.config,
                cancellation_check=check_cancellation,
            )
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

        # Step 5: Check if job was cancelled during execution
        db.refresh(job)
        if job.status in (AssessmentStatus.CANCELLATION_REQUESTED, AssessmentStatus.CANCELLED):
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

        # ----------------------------------------------------------------------
        # Step 6: Normalized Untrusted Evidence Boundary
        # ----------------------------------------------------------------------
        persisted_findings_count = 0
        persisted_evidence_count = 0
        persisted_findings_list: List[AssessmentFinding] = []

        # Bound maximum ingested findings to 50
        raw_findings = result.findings[:50]

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

                # Enforce 64KB max safety limit on payload
                safe_payload = raw_ev.payload[:65536]
                sha256 = hashlib.sha256(safe_payload.encode("utf-8")).hexdigest()

                evidence = FindingEvidence(
                    finding_id=finding.id,
                    evidence_type=ev_type,
                    payload=safe_payload,
                    sha256_hash=sha256,
                    observed_at=raw_ev.observed_at,
                )
                db.add(evidence)
                persisted_evidence_count += 1

        # Phase 3: Deduplicate and correlate into canonical VulnerabilityFindings
        # Note: Ingestion never auto-closes or marks findings FALSE_POSITIVE or REMEDIATED.
        canonical_findings = []
        if persisted_findings_list:
            canonical_findings = FindingDeduplicationService.ingest_job_findings(
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
            "is_simulated": job.is_simulated,
            "policy_version": job.policy_version,
            "adapter_name": job.adapter_name,
            "adapter_version": job.adapter_version,
        }

        if not result.success:
            if persisted_findings_count > 0:
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

        # Phase 4: Reconcile Asset Inventory and auto-populate Security Knowledge Graph
        try:
            cls.integrate_assessment_assets_and_graph(
                job=job,
                canonical_findings=canonical_findings,
                db=db,
                client_ip=client_ip,
            )
        except Exception as e:
            # Graph and asset ingestion failure must not lose the valid assessment result
            import logging
            logging.getLogger("vapt.assessment").warning(
                f"Asset/Graph integration warning for job {job.id}: {e}", exc_info=True
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

        db.flush()
