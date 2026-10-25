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
