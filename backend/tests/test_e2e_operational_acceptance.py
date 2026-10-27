import os
import hashlib
import pytest
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.assessment import (
    AssessmentJob,
    AssessmentFinding,
    FindingEvidence,
    FindingSeverity,
    FindingConfidence,
    AssessmentStatus,
)
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.graph import GraphNode, GraphNodeCategory, GraphRelationship, RelationshipType
from app.models.verification import VerificationOutcome, VerificationMethod
from app.services.scope_engine import ScopeEngine
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.integrity_service import IntegrityService
from app.services.finding_deduplication_service import FindingDeduplicationService
from app.services.knowledge_graph_service import KnowledgeGraphService
from app.services.contextual_risk_service import ContextualRiskService
from app.services.remediation_verification_service import RemediationVerificationService
from app.services.backup_service import BackupRecoveryService


def test_complete_simulated_end_to_end_acceptance_workflow(db: Session, tmp_path):
    """
    POST-AUDIT ACCEPTANCE: Full 13-Step Repeatable Simulated Assessment Workflow.
    Executes entirely in memory / local disposable DB without live sockets or external calls.
    """
    # =========================================================================
    # Step 1: Create the project and authorized assessment scope
    # =========================================================================
    org = Organization(name="Acceptance Org", slug="acceptance-org")
    db.add(org)
    db.commit()

    lead_user = User(
        email=f"lead_{org.id[:8]}@example.com",
        full_name="Lead User",
        hashed_password="hash_secure_password_test_123",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    tester_user = User(
        email=f"tester_{org.id[:8]}@example.com",
        full_name="Tester User",
        hashed_password="hash_secure_password_test_123",
        system_role=SystemRole.SECURITY_TESTER,
        is_active=True,
    )
    db.add_all([lead_user, tester_user])
    db.commit()

    project = Project(
        name="Acceptance Project Alpha",
        description="E2E Acceptance Project",
        organization_id=org.id,
    )
    db.add(project)
    db.commit()

    member_lead = ProjectMember(project_id=project.id, user_id=lead_user.id, role=ProjectRole.LEAD)
    member_tester = ProjectMember(project_id=project.id, user_id=tester_user.id, role=ProjectRole.TESTER)
    db.add_all([member_lead, member_tester])
    db.commit()

    # Scope Inclusion (CIDR)
    target = ScopeTarget(
        project_id=project.id,
        target_type=TargetType.CIDR,
        target_value="192.168.100.0/24",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorized_by_id=lead_user.id,
        created_by_id=tester_user.id,
    )
    # Scope Exclusion (Overlapping IP)
    exclusion = ScopeExclusion(
        project_id=project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="192.168.100.50",
        reason="Mission critical billing system",
        created_by_id=lead_user.id,
    )
    db.add_all([target, exclusion])
    db.commit()

    # =========================================================================
    # Step 2: Verify scope inclusions, exclusions, authorization and preflight behavior
    # =========================================================================
    # 2a. In-scope authorized target
    res_in = ScopeEngine.validate_target_in_scope(db, project.id, "192.168.100.10")
    assert res_in["is_authorized"] is True, "Authorized in-scope IP was rejected"
    assert res_in["status"] == "AUTHORIZED"

    # 2b. Excluded target within CIDR must be DENIED
    res_ex = ScopeEngine.validate_target_in_scope(db, project.id, "192.168.100.50")
    assert res_ex["is_authorized"] is False, "Excluded target was incorrectly allowed"
    assert res_ex["status"] == "EXCLUDED"

    # 2c. Out of scope target must be DENIED
    res_out = ScopeEngine.validate_target_in_scope(db, project.id, "10.0.0.1")
    assert res_out["is_authorized"] is False, "Out of scope target was incorrectly allowed"

    # =========================================================================
    # Step 3 & 4: Submit simulated assessment job & verify worker claim ownership
    # =========================================================================
    job = AssessmentJob(
        project_id=project.id,
        adapter_name="passive_header_adapter",
        target_input="192.168.100.10",
        created_by_id=tester_user.id,
        status=AssessmentStatus.QUEUED,
    )
    db.add(job)
    db.commit()

    # Test worker claim ownership
    claimed_job = AssessmentExecutionEngine.preflight_and_claim_job(db, job.id, worker_id="acceptance-worker-01")
    assert claimed_job.status == AssessmentStatus.RUNNING
    assert claimed_job.claimed_by == "acceptance-worker-01"

    # Execute simulation in worker
    exec_result = AssessmentExecutionEngine.execute_job(db, job.id, worker_id="acceptance-worker-01")
    assert exec_result.status == AssessmentStatus.COMPLETED
    db.refresh(job)
    assert job.status == AssessmentStatus.COMPLETED
    assert job.completed_at is not None
    assert job.started_at is not None
    duration = (job.completed_at - job.started_at).total_seconds()
    assert duration >= 0

    # =========================================================================
    # Step 5 & 6: Persist findings and evidence & validate evidence hashes
    # =========================================================================
    raw_findings = db.query(AssessmentFinding).filter(AssessmentFinding.job_id == job.id).all()
    assert len(raw_findings) > 0, "No raw findings generated by passive header simulation"
    for rf in raw_findings:
        assert rf.is_simulated is True, "Raw finding is not flagged as simulated"

    # Check evidence persistence
    finding_ids = [f.id for f in raw_findings]
    evidence_items = db.query(FindingEvidence).filter(FindingEvidence.finding_id.in_(finding_ids)).all()
    assert len(evidence_items) > 0, "No evidence items generated"

    # Recompute byte hashes
    for ev in evidence_items:
        payload_bytes = (ev.payload or "").encode("utf-8")
        computed_hash = hashlib.sha256(payload_bytes).hexdigest()
        assert computed_hash == ev.sha256_hash, f"Evidence hash mismatch for evidence {ev.id}"

    # Run IntegrityService evidence verification
    integrity_res = IntegrityService.verify_evidence_integrity(db, job.id)
    assert integrity_res["is_valid"] is True, "Evidence integrity check failed"
    assert len(integrity_res["corrupted_evidence_ids"]) == 0
    assert len(integrity_res["merkle_root"]) == 64

    # =========================================================================
    # Step 7: Verify finding lifecycle, deduplication and correlation
    # =========================================================================
    canonical_findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project.id).all()
    assert len(canonical_findings) > 0, "Canonical findings were not created"

    test_finding = canonical_findings[0]
    initial_occurrences = test_finding.occurrence_count

    # Simulate second identical finding ingestion to test deduplication
    re_detected = FindingDeduplicationService.ingest_job_findings(
        job=job,
        raw_findings=[raw_findings[0]],
        db=db,
    )
    db.refresh(test_finding)
    assert test_finding.occurrence_count == initial_occurrences + 1, "Deduplication failed to increment occurrence count"

    # Transition lifecycle
    test_finding.status = FindingLifecycleStatus.CONFIRMED
    db.commit()
    test_finding.status = FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION
    db.commit()
    db.refresh(test_finding)
    assert test_finding.status == FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION

    # =========================================================================
    # Step 8: Verify asset inventory, graph isolation and risk prioritization
    # =========================================================================
    # Create second project to verify cross-project graph isolation
    proj_beta = Project(name="Project Beta Isolation Target", organization_id=org.id)
    db.add(proj_beta)
    db.commit()

    node_beta = KnowledgeGraphService.get_or_create_node(
        db=db,
        project_id=proj_beta.id,
        category=GraphNodeCategory.ASSET,
        label="beta.internal.host",
        properties={"criticality": "HIGH"},
    )
    db.commit()

    # Query graph nodes for Project Alpha
    alpha_nodes = KnowledgeGraphService.list_nodes(db=db, project_id=project.id)
    alpha_node_ids = [n.id for n in alpha_nodes]
    assert node_beta.id not in alpha_node_ids, "Cross-project graph leakage detected: Beta node found in Alpha query"

    # Contextual risk calculation
    risk_calc = ContextualRiskService.calculate_score_and_factors(finding=test_finding)
    assert 0.0 <= risk_calc["score"] <= 100.0, "Risk score outside [0, 100]"
    assert "uncertainty_range" in risk_calc
    assert risk_calc["uncertainty_range"]["uncertainty_margin"] >= 3.0
    assert "factor_breakdown" in risk_calc

    # =========================================================================
    # Step 9: Generate project-scoped report or evidence manifest
    # =========================================================================
    manifest = BackupRecoveryService.export_project_manifest(
        db=db,
        project_id=project.id,
        actor_id=tester_user.id,
        verify_evidence_integrity=True,
    )
    assert manifest["project"]["id"] == project.id
    assert manifest["scope_targets_count"] >= 1
    assert manifest["vulnerability_findings_count"] >= 1
    assert len(manifest["manifest_sha256"]) == 64
    assert "evidence_integrity" in manifest
    assert manifest["evidence_integrity"]["verified"] is True
    assert manifest["evidence_integrity"]["total_evidence_items"] >= len(evidence_items)

    # =========================================================================
    # Step 10: Exercise supported remediation workflow & independent verification
    # =========================================================================
    verification_entry = RemediationVerificationService.record_verification(
        project_id=project.id,
        finding_id=test_finding.id,
        outcome=VerificationOutcome.VERIFIED_FIXED,
        verification_criteria="HSTS and Content-Security-Policy headers verified present on target",
        verification_evidence_summary="Simulated re-scan confirmed all security headers populated",
        notes="Remediation confirmed via automated passive check",
        verifier=lead_user,
        verifier_role=ProjectRole.LEAD,
        db=db,
        verification_method=VerificationMethod.PASSIVE_SCAN,
    )
    db.commit()
    db.refresh(test_finding)
    assert test_finding.status == FindingLifecycleStatus.VERIFIED_CLOSED, "Finding was not closed after verification"
    assert verification_entry.outcome == VerificationOutcome.VERIFIED_FIXED

    # =========================================================================
    # Step 11: Restart application session & verify required state persists
    # =========================================================================
    # Emulate session reset
    project_id = project.id
    finding_id = test_finding.id
    db.expire_all()

    # Re-fetch from fresh state
    refetched_project = db.query(Project).filter(Project.id == project_id).first()
    assert refetched_project is not None
    refetched_finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding_id).first()
    assert refetched_finding is not None
    assert refetched_finding.status == FindingLifecycleStatus.VERIFIED_CLOSED

    # =========================================================================
    # Step 12: Back up database, restore to sandbox, and verify integrity
    # =========================================================================
    backup_dir = str(tmp_path / "backups")
    os.makedirs(backup_dir, exist_ok=True)
    backup_meta = BackupRecoveryService.create_database_backup(db, backup_dir=backup_dir)
    assert os.path.exists(backup_meta.backup_path)
    assert len(backup_meta.sha256_hash) == 64

    # Verify and restore to disposable sandbox
    restore_report = BackupRecoveryService.verify_and_test_restore(
        backup_file_path=backup_meta.backup_path,
        expected_sha256=backup_meta.sha256_hash,
    )
    assert restore_report["is_valid"] is True
    assert restore_report["integrity_result"] == "ok"
    assert restore_report["table_count"] > 10

    # =========================================================================
    # Step 13: Clean up disposable test project (Tombstone Purge)
    # =========================================================================
    purge_res = BackupRecoveryService.purge_project_data(
        db=db,
        project_id=project.id,
        actor_id=lead_user.id,
        confirmation_phrase=f"PURGE PROJECT {project.name}",
    )
    assert purge_res["status"] == "PURGED"

    # Confirm project is deleted
    assert db.query(Project).filter(Project.id == project.id).first() is None
    # Confirm cascading deletion removed targets
    assert db.query(ScopeTarget).filter(ScopeTarget.project_id == project.id).count() == 0
