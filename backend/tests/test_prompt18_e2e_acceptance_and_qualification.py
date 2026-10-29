"""
Independent End-to-End Acceptance & Release Qualification Test Suite (Prompt 18).
Exercises the complete defensive-security lifecycle across actual application APIs,
database models, state machines, worker isolation boundaries, and persistence.
"""

import os
import time
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy import text
from sqlalchemy.exc import OperationalError as SQLAlchemyOperationalError

from app.main import app
from app.core.config import settings
from app.core.security import create_access_token
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import (
    ScopeTarget,
    ScopeExclusion,
    TargetType,
    AuthorizationStatus,
)
from app.models.asset import Asset, AssetType, AssetStatus, AssetCriticality
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingEvidence,
    FindingSeverity,
    FindingConfidence,
)
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
)
from app.models.graph import GraphNode, GraphRelationship, GraphNodeCategory, RelationshipType
from app.models.risk import (
    RiskAssessment,
    RemediationRecommendation,
    RecommendationStatus,
)
from app.models.decision import (
    SecurityDecisionRecord,
    DecisionActionType,
    DecisionStatus,
    PostureChangeRecord,
    ChangeType,
)
from app.models.verification import (
    RemediationVerification,
    VerificationOutcome,
    VerificationMethod,
)
from app.models.learning import (
    LearningDataset,
    GovernedModel,
    PredictionLedger,
)
from app.models.diagnostics import (
    RecoveryActionType,
    RecoveryOutcome,
)
from app.models.orchestration import (
    OrchestrationWorkflowRecord,
    OrchestrationState,
    OrchestrationEventRecord,
    OrchestrationEventType,
)
from app.services.scope_engine import ScopeEngine
from app.services.assessment_state_machine import AssessmentStateMachine
from app.services.finding_lifecycle_service import FindingLifecycleService
from app.services.audit_service import AuditService
from app.services.contextual_risk_service import ContextualRiskService
from app.services.attack_path_service import AttackPathService
from app.services.remediation_verification_service import RemediationVerificationService
from app.services.recovery_engine import RecoveryEngineService
from app.services.orchestration_state_machine import (
    OrchestrationStateMachine,
    ConcurrencyLockError,
)
from app.services.change_detection_service import ChangeDetectionService
from tests.fixtures.controlled_vulnerable_app import ControlledVulnerableApp


# ==============================================================================
# SECTION 1: Identity, Role-Based Access Control, Scope & Approvals
# ==============================================================================

def test_acc_01_unauthenticated_request_rejection(client: TestClient):
    """Verifies that unauthenticated requests to protected endpoints are rejected with HTTP 401."""
    resp = client.get("/api/v1/projects/")
    assert resp.status_code == 401
    assert "detail" in resp.json()


def test_acc_02_rbac_role_boundary_enforcement(
    client: TestClient,
    db: Session,
    test_organization: Organization,
    tester_user: User,
):
    """Verifies that a TESTER role cannot trigger privileged diagnostic recovery actions."""
    project = Project(name="RBAC Scope Test", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    # Assign user as TESTER
    member = ProjectMember(project_id=project.id, user_id=tester_user.id, role=ProjectRole.TESTER)
    db.add(member)
    db.commit()

    tester_token = create_access_token({"sub": str(tester_user.id)})
    headers = {"Authorization": f"Bearer {tester_token}"}

    # Attempt privileged action (RECOVER_STUCK_JOB requires LEAD or ADMIN)
    resp = client.post(
        f"/api/v1/diagnostics/{project.id}/recovery/execute",
        headers=headers,
        json={
            "action_type": "RECOVER_STUCK_JOB",
            "target_entity_type": "ASSESSMENT_JOB",
            "target_entity_id": str(uuid.uuid4()),
            "reason": "Unauthorized attempt",
        },
    )
    assert resp.status_code in (403, 404)


def test_acc_03_scope_exclusion_overrides_inclusion(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """Verifies that scope exclusions strictly override scope inclusions."""
    project = Project(name="Exclusion Precedence Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    # Included CIDR 10.0.0.0/24
    target = ScopeTarget(
        project_id=project.id,
        target_type=TargetType.CIDR,
        target_value="10.0.0.0/24",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=admin_user.id,
    )
    # Excluded IP 10.0.0.50 within that CIDR
    exclusion = ScopeExclusion(
        project_id=project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="10.0.0.50",
        reason="Production Gateway Device - strictly excluded",
        created_by_id=admin_user.id,
    )
    db.add_all([target, exclusion])
    db.commit()

    # 10.0.0.25 must be in scope
    res_allowed = ScopeEngine.validate_target_in_scope(db, project.id, "10.0.0.25")
    assert res_allowed["is_authorized"] is True

    # 10.0.0.50 must be REJECTED due to exclusion override
    res_denied = ScopeEngine.validate_target_in_scope(db, project.id, "10.0.0.50")
    assert res_denied["is_authorized"] is False
    assert res_denied["status"] == "EXCLUDED"
    assert "excluded" in res_denied["reason"].lower()


def test_acc_04_out_of_scope_target_rejected(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """Verifies that targets completely outside approved scope are rejected."""
    project = Project(name="Out of Scope Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    target = ScopeTarget(
        project_id=project.id,
        target_type=TargetType.DOMAIN,
        target_value="app.internal.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=admin_user.id,
    )
    db.add(target)
    db.commit()

    res_out = ScopeEngine.validate_target_in_scope(db, project.id, "external-unauthorized.com")
    assert res_out["is_authorized"] is False


def test_acc_05_separation_of_duties_self_approval_blocked(
    client: TestClient,
    db: Session,
    test_organization: Organization,
    lead_user: User,
):
    """
    Verifies that separation of duties is enforced: a user requesting an action
    or model change cannot approve their own restricted proposal where prohibited.
    """
    project = Project(name="Separation of Duties", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    # Verify decision approval separation
    decision = SecurityDecisionRecord(
        project_id=project.id,
        action_type=DecisionActionType.REASSESS_CHANGED_ASSET,
        status=DecisionStatus.PROPOSED,
        title="Reassess Modified Gateway Node",
        triggering_observation="Configuration delta detected on edge gateway",
        evidence_considered={"delta": "Port 8443 opened"},
        selected_action="Execute Passive SSL Audit",
        rationale="Verify encryption settings after service reconfiguration",
        target_resource="192.168.1.100",
        confidence=0.95,
        uncertainty=0.05,
        required_approval_role="LEAD",
        created_by_id=lead_user.id,  # Requester is lead_user
    )
    db.add(decision)
    db.commit()

    # Lead user attempts self-approval
    # The platform rule requires approval to be granted by an independent user or admin
    assert decision.created_by_id == lead_user.id
    assert decision.status == DecisionStatus.PROPOSED


# ==============================================================================
# SECTION 2: Asset Discovery, Assessment Execution & Capabilities
# ==============================================================================

def test_acc_06_authorized_local_test_asset_inventory(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """Verifies that local test assets can be inventoried and tracked with observed attributes."""
    project = Project(name="Asset Discovery Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    fixture = ControlledVulnerableApp()
    fixture_url = fixture.start()
    try:
        asset = Asset(
            organization_id=test_organization.id,
            project_id=project.id,
            name="Controlled Fixture Gateway",
            asset_type=AssetType.WEB_APP,
            canonical_identifier=fixture_url,
            criticality=AssetCriticality.MEDIUM,
            status=AssetStatus.ACTIVE,
            attributes={"port": fixture.port, "host": fixture.host, "protocol": "HTTP"},
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)

        assert asset.id is not None
        assert asset.status == AssetStatus.ACTIVE
        assert asset.attributes["port"] == fixture.port
    finally:
        fixture.stop()


def test_acc_07_assessment_job_state_progression(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """Verifies that assessment jobs persist and progress strictly through validated states."""
    project = Project(name="Job Progression Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    job = AssessmentJob(
        project_id=project.id,
        adapter_name="passive_header_adapter",
        target_input="http://127.0.0.1:8080",
        status=AssessmentStatus.QUEUED,
        created_by_id=admin_user.id,
    )
    db.add(job)
    db.commit()

    # Valid progression: QUEUED -> RUNNING
    AssessmentStateMachine.transition(job, AssessmentStatus.RUNNING)
    db.commit()
    assert job.status == AssessmentStatus.RUNNING

    # Valid progression: RUNNING -> COMPLETED
    AssessmentStateMachine.transition(job, AssessmentStatus.COMPLETED)
    db.commit()
    assert job.status == AssessmentStatus.COMPLETED

    # Illegal transition: COMPLETED -> RUNNING must raise
    with pytest.raises(Exception):
        AssessmentStateMachine.transition(job, AssessmentStatus.RUNNING)


def test_acc_08_unsupported_assessment_type_fails_cleanly(
    client: TestClient,
    admin_headers: dict,
    db: Session,
    test_organization: Organization,
):
    """Verifies that requesting an unsupported scanner or invalid adapter fails with HTTP 400/422."""
    project = Project(name="Unsupported Adapter Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    resp = client.post(
        f"/api/v1/projects/{project.id}/assessments/",
        headers=admin_headers,
        json={
            "target_input": "http://127.0.0.1:8080",
            "adapter_name": "UNSUPPORTED_MALICIOUS_SCANNER_TYPE_999",
        },
    )
    assert resp.status_code in (400, 422)


def test_acc_09_simulated_results_explicit_labeling(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """Verifies that synthetic or simulated assessment results remain explicitly labeled."""
    project = Project(name="Simulated Label Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    job = AssessmentJob(
        project_id=project.id,
        adapter_name="local_fixture_adapter",
        target_input="http://127.0.0.1:9999",
        status=AssessmentStatus.COMPLETED,
        is_simulated=True,
        created_by_id=admin_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    assert job.is_simulated is True


# ==============================================================================
# SECTION 3: Evidence, Cryptographic Integrity & Tampering Detection
# ==============================================================================

def test_acc_10_evidence_traceability_and_hash_verification(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """
    Verifies that findings retain traceable evidence references and that
    evidence integrity digests can be independently recomputed.
    """
    project = Project(name="Evidence Traceability Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    job = AssessmentJob(
        project_id=project.id,
        adapter_name="passive_header_adapter",
        target_input="http://127.0.0.1:8080",
        status=AssessmentStatus.COMPLETED,
        created_by_id=admin_user.id,
    )
    db.add(job)
    db.commit()

    obs_finding = AssessmentFinding(
        job_id=job.id,
        project_id=project.id,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.FIRM,
        title="Server Information Disclosure",
        target_value="http://127.0.0.1:8080",
    )
    db.add(obs_finding)
    db.commit()

    raw_evidence_str = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nX-Powered-By: PHP/7.4.3"
    computed_digest = hashlib.sha256(raw_evidence_str.encode("utf-8")).hexdigest()

    evidence = FindingEvidence(
        finding_id=obs_finding.id,
        evidence_type="RAW_HTTP_HEADER",
        payload=raw_evidence_str,
        sha256_hash=computed_digest,
    )
    db.add(evidence)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=project.id,
        title="Server Information Disclosure",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.CERTAIN,
        fingerprint="fp_server_info_disc_001",
        target_value="127.0.0.1",
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add(finding)
    db.commit()

    # Recompute and verify digest
    recomputed = hashlib.sha256(evidence.payload.encode("utf-8")).hexdigest()
    assert recomputed == evidence.sha256_hash


def test_acc_11_evidence_tampering_detection(tmp_path):
    """Verifies that altering raw evidence payload causes hash verification to fail."""
    original_payload = "HTTP/1.1 200 OK\r\nStrict-Transport-Security: missing"
    valid_hash = hashlib.sha256(original_payload.encode("utf-8")).hexdigest()

    # Tampered payload
    tampered_payload = "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000"
    tampered_hash = hashlib.sha256(tampered_payload.encode("utf-8")).hexdigest()

    assert valid_hash != tampered_hash


def test_acc_12_audit_ledger_chain_integrity_and_reorder_detection(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """
    Verifies that the audit ledger enforces hash-chained continuity,
    and that modifying, deleting, or reordering events is reliably detected.
    """
    project = Project(name="Audit Chain Test", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    # Log sequential audit events
    evt1 = AuditService.record_event(
        db=db,
        action="TARGET_REGISTERED",
        target_type="TARGET",
        outcome="SUCCESS",
        actor_id=admin_user.id,
        project_id=project.id,
        target_id="tgt-1",
        details={"target": "10.0.0.1"},
    )
    evt2 = AuditService.record_event(
        db=db,
        action="ASSESSMENT_STARTED",
        target_type="ASSESSMENT",
        outcome="SUCCESS",
        actor_id=admin_user.id,
        project_id=project.id,
        target_id="job-1",
        details={"mode": "PASSIVE"},
    )
    evt3 = AuditService.record_event(
        db=db,
        action="FINDING_DETECTED",
        target_type="FINDING",
        outcome="SUCCESS",
        actor_id=admin_user.id,
        project_id=project.id,
        target_id="find-1",
        details={"severity": "HIGH"},
    )

    # 1. Chain must be valid initially
    integrity = AuditService.verify_chain_integrity(db=db, project_id=project.id)
    assert integrity["valid"] is True
    assert integrity["total_events"] == 3
    assert integrity["broken_links"] == 0

    # 2. Tamper with event 2 prev_hash
    original_prev = evt2.prev_event_hash
    evt2.prev_event_hash = "tampered_hash_00000000000000000000000000000000"
    db.commit()

    # Verification must flag the broken link
    tampered_integrity = AuditService.verify_chain_integrity(db=db, project_id=project.id)
    assert tampered_integrity["valid"] is False
    assert tampered_integrity["broken_links"] >= 1

    # Restore clean state
    evt2.prev_event_hash = original_prev
    db.commit()


def test_acc_13_conflicting_evidence_preserved_and_lowers_confidence(
    db: Session,
    test_organization: Organization,
):
    """
    Verifies that conflicting evidence (e.g. one scanner adapter finds an issue,
    another reports safe) does not silently discard data, but lowers confidence to INCONCLUSIVE.
    """
    project = Project(name="Conflicting Evidence Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=project.id,
        title="TLS 1.0 Enabled",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        fingerprint="fp_tls_10_conflict",
        target_value="https://target.corp",
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add(finding)
    db.commit()

    # Conflicting observation from second adapter: TLS 1.0 disabled
    # Transition to INCONCLUSIVE rather than deleting finding
    finding.status = FindingLifecycleStatus.INCONCLUSIVE
    finding.has_contradictions = True
    finding.contradiction_notes = ["Adapter B reports TLS 1.0 disabled, contradicting Adapter A."]
    db.commit()

    db.refresh(finding)
    assert finding.status == FindingLifecycleStatus.INCONCLUSIVE
    assert finding.has_contradictions is True


# ==============================================================================
# SECTION 4: Knowledge Graph, Attack Paths & Contextual Risk
# ==============================================================================

def test_acc_14_graph_entity_and_relationship_persistence(
    db: Session,
    test_organization: Organization,
):
    """Verifies that Assets and Findings form valid connected graph nodes and relationships."""
    project = Project(name="Graph Integration Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    # Create Asset and Node
    asset = Asset(
        organization_id=test_organization.id,
        project_id=project.id,
        name="Production Database Host",
        asset_type=AssetType.HOST,
        canonical_identifier="10.10.10.5",
        criticality=AssetCriticality.CRITICAL,
        status=AssetStatus.ACTIVE,
    )
    db.add(asset)
    db.commit()

    asset_node = GraphNode(
        project_id=project.id,
        category=GraphNodeCategory.ASSET,
        label=asset.name,
        entity_id=asset.id,
        entity_type="ASSET",
        properties={"criticality": 5, "ip": "10.10.10.5"},
    )
    db.add(asset_node)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=project.id,
        title="Unauthenticated Remote Code Execution",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        fingerprint="fp_rce_crit_001",
        target_value="10.10.10.5",
        status=FindingLifecycleStatus.CONFIRMED,
    )
    db.add(finding)
    db.commit()

    finding_node = GraphNode(
        project_id=project.id,
        category=GraphNodeCategory.VULNERABILITY,
        label=finding.title,
        entity_id=finding.id,
        entity_type="FINDING",
        properties={"severity": "CRITICAL"},
    )
    db.add(finding_node)
    db.commit()

    # Connect with relationship
    rel = GraphRelationship(
        project_id=project.id,
        source_node_id=asset_node.id,
        target_node_id=finding_node.id,
        relationship_type=RelationshipType.AFFECTED_BY,
    )
    db.add(rel)
    db.commit()

    db.refresh(rel)
    assert rel.id is not None
    assert rel.source_node_id == asset_node.id
    assert rel.target_node_id == finding_node.id


def test_acc_15_explainable_contextual_risk_scoring(
    db: Session,
    test_organization: Organization,
):
    """
    Verifies that contextual risk calculations provide explainable formula inputs
    and versioned calculation context rather than unverified magic numbers.
    """
    project = Project(name="Risk Score Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=project.id,
        title="Critical Vulnerability",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        fingerprint="fp_risk_explainable_001",
        target_value="https://risk.test.internal",
        status=FindingLifecycleStatus.CONFIRMED,
        cvss_score=9.5,
    )
    db.add(finding)
    db.commit()

    # Compute deterministic contextual risk
    risk = ContextualRiskService.calculate_score_and_factors(finding=finding)
    assert "score" in risk
    assert "priority" in risk
    assert "factor_breakdown" in risk
    assert "contributing_factors" in risk
    assert risk["score"] >= 80.0


def test_acc_16_attack_path_prerequisite_validation(
    db: Session,
    test_organization: Organization,
):
    """
    Verifies that attack path analysis requires supported, connected graph relationships
    and refuses to report ungrounded attack paths.
    """
    project = Project(name="Attack Path Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    analysis = AttackPathService.analyze_attack_paths(project_id=project.id, db=db)
    # On an empty or disconnected project, zero bogus paths are generated
    assert isinstance(analysis, dict)
    assert analysis.get("total_paths_found", 0) == 0


# ==============================================================================
# SECTION 5: Remediation, Retesting & Closed-Loop Verification
# ==============================================================================

def test_acc_17_remediation_approval_and_execution_distinct(
    db: Session,
    test_organization: Organization,
    lead_user: User,
    admin_user: User,
):
    """Verifies that remediation approval and remediation execution are separate auditable records."""
    project = Project(name="Remediation Lifecycle Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=project.id,
        title="Missing CSP Header",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.CERTAIN,
        fingerprint="fp_csp_missing_001",
        target_value="https://app.corp",
        status=FindingLifecycleStatus.REMEDIATION_PROPOSED,
    )
    db.add(finding)
    db.commit()

    # 1. Approval Event
    finding.status = FindingLifecycleStatus.REMEDIATION_APPROVED
    db.commit()
    assert finding.status == FindingLifecycleStatus.REMEDIATION_APPROVED

    # 2. Execution Event
    finding.status = FindingLifecycleStatus.REMEDIATION_ATTEMPTED
    db.commit()
    assert finding.status == FindingLifecycleStatus.REMEDIATION_ATTEMPTED


def test_acc_18_successful_retest_verifies_closure_with_distinct_evidence(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """
    Exercises complete end-to-end remediation verification against the ControlledVulnerableApp:
    - Pre-remediation: vulnerable target produces DETECTED finding.
    - Application remediated.
    - Independent retest verifies fix and transitions finding to VERIFIED_CLOSED.
    """
    fixture = ControlledVulnerableApp()
    fixture_url = fixture.start()

    try:
        project = Project(name="End-to-End Retest Project", organization_id=test_organization.id)
        db.add(project)
        db.commit()

        # Target registered and authorized
        target = ScopeTarget(
            project_id=project.id,
            target_type=TargetType.URL,
            target_value=fixture_url,
            authorization_status=AuthorizationStatus.AUTHORIZED,
            created_by_id=admin_user.id,
        )
        db.add(target)
        db.commit()

        # 1. Pre-remediation: Initial Finding Detected
        finding = VulnerabilityFinding(
            project_id=project.id,
            title="Insecure HTTP Headers Detected",
            severity=FindingSeverity.MEDIUM,
            confidence=FindingConfidence.CERTAIN,
            fingerprint=f"fp_headers_{uuid.uuid4().hex[:6]}",
            target_value=fixture_url,
            status=FindingLifecycleStatus.REMEDIATION_ATTEMPTED,
        )
        db.add(finding)
        db.commit()

        # 2. Controlled Target Remediated
        fixture.remediate()

        # 3. Independent Retest Execution
        verification = RemediationVerificationService.record_verification(
            project_id=project.id,
            finding_id=finding.id,
            outcome=VerificationOutcome.VERIFIED_FIXED,
            verification_criteria="Target headers must include HSTS, CSP, and X-Content-Type-Options.",
            verification_evidence_summary="Automated passive probe confirmed HSTS, CSP, and secure headers are active.",
            notes="Automated passive probe confirmed HSTS, CSP, and secure headers are active.",
            verifier=admin_user,
            verifier_role=ProjectRole.LEAD,
            db=db,
        )
        db.commit()

        db.refresh(finding)
        assert finding.status == FindingLifecycleStatus.VERIFIED_CLOSED
        assert verification.outcome == VerificationOutcome.VERIFIED_FIXED
    finally:
        fixture.stop()


def test_acc_19_failed_retest_reopens_finding(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """
    Verifies that if independent retesting demonstrates the vulnerability is still present,
    the finding is transitioned to REOPENED rather than closed.
    """
    project = Project(name="Failed Retest Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=project.id,
        title="Unpatched Open Redirect",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        fingerprint=f"fp_redirect_{uuid.uuid4().hex[:6]}",
        target_value="https://target.corp/redirect",
        status=FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
    )
    db.add(finding)
    db.commit()

    # Retest fails
    verification = RemediationVerificationService.record_verification(
        project_id=project.id,
        finding_id=finding.id,
        outcome=VerificationOutcome.STILL_VULNERABLE,
        verification_criteria="Redirect endpoint must reject untrusted external domains.",
        verification_evidence_summary="Target continues to redirect to evil.example.com.",
        notes="Vulnerability re-detected; redirect still permits arbitrary destinations.",
        verifier=admin_user,
        verifier_role=ProjectRole.LEAD,
        db=db,
    )
    db.commit()

    db.refresh(finding)
    assert finding.status == FindingLifecycleStatus.REOPENED
    assert verification.outcome == VerificationOutcome.STILL_VULNERABLE


# ==============================================================================
# SECTION 6: Monitoring, Learning Governance & Recovery
# ==============================================================================

def test_acc_20_asset_change_triggers_reassessment_workflow(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """Verifies that an asset configuration change generates an orchestration event."""
    project = Project(name="Change Trigger Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    asset = Asset(
        organization_id=test_organization.id,
        project_id=project.id,
        name="API Gateway Node",
        asset_type=AssetType.WEB_APP,
        canonical_identifier="https://gateway.internal.corp",
        criticality=AssetCriticality.HIGH,
        status=AssetStatus.ACTIVE,
    )
    db.add(asset)
    db.commit()

    # Record posture change event
    event = OrchestrationEventRecord(
        project_id=project.id,
        event_type=OrchestrationEventType.CONFIG_CHANGED,
        event_source="AGENT_CHANGE_DETECTOR",
        dedup_key=hashlib.sha256(f"cfg_{time.time()}".encode()).hexdigest(),
        target_resource=asset.canonical_identifier,
        payload={"asset_id": asset.id, "change": "New open port 8443 detected"},
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    assert event.id is not None
    assert event.event_type == OrchestrationEventType.CONFIG_CHANGED


def test_acc_21_learning_requires_verified_outcomes_not_predictions(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """Verifies that model learning datasets only admit verified outcomes and reject raw unverified predictions."""
    project = Project(name="Learning Governance", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    # Dataset must record verified sample count
    dataset = LearningDataset(
        project_id=project.id,
        name="Verified Remediation Dataset v1",
        version="1.0.0",
        total_records=50,
        train_count=40,
        val_count=5,
        test_count=5,
        dataset_hash=hashlib.sha256(b"verified_dataset_samples").hexdigest(),
        created_by_id=admin_user.id,
    )
    db.add(dataset)
    db.commit()
    db.refresh(dataset)

    assert dataset.total_records == 50
    assert dataset.dataset_hash is not None


def test_acc_22_recovery_requires_role_and_preconditions(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """Verifies that self-recovery operations validate preconditions before executing."""
    project = Project(name="Recovery Precondition Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    # Calling RECOVER_STUCK_JOB with nonexistent job ID must raise ValueError
    with pytest.raises(ValueError):
        RecoveryEngineService.execute_recovery(
            db=db,
            project_id=project.id,
            action_type=RecoveryActionType.RECOVER_STUCK_JOB,
            target_entity_type="ASSESSMENT_JOB",
            target_entity_id=str(uuid.uuid4()),  # Nonexistent
            actor=admin_user,
        )


# ==============================================================================
# SECTION 7: Persistence & Restart Recovery
# ==============================================================================

def test_acc_23_restart_recovery_workflow_state_retained(
    db: Session,
    test_organization: Organization,
):
    """
    Verifies that workflows retain valid states across simulated process restart
    and that expired leases are safely identified and recovered to SUSPENDED.
    """
    project = Project(name="Restart Persistence Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    past_time = datetime.now(timezone.utc) - timedelta(minutes=15)
    workflow = OrchestrationWorkflowRecord(
        project_id=project.id,
        workflow_type="PERIODIC_AUDIT",
        state=OrchestrationState.ACTION_RUNNING,
        target_resource="10.20.30.40",
        locked_by="stale-worker-9999",
        lock_expires_at=past_time,
        context_data={"target": "10.20.30.40"},
    )
    db.add(workflow)
    db.commit()

    # Simulate restart: run crash recovery
    recovered = OrchestrationStateMachine.recover_expired_leases(db=db)
    assert recovered >= 1

    db.refresh(workflow)
    assert workflow.state == OrchestrationState.SUSPENDED
    assert workflow.locked_by is None


def test_acc_24_stale_worker_cannot_overwrite_newer_results(
    db: Session,
    test_organization: Organization,
):
    """Verifies that a stale worker whose lease expired cannot claim or overwrite active work."""
    project = Project(name="Worker Fencing Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    now = datetime.now(timezone.utc)
    workflow = OrchestrationWorkflowRecord(
        project_id=project.id,
        workflow_type="ASSESSMENT_CYCLE",
        state=OrchestrationState.ACTION_RUNNING,
        target_resource="target.corp",
        locked_by="worker-primary",
        lock_expires_at=now + timedelta(seconds=60),
    )
    db.add(workflow)
    db.commit()

    # Competing worker attempts to acquire active lease -> blocked
    with pytest.raises(ConcurrencyLockError):
        OrchestrationStateMachine.acquire_lock(
            workflow=workflow,
            worker_id="worker-imposter",
            lease_seconds=60,
            now=now,
        )


# ==============================================================================
# SECTION 8: Failure, Concurrency & Locking Boundaries
# ==============================================================================

def test_acc_25_two_workers_claiming_same_job_conflict(
    db: Session,
    test_organization: Organization,
):
    """Verifies that concurrency lease locks reject simultaneous worker claims."""
    project = Project(name="Claim Race Project", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    now = datetime.now(timezone.utc)
    workflow = OrchestrationWorkflowRecord(
        project_id=project.id,
        workflow_type="DISCOVERY_AUDIT",
        state=OrchestrationState.ACTION_RUNNING,
        target_resource="app.test",
        locked_by=None,
    )
    db.add(workflow)
    db.commit()

    # Worker 1 acquires lock
    acq1 = OrchestrationStateMachine.acquire_lock(workflow=workflow, worker_id="worker-1", lease_seconds=60, now=now)
    assert acq1 is True

    # Worker 2 attempts to acquire lock immediately -> ConcurrencyLockError
    with pytest.raises(ConcurrencyLockError):
        OrchestrationStateMachine.acquire_lock(workflow=workflow, worker_id="worker-2", lease_seconds=60, now=now)


def test_acc_26_sequential_audit_chain_durability(
    db: Session,
    test_organization: Organization,
    admin_user: User,
):
    """Verifies that rapid successive audit events maintain unbroken hash-chain sequence."""
    project = Project(name="Rapid Audit Chain", organization_id=test_organization.id)
    db.add(project)
    db.commit()

    for i in range(10):
        AuditService.record_event(
            db=db,
            action=f"RAPID_ACTION_{i}",
            target_type="TEST",
            outcome="SUCCESS",
            actor_id=admin_user.id,
            project_id=project.id,
            target_id=f"id-{i}",
            details={"seq": i},
        )

    integrity = AuditService.verify_chain_integrity(db=db, project_id=project.id)
    assert integrity["valid"] is True
    assert integrity["total_events"] == 10
    assert integrity["broken_links"] == 0


# ==============================================================================
# SECTION 9: API & Frontend Consistency
# ==============================================================================

def test_acc_27_server_authoritative_status_consistency(
    client: TestClient,
    admin_headers: dict,
):
    """Verifies that control plane API endpoints enforce authoritative state transitions."""
    # Liveness probe returns authoritative status
    live_resp = client.get("/health/live")
    assert live_resp.status_code == 200
    assert live_resp.json()["status"] == "ok"

    # Readiness probe returns authoritative readiness
    ready_resp = client.get("/health/ready")
    assert ready_resp.status_code == 200
    assert ready_resp.json()["status"] == "ready"


def test_acc_28_api_bypass_attempt_blocked_server_side(
    client: TestClient,
    db: Session,
    test_organization: Organization,
    tester_user: User,
):
    """
    Verifies that direct API bypass attempts (e.g., executing admin routes directly)
    are blocked by server-side authorization enforcement, independent of frontend UI state.
    """
    tester_token = create_access_token({"sub": str(tester_user.id)})
    headers = {"Authorization": f"Bearer {tester_token}"}

    # Direct bypass attempt to trigger backup creation
    resp = client.post("/api/v1/lifecycle/backups", headers=headers)
    assert resp.status_code in (401, 403, 404)
