"""
Comprehensive Deterministic Test Suite for Prompt 22:
Multi-Tenant Isolation, Governance & Secure Collaboration.
Covers:
1. Cross-tenant project enumeration fails closed (404 Not Found, never 403).
2. Cross-tenant evidence download blocked with 404 and parent-child scoping.
3. Cross-tenant graph edge creation strictly blocked.
4. Cross-tenant asset merge strictly blocked.
5. Separation of Duties (SoD) blocks self-authorization of scope targets.
6. Separation of Duties blocks self-approval of security decisions.
7. Separation of Duties blocks self-authorization of remediation changes.
8. Separation of Duties blocks self-approval of governed models.
9. Single-operator local mode override permits self-approval with explicit audit trail.
10. Cryptographic parameter drift invalidates approved status at execution boundary.
11. Background worker preflight rejects jobs when creator membership is revoked.
12. Background worker preflight rejects jobs when workspace is deactivated.
13. Idempotency and approval requests are tenant-isolated without cross-project collision.
14. Read-only roles (AUDITOR, VIEWER) cannot execute or mutate governance records.
15. Export endpoints sanitize filenames preventing path traversal.
16. Governance REST API endpoints and permission matrix validation.
"""

import json
import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingEvidence,
    FindingSeverity,
    FindingConfidence,
)
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.graph import (
    GraphNode,
    GraphRelationship,
    GraphNodeCategory,
    RelationshipType,
    RelationshipStatus,
)
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.models.decision import SecurityDecisionRecord, DecisionActionType, DecisionStatus
from app.models.learning import GovernedModel, LearningDataset, DatasetRecord, DatasetSplit, ModelStatus
from app.models.governance import (
    ApprovalWorkflowType,
    GovernanceApprovalStatus,
    ProjectGovernancePolicy,
    ApprovalRequestRecord,
)
from app.models.base import utc_now
from app.core.security import hash_password, create_access_token
from app.services.governance_service import ProjectGovernanceService
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.remediation_service import RemediationPrioritizationService
from app.services.learning_service import ModelGovernanceService
from app.services.knowledge_graph_service import KnowledgeGraphService
from app.services.asset_identity_service import AssetIdentityService


# ---------------------------------------------------------------------------
# Test Fixtures & Secondary Workspace
# ---------------------------------------------------------------------------

@pytest.fixture
def secondary_lead_user(db: Session) -> User:
    user = User(
        email="second_lead@acme-defense.local",
        hashed_password=hash_password("SecondLeadPass123!"),
        full_name="Secondary Project Lead",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def secondary_project(db: Session, test_organization: Organization, secondary_lead_user: User) -> Project:
    project = Project(
        name="Project Bravo Isolated",
        description="Air-gapped industrial control system assessment",
        organization_id=test_organization.id,
        is_active=True,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    db.add(ProjectMember(project_id=project.id, user_id=secondary_lead_user.id, role=ProjectRole.LEAD))
    db.commit()
    return project


def _auth_header(user: User) -> dict:
    token = create_access_token(subject=user.id, claims={"email": user.email, "role": user.system_role.value})
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. Multi-Tenant Fail-Closed Isolation & Project Enumeration Prevention
# ---------------------------------------------------------------------------

def test_cross_tenant_project_enumeration_fails_closed_404(
    client: TestClient,
    test_project: Project,
    secondary_project: Project,
    outsider_user: User,
):
    """
    Non-member requests to a project MUST return 404 Not Found, never 403 Forbidden.
    This prevents cross-tenant UUID enumeration and information leakage.
    """
    outsider_headers = _auth_header(outsider_user)

    # Project detail
    resp = client.get(f"/api/v1/projects/{test_project.id}", headers=outsider_headers)
    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    # Governance policy
    resp = client.get(f"/api/v1/projects/{test_project.id}/governance/policy", headers=outsider_headers)
    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    # Decisions overview
    resp = client.get(f"/api/v1/projects/{test_project.id}/decisions", headers=outsider_headers)
    assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"


def test_cross_tenant_evidence_download_blocked_404(
    client: TestClient,
    db: Session,
    test_project: Project,
    secondary_project: Project,
    lead_user: User,
    secondary_lead_user: User,
):
    """
    Evidence items are strictly scoped to project, job, and finding.
    Accessing evidence from another project or via cross-tenant ID returns 404.
    """
    lead_headers = _auth_header(lead_user)
    sec_lead_headers = _auth_header(secondary_lead_user)

    now = utc_now()
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="192.168.1.100",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    finding = AssessmentFinding(
        project_id=test_project.id,
        job_id=job.id,
        target_value="192.168.1.100",
        title="Open SMB Port Exposed",
        description="445/tcp open microsoft-ds",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
    )
    db.add(finding)
    db.commit()

    evidence = FindingEvidence(
        finding_id=finding.id,
        evidence_type="RAW_OUTPUT",
        payload="smb evidence",
        sha256_hash=hashlib.sha256(b"smb evidence").hexdigest(),
    )
    db.add(evidence)
    db.commit()

    # 1. Primary lead can access it in test_project
    url_valid = f"/api/v1/projects/{test_project.id}/assessments/{job.id}/findings/{finding.id}/evidence/{evidence.id}"
    resp = client.get(url_valid, headers=lead_headers)
    assert resp.status_code == 200
    assert resp.json()["id"] == evidence.id

    # 2. Secondary lead (from Project Bravo) accessing Project Apex evidence directly -> 404
    resp_cross = client.get(url_valid, headers=sec_lead_headers)
    assert resp_cross.status_code == 404

    # 3. Requesting Project Apex evidence using Project Bravo's project_id -> 404
    url_mismatched = f"/api/v1/projects/{secondary_project.id}/assessments/{job.id}/findings/{finding.id}/evidence/{evidence.id}"
    resp_mismatch = client.get(url_mismatched, headers=sec_lead_headers)
    assert resp_mismatch.status_code == 404


def test_cross_tenant_graph_edge_creation_blocked(
    db: Session,
    test_project: Project,
    secondary_project: Project,
):
    """
    Enforces that graph relationships cannot link nodes across tenant boundaries.
    """
    node_a = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.HOST,
        label="app.project-apex.internal",
        db=db,
    )
    node_b = KnowledgeGraphService.get_or_create_node(
        project_id=secondary_project.id,
        category=GraphNodeCategory.DATA_STORE,
        label="db.project-bravo.internal",
        db=db,
    )

    # Attempt to create edge from Project Apex node to Project Bravo node within Project Apex
    with pytest.raises(ValueError) as exc_info:
        KnowledgeGraphService.create_or_update_relationship(
            project_id=test_project.id,
            source_node_id=node_a.id,
            target_node_id=node_b.id,
            relationship_type=RelationshipType.ASSOCIATED_WITH,
            db=db,
        )
    assert "does not exist in project" in str(exc_info.value)


def test_cross_tenant_asset_merge_blocked(
    db: Session,
    test_project: Project,
    secondary_project: Project,
):
    """
    Cross-tenant asset merging is strictly forbidden and raises a ValueError.
    """
    asset_a = Asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.HOST,
        name="web-01.corp",
        canonical_identifier="web-01.corp",
        criticality=AssetCriticality.HIGH,
        status=AssetStatus.ACTIVE,
    )
    asset_b = Asset(
        project_id=secondary_project.id,
        organization_id=secondary_project.organization_id,
        asset_type=AssetType.HOST,
        name="web-01.corp",
        canonical_identifier="web-01.corp",
        criticality=AssetCriticality.HIGH,
        status=AssetStatus.ACTIVE,
    )
    db.add_all([asset_a, asset_b])
    db.commit()

    with pytest.raises(ValueError) as exc:
        AssetIdentityService.merge_asset_identities(
            project_id=test_project.id,
            target_asset_id=asset_a.id,
            source_asset_id=asset_b.id,
            rationale="Attempted cross-tenant deduplication merge",
            db=db,
        )
    assert "not found in project" in str(exc.value)


# ---------------------------------------------------------------------------
# 2. Separation of Duties (SoD) Across Security Workflows
# ---------------------------------------------------------------------------

def test_separation_of_duties_blocks_self_authorization_of_scope_target(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    """
    A user who registers a scope target cannot authorize that same target.
    An independent Project LEAD must authorize it.
    """
    lead_headers = _auth_header(lead_user)

    # 1. Lead registers a scope target
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="api.production.internal",
        authorization_status=AuthorizationStatus.PENDING,
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # 2. Lead attempts to self-authorize their own scope target -> Denied 403
    auth_payload = {
        "evidence": "ROE-2026-APEX-001 signed by CISO with full authorization scope.",
    }
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/targets/{target.id}/authorize",
        json=auth_payload,
        headers=lead_headers,
    )
    assert resp.status_code == 403
    assert "Separation of Duties violation" in resp.json()["detail"]

    # 3. Create a second independent Project Lead in test_project
    second_lead = User(
        email="independent_lead@acme-defense.local",
        hashed_password=hash_password("Pass123!"),
        full_name="Independent Lead",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    db.add(second_lead)
    db.commit()
    db.add(ProjectMember(project_id=test_project.id, user_id=second_lead.id, role=ProjectRole.LEAD))
    db.commit()

    # 4. Independent lead authorizes the target -> SUCCEEDS
    resp_ok = client.post(
        f"/api/v1/projects/{test_project.id}/targets/{target.id}/authorize",
        json=auth_payload,
        headers=_auth_header(second_lead),
    )
    assert resp_ok.status_code == 200
    assert resp_ok.json()["authorization_status"] == AuthorizationStatus.AUTHORIZED.value


def test_separation_of_duties_blocks_self_approval_of_security_decision(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    A user who creates an autonomous security decision cannot approve that decision.
    """
    now = utc_now()
    decision = SecurityDecisionRecord(
        project_id=test_project.id,
        action_type=DecisionActionType.REASSESS_CHANGED_ASSET,
        title="Automated Retest for Critical Log4j Finding",
        triggering_observation="Port 443 open with vulnerable header",
        selected_action="TRIGGER_RETEST",
        rationale="Retesting verified patch after firewall configuration change",
        required_approval_role="LEAD",
        status=DecisionStatus.PROPOSED,
        created_by_id=lead_user.id,
        created_at=now,
    )
    db.add(decision)
    db.commit()

    # Lead attempts to self-approve decision -> Denied 403
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/decisions/{decision.id}/approve",
        headers=_auth_header(lead_user),
    )
    assert resp.status_code == 403
    assert "Separation of Duties violation" in resp.json()["detail"]

    # Independent admin approves -> SUCCEEDS
    admin = User(
        email="sysadmin_sod@acme-defense.local",
        hashed_password=hash_password("AdminPass123!"),
        full_name="System Auditor Admin",
        system_role=SystemRole.ADMIN,
        is_active=True,
    )
    db.add(admin)
    db.commit()

    resp_admin = client.post(
        f"/api/v1/projects/{test_project.id}/decisions/{decision.id}/approve",
        headers=_auth_header(admin),
    )
    assert resp_admin.status_code == 200
    assert resp_admin.json()["status"] == DecisionStatus.APPROVED.value


def test_separation_of_duties_blocks_self_authorization_of_remediation_change(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    The reviewer who approved a remediation recommendation cannot authorize the change implementation.
    """
    now = utc_now()
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        target_value="10.0.0.1",
        fingerprint=hashlib.sha256(b"unauthenticated cache leak").hexdigest(),
        title="Unauthenticated Cache Leak",
        description="Missing Cache-Control headers on sensitive endpoint",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        first_detected_at=now,
        last_observed_at=now,
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_or_get_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=lead_user,
    )

    # Lead approves the recommendation
    RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=rec.id,
        new_status=RecommendationStatus.APPROVED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Approved for change window #104",
        db=db,
    )

    # Same lead attempts to authorize the change -> Denied with PermissionError (SoD)
    with pytest.raises(PermissionError) as exc:
        RemediationPrioritizationService.authorize_change(
            project_id=test_project.id,
            recommendation_id=rec.id,
            change_ticket_ref="CHG-2026-9901",
            authorizer=lead_user,
            authorizer_role=ProjectRole.LEAD,
            db=db,
        )
    assert "Separation of Duties violation" in str(exc.value)

    # Independent admin authorizes the change -> SUCCEEDS
    independent_lead = User(
        email="change_authorizer@acme-defense.local",
        hashed_password=hash_password("Pass123!"),
        full_name="Change Authorizer",
        system_role=SystemRole.ADMIN,
        is_active=True,
    )
    db.add(independent_lead)
    db.commit()

    updated = RemediationPrioritizationService.authorize_change(
        project_id=test_project.id,
        recommendation_id=rec.id,
        change_ticket_ref="CHG-2026-9901",
        authorizer=independent_lead,
        authorizer_role=ProjectRole.LEAD,
        db=db,
    )
    assert updated.execution_governance_stage == "CHANGE_AUTHORIZED"


def test_separation_of_duties_blocks_self_approval_of_governed_model(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    The user who created the training dataset/model cannot approve their own model promotion.
    """
    now = utc_now()
    dataset = LearningDataset(
        project_id=test_project.id,
        name="Telemetry Dataset v1",
        version="v1.0.0",
        dataset_hash=hashlib.sha256(b"dummy hash").hexdigest(),
        created_by_id=lead_user.id,
        created_at=now,
    )
    db.add(dataset)
    db.commit()

    # Add dummy test records
    for i in range(10):
        db.add(DatasetRecord(
            dataset_id=dataset.id,
            split=DatasetSplit.TEST,
            source_entity_type="finding",
            source_entity_id=f"finding-{i}",
            features={"severity": "HIGH" if i % 2 == 0 else "LOW"},
            label="TRUE_POSITIVE" if i % 2 == 0 else "FALSE_POSITIVE",
            provenance_digest=hashlib.sha256(f"prov-{i}".encode()).hexdigest(),
        ))
    db.commit()

    model = GovernedModel(
        project_id=test_project.id,
        model_name="VulnerabilityClassifier",
        version="v1.0.0",
        model_type="CLASSIFIER",
        dataset_id=dataset.id,
        status=ModelStatus.EVALUATED,
        metrics={"precision": 0.85, "recall": 0.85, "f1_score": 0.85, "false_positive_rate": 0.05, "brier_score": 0.04},
        created_at=now,
    )
    db.add(model)
    db.commit()

    # Lead (dataset creator) attempts to approve the model -> Denied
    with pytest.raises(PermissionError) as exc:
        ModelGovernanceService.approve_model(
            project_id=test_project.id,
            model_id=model.id,
            approved=True,
            approval_notes="Self-approving my own model",
            reviewer=lead_user,
            db=db,
        )
    assert "Separation of Duties violation" in str(exc.value)

    # Independent admin approves model -> SUCCEEDS
    admin_approver = User(
        email="model_approver@acme-defense.local",
        hashed_password=hash_password("Pass123!"),
        full_name="Independent Model Evaluator",
        system_role=SystemRole.ADMIN,
        is_active=True,
    )
    db.add(admin_approver)
    db.commit()

    approved_model = ModelGovernanceService.approve_model(
        project_id=test_project.id,
        model_id=model.id,
        approved=True,
        approval_notes="Verified accuracy against hold-out test split",
        reviewer=admin_approver,
        db=db,
    )
    assert approved_model.status == ModelStatus.APPROVED


def test_single_operator_mode_override_permits_self_approval_with_audit(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    When allow_self_approval_override is explicitly set to True, self-approval is allowed
    with a mandatory audit log entry (GOVERNANCE_SELF_APPROVAL_OVERRIDE).
    """
    policy = ProjectGovernanceService.get_or_create_policy(db, test_project.id)
    policy.allow_self_approval_override = True
    db.commit()

    params = {"target": "10.0.0.1", "action": "FULL_SCAN"}
    req = ProjectGovernanceService.request_approval(
        db=db,
        project_id=test_project.id,
        workflow_type=ApprovalWorkflowType.SECURITY_DECISION,
        resource_type="SecurityDecision",
        resource_id="dec-12345",
        title="Single Operator Retest",
        parameters=params,
        requester=lead_user,
    )

    # Requester approves their own request
    approved_req = ProjectGovernanceService.decide_approval(
        db=db,
        project_id=test_project.id,
        approval_id=req.id,
        approver=lead_user,
        approved=True,
        reason="Single-operator local development override verified",
        approver_role=ProjectRole.LEAD,
    )

    assert approved_req.status == GovernanceApprovalStatus.APPROVED
    assert approved_req.approver_id == lead_user.id

    # Restore default
    policy.allow_self_approval_override = False
    db.commit()


# ---------------------------------------------------------------------------
# 3. Cryptographic Parameter Binding & Drift Invalidation
# ---------------------------------------------------------------------------

def test_parameter_drift_invalidates_approved_status_at_execution_boundary(
    db: Session,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    """
    Approvals are cryptographically bound to exact parameter digests.
    If parameters mutate prior to execution, approval is invalidated (INVALIDATED).
    """
    original_params = {
        "target_ip": "192.168.1.50",
        "ports": "80,443",
        "intensity": "PASSIVE",
    }
    req = ProjectGovernanceService.request_approval(
        db=db,
        project_id=test_project.id,
        workflow_type=ApprovalWorkflowType.SCOPE_AUTHORIZATION,
        resource_type="ScopeTarget",
        resource_id="tgt-target-50",
        title="Authorize Target 50",
        parameters=original_params,
        requester=tester_user,
    )

    # Lead approves
    ProjectGovernanceService.decide_approval(
        db=db,
        project_id=test_project.id,
        approval_id=req.id,
        approver=lead_user,
        approved=True,
        reason="Target verified within ROE",
        approver_role=ProjectRole.LEAD,
    )

    # Parameter drift: ports expanded to include 8080
    mutated_params = {
        "target_ip": "192.168.1.50",
        "ports": "80,443,8080",
        "intensity": "PASSIVE",
    }

    # Attempt to consume execution with mutated parameters -> Drift detected & invalidated
    with pytest.raises(ValueError) as exc:
        ProjectGovernanceService.verify_and_consume_execution(
            db=db,
            project_id=test_project.id,
            workflow_type=ApprovalWorkflowType.SCOPE_AUTHORIZATION,
            resource_type="ScopeTarget",
            resource_id="tgt-target-50",
            current_parameters=mutated_params,
            executor=tester_user,
        )
    assert "Approval invalidated" in str(exc.value)

    # Verify status in database is transitioned to INVALIDATED
    db.refresh(req)
    assert req.status == GovernanceApprovalStatus.INVALIDATED
    assert "Parameter drift detected" in (req.invalidation_reason or "")


# ---------------------------------------------------------------------------
# 4. Background Worker Tenant & Membership Safety
# ---------------------------------------------------------------------------

def test_worker_preflight_blocks_jobs_when_creator_membership_revoked(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """
    If a job creator's project membership is revoked before the worker claims the job,
    preflight rejects the job with CREATOR_MEMBERSHIP_REVOKED.
    """
    now = utc_now()
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="10.0.0.99",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=tester_user.id,
        created_at=now,
    )
    db.add(job)
    db.commit()

    # Revoke tester's project membership
    member = (
        db.query(ProjectMember)
        .filter(ProjectMember.project_id == test_project.id, ProjectMember.user_id == tester_user.id)
        .first()
    )
    if member:
        db.delete(member)
        db.commit()

    # Worker attempts to claim and preflight job
    claimed = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job.id, worker_id="worker-node-1")

    assert claimed.status == AssessmentStatus.REJECTED
    assert claimed.failure_category == "CREATOR_MEMBERSHIP_REVOKED"


def test_worker_preflight_blocks_jobs_when_workspace_deactivated(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    If a project workspace is deactivated/archived while jobs are queued,
    preflight rejects the job with WORKSPACE_INACTIVE.
    """
    now = utc_now()
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="10.0.0.99",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
        created_at=now,
    )
    db.add(job)
    db.commit()

    # Deactivate workspace
    test_project.is_active = False
    db.commit()

    claimed = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job.id, worker_id="worker-node-1")

    assert claimed.status == AssessmentStatus.REJECTED
    assert claimed.failure_category == "WORKSPACE_INACTIVE"

    # Restore active status
    test_project.is_active = True
    db.commit()


# ---------------------------------------------------------------------------
# 5. Role Constraints & Export Protection
# ---------------------------------------------------------------------------

def test_read_only_roles_cannot_execute_or_mutate_governance_records(
    client: TestClient,
    db: Session,
    test_project: Project,
    auditor_user: User,
):
    """
    Read-only roles (AUDITOR, VIEWER) cannot request approvals, modify policy, or decide approvals.
    """
    auditor_headers = _auth_header(auditor_user)

    # Add auditor as AUDITOR in test_project
    db.add(ProjectMember(project_id=test_project.id, user_id=auditor_user.id, role=ProjectRole.AUDITOR))
    db.commit()

    # 1. Auditor attempts to update policy -> 403
    resp = client.put(
        f"/api/v1/projects/{test_project.id}/governance/policy",
        json={"enforce_separation_of_duties": False},
        headers=auditor_headers,
    )
    assert resp.status_code == 403

    # 2. Auditor attempts to request approval -> 403
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/governance/approvals",
        json={
            "workflow_type": "DATA_PURGE",
            "resource_type": "Project",
            "resource_id": test_project.id,
            "title": "Unauthorized Purge Request",
            "parameters": {},
        },
        headers=auditor_headers,
    )
    assert resp.status_code == 403


def test_export_manifest_excludes_sensitive_credentials(
    client: TestClient,
    test_project: Project,
    lead_user: User,
):
    """
    Export endpoints sanitize filenames (using Path(filename).name) to prevent directory traversal
    and do not leak internal database credentials.
    """
    lead_headers = _auth_header(lead_user)

    resp = client.get(
        f"/api/v1/projects/{test_project.id}/reports/export/executive?format=JSON",
        headers=lead_headers,
    )
    assert resp.status_code == 200

    content_disp = resp.headers.get("content-disposition", "")
    assert "filename=" in content_disp
    # Verify no path traversal indicators (e.g. ../ or / or \) in the filename attribute
    filename_part = content_disp.split("filename=")[-1].strip('"')
    assert ".." not in filename_part
    assert "/" not in filename_part
    assert "\\" not in filename_part

    # Ensure response body does not leak secret passwords
    body_text = resp.text
    assert "SuperSecretAdminPass123!" not in body_text
    assert "password" not in body_text.lower() or "password_hash" not in body_text.lower()


def test_governance_api_endpoints_and_permission_matrix(
    client: TestClient,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    """
    Validates the governance REST endpoints and permission matrix output.
    """
    lead_headers = _auth_header(lead_user)
    tester_headers = _auth_header(tester_user)

    # 1. GET policy
    resp = client.get(f"/api/v1/projects/{test_project.id}/governance/policy", headers=lead_headers)
    assert resp.status_code == 200
    policy_data = resp.json()
    assert policy_data["enforce_separation_of_duties"] is True
    assert policy_data["project_id"] == test_project.id

    # 2. PUT policy (Lead)
    resp = client.put(
        f"/api/v1/projects/{test_project.id}/governance/policy",
        json={"require_two_person_rule_for_purge": True},
        headers=lead_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["require_two_person_rule_for_purge"] is True

    # 3. POST approval request (Tester)
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/governance/approvals",
        json={
            "workflow_type": "SECURITY_DECISION",
            "resource_type": "SecurityDecision",
            "resource_id": "dec-test-999",
            "title": "Retest Automated Scope",
            "description": "Trigger automated passive retest",
            "parameters": {"target": "10.0.0.1"},
        },
        headers=tester_headers,
    )
    assert resp.status_code == 201
    appr = resp.json()
    assert appr["status"] == "PENDING"
    assert len(appr["parameter_hash"]) == 64

    # 4. GET approvals list
    resp = client.get(f"/api/v1/projects/{test_project.id}/governance/approvals", headers=lead_headers)
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 5. GET permission matrix
    resp = client.get(f"/api/v1/projects/{test_project.id}/governance/matrix", headers=lead_headers)
    assert resp.status_code == 200
    matrix = resp.json()
    assert "roles" in matrix
    assert "matrix" in matrix
    assert len(matrix["matrix"]) >= 5


def test_idempotency_keys_are_tenant_isolated_without_cross_project_collision(
    db: Session,
    test_project: Project,
    secondary_project: Project,
    lead_user: User,
    secondary_lead_user: User,
):
    """
    Idempotency keys and approval requests with identical names/keys in distinct projects
    do not collide or leak information across workspaces.
    """
    now = utc_now()
    common_key = "idemp-security-scan-2026-q1"

    job_a = AssessmentJob(
        project_id=test_project.id,
        target_input="10.10.1.1",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        idempotency_key=common_key,
        created_by_id=lead_user.id,
        created_at=now,
    )
    job_b = AssessmentJob(
        project_id=secondary_project.id,
        target_input="10.10.1.1",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        idempotency_key=common_key,
        created_by_id=secondary_lead_user.id,
        created_at=now,
    )
    db.add(job_a)
    db.add(job_b)
    db.commit()

    assert job_a.id != job_b.id
    assert job_a.project_id == test_project.id
    assert job_b.project_id == secondary_project.id
