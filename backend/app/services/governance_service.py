import json
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.governance import (
    ApprovalWorkflowType,
    GovernanceApprovalStatus,
    ProjectGovernancePolicy,
    ApprovalRequestRecord,
)
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectRole, ProjectMember
from app.models.base import utc_now
from app.services.audit_service import AuditService


class ProjectGovernanceService:
    """
    Unified Governance, Separation of Duties (SoD), and Approval Workflow Engine (Prompt 22).
    Enforces that:
    1. Requesters cannot approve their own sensitive operations when SoD is enabled.
    2. Single-operator local mode overrides are explicitly audited with SO_D_EXCEPTION flags.
    3. Approvals are cryptographically bound to exact parameter digests.
    4. Material parameter changes invalidate approvals and require re-approval before execution.
    5. Completed executions are distinctly separated from granted approvals.
    """

    @classmethod
    def compute_parameter_hash(cls, parameters: Dict[str, Any]) -> str:
        """Computes deterministic SHA-256 digest of canonicalized parameters."""
        canonical = json.dumps(parameters or {}, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def get_or_create_policy(cls, db: Session, project_id: str) -> ProjectGovernancePolicy:
        """Retrieves or lazily seeds the project governance policy."""
        policy = (
            db.query(ProjectGovernancePolicy)
            .filter(ProjectGovernancePolicy.project_id == project_id)
            .first()
        )
        if not policy:
            now = utc_now()
            policy = ProjectGovernancePolicy(
                project_id=project_id,
                enforce_separation_of_duties=True,
                allow_self_approval_override=False,
                require_two_person_rule_for_purge=True,
                require_lead_for_scope_authorization=True,
                require_lead_for_risk_acceptance=True,
                require_lead_for_remediation_approval=True,
                require_lead_for_model_promotion=True,
                policy_version="v2026.2.0",
                created_at=now,
                updated_at=now,
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
        return policy

    @classmethod
    def update_policy(
        cls,
        db: Session,
        project_id: str,
        updates: Dict[str, Any],
        actor: User,
        client_ip: Optional[str] = None,
    ) -> ProjectGovernancePolicy:
        """Updates project governance policy settings with full audit trail."""
        policy = cls.get_or_create_policy(db, project_id)

        allowed_keys = {
            "enforce_separation_of_duties",
            "allow_self_approval_override",
            "require_two_person_rule_for_purge",
            "require_lead_for_scope_authorization",
            "require_lead_for_risk_acceptance",
            "require_lead_for_remediation_approval",
            "require_lead_for_model_promotion",
            "policy_version",
        }

        changes = {}
        for k, v in updates.items():
            if k in allowed_keys and getattr(policy, k) != v:
                changes[k] = {"old": getattr(policy, k), "new": v}
                setattr(policy, k, v)

        policy.updated_at = utc_now()
        db.commit()
        db.refresh(policy)

        AuditService.record_event(
            db=db,
            action="PROJECT_GOVERNANCE_POLICY_UPDATE",
            target_type="project_governance_policy",
            target_id=policy.id,
            project_id=project_id,
            actor_id=actor.id,
            actor_email=actor.email,
            outcome="SUCCESS",
            ip_address=client_ip,
            details={"changes": changes},
        )
        return policy

    @classmethod
    def request_approval(
        cls,
        db: Session,
        project_id: str,
        workflow_type: ApprovalWorkflowType,
        resource_type: str,
        resource_id: str,
        title: str,
        parameters: Dict[str, Any],
        requester: User,
        description: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> ApprovalRequestRecord:
        """
        Creates an approval request record bound to exact parameter hash.
        Supersedes any existing PENDING requests for the same resource.
        """
        param_hash = cls.compute_parameter_hash(parameters)
        now = utc_now()
        policy = cls.get_or_create_policy(db, project_id)

        # Invalidate any prior pending requests for this resource
        existing_pendings = (
            db.query(ApprovalRequestRecord)
            .filter(
                ApprovalRequestRecord.project_id == project_id,
                ApprovalRequestRecord.resource_type == resource_type,
                ApprovalRequestRecord.resource_id == resource_id,
                ApprovalRequestRecord.status == GovernanceApprovalStatus.PENDING,
            )
            .all()
        )
        for ep in existing_pendings:
            ep.status = GovernanceApprovalStatus.SUPERSEDED if hasattr(GovernanceApprovalStatus, "SUPERSEDED") else GovernanceApprovalStatus.INVALIDATED
            ep.invalidated_at = now
            ep.invalidation_reason = "Superseded by new approval request."

        req = ApprovalRequestRecord(
            project_id=project_id,
            workflow_type=workflow_type,
            resource_type=resource_type,
            resource_id=resource_id,
            status=GovernanceApprovalStatus.PENDING,
            title=title,
            description=description,
            parameter_hash=param_hash,
            parameters_snapshot=parameters,
            requester_id=requester.id,
            requested_at=now,
            policy_version=policy.policy_version,
            created_at=now,
            updated_at=now,
        )
        db.add(req)
        db.commit()
        db.refresh(req)

        AuditService.record_event(
            db=db,
            action="GOVERNANCE_APPROVAL_REQUESTED",
            target_type=resource_type,
            target_id=resource_id,
            project_id=project_id,
            actor_id=requester.id,
            actor_email=requester.email,
            outcome="SUCCESS",
            ip_address=client_ip,
            details={
                "approval_id": req.id,
                "workflow_type": workflow_type.value,
                "parameter_hash": param_hash,
            },
        )
        return req

    @classmethod
    def decide_approval(
        cls,
        db: Session,
        project_id: str,
        approval_id: str,
        approver: User,
        approved: bool,
        reason: str,
        approver_role: Optional[ProjectRole] = None,
        client_ip: Optional[str] = None,
    ) -> ApprovalRequestRecord:
        """
        Processes an approval decision (APPROVE or REJECT).
        Strictly enforces Separation of Duties: Requester cannot approve their own request
        unless single-operator override is explicitly active.
        """
        approval = (
            db.query(ApprovalRequestRecord)
            .filter(
                ApprovalRequestRecord.id == approval_id,
                ApprovalRequestRecord.project_id == project_id,
            )
            .first()
        )
        if not approval:
            raise ValueError(f"Approval request '{approval_id}' not found in project '{project_id}'.")

        if approval.status != GovernanceApprovalStatus.PENDING:
            raise ValueError(
                f"Cannot decide approval: Request '{approval_id}' has status '{approval.status.value}', expected 'PENDING'."
            )

        now = utc_now()
        policy = cls.get_or_create_policy(db, project_id)

        # Role verification: Approver must be Project LEAD or System ADMIN
        is_lead = (approver_role == ProjectRole.LEAD)
        is_admin = (approver.system_role == SystemRole.ADMIN)
        if not (is_lead or is_admin):
            raise PermissionError("Only Project LEAD or System ADMIN can decide approval requests.")

        # Separation of Duties (SoD) verification
        is_self_approval = (approver.id == approval.requester_id)
        if is_self_approval:
            if policy.enforce_separation_of_duties and not policy.allow_self_approval_override:
                AuditService.record_event(
                    db=db,
                    action="GOVERNANCE_APPROVAL_DENIED_SOD",
                    target_type=approval.resource_type,
                    target_id=approval.resource_id,
                    project_id=project_id,
                    actor_id=approver.id,
                    actor_email=approver.email,
                    outcome="DENIED",
                    ip_address=client_ip,
                    details={
                        "approval_id": approval.id,
                        "workflow_type": approval.workflow_type.value,
                        "reason": "Separation of Duties violation: Requester attempted self-approval.",
                    },
                )
                raise PermissionError("Separation of Duties violation: The requester cannot approve their own authorization request.")
            elif policy.allow_self_approval_override:
                # Permitted under documented single-operator exception, but logged prominently
                AuditService.record_event(
                    db=db,
                    action="GOVERNANCE_SELF_APPROVAL_OVERRIDE",
                    target_type=approval.resource_type,
                    target_id=approval.resource_id,
                    project_id=project_id,
                    actor_id=approver.id,
                    actor_email=approver.email,
                    outcome="SUCCESS",
                    ip_address=client_ip,
                    details={
                        "approval_id": approval.id,
                        "workflow_type": approval.workflow_type.value,
                        "notes": "Single-operator local mode exception: Requester self-approved request.",
                    },
                )

        new_status = GovernanceApprovalStatus.APPROVED if approved else GovernanceApprovalStatus.REJECTED
        approval.status = new_status
        approval.approver_id = approver.id
        approval.decided_at = now
        approval.decision_reason = (reason or "").strip()
        approval.updated_at = now

        db.commit()
        db.refresh(approval)

        AuditService.record_event(
            db=db,
            action=f"GOVERNANCE_APPROVAL_{new_status.value}",
            target_type=approval.resource_type,
            target_id=approval.resource_id,
            project_id=project_id,
            actor_id=approver.id,
            actor_email=approver.email,
            outcome="SUCCESS" if approved else "REJECTED",
            ip_address=client_ip,
            details={
                "approval_id": approval.id,
                "workflow_type": approval.workflow_type.value,
                "decision_reason": approval.decision_reason,
            },
        )
        return approval

    @classmethod
    def verify_and_consume_execution(
        cls,
        db: Session,
        project_id: str,
        workflow_type: ApprovalWorkflowType,
        resource_type: str,
        resource_id: str,
        current_parameters: Dict[str, Any],
        executor: User,
        client_ip: Optional[str] = None,
    ) -> ApprovalRequestRecord:
        """
        Validates that a valid APPROVED record exists immediately before execution,
        checks for material parameter drift (invalidation),
        and marks the approval as EXECUTED to prevent replay attacks.
        """
        now = utc_now()
        approval = (
            db.query(ApprovalRequestRecord)
            .filter(
                ApprovalRequestRecord.project_id == project_id,
                ApprovalRequestRecord.workflow_type == workflow_type,
                ApprovalRequestRecord.resource_type == resource_type,
                ApprovalRequestRecord.resource_id == resource_id,
                ApprovalRequestRecord.status == GovernanceApprovalStatus.APPROVED,
            )
            .order_by(ApprovalRequestRecord.decided_at.desc())
            .first()
        )
        if not approval:
            raise PermissionError(
                f"Execution denied: No valid 'APPROVED' governance record found for {resource_type} '{resource_id}'."
            )

        # Check for parameter drift: parameters must match approved parameter_hash
        current_hash = cls.compute_parameter_hash(current_parameters)
        if current_hash != approval.parameter_hash:
            approval.status = GovernanceApprovalStatus.INVALIDATED
            approval.invalidated_at = now
            approval.invalidation_reason = (
                f"Parameter drift detected at execution boundary: approved hash '{approval.parameter_hash[:12]}...' "
                f"does not match current parameters hash '{current_hash[:12]}...'."
            )
            approval.updated_at = now
            db.commit()

            AuditService.record_event(
                db=db,
                action="GOVERNANCE_APPROVAL_INVALIDATED_ON_EXECUTION",
                target_type=resource_type,
                target_id=resource_id,
                project_id=project_id,
                actor_id=executor.id,
                actor_email=executor.email,
                outcome="DENIED",
                ip_address=client_ip,
                details={
                    "approval_id": approval.id,
                    "reason": approval.invalidation_reason,
                },
            )
            raise ValueError("Approval invalidated: Material parameters have changed since approval was granted. Re-approval required.")

        # Transition to EXECUTED
        approval.status = GovernanceApprovalStatus.EXECUTED
        approval.executed_at = now
        approval.executed_by_id = executor.id
        approval.updated_at = now

        db.commit()
        db.refresh(approval)

        AuditService.record_event(
            db=db,
            action="GOVERNANCE_APPROVAL_EXECUTED",
            target_type=resource_type,
            target_id=resource_id,
            project_id=project_id,
            actor_id=executor.id,
            actor_email=executor.email,
            outcome="SUCCESS",
            ip_address=client_ip,
            details={
                "approval_id": approval.id,
                "workflow_type": workflow_type.value,
            },
        )
        return approval

    @classmethod
    def invalidate_approvals_for_resource(
        cls,
        db: Session,
        project_id: str,
        resource_type: str,
        resource_id: str,
        reason: str,
    ) -> int:
        """Invalidates all pending or approved requests when an underlying resource changes."""
        now = utc_now()
        records = (
            db.query(ApprovalRequestRecord)
            .filter(
                ApprovalRequestRecord.project_id == project_id,
                ApprovalRequestRecord.resource_type == resource_type,
                ApprovalRequestRecord.resource_id == resource_id,
                ApprovalRequestRecord.status.in_([
                    GovernanceApprovalStatus.PENDING,
                    GovernanceApprovalStatus.APPROVED,
                ]),
            )
            .all()
        )
        count = len(records)
        for r in records:
            r.status = GovernanceApprovalStatus.INVALIDATED
            r.invalidated_at = now
            r.invalidation_reason = reason
            r.updated_at = now
        db.commit()
        return count

    @classmethod
    def get_permission_matrix(cls) -> Dict[str, Any]:
        """
        Formal permission matrix specifying allowable operations across system and project roles.
        Separates read, create, modify, approve, execute, export, and delete permissions.
        """
        return {
            "version": "2026.2",
            "roles": {
                "SystemRole": ["ADMIN", "SECURITY_LEAD", "SECURITY_TESTER", "AUDITOR", "VIEWER"],
                "ProjectRole": ["LEAD", "TESTER", "AUDITOR", "VIEWER"],
            },
            "matrix": [
                {
                    "resource": "Projects / Workspaces",
                    "actions": {
                        "read": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                        "create": ["ADMIN", "SECURITY_LEAD", "SECURITY_TESTER"],
                        "modify": ["ADMIN", "LEAD"],
                        "delete_or_purge": ["ADMIN", "LEAD"],
                    },
                },
                {
                    "resource": "Scope Targets & Exclusions",
                    "actions": {
                        "read": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                        "register_candidate": ["ADMIN", "LEAD", "TESTER"],
                        "authorize_scope": ["ADMIN", "LEAD"],  # Requires SoD: requester != approver
                        "revoke_scope": ["ADMIN", "LEAD"],
                        "add_exclusion": ["ADMIN", "LEAD", "TESTER"],
                    },
                },
                {
                    "resource": "Assessments & Worker Jobs",
                    "actions": {
                        "read": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                        "queue_job": ["ADMIN", "LEAD", "TESTER"],
                        "cancel_job": ["ADMIN", "LEAD"],
                        "retry_or_recover": ["ADMIN", "LEAD"],
                    },
                },
                {
                    "resource": "Findings & Evidence",
                    "actions": {
                        "read": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                        "transition_lifecycle": ["ADMIN", "LEAD", "TESTER"],
                        "accept_risk": ["ADMIN", "LEAD"],  # Requires compensating controls & expiration
                        "mark_false_positive": ["ADMIN", "LEAD", "TESTER"],
                    },
                },
                {
                    "resource": "Security Knowledge Graph",
                    "actions": {
                        "read": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                        "create_node_or_edge": ["ADMIN", "LEAD", "TESTER"],
                        "reconcile_and_repair": ["ADMIN", "LEAD"],
                    },
                },
                {
                    "resource": "Security Decisions & Approvals",
                    "actions": {
                        "read": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                        "propose_decision": ["ADMIN", "LEAD", "TESTER"],
                        "approve_decision": ["ADMIN", "LEAD"],  # Requires SoD: proposer != approver
                        "execute_decision": ["ADMIN", "LEAD", "TESTER"],  # Requires APPROVED status
                    },
                },
                {
                    "resource": "Remediation Guidance & Changes",
                    "actions": {
                        "read": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                        "generate_recommendation": ["ADMIN", "LEAD", "TESTER"],
                        "approve_recommendation": ["ADMIN", "LEAD"],
                        "authorize_change": ["ADMIN", "LEAD"],  # Requires SoD & valid ticket
                        "verify_remediation": ["ADMIN", "LEAD", "TESTER"],
                    },
                },
                {
                    "resource": "Governed Models & Predictions",
                    "actions": {
                        "read": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                        "train_candidate": ["ADMIN", "LEAD", "TESTER"],
                        "approve_model": ["ADMIN", "LEAD"],  # Requires SoD: creator != approver
                        "activate_or_rollback": ["ADMIN", "LEAD"],
                    },
                },
                {
                    "resource": "Reports & Direct Exports",
                    "actions": {
                        "read_or_generate": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                        "export_stream": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                    },
                },
                {
                    "resource": "Audit History Ledger",
                    "actions": {
                        "read_project_ledger": ["ADMIN", "LEAD", "TESTER", "AUDITOR", "VIEWER"],
                        "read_global_ledger": ["ADMIN", "AUDITOR"],
                        "verify_tamper_chain": ["ADMIN", "LEAD", "AUDITOR"],
                    },
                },
            ],
        }
