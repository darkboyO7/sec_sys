"""
Fine-Grained Permission Definitions & Role-Permission Matrix (Prompt 36).
Centralizes authorization constants and defines least-privilege role mappings.
"""
import enum
from typing import Dict, List, Set, Optional
from app.models.user import SystemRole
from app.models.project import ProjectRole


class Permission(str, enum.Enum):
    # Asset Management
    ASSET_READ = "asset:read"
    ASSET_CREATE = "asset:create"
    ASSET_UPDATE = "asset:update"
    ASSET_DELETE = "asset:delete"

    # Scope Governance
    SCOPE_READ = "scope:read"
    SCOPE_MANAGE = "scope:manage"
    SCOPE_APPROVE = "scope:approve"

    # Assessment Execution & Scheduling
    ASSESSMENT_READ = "assessment:read"
    ASSESSMENT_LAUNCH = "assessment:launch"
    ASSESSMENT_CANCEL = "assessment:cancel"
    SCHEDULING_READ = "scheduling:read"
    SCHEDULING_DISPATCH = "scheduling:dispatch"
    SCHEDULING_MANAGE = "scheduling:manage"

    # Findings & Evidence
    FINDING_READ = "finding:read"
    FINDING_MUTATE = "finding:mutate"
    FINDING_APPROVE_RISK = "finding:approve_risk"
    EVIDENCE_READ = "evidence:read"
    EVIDENCE_RETENTION_MANAGE = "evidence:retention_manage"

    # Remediation & Verification
    REMEDIATION_PROPOSE = "remediation:propose"
    REMEDIATION_APPROVE = "remediation:approve"
    REMEDIATION_VERIFY = "remediation:verify"

    # Threat Intelligence
    THREAT_INTEL_READ = "threat_intel:read"
    THREAT_INTEL_SYNC = "threat_intel:sync"
    THREAT_CORRELATE = "threat_intel:correlate"

    # Compliance & Reporting
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_EVALUATE = "compliance:evaluate"
    COMPLIANCE_MANAGE = "compliance:manage"
    REPORT_GENERATE = "report:generate"
    REPORT_READ = "report:read"

    # Disaster Recovery & Administrative
    RECOVERY_DRILL = "recovery:drill"
    POLICY_MANAGE = "policy:manage"
    ADMIN_ACTIONS = "admin:actions"


# ---------------------------------------------------------------------------
# Project Role Permissions Mapping (Tenant / Project Scope)
# ---------------------------------------------------------------------------
PROJECT_ROLE_PERMISSIONS: Dict[ProjectRole, Set[Permission]] = {
    ProjectRole.LEAD: {
        Permission.ASSET_READ,
        Permission.ASSET_CREATE,
        Permission.ASSET_UPDATE,
        Permission.ASSET_DELETE,
        Permission.SCOPE_READ,
        Permission.SCOPE_MANAGE,
        Permission.SCOPE_APPROVE,
        Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_LAUNCH,
        Permission.ASSESSMENT_CANCEL,
        Permission.SCHEDULING_READ,
        Permission.SCHEDULING_DISPATCH,
        Permission.SCHEDULING_MANAGE,
        Permission.FINDING_READ,
        Permission.FINDING_MUTATE,
        Permission.FINDING_APPROVE_RISK,
        Permission.EVIDENCE_READ,
        Permission.EVIDENCE_RETENTION_MANAGE,
        Permission.REMEDIATION_PROPOSE,
        Permission.REMEDIATION_APPROVE,
        Permission.REMEDIATION_VERIFY,
        Permission.THREAT_INTEL_READ,
        Permission.THREAT_INTEL_SYNC,
        Permission.THREAT_CORRELATE,
        Permission.COMPLIANCE_READ,
        Permission.COMPLIANCE_EVALUATE,
        Permission.COMPLIANCE_MANAGE,
        Permission.REPORT_GENERATE,
        Permission.REPORT_READ,
        Permission.POLICY_MANAGE,
    },
    ProjectRole.TESTER: {
        Permission.ASSET_READ,
        Permission.ASSET_CREATE,
        Permission.ASSET_UPDATE,
        Permission.SCOPE_READ,
        Permission.SCOPE_MANAGE,
        Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_LAUNCH,
        Permission.ASSESSMENT_CANCEL,
        Permission.SCHEDULING_READ,
        Permission.SCHEDULING_DISPATCH,
        Permission.FINDING_READ,
        Permission.FINDING_MUTATE,
        Permission.EVIDENCE_READ,
        Permission.REMEDIATION_PROPOSE,
        Permission.REMEDIATION_VERIFY,
        Permission.THREAT_INTEL_READ,
        Permission.THREAT_INTEL_SYNC,
        Permission.THREAT_CORRELATE,
        Permission.COMPLIANCE_READ,
        Permission.COMPLIANCE_EVALUATE,
        Permission.REPORT_GENERATE,
        Permission.REPORT_READ,
    },
    ProjectRole.VIEWER: {
        Permission.ASSET_READ,
        Permission.SCOPE_READ,
        Permission.ASSESSMENT_READ,
        Permission.SCHEDULING_READ,
        Permission.FINDING_READ,
        Permission.EVIDENCE_READ,
        Permission.THREAT_INTEL_READ,
        Permission.COMPLIANCE_READ,
        Permission.REPORT_READ,
    },
}

# ---------------------------------------------------------------------------
# System Role Permissions Mapping (Global / Platform Scope)
# ---------------------------------------------------------------------------
SYSTEM_ROLE_PERMISSIONS: Dict[SystemRole, Set[Permission]] = {
    SystemRole.ADMIN: set(Permission),  # All permissions
    SystemRole.SECURITY_LEAD: {
        p for p in Permission if p != Permission.ADMIN_ACTIONS
    },
    SystemRole.SECURITY_TESTER: {
        Permission.ASSET_READ,
        Permission.ASSET_CREATE,
        Permission.ASSET_UPDATE,
        Permission.SCOPE_READ,
        Permission.SCOPE_MANAGE,
        Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_LAUNCH,
        Permission.ASSESSMENT_CANCEL,
        Permission.SCHEDULING_READ,
        Permission.SCHEDULING_DISPATCH,
        Permission.FINDING_READ,
        Permission.FINDING_MUTATE,
        Permission.EVIDENCE_READ,
        Permission.REMEDIATION_PROPOSE,
        Permission.REMEDIATION_VERIFY,
        Permission.THREAT_INTEL_READ,
        Permission.THREAT_CORRELATE,
        Permission.COMPLIANCE_READ,
        Permission.COMPLIANCE_EVALUATE,
        Permission.REPORT_GENERATE,
        Permission.REPORT_READ,
    },
    SystemRole.AUDITOR: {
        Permission.ASSET_READ,
        Permission.SCOPE_READ,
        Permission.ASSESSMENT_READ,
        Permission.SCHEDULING_READ,
        Permission.FINDING_READ,
        Permission.EVIDENCE_READ,
        Permission.THREAT_INTEL_READ,
        Permission.COMPLIANCE_READ,
        Permission.REPORT_READ,
    },
    SystemRole.VIEWER: {
        Permission.ASSET_READ,
        Permission.SCOPE_READ,
        Permission.ASSESSMENT_READ,
        Permission.SCHEDULING_READ,
        Permission.FINDING_READ,
        Permission.EVIDENCE_READ,
        Permission.THREAT_INTEL_READ,
        Permission.COMPLIANCE_READ,
        Permission.REPORT_READ,
    },
}


def get_granted_permissions(
    system_role: SystemRole,
    project_role: Optional[ProjectRole] = None,
) -> Set[Permission]:
    """Calculate effective permissions for a user based on system and project roles."""
    if system_role == SystemRole.ADMIN:
        return set(Permission)

    permissions = set(SYSTEM_ROLE_PERMISSIONS.get(system_role, set()))
    if project_role:
        permissions.update(PROJECT_ROLE_PERMISSIONS.get(project_role, set()))
    return permissions


def has_permission(
    system_role: SystemRole,
    required_permission: Permission,
    project_role: Optional[ProjectRole] = None,
) -> bool:
    """Check if a specific permission is granted by either system or project role."""
    granted = get_granted_permissions(system_role, project_role)
    return required_permission in granted
