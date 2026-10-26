import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.finding import VulnerabilityFinding
from app.models.asset import Asset
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.services.audit_service import AuditService
from app.models.base import utc_now


class RemediationPrioritizationService:
    """
    Evidence-Backed Remediation Recommendation & Prioritization Service.
    Maps identified vulnerability patterns to defensive corrective actions,
    prerequisites, operational rollback procedures, and independent verification criteria.
    Operates strictly in an advisory / decision-support capacity without executing changes.
    """

    REMEDIATION_CATALOG: List[Dict[str, Any]] = [
        {
            "pattern": r"(?i)(sql\s*injection|sqli|cwe-89)",
            "title": "Enforce Parameterized Queries and Least-Privilege DB Access",
            "action_type": "CODE_REFACTOR",
            "description": (
                "Refactor dynamic SQL construction to use parameterized prepared statements or ORM queries. "
                "Bind all user input variables explicitly. Ensure database connection credentials operate with "
                "least-privilege permissions, restricting schema modification and administrative procedures."
            ),
            "rationale": "Direct SQL concatenation allows untrusted user input to alter SQL grammar, leading to unauthorized data exposure.",
            "qualitative_benefit": "Eliminates input injection vector at application boundary; prevents unauthorized read/write access to persistent datastore.",
            "estimated_risk_reduction": 0.85,
            "root_cause": "Dynamic SQL string concatenation without parameter binding in data-access layer.",
            "recommended_change": "Replace string interpolation with parameterized prepared statements or ORM queries across all data-access call sites.",
            "estimated_effort": "MEDIUM (1-2d)",
            "related_controls": ["CIS-Control-16.11", "NIST-SP800-53-SI-10", "OWASP-A03:2021"],
            "prerequisites": [
                "Locate query call sites in application data-access layer.",
                "Ensure database driver supports parameterized prepared statements.",
                "Stage test environment with identical schema for regression verification.",
            ],
            "operational_impact": "Low to medium. Requires code refactoring and regression testing of data-access endpoints. No persistent downtime.",
            "rollback_procedure": "Revert commit to previous data-access layer version if regression tests fail.",
            "verification_criteria": "Target endpoint rejects quote-based SQL payloads (`' OR '1'='1`) with safe errors and passes baseline functional queries.",
            "verification_test_profile": "WEB_APPLICATION_BASELINE",
            "requires_approval": True,
            "approval_role": "LEAD",
        },
        {
            "pattern": r"(?i)(cross-site\s*scripting|xss|cwe-79)",
            "title": "Implement Context-Aware Output Encoding and Content-Security-Policy",
            "action_type": "INPUT_OUTPUT_SANITIZATION",
            "description": (
                "Apply context-aware contextual HTML/JavaScript output encoding to all dynamic template reflections. "
                "Deploy a restrictive Content-Security-Policy (CSP) HTTP header (e.g. `default-src 'self'`) to disallow "
                "inline script execution."
            ),
            "rationale": "Unescaped user input reflected in DOM contexts enables arbitrary client-side script execution in user browser sessions.",
            "qualitative_benefit": "Neutralizes client-side script injection and cross-site cookie/token theft.",
            "estimated_risk_reduction": 0.75,
            "root_cause": "Direct reflection of unencoded user-controlled inputs in dynamic HTML/template rendering.",
            "recommended_change": "Enforce context-sensitive output escaping in UI templating engines and configure strict Content-Security-Policy (CSP).",
            "estimated_effort": "LOW (< 2h)",
            "related_controls": ["CIS-Control-16.12", "NIST-SP800-53-SC-18", "OWASP-A03:2021"],
            "prerequisites": [
                "Audit web frontend templates for raw HTML unescaped interpolations.",
                "Evaluate existing third-party scripts before enforcing strict CSP.",
            ],
            "operational_impact": "Low. Incorrect CSP directives may block legitimate third-party UI widgets if not properly allowlisted.",
            "rollback_procedure": "Revert CSP header in reverse-proxy or web application server config.",
            "verification_criteria": "Payload reflection contains encoded entities (`&lt;script&gt;`) and does not trigger DOM execution.",
            "verification_test_profile": "WEB_APPLICATION_BASELINE",
            "requires_approval": True,
            "approval_role": "LEAD",
        },
        {
            "pattern": r"(?i)(outdated|vulnerable\s*component|cve-|log4j|dependency)",
            "title": "Upgrade Component Dependency to Patched Release",
            "action_type": "PATCH_UPDATE",
            "description": (
                "Update software package dependency manifest to the latest vendor-patched release. "
                "Verify compatibility with application test suite. If an immediate upgrade is blocked by breaking changes, "
                "implement a temporary defensive configuration flag or perimeter rule."
            ),
            "rationale": "Known vulnerabilities in third-party libraries have public CVE signatures and readily available exploit patterns.",
            "qualitative_benefit": "Completely removes vulnerable binary symbols and known exploit entry points.",
            "estimated_risk_reduction": 0.90,
            "root_cause": "Unpinned or unmaintained third-party library with published CVE identifiers.",
            "recommended_change": "Update library version specification in package manifest to vendor-patched release and run regression tests.",
            "estimated_effort": "LOW (< 2h)",
            "related_controls": ["CIS-Control-2.2", "NIST-SP800-53-SI-2", "OWASP-A06:2021"],
            "prerequisites": [
                "Inspect dependency lockfile and release notes for breaking API changes.",
                "Execute integration test suite in staging environment.",
            ],
            "operational_impact": "Medium. May require minor code adaptations if major version change introduces breaking changes.",
            "rollback_procedure": "Restore previous package version in lockfile and redeploy prior artifact.",
            "verification_criteria": "Software dependency audit verifies package version is at or above the patched vendor threshold.",
            "verification_test_profile": "DEPENDENCY_AUDIT_BASELINE",
            "requires_approval": True,
            "approval_role": "LEAD",
        },
        {
            "pattern": r"(?i)(tls|ssl|crypto|cipher|cwe-326|cwe-327)",
            "title": "Hardening Transport Layer Security (TLS 1.2+ Enforced)",
            "action_type": "CONFIG_HARDENING",
            "description": (
                "Disable legacy TLS 1.0 and 1.1 protocols on web servers and load balancers. "
                "Enforce TLS 1.2 and TLS 1.3 with forward-secret cipher suites (ECDHE-ECDSA-AES256-GCM-SHA384). "
                "Enable HSTS header (`Strict-Transport-Security`)."
            ),
            "rationale": "Obsolete cryptographic protocols and weak ciphers are susceptible to passive eavesdropping and downgrade attacks.",
            "qualitative_benefit": "Ensures confidentiality and integrity of network transit against on-path eavesdroppers.",
            "estimated_risk_reduction": 0.70,
            "root_cause": "Legacy TLS 1.0/1.1 protocols and weak cipher suites enabled on web/load-balancer endpoints.",
            "recommended_change": "Disable legacy protocols, enforce TLS 1.2+ with forward-secret cipher suites and enable HSTS header.",
            "estimated_effort": "LOW (< 2h)",
            "related_controls": ["CIS-Control-3.10", "NIST-SP800-53-SC-8", "OWASP-A02:2021"],
            "prerequisites": [
                "Verify connecting legacy clients support TLS 1.2.",
                "Ensure valid certificate is installed.",
            ],
            "operational_impact": "Low. May disconnect very old legacy HTTP clients unable to negotiate TLS 1.2.",
            "rollback_procedure": "Re-enable TLS 1.1 in web server configuration if mission-critical legacy client fails.",
            "verification_criteria": "SSL handshake probe confirms rejection of TLS 1.0/1.1 and acceptance of TLS 1.2/1.3 ciphers.",
            "verification_test_profile": "PORT_SERVICE_BASELINE",
            "requires_approval": False,
            "approval_role": "ANALYST",
        },
        {
            "pattern": r"(?i)(header|information\s*disclosure|cwe-200|cwe-16)",
            "title": "Configure Secure HTTP Headers and Suppress Server Banners",
            "action_type": "CONFIG_HARDENING",
            "description": (
                "Configure defensive security response headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, "
                "`Referrer-Policy: strict-origin-when-cross-origin`. Suppress `Server` and `X-Powered-By` version headers."
            ),
            "rationale": "Missing security headers expose browsers to MIME sniffing and clickjacking, while server banners reveal software fingerprints.",
            "qualitative_benefit": "Restricts browser vulnerability surfaces and denies reconnaissance information to automated scanners.",
            "estimated_risk_reduction": 0.40,
            "root_cause": "Missing defensive HTTP response headers and verbose server banner disclosure.",
            "recommended_change": "Inject X-Content-Type-Options, X-Frame-Options, Referrer-Policy and suppress Server/X-Powered-By banners.",
            "estimated_effort": "LOW (< 2h)",
            "related_controls": ["CIS-Control-4.1", "NIST-SP800-53-SC-5", "OWASP-A05:2021"],
            "prerequisites": [
                "Check whether application requires framing in an authorized iframe portal.",
            ],
            "operational_impact": "Negligible. Rarely causes client disruptions.",
            "rollback_procedure": "Remove headers from reverse proxy configuration.",
            "verification_criteria": "HTTP response header inspection verifies presence of all mandatory security headers.",
            "verification_test_profile": "WEB_APPLICATION_BASELINE",
            "requires_approval": False,
            "approval_role": "ANALYST",
        },
    ]

    @classmethod
    def generate_or_get_recommendation(
        cls,
        project_id: str,
        finding_id: str,
        db: Session,
        actor: Optional[User] = None,
        client_ip: Optional[str] = None,
    ) -> RemediationRecommendation:
        """
        Generates or retrieves the current remediation recommendation for a finding.
        Matches the finding against the defensive catalog or defaults to MANUAL_ANALYST_REVIEW.
        """
        finding = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.id == finding_id,
                VulnerabilityFinding.project_id == project_id,
            )
            .first()
        )
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found in project '{project_id}'.")

        # Check for existing active recommendation
        existing = (
            db.query(RemediationRecommendation)
            .filter(
                RemediationRecommendation.project_id == project_id,
                RemediationRecommendation.finding_id == finding_id,
            )
            .first()
        )
        if existing:
            return existing

        # Match finding title, description, or vuln_id
        text_corpus = f"{finding.title} {finding.description} {finding.vuln_id or ''}"
        matched_item = None
        for item in cls.REMEDIATION_CATALOG:
            if re.search(item["pattern"], text_corpus):
                matched_item = item
                break

        if not matched_item:
            # Fallback for novel or unmapped findings
            matched_item = {
                "title": f"Investigate and Remediate: {finding.title[:80]}",
                "action_type": "MANUAL_ANALYST_REVIEW",
                "description": (
                    f"Finding '{finding.title}' does not match standard automated defensive playbooks. "
                    "Conduct a manual code and configuration review to identify root cause and design an appropriate fix."
                ),
                "rationale": "Unmapped vulnerability pattern requires human analyst review to avoid disruptive corrective actions.",
                "qualitative_benefit": "Identifies precise remediation strategy tailored to specific custom software logic.",
                "estimated_risk_reduction": 0.50,
                "root_cause": "Unmapped security observation requiring manual triage and context-specific investigation.",
                "recommended_change": "Engage software development team to audit finding context, isolate root cause, and implement defensive fix.",
                "estimated_effort": "MEDIUM (1-2d)",
                "related_controls": ["CIS-Control-16.1", "NIST-SP800-53-RA-5"],
                "prerequisites": [
                    "Review scanner observation evidence and reproduction steps.",
                    "Engage application engineering owner.",
                ],
                "operational_impact": "Requires developer investigation and manual verification.",
                "rollback_procedure": "Document manual rollback steps prior to applying custom patch.",
                "verification_criteria": "Targeted security re-test confirming finding cannot be reproduced on target.",
                "verification_test_profile": "WEB_APPLICATION_BASELINE",
                "requires_approval": True,
                "approval_role": "LEAD",
            }

        rec = RemediationRecommendation(
            project_id=project_id,
            finding_id=finding.id,
            asset_id=finding.asset_id,
            title=matched_item["title"],
            action_type=matched_item["action_type"],
            description=matched_item["description"],
            rationale=matched_item["rationale"],
            qualitative_benefit=matched_item["qualitative_benefit"],
            estimated_risk_reduction=matched_item.get("estimated_risk_reduction"),
            root_cause=matched_item.get("root_cause"),
            recommended_change=matched_item.get("recommended_change"),
            estimated_effort=matched_item.get("estimated_effort"),
            related_controls=matched_item.get("related_controls", []),
            execution_governance_stage="GENERATED",
            prerequisites=matched_item.get("prerequisites", []),
            operational_impact=matched_item["operational_impact"],
            rollback_procedure=matched_item["rollback_procedure"],
            verification_criteria=matched_item["verification_criteria"],
            verification_test_profile=matched_item.get("verification_test_profile"),
            requires_approval=matched_item.get("requires_approval", True),
            approval_role=matched_item.get("approval_role", "LEAD"),
            status=RecommendationStatus.PENDING_REVIEW,
        )
        db.add(rec)
        db.flush()

        AuditService.log(
            db=db,
            action="REMEDIATION_RECOMMENDATION_GENERATED",
            actor_id=actor.id if actor else None,
            target_resource=f"remediation:{rec.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "finding_id": finding.id,
                "action_type": rec.action_type,
                "title": rec.title,
            },
        )
        db.commit()
        db.refresh(rec)
        return rec

    @classmethod
    def review_recommendation(
        cls,
        project_id: str,
        recommendation_id: str,
        new_status: RecommendationStatus,
        reviewer: User,
        reviewer_role: Optional[ProjectRole],
        review_notes: str,
        db: Session,
        client_ip: Optional[str] = None,
    ) -> RemediationRecommendation:
        """
        Reviews a remediation recommendation (APPROVE, DEFER, REJECT).
        Enforces that approval requires Project LEAD or System ADMIN role.
        Does NOT execute any code or commands.
        """
        rec = (
            db.query(RemediationRecommendation)
            .filter(
                RemediationRecommendation.id == recommendation_id,
                RemediationRecommendation.project_id == project_id,
            )
            .first()
        )
        if not rec:
            raise ValueError(f"Remediation recommendation '{recommendation_id}' not found in project '{project_id}'.")

        clean_notes = (review_notes or "").strip()
        if len(clean_notes) < 3:
            raise ValueError("Review justification is mandatory (minimum 3 characters required).")

        # Check role permission if approval is required
        if new_status == RecommendationStatus.APPROVED and rec.requires_approval:
            is_lead = (reviewer_role == ProjectRole.LEAD)
            is_admin = (reviewer.system_role == SystemRole.ADMIN)
            if not (is_lead or is_admin):
                raise PermissionError("Only Project LEAD or System ADMIN can approve remediation recommendations.")

        rec.status = new_status
        rec.reviewed_by_id = reviewer.id
        rec.reviewed_at = utc_now()
        rec.review_notes = clean_notes

        if new_status == RecommendationStatus.APPROVED:
            rec.execution_governance_stage = "APPROVED"
        elif new_status == RecommendationStatus.REJECTED:
            rec.execution_governance_stage = "REJECTED"
        elif new_status == RecommendationStatus.DEFERRED:
            rec.execution_governance_stage = "DEFERRED"
        else:
            rec.execution_governance_stage = "UNDER_REVIEW"

        AuditService.log(
            db=db,
            action=f"REMEDIATION_RECOMMENDATION_{new_status.value}",
            actor_id=reviewer.id,
            target_resource=f"remediation:{rec.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "finding_id": rec.finding_id,
                "new_status": new_status.value,
                "review_notes": rec.review_notes,
                "governance_stage": rec.execution_governance_stage,
            },
        )
        db.commit()
        db.refresh(rec)
        return rec

    @classmethod
    def authorize_change(
        cls,
        project_id: str,
        recommendation_id: str,
        change_ticket_ref: str,
        authorizer: User,
        authorizer_role: Optional[ProjectRole],
        db: Session,
        client_ip: Optional[str] = None,
    ) -> RemediationRecommendation:
        """
        Authorizes a change implementation for an APPROVED remediation recommendation.
        Strictly enforces that:
        1. The recommendation is already in APPROVED status (cannot authorize unapproved or rejected recommendations).
        2. The authorizer has Project LEAD or System ADMIN privileges.
        3. A non-empty change ticket reference (e.g. Jira/ServiceNow ticket ID) is supplied.
        4. No automated command, shell, or infrastructure modification is performed (pure governance boundary).
        """
        rec = (
            db.query(RemediationRecommendation)
            .filter(
                RemediationRecommendation.id == recommendation_id,
                RemediationRecommendation.project_id == project_id,
            )
            .first()
        )
        if not rec:
            raise ValueError(f"Remediation recommendation '{recommendation_id}' not found in project '{project_id}'.")

        # Governance gate: must be APPROVED
        if rec.status != RecommendationStatus.APPROVED:
            raise ValueError(
                f"Cannot authorize change: recommendation '{recommendation_id}' has status '{rec.status.value}', "
                "must be 'APPROVED' first."
            )

        # RBAC gate: authorizer must be LEAD or ADMIN
        is_lead = (authorizer_role == ProjectRole.LEAD)
        is_admin = (authorizer.system_role == SystemRole.ADMIN)
        if not (is_lead or is_admin):
            raise PermissionError("Only Project LEAD or System ADMIN can authorize remediation changes.")

        ticket = (change_ticket_ref or "").strip()
        if len(ticket) < 3:
            raise ValueError("Valid change ticket reference is mandatory (minimum 3 characters).")

        rec.execution_governance_stage = "CHANGE_AUTHORIZED"
        if rec.review_notes:
            rec.review_notes = f"{rec.review_notes}\n[Change Authorized: {ticket}]"
        else:
            rec.review_notes = f"[Change Authorized: {ticket}]"

        AuditService.log(
            db=db,
            action="REMEDIATION_CHANGE_AUTHORIZED",
            actor_id=authorizer.id,
            target_resource=f"remediation:{rec.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "finding_id": rec.finding_id,
                "change_ticket_ref": ticket,
                "governance_stage": rec.execution_governance_stage,
                "status": rec.status.value,
            },
        )
        db.commit()
        db.refresh(rec)
        return rec
