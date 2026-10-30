import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.finding import VulnerabilityFinding
from app.models.asset import Asset
from app.models.risk import (
    RemediationRecommendation,
    RecommendationStatus,
    GuidanceType,
    BusinessPriority,
    RemediationUrgency,
    RecommendationFeedbackType,
    RecommendationFeedback,
)
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
        {
            "pattern": r"(?i)(cors|access-control-allow-origin|cwe-942)",
            "title": "Restrict Cross-Origin Resource Sharing (CORS) Origins",
            "action_type": "CONFIG_HARDENING",
            "description": (
                "Disallow wildcard Access-Control-Allow-Origin with credentials. "
                "Explicitly validate incoming Origin against an authorized allowlist and never reflect unvalidated origins."
            ),
            "rationale": "Permissive CORS with credentials enables malicious origins to exfiltrate authenticated session data.",
            "qualitative_benefit": "Prevents cross-origin data exfiltration and credential theft.",
            "estimated_risk_reduction": 0.80,
            "root_cause": "Wildcard or arbitrary origin reflection configured concurrently with credentials support.",
            "recommended_change": "Configure CORS middleware with explicit domain allowlist and require credentials only on verified origins.",
            "estimated_effort": "LOW (< 2h)",
            "related_controls": ["OWASP-A01:2021", "NIST-SP800-53-AC-4"],
            "prerequisites": ["Identify legitimate partner and API consumer domains."],
            "operational_impact": "Low. Unauthorized cross-origin requests will be blocked by browsers.",
            "rollback_procedure": "Revert CORS origin allowlist in reverse proxy or API gateway.",
            "verification_criteria": "Cross-origin requests from unauthorized origins do not receive ACAO headers.",
            "verification_test_profile": "LIVE_WEB_SECURITY_AUDIT",
            "requires_approval": True,
            "approval_role": "LEAD",
        },
        {
            "pattern": r"(?i)(cache-control|cwe-525|cwe-524|no-store)",
            "title": "Enforce Cache-Control: no-store on Sensitive and Authenticated Endpoints",
            "action_type": "CONFIG_HARDENING",
            "description": (
                "Send 'Cache-Control: no-store, max-age=0' and 'Pragma: no-cache' on all authenticated and cookie-setting HTTP responses "
                "to prevent caching on intermediate proxy or browser disk caches."
            ),
            "rationale": "Cached sensitive session tokens or PII on client disks can be extracted by subsequent users on shared machines.",
            "qualitative_benefit": "Ensures sensitive transactional and authentication data is not retained in local or intermediary web caches.",
            "estimated_risk_reduction": 0.50,
            "root_cause": "Absence of explicit Cache-Control no-store directive on authenticated web responses.",
            "recommended_change": "Inject Cache-Control: no-store, max-age=0 on all authenticated route handlers.",
            "estimated_effort": "LOW (< 2h)",
            "related_controls": ["OWASP-A04:2021", "NIST-SP800-53-SC-28"],
            "prerequisites": ["Identify static asset paths vs dynamic authenticated API routes."],
            "operational_impact": "Negligible. Authenticated API data is re-fetched per request as intended.",
            "rollback_procedure": "Revert Cache-Control header directive in web server config.",
            "verification_criteria": "Response headers on sensitive endpoints contain 'Cache-Control: no-store'.",
            "verification_test_profile": "LIVE_WEB_SECURITY_AUDIT",
            "requires_approval": False,
            "approval_role": "ANALYST",
        },
        {
            "pattern": r"(?i)(cookie|httponly|samesite|cwe-614|cwe-1004)",
            "title": "Enforce HttpOnly, Secure, and SameSite Flags on Session Cookies",
            "action_type": "CONFIG_HARDENING",
            "description": (
                "Configure all session and authentication cookies with Secure, HttpOnly, and SameSite=Lax (or Strict) attributes."
            ),
            "rationale": "Missing HttpOnly exposes cookies to XSS theft; missing Secure exposes cookies to plaintext transmission; missing SameSite exposes sessions to CSRF.",
            "qualitative_benefit": "Prevents JavaScript access to authentication credentials and blocks cross-site request forgery.",
            "estimated_risk_reduction": 0.70,
            "root_cause": "Session management framework configured without mandatory cookie security attributes.",
            "recommended_change": "Configure session cookie middleware to append Secure; HttpOnly; SameSite=Lax.",
            "estimated_effort": "LOW (< 2h)",
            "related_controls": ["OWASP-A07:2021", "NIST-SP800-53-SC-23"],
            "prerequisites": ["Ensure application is served strictly over HTTPS."],
            "operational_impact": "Low. Cross-origin iframe integrations may require SameSite=None; Secure if authorized.",
            "rollback_procedure": "Adjust session cookie attribute dictionary in application configuration.",
            "verification_criteria": "Set-Cookie headers contain HttpOnly, Secure, and SameSite attributes.",
            "verification_test_profile": "LIVE_WEB_SECURITY_AUDIT",
            "requires_approval": False,
            "approval_role": "ANALYST",
        },
        {
            "pattern": r"(?i)(security\.txt|rfc\s*9116)",
            "title": "Publish RFC 9116 security.txt Vulnerability Disclosure Policy",
            "action_type": "POLICY_CONFIGURATION",
            "description": (
                "Publish a standard RFC 9116 security policy at /.well-known/security.txt declaring Contact, Expires, Encryption, and Preferred-Languages."
            ),
            "rationale": "Enables ethical security researchers to securely report discovered vulnerabilities directly to the security team.",
            "qualitative_benefit": "Accelerates vulnerability reporting and provides verified PGP keys for encrypted vulnerability disclosure.",
            "estimated_risk_reduction": 0.20,
            "root_cause": "Absence of standardized /.well-known/security.txt disclosure document.",
            "recommended_change": "Place RFC 9116 compliant security.txt file at webroot /.well-known/security.txt with valid Contact and Expires directives.",
            "estimated_effort": "LOW (< 2h)",
            "related_controls": ["ISO-27001-A.12.6.1", "RFC-9116"],
            "prerequisites": ["Establish dedicated security response email or vulnerability disclosure program."],
            "operational_impact": "None.",
            "rollback_procedure": "Remove or modify security.txt file.",
            "verification_criteria": "HTTP GET to /.well-known/security.txt returns 200 OK with Contact and Expires fields.",
            "verification_test_profile": "LIVE_SECURITY_RESOURCES",
            "requires_approval": False,
            "approval_role": "ANALYST",
        },
    ]

    @classmethod
    def _sanitize_advisory_text(cls, text: Any) -> str:
        """Sanitizes text against shell command injection and dangerous sequences."""
        if not text:
            return ""
        s = str(text).strip()
        dangerous_patterns = [r"(\brm\s+-rf\b)", r"(\bcurl\s+.*\|\s*sh\b)", r"(\bwget\s+.*\|\s*sh\b)", r"(`[^`]+`)"]
        for p in dangerous_patterns:
            s = re.sub(p, "[REDACTED_COMMAND]", s, flags=re.IGNORECASE)
        return s[:2000]

    @classmethod
    def _sanitize_recommended_change(cls, text: Any) -> str:
        """Enforces that model or external input never invents fake commands or fake resolution."""
        if not text:
            return "Perform manual code and configuration review with software owner."
        s = str(text).strip()
        fake_resolution_patterns = [
            r"(?i)\b(vulnerability\s+is\s+(already\s+)?(fixed|resolved|remediated|closed))\b",
            r"(?i)\b(successfully\s+(fixed|resolved|closed|remediated))\b",
        ]
        for p in fake_resolution_patterns:
            if re.search(p, s):
                return "Perform manual verification re-testing. Unverified claims of resolution are rejected."
        dangerous_patterns = [r"(\brm\s+-rf\b)", r"(\bcurl\s+.*\|\s*sh\b)", r"(\bwget\s+.*\|\s*sh\b)"]
        for p in dangerous_patterns:
            s = re.sub(p, "[DISALLOWED_SHELL_COMMAND]", s, flags=re.IGNORECASE)
        return s[:2000]

    @classmethod
    def generate_explainable_recommendation(
        cls,
        project_id: str,
        finding_id: str,
        db: Session,
        actor: Optional[User] = None,
        client_ip: Optional[str] = None,
        advisory_input: Optional[Dict[str, Any]] = None,
        force_regenerate: bool = False,
    ) -> RemediationRecommendation:
        """
        Generates or retrieves an explainable, evidence-backed remediation recommendation (Prompt 51).
        Separates technical severity, business priority, confidence, urgency, and effort.
        Grounds decisions in actual observation evidence and asset context.
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

        # Check existing latest recommendation
        existing = (
            db.query(RemediationRecommendation)
            .filter(
                RemediationRecommendation.project_id == project_id,
                RemediationRecommendation.finding_id == finding_id,
                RemediationRecommendation.is_latest == True,
            )
            .first()
        )
        if existing and not force_regenerate:
            return existing

        # Fetch Asset context
        asset = None
        if finding.asset_id:
            asset = db.query(Asset).filter(Asset.id == finding.asset_id, Asset.project_id == project_id).first()

        # Step 1: Collect Source Evidence IDs
        source_evidence_ids: List[str] = []
        if finding.observations:
            for obs in finding.observations:
                if obs.evidence_items:
                    for ev in obs.evidence_items:
                        if ev.id and ev.id not in source_evidence_ids:
                            source_evidence_ids.append(ev.id)
                if obs.id and obs.id not in source_evidence_ids:
                    source_evidence_ids.append(obs.id)

        try:
            from app.models.forensic_evidence import ForensicEvidenceRecord
            forensic_recs = db.query(ForensicEvidenceRecord.id).filter(
                ForensicEvidenceRecord.project_id == project_id,
                ForensicEvidenceRecord.finding_id == finding.id,
            ).all()
            for (f_id,) in forensic_recs:
                if f_id and f_id not in source_evidence_ids:
                    source_evidence_ids.append(f_id)
        except Exception:
            pass

        # Step 2: Resolve Exposure
        is_internet_facing = False
        if asset:
            if asset.environment and asset.environment.upper() == "PRODUCTION":
                is_internet_facing = True
            if asset.attributes:
                if asset.attributes.get("internet_facing") or asset.attributes.get("public_ip"):
                    is_internet_facing = True
        if finding.target_value:
            tv = str(finding.target_value).lower()
            if tv.startswith("http://") or tv.startswith("https://") or ("0.0.0.0" not in tv and "127.0.0.1" not in tv and "localhost" not in tv):
                is_internet_facing = True

        # Step 3: Match Catalog or Process Advisory Input
        text_corpus = f"{finding.title} {finding.description} {finding.vuln_id or ''}"
        matched_item = None
        for item in cls.REMEDIATION_CATALOG:
            if re.search(item["pattern"], text_corpus):
                matched_item = item
                break

        missing_prereqs: List[str] = []
        compatibility_concerns: List[str] = []
        dependencies: List[str] = []

        if matched_item:
            guidance_type = GuidanceType.VERIFIED_INSTRUCTION
            title = matched_item["title"]
            action_type = matched_item["action_type"]
            description = matched_item["description"]
            rationale = matched_item["rationale"]
            qualitative_benefit = matched_item["qualitative_benefit"]
            estimated_risk_reduction = matched_item.get("estimated_risk_reduction", 0.70)
            root_cause = matched_item.get("root_cause")
            recommended_change = matched_item.get("recommended_change")
            estimated_effort = matched_item.get("estimated_effort", "LOW (< 2h)")
            related_controls = matched_item.get("related_controls", [])
            prerequisites = list(matched_item.get("prerequisites", []))
            operational_impact = matched_item["operational_impact"]
            rollback_procedure = matched_item["rollback_procedure"]
            verification_criteria = matched_item["verification_criteria"]
            verification_test_profile = matched_item.get("verification_test_profile")
            requires_approval = matched_item.get("requires_approval", True)
            approval_role = matched_item.get("approval_role", "LEAD")

            if "Locate query call sites" in str(prerequisites):
                missing_prereqs.append("Call site static audit required before refactor commit.")
            if "legacy clients" in str(prerequisites):
                compatibility_concerns.append("Legacy client connection termination if TLS 1.0/1.1 disabled.")
            if "CSP" in title:
                compatibility_concerns.append("Inline scripts and unlisted third-party analytics may be blocked by strict CSP.")
            dependencies.extend(["Application Runtime", "Web Server / Reverse Proxy"])
            advisory_disclaimer = (
                "Verified catalog recommendation grounded in validated defensive templates. "
                "Automated command execution is prohibited; manual change authorization and independent "
                "verification re-testing are required."
            )
        elif advisory_input:
            guidance_type = GuidanceType.UNVERIFIED_SUGGESTION
            raw_title = advisory_input.get("title", f"Advisory Proposal: {finding.title[:70]}")
            title = cls._sanitize_advisory_text(raw_title)
            action_type = advisory_input.get("action_type", "ADVISORY_PROPOSAL")
            description = cls._sanitize_advisory_text(advisory_input.get("description", "Unverified advisory proposal requiring human expert review."))
            rationale = cls._sanitize_advisory_text(advisory_input.get("rationale", "Generated from external or heuristic advisory input."))
            qualitative_benefit = cls._sanitize_advisory_text(advisory_input.get("qualitative_benefit", "Potential reduction in attack surface pending manual code review."))
            estimated_risk_reduction = float(advisory_input.get("estimated_risk_reduction", 0.50))
            root_cause = cls._sanitize_advisory_text(advisory_input.get("root_cause", "Unverified observation requiring contextual code inspection."))

            raw_rec = advisory_input.get("recommended_change", "")
            recommended_change = cls._sanitize_recommended_change(raw_rec)
            estimated_effort = advisory_input.get("estimated_effort", "MEDIUM (1-2d)")
            related_controls = advisory_input.get("related_controls", ["NIST-SP800-53-RA-5"])
            prerequisites = advisory_input.get("prerequisites", ["Manual verification of finding reproducibility", "Source code audit"])
            missing_prereqs = ["Target software vendor documentation review", "Staging environment compatibility test"]
            operational_impact = advisory_input.get("operational_impact", "Unknown operational impact. Thorough staging verification required.")
            compatibility_concerns = ["Potential breaking changes in unverified patches or configuration keys."]
            dependencies = ["Software Deployment Pipeline"]
            rollback_procedure = advisory_input.get("rollback_procedure", "Maintain full backup of configuration and source tree before applying changes.")
            verification_criteria = advisory_input.get("verification_criteria", "Targeted re-test confirming finding cannot be reproduced on target.")
            verification_test_profile = advisory_input.get("verification_test_profile", "WEB_APPLICATION_BASELINE")
            requires_approval = True
            approval_role = "LEAD"
            advisory_disclaimer = (
                "NOTICE: This recommendation is an UNVERIFIED SUGGESTION generated from external or heuristic input. "
                "It has NOT been verified against deterministic test profiles. Manual code and configuration review "
                "is strictly required before taking any action. Automated execution is prohibited."
            )
        else:
            guidance_type = GuidanceType.GENERAL_GUIDANCE
            title = f"Investigate and Remediate: {finding.title[:80]}"
            action_type = "MANUAL_ANALYST_REVIEW"
            description = (
                f"Finding '{finding.title}' does not match standard automated defensive playbooks. "
                "Conduct a manual code and configuration review to identify root cause and design an appropriate fix."
            )
            rationale = "Unmapped vulnerability pattern requires human analyst review to avoid disruptive corrective actions."
            qualitative_benefit = "Identifies precise remediation strategy tailored to specific custom software logic."
            estimated_risk_reduction = 0.50
            root_cause = "Unmapped security observation requiring manual triage and context-specific investigation."
            recommended_change = (
                "Product-specific configuration instructions are unavailable for target software. "
                "Consult official vendor documentation and perform manual configuration audit."
            )
            estimated_effort = "MEDIUM (1-2d)"
            related_controls = ["CIS-Control-16.1", "NIST-SP800-53-RA-5"]
            prerequisites = [
                "Review scanner observation evidence and reproduction steps.",
                "Engage application engineering owner.",
            ]
            missing_prereqs = ["Application owner assignment", "Baseline architecture review"]
            operational_impact = "Requires developer investigation and manual verification."
            compatibility_concerns = ["Custom configuration changes require regression testing."]
            dependencies = ["Application Engineering Team"]
            rollback_procedure = "Document manual rollback steps prior to applying custom patch."
            verification_criteria = "Targeted security re-test confirming finding cannot be reproduced on target."
            verification_test_profile = "WEB_APPLICATION_BASELINE"
            requires_approval = True
            approval_role = "LEAD"
            advisory_disclaimer = (
                "NOTICE: Standard defensive guidance. Specific vendor patches or configuration instructions "
                "must be confirmed against target platform documentation. Automated execution is prohibited."
            )

        # Step 4: Compute Technical Severity & Business Priority
        tech_sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        if finding.cvss_score:
            if finding.cvss_score >= 9.0:
                tech_sev = "CRITICAL"
            elif finding.cvss_score >= 7.0:
                tech_sev = "HIGH"
            elif finding.cvss_score >= 4.0:
                tech_sev = "MEDIUM"
            else:
                tech_sev = "LOW"

        sev_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        s_weight = sev_weights.get(tech_sev, 2)

        crit_val = asset.criticality.value if (asset and hasattr(asset.criticality, "value")) else "MEDIUM"
        a_weight = sev_weights.get(crit_val, 2)

        exposure_bonus = 1 if is_internet_facing else 0
        total_priority_score = s_weight + a_weight + exposure_bonus

        if total_priority_score >= 8:
            business_priority = BusinessPriority.P1_CRITICAL
            remediation_urgency = RemediationUrgency.IMMEDIATE
        elif total_priority_score >= 6:
            business_priority = BusinessPriority.P2_HIGH
            remediation_urgency = RemediationUrgency.SCHEDULED_SPRINT
        elif total_priority_score >= 4:
            business_priority = BusinessPriority.P3_MEDIUM
            remediation_urgency = RemediationUrgency.NEXT_CYCLE
        else:
            business_priority = BusinessPriority.P4_LOW
            remediation_urgency = RemediationUrgency.BACKLOG

        # Step 5: Confidence Calculation
        if guidance_type == GuidanceType.VERIFIED_INSTRUCTION:
            base_conf = 0.85
        elif guidance_type == GuidanceType.GENERAL_GUIDANCE:
            base_conf = 0.60
        else:
            base_conf = 0.35

        if len(source_evidence_ids) > 0:
            base_conf += 0.10
        else:
            base_conf -= 0.15

        if asset is None:
            base_conf -= 0.10

        if not finding.is_simulated:
            base_conf += 0.05

        if guidance_type == GuidanceType.UNVERIFIED_SUGGESTION:
            confidence = min(0.50, max(0.10, base_conf))
        else:
            confidence = min(1.00, max(0.10, base_conf))

        confidence = round(confidence, 2)

        # Step 6: Detailed Ranking Factors
        ranking_factors = {
            "technical_severity": tech_sev,
            "cvss_base_score": finding.cvss_score,
            "asset_criticality": crit_val if asset else "UNKNOWN",
            "asset_name": asset.name if asset else "UNASSIGNED",
            "is_internet_facing": is_internet_facing,
            "evidence_item_count": len(source_evidence_ids),
            "evidence_strength": "CONFIRMED" if len(source_evidence_ids) > 0 else "ABSENT_OR_UNVERIFIED",
            "guidance_type": guidance_type.value,
            "business_priority": business_priority.value,
            "remediation_urgency": remediation_urgency.value,
            "confidence_score": confidence,
            "factor_explanation": (
                f"Ranked {business_priority.value} with {remediation_urgency.value} urgency because finding has "
                f"{tech_sev} severity on {crit_val if asset else 'unclassified'} asset "
                f"({len(source_evidence_ids)} verified evidence items, exposure={is_internet_facing})."
            ),
        }

        # Step 7: Version Lineage Handling
        now = utc_now()
        if existing:
            version = existing.version + 1
            prior_version_id = existing.id
            existing.is_latest = False
            existing.superseded_at = now
        else:
            version = 1
            prior_version_id = None

        rec = RemediationRecommendation(
            project_id=project_id,
            finding_id=finding.id,
            asset_id=finding.asset_id,
            title=title,
            action_type=action_type,
            description=description,
            rationale=rationale,
            qualitative_benefit=qualitative_benefit,
            estimated_risk_reduction=estimated_risk_reduction,
            root_cause=root_cause,
            recommended_change=recommended_change,
            estimated_effort=estimated_effort,
            related_controls=related_controls,
            execution_governance_stage="GENERATED",
            prerequisites=prerequisites,
            operational_impact=operational_impact,
            rollback_procedure=rollback_procedure,
            verification_criteria=verification_criteria,
            verification_test_profile=verification_test_profile,
            requires_approval=requires_approval,
            approval_role=approval_role,
            status=RecommendationStatus.PENDING_REVIEW,
            guidance_type=guidance_type,
            technical_severity=tech_sev,
            business_priority=business_priority,
            confidence=confidence,
            remediation_urgency=remediation_urgency,
            source_evidence_ids=source_evidence_ids,
            ranking_factors=ranking_factors,
            advisory_disclaimer=advisory_disclaimer,
            missing_prerequisites=missing_prereqs,
            compatibility_concerns=compatibility_concerns,
            dependencies=dependencies,
            version=version,
            prior_version_id=prior_version_id,
            is_latest=True,
        )
        db.add(rec)
        db.flush()

        AuditService.log(
            db=db,
            action="REMEDIATION_RECOMMENDATION_EXPLAINABLE_GENERATED",
            actor_id=actor.id if actor else None,
            target_resource=f"remediation:{rec.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "finding_id": finding.id,
                "version": version,
                "guidance_type": guidance_type.value,
                "business_priority": business_priority.value,
                "confidence": confidence,
            },
        )
        db.commit()
        db.refresh(rec)
        return rec

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
        Backwards-compatible wrapper delegating to explainable recommendation generation.
        """
        return cls.generate_explainable_recommendation(
            project_id=project_id,
            finding_id=finding_id,
            db=db,
            actor=actor,
            client_ip=client_ip,
            advisory_input=None,
            force_regenerate=False,
        )

    @classmethod
    def get_recommendation_versions(
        cls,
        project_id: str,
        recommendation_id: str,
        db: Session,
    ) -> List[RemediationRecommendation]:
        """
        Retrieves all chronological versions of a recommendation without rewriting history.
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

        return (
            db.query(RemediationRecommendation)
            .filter(
                RemediationRecommendation.project_id == project_id,
                RemediationRecommendation.finding_id == rec.finding_id,
            )
            .order_by(RemediationRecommendation.version.asc())
            .all()
        )

    @classmethod
    def record_feedback(
        cls,
        project_id: str,
        recommendation_id: str,
        feedback_type: RecommendationFeedbackType,
        user: Optional[User],
        db: Session,
        rating: Optional[int] = None,
        comment: Optional[str] = None,
        was_actionable: bool = True,
        applied_as_instructed: Optional[bool] = None,
        client_ip: Optional[str] = None,
    ) -> RecommendationFeedback:
        """
        Records user feedback on recommendation usefulness without rewriting history (Prompt 51).
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

        if rating is not None and not (1 <= rating <= 5):
            raise ValueError("Feedback rating must be an integer between 1 and 5.")

        clean_comment = (comment or "").strip()[:1000] if comment else None

        feedback = RecommendationFeedback(
            project_id=project_id,
            recommendation_id=rec.id,
            user_id=user.id if user else None,
            feedback_type=feedback_type,
            rating=rating,
            comment=clean_comment,
            was_actionable=was_actionable,
            applied_as_instructed=applied_as_instructed,
        )
        db.add(feedback)
        db.flush()

        AuditService.log(
            db=db,
            action="REMEDIATION_RECOMMENDATION_FEEDBACK_RECORDED",
            actor_id=user.id if user else None,
            target_resource=f"remediation_feedback:{feedback.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "recommendation_id": rec.id,
                "feedback_type": feedback_type.value,
                "rating": rating,
                "was_actionable": was_actionable,
            },
        )
        db.commit()
        db.refresh(feedback)
        return feedback

    @classmethod
    def get_recommendation_usefulness_metrics(cls, project_id: str, db: Session) -> Dict[str, Any]:
        """
        Measures recommendation usefulness strictly from actual review and outcome data (Prompt 51).
        Never fabricates recommendation-quality metrics.
        """
        all_recs = db.query(RemediationRecommendation).filter(RemediationRecommendation.project_id == project_id).all()
        total_recs = len(all_recs)
        latest_recs = [r for r in all_recs if r.is_latest]

        by_status = {"PENDING_REVIEW": 0, "APPROVED": 0, "DEFERRED": 0, "REJECTED": 0}
        by_guidance_type = {g.value: 0 for g in GuidanceType}
        by_urgency = {u.value: 0 for u in RemediationUrgency}
        by_business_priority = {b.value: 0 for b in BusinessPriority}

        for r in latest_recs:
            st = r.status.value if hasattr(r.status, "value") else str(r.status)
            if st in by_status:
                by_status[st] += 1
            gt = r.guidance_type.value if hasattr(r.guidance_type, "value") else str(r.guidance_type)
            if gt in by_guidance_type:
                by_guidance_type[gt] += 1
            urg = r.remediation_urgency.value if hasattr(r.remediation_urgency, "value") else str(r.remediation_urgency)
            if urg in by_urgency:
                by_urgency[urg] += 1
            bp = r.business_priority.value if hasattr(r.business_priority, "value") else str(r.business_priority)
            if bp in by_business_priority:
                by_business_priority[bp] += 1

        reviewed_count = by_status["APPROVED"] + by_status["DEFERRED"] + by_status["REJECTED"]
        approval_rate = round(by_status["APPROVED"] / reviewed_count, 3) if reviewed_count > 0 else None

        # Feedback metrics
        feedbacks = db.query(RecommendationFeedback).filter(RecommendationFeedback.project_id == project_id).all()
        total_feedback_count = len(feedbacks)
        by_feedback_type = {f.value: 0 for f in RecommendationFeedbackType}
        actionable_count = 0
        not_actionable_count = 0
        applied_count = 0
        ratings: List[int] = []

        for fb in feedbacks:
            ft = fb.feedback_type.value if hasattr(fb.feedback_type, "value") else str(fb.feedback_type)
            if ft in by_feedback_type:
                by_feedback_type[ft] += 1
            if fb.was_actionable:
                actionable_count += 1
            else:
                not_actionable_count += 1
            if fb.applied_as_instructed:
                applied_count += 1
            if fb.rating is not None:
                ratings.append(fb.rating)

        actionable_ratio = round(actionable_count / total_feedback_count, 3) if total_feedback_count > 0 else None
        average_rating = round(sum(ratings) / len(ratings), 2) if ratings else None
        helpful_tot = by_feedback_type.get("HELPFUL", 0)
        unhelpful_tot = by_feedback_type.get("UNHELPFUL", 0)
        helpfulness_ratio = round(helpful_tot / (helpful_tot + unhelpful_tot), 3) if (helpful_tot + unhelpful_tot) > 0 else None

        # Verification / retest metrics
        verified_recs = [r for r in all_recs if r.verified_outcome is not None or r.verification_id is not None]
        total_verified_count = len(verified_recs)
        by_verified_outcome: Dict[str, int] = {}
        for r in verified_recs:
            vo = str(r.verified_outcome) if r.verified_outcome else "UNSPECIFIED"
            by_verified_outcome[vo] = by_verified_outcome.get(vo, 0) + 1

        v_fixed = by_verified_outcome.get("VERIFIED_FIXED", 0)
        v_persisted = by_verified_outcome.get("STILL_VULNERABLE", 0) + by_verified_outcome.get("PARTIALLY_REMEDIATED", 0)
        tot_conclusive = v_fixed + v_persisted
        verified_resolution_rate = round(v_fixed / tot_conclusive, 3) if tot_conclusive > 0 else None

        return {
            "project_id": project_id,
            "total_recommendations": total_recs,
            "latest_recommendations": len(latest_recs),
            "by_status": by_status,
            "reviewed_count": reviewed_count,
            "approval_rate": approval_rate,
            "by_guidance_type": by_guidance_type,
            "by_urgency": by_urgency,
            "by_business_priority": by_business_priority,
            "total_feedback_count": total_feedback_count,
            "by_feedback_type": by_feedback_type,
            "actionable_count": actionable_count,
            "not_actionable_count": not_actionable_count,
            "actionable_ratio": actionable_ratio,
            "applied_count": applied_count,
            "average_rating": average_rating,
            "helpfulness_ratio": helpfulness_ratio,
            "total_verified_count": total_verified_count,
            "by_verified_outcome": by_verified_outcome,
            "verified_resolution_rate": verified_resolution_rate,
            "data_grounding_notice": (
                "Recommendation usefulness metrics are measured strictly from actual historical review decisions, "
                "user feedback submissions, and independent re-test verification outcomes. "
                "Zero synthetic, simulated, or fabricated scores."
            ),
        }

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
        expected_status: Optional[RecommendationStatus] = None,
    ) -> RemediationRecommendation:
        """
        Reviews a remediation recommendation (APPROVE, DEFER, REJECT).
        Enforces that approval requires Project LEAD or System ADMIN role.
        Optimistic concurrency control: if expected_status is supplied, checks that rec.status matches.
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

        # Concurrency check if an expected predecessor status was supplied
        if expected_status is not None and rec.status != expected_status:
            raise ValueError(
                f"Concurrency conflict: recommendation '{recommendation_id}' status changed from '{expected_status.value}' to '{rec.status.value}'."
            )

        # Check role permission if approval is required
        if new_status == RecommendationStatus.APPROVED and rec.requires_approval:
            is_lead = (reviewer_role == ProjectRole.LEAD)
            is_admin = (reviewer.system_role == SystemRole.ADMIN)
            if not (is_lead or is_admin):
                raise PermissionError("Only Project LEAD or System ADMIN can approve remediation recommendations.")

        target_expected_status = expected_status or rec.status
        now = utc_now()

        if new_status == RecommendationStatus.APPROVED:
            gov_stage = "APPROVED"
        elif new_status == RecommendationStatus.REJECTED:
            gov_stage = "REJECTED"
        elif new_status == RecommendationStatus.DEFERRED:
            gov_stage = "DEFERRED"
        else:
            gov_stage = "UNDER_REVIEW"

        # Atomic optimistic concurrency check: verify recommendation has not transitioned concurrently
        rows = (
            db.query(RemediationRecommendation)
            .filter(
                RemediationRecommendation.id == recommendation_id,
                RemediationRecommendation.project_id == project_id,
                RemediationRecommendation.status == target_expected_status,
            )
            .update(
                {
                    "status": new_status,
                    "reviewed_by_id": reviewer.id,
                    "reviewed_at": now,
                    "review_notes": clean_notes,
                    "execution_governance_stage": gov_stage,
                },
                synchronize_session="fetch",
            )
        )
        if rows == 0:
            fresh = db.query(RemediationRecommendation).filter(RemediationRecommendation.id == recommendation_id).first()
            current_st = fresh.status.value if fresh else "DELETED"
            raise ValueError(
                f"Concurrency conflict: Remediation recommendation '{recommendation_id}' status changed from '{expected_status.value}' to '{current_st}'."
            )

        rec.status = new_status
        rec.reviewed_by_id = reviewer.id
        rec.reviewed_at = now
        rec.review_notes = clean_notes
        rec.execution_governance_stage = gov_stage

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

        # Separation of Duties check: Authorizer must be distinct from the reviewer who initially approved the recommendation
        from app.services.governance_service import ProjectGovernanceService
        policy = ProjectGovernanceService.get_or_create_policy(db, project_id)
        if policy.enforce_separation_of_duties and not policy.allow_self_approval_override:
            if rec.reviewed_by_id and authorizer.id == rec.reviewed_by_id:
                AuditService.record_event(
                    db=db,
                    action="REMEDIATION_AUTHORIZE_CHANGE_DENIED_SOD",
                    target_type="remediation_recommendation",
                    target_id=rec.id,
                    project_id=project_id,
                    actor_id=authorizer.id,
                    actor_email=authorizer.email,
                    outcome="DENIED",
                    details={"reason": "Separation of Duties violation: The reviewer who approved the recommendation cannot unilaterally authorize the change."},
                )
                raise PermissionError("Separation of Duties violation: An independent Project LEAD or Administrator must authorize the change implementation.")

        ticket = (change_ticket_ref or "").strip()
        if len(ticket) < 3:
            raise ValueError("Valid change ticket reference is mandatory (minimum 3 characters).")

        # Double-authorization prevention & atomic stage transition check
        if rec.execution_governance_stage == "CHANGE_AUTHORIZED":
            raise ValueError(f"Change implementation has already been authorized for recommendation '{recommendation_id}'.")

        updated_notes = f"{rec.review_notes}\n[Change Authorized: {ticket}]" if rec.review_notes else f"[Change Authorized: {ticket}]"

        rows = (
            db.query(RemediationRecommendation)
            .filter(
                RemediationRecommendation.id == recommendation_id,
                RemediationRecommendation.project_id == project_id,
                RemediationRecommendation.status == RecommendationStatus.APPROVED,
                RemediationRecommendation.execution_governance_stage == "APPROVED",
            )
            .update(
                {
                    "execution_governance_stage": "CHANGE_AUTHORIZED",
                    "review_notes": updated_notes,
                },
                synchronize_session="fetch",
            )
        )
        if rows == 0:
            fresh = db.query(RemediationRecommendation).filter(RemediationRecommendation.id == recommendation_id).first()
            curr_stage = fresh.execution_governance_stage if fresh else "DELETED"
            raise ValueError(
                f"Concurrency conflict: Change authorization failed because recommendation '{recommendation_id}' is in stage '{curr_stage}', expected 'APPROVED'."
            )

        rec.execution_governance_stage = "CHANGE_AUTHORIZED"
        rec.review_notes = updated_notes

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
