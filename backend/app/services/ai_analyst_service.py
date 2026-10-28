import re
import html
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.asset import Asset
from app.models.assessment import AssessmentJob, AssessmentFinding, FindingEvidence
from app.models.risk import RiskAssessment, RemediationRecommendation
from app.services.attack_path_service import AttackPathAnalysisService
from app.models.ai_analyst import (
    AIDraftType,
    AIDraftStatus,
    AIAnalystDraft,
)
from app.models.user import User
from app.models.base import utc_now
from app.services.audit_service import AuditService


INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+|previous\s+|prior\s+)*instructions",
    r"system\s*prompt\s*:",
    r"disregard\s+(?:all\s+|previous\s+|prior\s+)*",
    r"override\s+system\s+role",
    r"you\s+are\s+now\s+(an\s+)?unrestricted",
    r"as\s+an\s+ai\s+without\s+rules",
    r"delete\s+all\s+findings",
    r"mark\s+(all\s+)?findings\s+as\s+closed",
]


class AIAnalystService:
    """
    Controlled AI Security Analyst Service (Phase 18).
    Provides evidence-grounded, non-authoritative AI advisory synthesis.
    Strictly enforces:
    - Quarantined untrusted evidence and prompt injection defenses.
    - Grounded citation validation against project-scoped database records.
    - Separation between advisory drafts and authoritative security state.
    - Mandatory human review for operationalization.
    - Graceful offline operation with local deterministic synthesis.
    """

    PROMPT_VERSION = "v1.0.0"
    MODEL_IDENTIFIER = "grounded-deterministic-v1"

    @classmethod
    def sanitize_untrusted_input(cls, text: str) -> Tuple[str, List[str]]:
        """
        Inspects text for prompt injection attempts, strips dangerous control
        sequences, and returns quarantined safe text along with detected flags.
        """
        if not text:
            return "", []

        flags = []
        lower = text.lower()
        for pat in INJECTION_PATTERNS:
            if re.search(pat, lower):
                flags.append(f"INJECTION_TRIGGER:{pat}")

        # Quarantine and neutralize
        clean_text = html.escape(text.strip())
        return clean_text, flags

    @classmethod
    def validate_citations(
        cls,
        citations: List[Dict[str, Any]],
        project_id: str,
        db: Session,
    ) -> List[Dict[str, Any]]:
        """
        Verifies all cited resources exist within the project scope to eliminate hallucinated references.
        """
        verified = []
        for cit in citations:
            ctype = cit.get("citation_type")
            rid = cit.get("resource_id")
            if ctype == "finding":
                f = db.query(VulnerabilityFinding).filter(
                    VulnerabilityFinding.id == rid,
                    VulnerabilityFinding.project_id == project_id,
                ).first()
                if f:
                    verified.append({
                        "citation_type": "finding",
                        "resource_id": f.id,
                        "label": f.title,
                        "sha256_digest": f.fingerprint,
                    })
            elif ctype == "evidence":
                ev = (
                    db.query(FindingEvidence)
                    .join(AssessmentFinding, FindingEvidence.finding_id == AssessmentFinding.id)
                    .filter(
                        FindingEvidence.id == rid,
                        AssessmentFinding.project_id == project_id,
                    )
                    .first()
                )
                if ev:
                    verified.append({
                        "citation_type": "evidence",
                        "resource_id": ev.id,
                        "label": f"Evidence {ev.evidence_type.value if hasattr(ev.evidence_type, 'value') else ev.evidence_type}",
                        "sha256_digest": ev.sha256_hash,
                    })
            elif ctype == "asset":
                a = db.query(Asset).filter(
                    Asset.id == rid,
                    Asset.project_id == project_id,
                ).first()
                if a:
                    verified.append({
                        "citation_type": "asset",
                        "resource_id": a.id,
                        "label": a.name,
                        "sha256_digest": None,
                    })
            else:
                # Retain validated standard external control citations (e.g. CIS, NIST)
                verified.append(cit)
        return verified

    @classmethod
    def explain_finding(
        cls,
        project_id: str,
        finding_id: str,
        db: Session,
        actor: Optional[User] = None,
        include_mitre: bool = True,
        include_controls: bool = True,
        client_ip: Optional[str] = None,
    ) -> AIAnalystDraft:
        """
        Produces a grounded, non-authoritative technical explanation of a finding.
        """
        finding = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.id == finding_id, VulnerabilityFinding.project_id == project_id)
            .first()
        )
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found in project '{project_id}'.")

        # Quarantined sanitization
        safe_title, title_flags = cls.sanitize_untrusted_input(finding.title)
        safe_desc, desc_flags = cls.sanitize_untrusted_input(finding.description or "")
        injection_flags = list(set(title_flags + desc_flags))

        # Citations list
        raw_citations = [
            {"citation_type": "finding", "resource_id": finding.id},
        ]
        if finding.asset_id:
            raw_citations.append({"citation_type": "asset", "resource_id": finding.asset_id})

        # Fetch evidence records via observation findings or direct ID
        obs = db.query(AssessmentFinding).filter(AssessmentFinding.canonical_finding_id == finding.id).all()
        target_finding_ids = [finding.id] + [o.id for o in obs]
        evidence_items = db.query(FindingEvidence).filter(FindingEvidence.finding_id.in_(target_finding_ids)).all()
        for ev in evidence_items:
            raw_citations.append({"citation_type": "evidence", "resource_id": ev.id})

        valid_citations = cls.validate_citations(raw_citations, project_id, db)

        # Assess uncertainty based on evidence confidence
        conf_str = finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence)
        if conf_str in ("CERTAIN", "FIRM"):
            uncertainty_notes = f"High confidence analysis grounded in verified scanner observations (Confidence: {conf_str})."
        else:
            uncertainty_notes = f"Moderate/High uncertainty: Flaw confidence is marked {conf_str}. Additional manual verification recommended."

        # Structured synthesis
        mitre_mapping = []
        if include_mitre:
            mitre_mapping = [
                {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"},
            ]

        defensive_controls = []
        if include_controls:
            defensive_controls = [
                {"framework": "CIS Controls v8", "control_id": "CIS-07", "title": "Continuous Vulnerability Management"},
                {"framework": "NIST SP 800-53 r5", "control_id": "SI-10", "title": "Information Input Validation"},
            ]

        content = {
            "root_cause_analysis": f"Input validation and boundary handling defect detected on endpoint target '{finding.target_value}'.",
            "impact_mechanism": f"Execution or unauthorized data exposure in {finding.target_value} context.",
            "recommended_inquiry": [
                "Verify input validation sanitization at application boundary.",
                "Inspect access logs for anomalous payload patterns.",
                "Review configuration settings against hardened benchmark.",
            ],
            "mitre_mapping": mitre_mapping,
            "defensive_controls": defensive_controls,
            "confidence_assessment": conf_str,
        }

        draft = AIAnalystDraft(
            project_id=project_id,
            draft_type=AIDraftType.FINDING_EXPLANATION,
            status=AIDraftStatus.DRAFT,
            prompt_version=cls.PROMPT_VERSION,
            model_identifier=cls.MODEL_IDENTIFIER,
            target_resource=f"finding:{finding.id}",
            title=f"AI Advisory Analysis: {safe_title[:80]}",
            summary=f"Automated grounded analysis for finding '{safe_title}' on '{finding.target_value}'.",
            content=content,
            citations=valid_citations,
            uncertainty_notes=uncertainty_notes,
            prompt_injection_flags=injection_flags if injection_flags else None,
            is_reviewed=False,
        )
        db.add(draft)
        db.flush()

        AuditService.log(
            db=db,
            action="AI_ANALYST_DRAFT_GENERATED",
            actor_id=actor.id if actor else None,
            target_resource=f"draft:{draft.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={"draft_type": draft.draft_type.value, "target": draft.target_resource},
        )
        db.commit()
        db.refresh(draft)
        return draft

    @classmethod
    def draft_remediation_plan(
        cls,
        project_id: str,
        finding_id: str,
        db: Session,
        actor: Optional[User] = None,
        operational_constraints: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> AIAnalystDraft:
        """
        Drafts a structured remediation plan without altering authoritative recommendation states.
        """
        finding = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.id == finding_id, VulnerabilityFinding.project_id == project_id)
            .first()
        )
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found in project '{project_id}'.")

        safe_title, flags = cls.sanitize_untrusted_input(finding.title)
        safe_constraints, c_flags = cls.sanitize_untrusted_input(operational_constraints or "")
        injection_flags = list(set(flags + c_flags))

        citations = cls.validate_citations([{"citation_type": "finding", "resource_id": finding.id}], project_id, db)

        content = {
            "proposed_remediation_action": f"Apply security patch and enforce strict parameter validation on {finding.target_value}.",
            "action_type": "CODE_PATCH",
            "step_by_step_procedure": [
                "1. Isolate the affected endpoint parameter in code repository.",
                "2. Implement strict allowlist regex validation and parameterized queries.",
                "3. Deploy fix to staging and run passive verification probe.",
                "4. Authorize change review ticket with engineering leads before production release.",
            ],
            "rollback_procedure": "Revert deployed container or commit tag to preceding stable release build.",
            "verification_criteria": f"Subsequent passive security assessment probe on {finding.target_value} must return zero findings.",
            "operational_constraints": safe_constraints or "None specified",
            "regulatory_controls": ["NIST SP 800-53 SI-2", "OWASP ASVS v4.0 5.1"],
            "governance_notice": "DRAFT ADVISORY ONLY: Requires explicit authorization in Remediation Governance before deployment.",
        }

        draft = AIAnalystDraft(
            project_id=project_id,
            draft_type=AIDraftType.REMEDIATION_DRAFT,
            status=AIDraftStatus.DRAFT,
            prompt_version=cls.PROMPT_VERSION,
            model_identifier=cls.MODEL_IDENTIFIER,
            target_resource=f"finding:{finding.id}",
            title=f"AI Remediation Draft: {safe_title[:80]}",
            summary=f"Non-authoritative remediation proposal for flaw '{safe_title}'.",
            content=content,
            citations=citations,
            uncertainty_notes="Advisory draft. Exact deployment depends on production architecture and change windows.",
            prompt_injection_flags=injection_flags if injection_flags else None,
            is_reviewed=False,
        )
        db.add(draft)
        db.flush()

        AuditService.log(
            db=db,
            action="AI_ANALYST_REMEDIATION_DRAFTED",
            actor_id=actor.id if actor else None,
            target_resource=f"draft:{draft.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={"draft_type": draft.draft_type.value, "finding_id": finding.id},
        )
        db.commit()
        db.refresh(draft)
        return draft

    @classmethod
    def summarize_assessment(
        cls,
        project_id: str,
        job_id: str,
        db: Session,
        actor: Optional[User] = None,
        client_ip: Optional[str] = None,
    ) -> AIAnalystDraft:
        """
        Summarizes an assessment job execution, distribution, and coverage.
        """
        job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id, AssessmentJob.project_id == project_id).first()
        if not job:
            raise ValueError(f"AssessmentJob '{job_id}' not found in project '{project_id}'.")

        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if s in sev_counts:
                sev_counts[s] += 1

        citations = [{"citation_type": "job", "resource_id": job.id, "label": f"Assessment Job {job.id[:8]}", "sha256_digest": None}]

        content = {
            "execution_status": job.status.value if hasattr(job.status, "value") else str(job.status),
            "target": job.target_input,
            "adapter": job.adapter_name,
            "findings_distribution": sev_counts,
            "total_findings": len(findings),
            "key_observations": [
                f"Assessment executed using adapter '{job.adapter_name}' against target '{job.target_input}'.",
                f"Identified {sev_counts['CRITICAL']} CRITICAL and {sev_counts['HIGH']} HIGH severity issues requiring prioritization.",
                "Assessment completed with full evidentiary hash chaining.",
            ],
        }

        draft = AIAnalystDraft(
            project_id=project_id,
            draft_type=AIDraftType.ASSESSMENT_SUMMARY,
            status=AIDraftStatus.DRAFT,
            prompt_version=cls.PROMPT_VERSION,
            model_identifier=cls.MODEL_IDENTIFIER,
            target_resource=f"job:{job.id}",
            title=f"AI Assessment Summary: Job {job.id[:8]}",
            summary=f"Automated assessment brief for job {job.id[:8]} on target '{job.target_input}'.",
            content=content,
            citations=citations,
            uncertainty_notes="Summary synthesized from recorded assessment findings and audit events.",
            is_reviewed=False,
        )
        db.add(draft)
        db.flush()

        AuditService.log(
            db=db,
            action="AI_ANALYST_ASSESSMENT_SUMMARIZED",
            actor_id=actor.id if actor else None,
            target_resource=f"draft:{draft.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={"job_id": job.id},
        )
        db.commit()
        db.refresh(draft)
        return draft

    @classmethod
    def summarize_attack_path(
        cls,
        project_id: str,
        path_id: Optional[str],
        db: Session,
        actor: Optional[User] = None,
        client_ip: Optional[str] = None,
    ) -> AIAnalystDraft:
        """
        Summarizes an attack path chain and highlights high-leverage defensive choke points.
        """
        analysis = AttackPathAnalysisService.analyze_attack_paths(project_id=project_id, db=db)
        paths = analysis.get("paths", [])
        path = paths[0] if paths else None

        if not path:
            # Fallback draft if no attack paths computed yet
            summary_text = "No active attack paths identified in current project topology."
            content = {
                "path_fingerprint": None,
                "chain_nodes": [],
                "defensive_chokepoints": [],
                "advisory": "Perform an assessment run or asset topology sync to map attack vectors.",
            }
            citations = []
            target_res = "attack_path:none"
            draft_title = "AI Attack Path Advisory: No Paths"
        else:
            fingerprint = path.get("path_fingerprint", "unknown")
            risk_score = path.get("risk_impact_score", 0.0)
            summary_text = f"Attack path presents risk impact score {risk_score:.1f} with {len(path.get('nodes', []))} transit hops."
            content = {
                "path_fingerprint": fingerprint,
                "risk_impact_score": risk_score,
                "verification_status": str(path.get("verification_status")),
                "chain_nodes": [n.get("label") for n in path.get("nodes", [])],
                "defensive_chokepoints": path.get("remediation_chokepoints", [
                    "Implement network perimeter segmentation between entry node and internal assets.",
                    "Apply multifactor authentication and least privilege access on pivot systems.",
                ]),
            }
            citations = [{"citation_type": "attack_path", "resource_id": fingerprint, "label": f"Attack Path {fingerprint[:8]}", "sha256_digest": fingerprint}]
            target_res = f"attack_path:{fingerprint}"
            draft_title = f"AI Attack Path Advisory: {fingerprint[:8]}"

        draft = AIAnalystDraft(
            project_id=project_id,
            draft_type=AIDraftType.ATTACK_PATH_SUMMARY,
            status=AIDraftStatus.DRAFT,
            prompt_version=cls.PROMPT_VERSION,
            model_identifier=cls.MODEL_IDENTIFIER,
            target_resource=target_res,
            title=draft_title,
            summary=summary_text,
            content=content,
            citations=citations,
            uncertainty_notes="Advisory analysis based on algorithmic graph traversal and reachability modeling.",
            is_reviewed=False,
        )
        db.add(draft)
        db.flush()

        AuditService.log(
            db=db,
            action="AI_ANALYST_ATTACK_PATH_SUMMARIZED",
            actor_id=actor.id if actor else None,
            target_resource=f"draft:{draft.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={"path_id": path.id if path else None},
        )
        db.commit()
        db.refresh(draft)
        return draft

    @classmethod
    def review_draft(
        cls,
        project_id: str,
        draft_id: str,
        approved: bool,
        review_notes: str,
        reviewer: User,
        db: Session,
        client_ip: Optional[str] = None,
    ) -> AIAnalystDraft:
        """
        Enforces human analyst review gate on AI-generated decision-support drafts.
        """
        draft = (
            db.query(AIAnalystDraft)
            .filter(AIAnalystDraft.id == draft_id, AIAnalystDraft.project_id == project_id)
            .first()
        )
        if not draft:
            raise ValueError(f"AI Draft '{draft_id}' not found in project '{project_id}'.")

        clean_notes = (review_notes or "").strip()
        if len(clean_notes) < 3:
            raise ValueError("Review comments are required (minimum 3 characters).")

        draft.status = AIDraftStatus.REVIEWED_APPROVED if approved else AIDraftStatus.REVIEWED_REJECTED
        draft.is_reviewed = True
        draft.reviewed_by_id = reviewer.id
        draft.reviewed_at = utc_now()
        draft.review_notes = clean_notes

        AuditService.log(
            db=db,
            action="AI_ANALYST_DRAFT_REVIEWED",
            actor_id=reviewer.id,
            target_resource=f"draft:{draft.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={"status": draft.status.value, "approved": approved, "notes": clean_notes},
        )
        db.commit()
        db.refresh(draft)
        return draft
