import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from app.models.project import Project
from app.models.user import User
from app.models.asset import Asset
from app.models.finding import VulnerabilityFinding
from app.models.assessment import FindingEvidence
from app.models.incident import (
    CaseSeverity,
    CaseStatus,
    RelationshipType,
    CorrelationType,
    IncidentCase,
    IncidentCaseAsset,
    IncidentCaseFinding,
    IncidentCaseEvidence,
    IncidentCaseTransition,
    IncidentCaseNote,
)
from app.models.base import utc_now
from app.services.audit_service import AuditService
from app.services.governance_service import ProjectGovernanceService


class IncidentInvestigationService:
    """
    Evidence-Preserving Security Incident Investigation & Case Management Service (Prompt 39).
    Connects observations, findings, and evidence into reviewable cases while strictly
    separating empirical correlation from confirmed causation and preserving contradictory evidence.
    """

    @classmethod
    def generate_case_number(cls, db: Session, project_id: str) -> str:
        year = utc_now().year
        count = (
            db.query(IncidentCase)
            .filter(IncidentCase.project_id == project_id)
            .count()
        )
        return f"INC-{year}-{count + 1:04d}"

    @classmethod
    def create_case(
        cls,
        db: Session,
        project_id: str,
        title: str,
        description: Optional[str] = None,
        severity: CaseSeverity = CaseSeverity.MEDIUM,
        lead_investigator_id: Optional[str] = None,
        assigned_team: Optional[str] = None,
        actor: Optional[User] = None,
    ) -> IncidentCase:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        clean_title = (title or "").strip()
        if len(clean_title) < 3:
            raise ValueError("Case title must be at least 3 characters.")

        if lead_investigator_id:
            lead = db.query(User).filter(User.id == lead_investigator_id).first()
            if not lead:
                raise ValueError(f"Lead investigator user '{lead_investigator_id}' not found.")

        case_number = cls.generate_case_number(db, project_id)
        now = utc_now()

        case = IncidentCase(
            project_id=project_id,
            case_number=case_number,
            title=clean_title,
            description=description.strip() if description else None,
            severity=severity,
            status=CaseStatus.OPEN,
            lead_investigator_id=lead_investigator_id,
            assigned_team=assigned_team,
            opened_at=now,
            alternative_explanations=[],
            is_containment_verified=False,
            created_at=now,
            updated_at=now,
        )
        db.add(case)
        db.flush()

        # Initial transition
        trans = IncidentCaseTransition(
            case_id=case.id,
            from_status=CaseStatus.OPEN,
            to_status=CaseStatus.OPEN,
            transitioned_by_id=actor.id if actor else None,
            reason="Case opened and initialized.",
            created_at=now,
        )
        db.add(trans)

        AuditService.record_event(
            db=db,
            action="INCIDENT_CASE_CREATED",
            target_type="incident_case",
            target_id=case.id,
            project_id=project_id,
            actor_id=actor.id if actor else None,
            outcome="SUCCESS",
            details={
                "case_number": case.case_number,
                "title": case.title,
                "severity": case.severity.value,
            },
        )
        db.commit()
        db.refresh(case)
        return case

    @classmethod
    def link_asset_to_case(
        cls,
        db: Session,
        project_id: str,
        case_id: str,
        asset_id: str,
        relationship_type: RelationshipType = RelationshipType.OBSERVED_CORRELATION,
        confidence: float = 0.5,
        is_contradictory: bool = False,
        notes: Optional[str] = None,
        actor: Optional[User] = None,
    ) -> IncidentCaseAsset:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id, IncidentCase.project_id == project_id)
            .first()
        )
        if not case:
            raise ValueError(f"IncidentCase '{case_id}' not found in project '{project_id}'.")

        asset = (
            db.query(Asset)
            .filter(Asset.id == asset_id, Asset.project_id == project_id)
            .first()
        )
        if not asset:
            raise ValueError(f"Asset '{asset_id}' not found in project '{project_id}'.")

        if not (0.0 <= confidence <= 1.0):
            raise ValueError("Confidence score must be between 0.0 and 1.0.")

        existing = (
            db.query(IncidentCaseAsset)
            .filter(IncidentCaseAsset.case_id == case_id, IncidentCaseAsset.asset_id == asset_id)
            .first()
        )
        if existing:
            existing.relationship_type = relationship_type
            existing.confidence = confidence
            existing.is_contradictory = is_contradictory
            existing.notes = notes
            db.commit()
            db.refresh(existing)
            return existing

        case_asset = IncidentCaseAsset(
            case_id=case_id,
            asset_id=asset_id,
            relationship_type=relationship_type,
            confidence=confidence,
            is_contradictory=is_contradictory,
            notes=notes,
            created_at=utc_now(),
        )
        db.add(case_asset)
        db.commit()
        db.refresh(case_asset)
        return case_asset

    @classmethod
    def link_finding_to_case(
        cls,
        db: Session,
        project_id: str,
        case_id: str,
        finding_id: str,
        correlation_type: CorrelationType = CorrelationType.PROBABLE_CORRELATION,
        confidence: float = 0.5,
        rationale: Optional[str] = None,
        actor: Optional[User] = None,
    ) -> IncidentCaseFinding:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id, IncidentCase.project_id == project_id)
            .first()
        )
        if not case:
            raise ValueError(f"IncidentCase '{case_id}' not found in project '{project_id}'.")

        finding = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.id == finding_id, VulnerabilityFinding.project_id == project_id)
            .first()
        )
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found in project '{project_id}'.")

        if not (0.0 <= confidence <= 1.0):
            raise ValueError("Confidence score must be between 0.0 and 1.0.")

        existing = (
            db.query(IncidentCaseFinding)
            .filter(IncidentCaseFinding.case_id == case_id, IncidentCaseFinding.finding_id == finding_id)
            .first()
        )
        if existing:
            existing.correlation_type = correlation_type
            existing.confidence = confidence
            existing.rationale = rationale
            db.commit()
            db.refresh(existing)
            return existing

        case_finding = IncidentCaseFinding(
            case_id=case_id,
            finding_id=finding_id,
            correlation_type=correlation_type,
            confidence=confidence,
            rationale=rationale,
            created_at=utc_now(),
        )
        db.add(case_finding)

        # Automatically link finding's asset if not yet linked
        if finding.asset_id:
            asset_link = (
                db.query(IncidentCaseAsset)
                .filter(IncidentCaseAsset.case_id == case_id, IncidentCaseAsset.asset_id == finding.asset_id)
                .first()
            )
            if not asset_link:
                new_asset_link = IncidentCaseAsset(
                    case_id=case_id,
                    asset_id=finding.asset_id,
                    relationship_type=RelationshipType.PRIMARY_TARGET,
                    confidence=confidence,
                    notes=f"Auto-linked from finding '{finding.title}'",
                    created_at=utc_now(),
                )
                db.add(new_asset_link)

        db.commit()
        db.refresh(case_finding)
        return case_finding

    @classmethod
    def attach_evidence_snapshot(
        cls,
        db: Session,
        project_id: str,
        case_id: str,
        evidence_summary: str,
        finding_evidence_id: Optional[str] = None,
        is_contradictory: bool = False,
        provenance_details: Optional[Dict[str, Any]] = None,
        actor: Optional[User] = None,
    ) -> IncidentCaseEvidence:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id, IncidentCase.project_id == project_id)
            .first()
        )
        if not case:
            raise ValueError(f"IncidentCase '{case_id}' not found in project '{project_id}'.")

        clean_summary = (evidence_summary or "").strip()
        if len(clean_summary) < 5:
            raise ValueError("Evidence summary must be at least 5 characters.")

        prov = provenance_details or {}
        digest_src = f"{case_id}:{clean_summary}:{json.dumps(prov, sort_keys=True)}"
        digest = hashlib.sha256(digest_src.encode("utf-8")).hexdigest()

        evidence = IncidentCaseEvidence(
            case_id=case_id,
            finding_evidence_id=finding_evidence_id,
            evidence_digest=digest,
            evidence_summary=clean_summary,
            is_contradictory=is_contradictory,
            provenance_details=prov,
            created_at=utc_now(),
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
        return evidence

    @classmethod
    def transition_case_status(
        cls,
        db: Session,
        project_id: str,
        case_id: str,
        to_status: CaseStatus,
        reason: str,
        actor: User,
        closure_summary: Optional[str] = None,
        reopening_rationale: Optional[str] = None,
        root_cause_hypothesis: Optional[str] = None,
        is_containment_verified: Optional[bool] = None,
    ) -> IncidentCase:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id, IncidentCase.project_id == project_id)
            .first()
        )
        if not case:
            raise ValueError(f"IncidentCase '{case_id}' not found in project '{project_id}'.")

        clean_reason = (reason or "").strip()
        if len(clean_reason) < 3:
            raise ValueError("Status transition reason must be at least 3 characters.")

        from_status = case.status
        now = utc_now()

        # Enforce valid state transitions
        valid_transitions = {
            CaseStatus.OPEN: [CaseStatus.TRIAGED, CaseStatus.INVESTIGATING, CaseStatus.CLOSED],
            CaseStatus.TRIAGED: [CaseStatus.INVESTIGATING, CaseStatus.CLOSED],
            CaseStatus.INVESTIGATING: [CaseStatus.CONTAINED, CaseStatus.CLOSED],
            CaseStatus.CONTAINED: [CaseStatus.CLOSED, CaseStatus.INVESTIGATING],
            CaseStatus.CLOSED: [CaseStatus.REOPENED],
            CaseStatus.REOPENED: [CaseStatus.INVESTIGATING, CaseStatus.CONTAINED, CaseStatus.CLOSED],
        }

        allowed = valid_transitions.get(from_status, [])
        if to_status not in allowed:
            raise ValueError(f"Illegal case transition from '{from_status.value}' to '{to_status.value}'.")

        # Controlled Case Closure Rules (Req 9, 10)
        if to_status == CaseStatus.CLOSED:
            if not closure_summary or len(closure_summary.strip()) < 10:
                raise ValueError("Case closure requires a detailed closure summary (minimum 10 characters).")

            # Check Separation of Duties (Req 9)
            policy = ProjectGovernanceService.get_or_create_policy(db, project_id)
            if policy.enforce_separation_of_duties and not policy.allow_self_approval_override:
                if case.lead_investigator_id == actor.id:
                    AuditService.record_event(
                        db=db,
                        action="CASE_CLOSURE_DENIED_SOD",
                        target_type="incident_case",
                        target_id=case.id,
                        project_id=project_id,
                        actor_id=actor.id,
                        actor_email=actor.email,
                        outcome="DENIED",
                        details={"reason": "Separation of Duties violation: The lead investigator cannot approve their own case closure."},
                    )
                    raise PermissionError("Separation of Duties violation: An independent Security Lead or Administrator must approve case closure.")

            case.closed_at = now
            case.closure_summary = closure_summary.strip()
            case.closure_approved_by_id = actor.id

        # Controlled Reopening Rules (Req 10)
        if to_status == CaseStatus.REOPENED:
            if not reopening_rationale or len(reopening_rationale.strip()) < 10:
                raise ValueError("Reopening a closed case requires an explicit justification (minimum 10 characters).")
            case.reopened_at = now
            case.reopening_rationale = reopening_rationale.strip()
            case.closed_at = None

        if root_cause_hypothesis is not None:
            case.root_cause_hypothesis = root_cause_hypothesis.strip()
        if is_containment_verified is not None:
            case.is_containment_verified = is_containment_verified

        case.status = to_status
        case.updated_at = now

        transition = IncidentCaseTransition(
            case_id=case.id,
            from_status=from_status,
            to_status=to_status,
            transitioned_by_id=actor.id,
            reason=clean_reason,
            created_at=now,
        )
        db.add(transition)

        AuditService.record_event(
            db=db,
            action="INCIDENT_CASE_STATUS_TRANSITIONED",
            target_type="incident_case",
            target_id=case.id,
            project_id=project_id,
            actor_id=actor.id,
            outcome="SUCCESS",
            details={
                "from_status": from_status.value,
                "to_status": to_status.value,
                "reason": clean_reason,
            },
        )
        db.commit()
        db.refresh(case)
        return case

    @classmethod
    def add_case_note(
        cls,
        db: Session,
        project_id: str,
        case_id: str,
        content: str,
        note_type: str = "ANALYST_OBSERVATION",
        is_alternative_hypothesis: bool = False,
        actor: Optional[User] = None,
    ) -> IncidentCaseNote:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id, IncidentCase.project_id == project_id)
            .first()
        )
        if not case:
            raise ValueError(f"IncidentCase '{case_id}' not found in project '{project_id}'.")

        clean_content = (content or "").strip()
        if len(clean_content) < 3:
            raise ValueError("Note content must be at least 3 characters.")

        note = IncidentCaseNote(
            case_id=case.id,
            author_id=actor.id if actor else None,
            note_type=note_type,
            content=clean_content,
            is_alternative_hypothesis=is_alternative_hypothesis,
            created_at=utc_now(),
        )
        db.add(note)

        if is_alternative_hypothesis:
            alt_list = list(case.alternative_explanations or [])
            alt_list.append({
                "hypothesis": clean_content,
                "author_id": actor.id if actor else None,
                "recorded_at": utc_now().isoformat(),
            })
            case.alternative_explanations = alt_list

        db.commit()
        db.refresh(note)
        return note

    @classmethod
    def explain_correlations(
        cls,
        db: Session,
        project_id: str,
        case_id: str,
    ) -> Dict[str, Any]:
        """
        Builds explainable correlation breakdown separating confirmed causal links
        from temporal correlations and contradictory evidence (Prompt 39 Req 4, 5, 6).
        """
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id, IncidentCase.project_id == project_id)
            .first()
        )
        if not case:
            raise ValueError(f"IncidentCase '{case_id}' not found in project '{project_id}'.")

        findings_links = db.query(IncidentCaseFinding).filter(IncidentCaseFinding.case_id == case_id).all()
        assets_links = db.query(IncidentCaseAsset).filter(IncidentCaseAsset.case_id == case_id).all()
        evidence_links = db.query(IncidentCaseEvidence).filter(IncidentCaseEvidence.case_id == case_id).all()

        causal_findings = []
        probable_findings = []
        temporal_only_findings = []
        contradictory_findings = []

        for lf in findings_links:
            item = {
                "finding_id": lf.finding_id,
                "title": lf.finding.title if lf.finding else "Unknown",
                "severity": lf.finding.severity.value if lf.finding and hasattr(lf.finding.severity, "value") else "MEDIUM",
                "confidence": lf.confidence,
                "rationale": lf.rationale,
            }
            if lf.correlation_type == CorrelationType.CONFIRMED_CAUSATION:
                causal_findings.append(item)
            elif lf.correlation_type == CorrelationType.PROBABLE_CORRELATION:
                probable_findings.append(item)
            elif lf.correlation_type == CorrelationType.TEMPORAL_COINCIDENCE:
                temporal_only_findings.append(item)
            elif lf.correlation_type == CorrelationType.CONTRADICTORY_EVIDENCE:
                contradictory_findings.append(item)

        contradictory_evidence_count = sum(1 for e in evidence_links if e.is_contradictory)

        return {
            "case_id": case.id,
            "case_number": case.case_number,
            "total_linked_findings": len(findings_links),
            "total_linked_assets": len(assets_links),
            "confirmed_causation": causal_findings,
            "probable_correlations": probable_findings,
            "temporal_coincidences": temporal_only_findings,
            "contradictory_findings": contradictory_findings,
            "contradictory_evidence_count": contradictory_evidence_count,
            "alternative_hypotheses_count": len(case.alternative_explanations or []),
            "correlation_summary": (
                f"{len(causal_findings)} confirmed causal links, {len(probable_findings)} probable correlations, "
                f"{len(temporal_only_findings)} temporal coincidences, and {len(contradictory_findings)} contradictory observations."
            ),
        }

    @classmethod
    def get_case_timeline(
        cls,
        db: Session,
        project_id: str,
        case_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Provides unified chronological investigation timeline with provenance (Prompt 39 Req 7).
        """
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id, IncidentCase.project_id == project_id)
            .first()
        )
        if not case:
            raise ValueError(f"IncidentCase '{case_id}' not found in project '{project_id}'.")

        events = []

        # 1. Transitions
        transitions = db.query(IncidentCaseTransition).filter(IncidentCaseTransition.case_id == case_id).all()
        for t in transitions:
            events.append({
                "event_type": "STATUS_TRANSITION",
                "timestamp": t.created_at,
                "actor_id": t.transitioned_by_id,
                "summary": f"Case transitioned from {t.from_status.value} to {t.to_status.value}",
                "details": {"reason": t.reason},
            })

        # 2. Findings Linked
        findings = db.query(IncidentCaseFinding).filter(IncidentCaseFinding.case_id == case_id).all()
        for f in findings:
            events.append({
                "event_type": "FINDING_LINKED",
                "timestamp": f.created_at,
                "summary": f"Linked finding '{f.finding.title if f.finding else f.finding_id}' ({f.correlation_type.value})",
                "details": {
                    "correlation_type": f.correlation_type.value,
                    "confidence": f.confidence,
                    "rationale": f.rationale,
                },
            })

        # 3. Assets Linked
        assets = db.query(IncidentCaseAsset).filter(IncidentCaseAsset.case_id == case_id).all()
        for a in assets:
            events.append({
                "event_type": "ASSET_LINKED",
                "timestamp": a.created_at,
                "summary": f"Linked asset '{a.asset.canonical_identifier if a.asset else a.asset_id}' ({a.relationship_type.value})",
                "details": {
                    "relationship_type": a.relationship_type.value,
                    "confidence": a.confidence,
                    "is_contradictory": a.is_contradictory,
                },
            })

        # 4. Evidence Snapshots
        evidence = db.query(IncidentCaseEvidence).filter(IncidentCaseEvidence.case_id == case_id).all()
        for e in evidence:
            events.append({
                "event_type": "EVIDENCE_ATTACHED",
                "timestamp": e.created_at,
                "summary": f"Evidence snapshot: {e.evidence_summary[:60]}",
                "details": {
                    "digest": e.evidence_digest,
                    "is_contradictory": e.is_contradictory,
                },
            })

        # 5. Notes
        notes = db.query(IncidentCaseNote).filter(IncidentCaseNote.case_id == case_id).all()
        for n in notes:
            events.append({
                "event_type": "ANALYST_NOTE",
                "timestamp": n.created_at,
                "actor_id": n.author_id,
                "summary": f"[{n.note_type}] {n.content[:60]}",
                "details": {
                    "note_type": n.note_type,
                    "is_alternative_hypothesis": n.is_alternative_hypothesis,
                },
            })

        # Sort timeline chronologically
        events.sort(key=lambda x: x["timestamp"] or utc_now())
        return events
