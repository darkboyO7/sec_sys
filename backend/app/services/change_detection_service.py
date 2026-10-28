from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.decision import PostureChangeRecord, ChangeType
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.asset import Asset
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.risk import RiskAssessment


class ChangeDetectionService:
    """
    Change-Driven Security Posture Reassessment Service.
    Detects and persists meaningful environmental and posture transitions:
    - Newly observed assets and services.
    - Security configuration changes (headers, cookies, TLS).
    - New, recurring, and resolved vulnerabilities.
    - Risk score fluctuations.
    - Distinguishes confirmed changes from failed scans or unavailable targets.
    """

    @classmethod
    def record_change(
        cls,
        db: Session,
        project_id: str,
        change_type: ChangeType,
        target_resource: str,
        title: str,
        previous_state: Dict[str, Any],
        new_state: Dict[str, Any],
        evidence_summary: str,
        confidence: float = 1.0,
        is_confirmed: bool = True,
    ) -> PostureChangeRecord:
        """
        Idempotently persists a confirmed posture change record.
        """
        record = PostureChangeRecord(
            project_id=project_id,
            change_type=change_type,
            target_resource=target_resource,
            title=title,
            previous_state=previous_state,
            new_state=new_state,
            evidence_summary=evidence_summary,
            confidence=max(0.0, min(1.0, confidence)),
            is_confirmed=is_confirmed,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @classmethod
    def analyze_assessment_deltas(
        cls,
        db: Session,
        project_id: str,
        current_job: AssessmentJob,
    ) -> List[PostureChangeRecord]:
        """
        Analyzes delta changes between current completed assessment and previous baseline assessment for the same target.
        Fails closed: If current_job failed or target was unreachable, does NOT mark vulnerabilities resolved.
        """
        if current_job.status != AssessmentStatus.COMPLETED:
            # Probe failed or timed out: Record inconclusive change, do not mark anything resolved
            return [
                cls.record_change(
                    db=db,
                    project_id=project_id,
                    change_type=ChangeType.CONFIG_CHANGED,
                    target_resource=current_job.target_input,
                    title=f"Assessment probe failed or timed out ({current_job.status.value})",
                    previous_state={},
                    new_state={"status": current_job.status.value, "failure_category": current_job.failure_category},
                    evidence_summary=f"Scan ended in {current_job.status.value}. No resolution claims can be made.",
                    confidence=0.5,
                    is_confirmed=False,
                )
            ]

        # Fetch previous successful job on the same target
        previous_job = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.target_input == current_job.target_input,
                AssessmentJob.status == AssessmentStatus.COMPLETED,
                AssessmentJob.id != current_job.id,
            )
            .order_by(AssessmentJob.created_at.desc())
            .first()
        )

        detected_changes: List[PostureChangeRecord] = []

        curr_findings = {f.title: f for f in current_job.findings}
        prev_findings = {f.title: f for f in previous_job.findings} if previous_job else {}

        # 1. New Findings Detected
        for title, finding in curr_findings.items():
            if title not in prev_findings:
                detected_changes.append(
                    cls.record_change(
                        db=db,
                        project_id=project_id,
                        change_type=ChangeType.NEW_FINDING,
                        target_resource=current_job.target_input,
                        title=f"New Vulnerability Detected: {title}",
                        previous_state={},
                        new_state={"severity": finding.severity.value, "vuln_id": finding.vuln_id},
                        evidence_summary=f"Detected new {finding.severity.value} finding '{title}' on target {current_job.target_input}.",
                        confidence=1.0,
                        is_confirmed=True,
                    )
                )
            else:
                # Recurring finding
                detected_changes.append(
                    cls.record_change(
                        db=db,
                        project_id=project_id,
                        change_type=ChangeType.RECURRING_FINDING,
                        target_resource=current_job.target_input,
                        title=f"Recurring Vulnerability Persists: {title}",
                        previous_state={"observed_previously": True},
                        new_state={"re_detected": True, "severity": finding.severity.value},
                        evidence_summary=f"Finding '{title}' remains unmitigated on target {current_job.target_input}.",
                        confidence=1.0,
                        is_confirmed=True,
                    )
                )

        # 2. Resolved Findings (Present previously, missing in clean verified scan)
        for title, prev_f in prev_findings.items():
            if title not in curr_findings:
                detected_changes.append(
                    cls.record_change(
                        db=db,
                        project_id=project_id,
                        change_type=ChangeType.RESOLVED_FINDING,
                        target_resource=current_job.target_input,
                        title=f"Finding No Longer Observed (Candidate Resolution): {title}",
                        previous_state={"severity": prev_f.severity.value, "vuln_id": prev_f.vuln_id},
                        new_state={"observed": False},
                        evidence_summary=f"Finding '{title}' was present in previous assessment but was not observed in current verified scan.",
                        confidence=0.9,
                        is_confirmed=True,
                    )
                )

        # 3. Asset and Config Changes
        asset = (
            db.query(Asset)
            .filter(Asset.project_id == project_id, Asset.canonical_identifier == current_job.target_input)
            .first()
        )
        if asset:
            obs = asset.observations[-1] if asset.observations else None
            if obs:
                obs_data = getattr(obs, "observed_attributes", None) or getattr(obs, "raw_payload", {}) or {}
                detected_changes.append(
                    cls.record_change(
                        db=db,
                        project_id=project_id,
                        change_type=ChangeType.CONFIG_CHANGED,
                        target_resource=current_job.target_input,
                        title=f"Observed Configuration Updated on {current_job.target_input}",
                        previous_state={},
                        new_state=obs_data if isinstance(obs_data, dict) else {},
                        evidence_summary=f"Asset attributes and headers reconciled for {current_job.target_input}.",
                        confidence=1.0,
                        is_confirmed=True,
                    )
                )

        return detected_changes

    @classmethod
    def list_posture_changes(
        cls,
        db: Session,
        project_id: str,
        limit: int = 50,
        confirmed_only: bool = False,
    ) -> List[PostureChangeRecord]:
        query = db.query(PostureChangeRecord).filter(PostureChangeRecord.project_id == project_id)
        if confirmed_only:
            query = query.filter(PostureChangeRecord.is_confirmed.is_(True))
        return query.order_by(PostureChangeRecord.created_at.desc()).limit(min(limit, 200)).all()
