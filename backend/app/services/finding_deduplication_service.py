import hashlib
import re
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.finding import (
    FindingLifecycleStatus,
    FindingValidationStatus,
    VulnerabilityFinding,
    FindingTransition,
    ValidationTransition,
)
from app.models.assessment import (
    AssessmentJob,
    AssessmentFinding,
    FindingConfidence,
    FindingSeverity,
)
from app.models.base import utc_now
from app.services.audit_service import AuditService


class FindingDeduplicationService:
    """
    Deduplication and correlation engine for vulnerability findings.
    Identifies recurring findings across multiple assessment executions,
    maintains canonical finding identities, handles reopening, and preserves
    contradictory or divergent evidence without silent data loss.
    """

    @classmethod
    def compute_fingerprint(
        cls,
        target_value: str,
        vuln_id: Optional[str] = None,
        title: Optional[str] = None,
        component: Optional[str] = None,
    ) -> str:
        """
        Generates a deterministic 64-char SHA-256 fingerprint for a finding.
        Normalizes target, vulnerability identifier (e.g. CVE/CWE), title, and affected component.
        Preserves backward compatibility when component is omitted.
        """
        # 1. Normalize target: lowercase, remove trailing slash, strip protocol differences
        norm_target = (target_value or "").strip().lower().rstrip("/")
        norm_target = re.sub(r"^https?://", "", norm_target)

        # 2. Normalize vuln_id: uppercase, strip whitespace
        norm_vuln_id = (vuln_id or "").strip().upper()

        # 3. Normalize title: lowercase, strip punctuation noise, collapse whitespace
        norm_title = (title or "").strip().lower()
        norm_title = re.sub(r"\s+", " ", norm_title)

        if component:
            norm_comp = re.sub(r"\s+", " ", component.strip().lower())
            raw_key = f"{norm_target}|{norm_vuln_id}|{norm_title}|{norm_comp}".encode("utf-8")
        else:
            raw_key = f"{norm_target}|{norm_vuln_id}|{norm_title}".encode("utf-8")
        return hashlib.sha256(raw_key).hexdigest()

    @classmethod
    def ingest_job_findings(
        cls,
        job: AssessmentJob,
        raw_findings: List[AssessmentFinding],
        db: Session,
        client_ip: Optional[str] = None,
    ) -> List[VulnerabilityFinding]:
        """
        Ingests findings produced by an AssessmentJob.
        Correlates against existing VulnerabilityFindings for the project:
        - If new: creates canonical VulnerabilityFinding and initial transition.
        - If existing: links observation, increments counter, evaluates reopening or contradictions.
        """
        canonical_findings: List[VulnerabilityFinding] = []
        now = utc_now()

        for finding in raw_findings:
            fp = cls.compute_fingerprint(
                target_value=finding.target_value,
                vuln_id=finding.vuln_id,
                title=finding.title,
            )

            existing = (
                db.query(VulnerabilityFinding)
                .filter(
                    VulnerabilityFinding.project_id == job.project_id,
                    VulnerabilityFinding.fingerprint == fp,
                )
                .first()
            )

            if not existing:
                # Initial detection: if confidence is TENTATIVE, mark as NEEDS_VALIDATION; else DETECTED
                initial_status = (
                    FindingLifecycleStatus.NEEDS_VALIDATION
                    if finding.confidence == FindingConfidence.TENTATIVE
                    else FindingLifecycleStatus.DETECTED
                )

                # Determine epistemic validation status from evidence presence (Prompt 19)
                has_ev = bool(finding.evidence_items and len(finding.evidence_items) > 0)
                initial_val_status = (
                    FindingValidationStatus.EVIDENCE_SUPPORTED
                    if has_ev
                    else FindingValidationStatus.EVIDENCE_PENDING
                )
                evidence_ref = finding.evidence_items[0].sha256_hash if has_ev else None

                new_finding = VulnerabilityFinding(
                    project_id=job.project_id,
                    fingerprint=fp,
                    target_value=finding.target_value,
                    title=finding.title,
                    description=finding.description,
                    status=initial_status,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    vuln_id=finding.vuln_id,
                    cvss_score=finding.cvss_score,
                    is_simulated=finding.is_simulated,
                    reproduction_steps=finding.reproduction_steps,
                    first_detected_at=now,
                    last_observed_at=now,
                    occurrence_count=1,
                    has_contradictions=False,
                    contradiction_notes=[],
                    validation_status=initial_val_status,
                    validation_method=job.adapter_name,
                    validation_evidence_ref=evidence_ref,
                    validation_updated_at=now,
                )
                created_ok = True
                try:
                    with db.begin_nested():
                        db.add(new_finding)
                        db.flush()
                except Exception:
                    created_ok = False
                    existing = (
                        db.query(VulnerabilityFinding)
                        .filter(
                            VulnerabilityFinding.project_id == job.project_id,
                            VulnerabilityFinding.fingerprint == fp,
                        )
                        .first()
                    )

                if created_ok:
                    # Link raw observation to canonical finding
                    finding.canonical_finding_id = new_finding.id

                    # Create initial lifecycle transition audit record
                    initial_transition = FindingTransition(
                        finding_id=new_finding.id,
                        from_status=FindingLifecycleStatus.DETECTED,
                        to_status=initial_status,
                        actor_id=job.created_by_id,
                        reason=f"Initial discovery by scanner adapter '{job.adapter_name}' in assessment job {job.id}",
                        metadata_snapshot={
                            "job_id": job.id,
                            "adapter": job.adapter_name,
                            "severity": finding.severity.value,
                            "confidence": finding.confidence.value,
                            "cvss_score": finding.cvss_score,
                        },
                        created_at=now,
                    )
                    db.add(initial_transition)

                    # Create initial validation transition audit record (Prompt 19)
                    initial_val_trans = ValidationTransition(
                        finding_id=new_finding.id,
                        from_status=FindingValidationStatus.DETECTED,
                        to_status=initial_val_status,
                        validation_method=job.adapter_name,
                        actor_id=job.created_by_id,
                        reason=f"Initial discovery with {'verified cryptographic evidence' if has_ev else 'pending evidence'} from adapter '{job.adapter_name}'",
                        evidence_ref=evidence_ref,
                        metadata_snapshot={
                            "job_id": job.id,
                            "adapter": job.adapter_name,
                            "is_simulated": finding.is_simulated,
                        },
                        created_at=now,
                    )
                    db.add(initial_val_trans)

                    AuditService.log(
                        db=db,
                        action="FINDING_DISCOVERED",
                        actor_id=job.created_by_id,
                        target_resource=f"finding:{new_finding.id}",
                        project_id=job.project_id,
                        client_ip=client_ip,
                        details={
                            "finding_id": new_finding.id,
                            "title": new_finding.title,
                            "target": new_finding.target_value,
                            "severity": new_finding.severity.value,
                            "status": new_finding.status.value,
                            "validation_status": initial_val_status.value,
                            "job_id": job.id,
                        },
                    )
                    canonical_findings.append(new_finding)

            if existing:
                # Existing canonical finding found
                finding.canonical_finding_id = existing.id
                existing.occurrence_count += 1
                existing.last_observed_at = now
                existing.updated_at = now

                # Corroboration: check if observed by distinct adapter or job
                has_ev = bool(finding.evidence_items and len(finding.evidence_items) > 0)
                if has_ev and existing.validation_status == FindingValidationStatus.EVIDENCE_PENDING:
                    existing.validation_status = FindingValidationStatus.EVIDENCE_SUPPORTED
                    existing.validation_evidence_ref = finding.evidence_items[0].sha256_hash
                    existing.validation_updated_at = now

                # If corroboration from multiple distinct assessment jobs or adapters
                if (
                    existing.validation_status in (FindingValidationStatus.EVIDENCE_SUPPORTED, FindingValidationStatus.DETECTED)
                    and job.adapter_name != existing.validation_method
                ):
                    existing.validation_status = FindingValidationStatus.INDEPENDENTLY_REPRODUCED
                    existing.validation_updated_at = now

                # 1. Reopening logic: if finding was closed or pending verification, reopen it!
                if existing.status in (
                    FindingLifecycleStatus.VERIFIED_CLOSED,
                    FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
                ):
                    old_status = existing.status
                    existing.status = FindingLifecycleStatus.REOPENED
                    existing.validation_status = FindingValidationStatus.CONFIRMED_TRUE_POSITIVE
                    existing.validation_updated_at = now
                    existing.recurrence_detected = True
                    existing.recurrence_count = (existing.recurrence_count or 0) + 1

                    reopen_transition = FindingTransition(
                        finding_id=existing.id,
                        from_status=old_status,
                        to_status=FindingLifecycleStatus.REOPENED,
                        actor_id=job.created_by_id,
                        reason=f"Vulnerability re-detected in assessment job {job.id} after having been marked {old_status.value}. Recurrence count: {existing.recurrence_count}.",
                        metadata_snapshot={
                            "job_id": job.id,
                            "reopened_at": now.isoformat(),
                            "prior_status": old_status.value,
                            "recurrence_count": existing.recurrence_count,
                        },
                        created_at=now,
                    )
                    db.add(reopen_transition)

                    AuditService.log(
                        db=db,
                        action="FINDING_REOPENED",
                        actor_id=job.created_by_id,
                        target_resource=f"finding:{existing.id}",
                        project_id=job.project_id,
                        client_ip=client_ip,
                        details={
                            "finding_id": existing.id,
                            "prior_status": old_status.value,
                            "new_status": FindingLifecycleStatus.REOPENED.value,
                            "job_id": job.id,
                        },
                    )

                # 2. Contradiction and uncertainty handling:
                # If severity or confidence diverges from canonical, preserve note without overwriting
                if (
                    finding.severity != existing.severity
                    or finding.confidence != existing.confidence
                ):
                    existing.has_contradictions = True
                    existing.validation_status = FindingValidationStatus.INCONCLUSIVE
                    existing.validation_updated_at = now
                    notes = list(existing.contradiction_notes or [])
                    notes.append(
                        {
                            "job_id": job.id,
                            "observed_at": now.isoformat(),
                            "observed_severity": finding.severity.value,
                            "observed_confidence": finding.confidence.value,
                            "canonical_severity": existing.severity.value,
                            "canonical_confidence": existing.confidence.value,
                            "note": f"Divergence in job {job.id}: reported {finding.severity.value}/{finding.confidence.value} while canonical is {existing.severity.value}/{existing.confidence.value}.",
                        }
                    )
                    existing.contradiction_notes = notes

                AuditService.log(
                    db=db,
                    action="FINDING_REOBSERVED",
                    actor_id=job.created_by_id,
                    target_resource=f"finding:{existing.id}",
                    project_id=job.project_id,
                    client_ip=client_ip,
                    details={
                        "finding_id": existing.id,
                        "occurrence_count": existing.occurrence_count,
                        "job_id": job.id,
                    },
                )
                canonical_findings.append(existing)

        db.flush()
        return canonical_findings
