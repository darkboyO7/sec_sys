import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.risk import RemediationRecommendation
from app.models.verification import RemediationVerification, VerificationOutcome, VerificationMethod
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.base import utc_now
from app.services.finding_lifecycle_service import FindingLifecycleService
from app.services.audit_service import AuditService
from app.services.scanner_adapters.base import AdapterRegistry, BaseScannerAdapter


class RemediationVerificationService:
    """
    Independent Remediation Verification Engine (Phase 14).
    Validates whether remediated vulnerabilities are genuinely resolved on target.
    Enforces that:
    1. A successful change ticket or recommendation approval NEVER automatically marks a finding as VERIFIED_CLOSED.
    2. Only an authorized re-test or rigorous independent verification with objective criteria can confirm resolution.
    3. Failed or partial verifications transition the finding to REOPENED and track recurrence.
    4. Inconclusive verification attempts never close the finding.
    5. Baseline and verification evidence hashes are immutably preserved.
    """

    @classmethod
    def get_baseline_evidence_hash(cls, finding: VulnerabilityFinding) -> str:
        """Extracts cryptographic hash of original baseline evidence."""
        if finding.observations:
            for obs in finding.observations:
                if obs.evidence_items:
                    for ev in obs.evidence_items:
                        if ev.sha256_hash:
                            return ev.sha256_hash
        return finding.fingerprint

    @classmethod
    def record_verification(
        cls,
        project_id: str,
        finding_id: str,
        outcome: VerificationOutcome,
        verification_criteria: str,
        verification_evidence_summary: str,
        notes: str,
        verifier: User,
        verifier_role: Optional[ProjectRole],
        db: Session,
        verification_method: VerificationMethod = VerificationMethod.PASSIVE_SCAN,
        verification_evidence_data: Optional[Dict[str, Any]] = None,
        recommendation_id: Optional[str] = None,
        baseline_evidence_hash: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> RemediationVerification:
        """
        Records an independent verification outcome and updates finding lifecycle state accordingly.
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

        # RBAC: Verifications can be recorded by TESTER, LEAD, or ADMIN
        is_lead_or_admin = (verifier.system_role == SystemRole.ADMIN) or (verifier_role == ProjectRole.LEAD)
        is_tester = (verifier_role == ProjectRole.TESTER)
        if not (is_lead_or_admin or is_tester):
            raise PermissionError("Only Project TESTER, LEAD, or System ADMIN can record remediation verifications.")

        clean_criteria = (verification_criteria or "").strip()
        if len(clean_criteria) < 5:
            raise ValueError("Verification criteria must be specified (minimum 5 characters).")

        clean_summary = (verification_evidence_summary or "").strip()
        if len(clean_summary) < 5:
            raise ValueError("Verification evidence summary must be specified (minimum 5 characters).")

        clean_notes = (notes or "").strip()
        if len(clean_notes) < 3:
            raise ValueError("Verification notes are required (minimum 3 characters).")

        effective_baseline_hash = baseline_evidence_hash or cls.get_baseline_evidence_hash(finding)
        now = utc_now()

        # Create the independent verification record
        verification = RemediationVerification(
            project_id=project_id,
            finding_id=finding.id,
            recommendation_id=recommendation_id,
            verifier_id=verifier.id,
            verification_method=verification_method,
            outcome=outcome,
            verification_criteria=clean_criteria,
            baseline_evidence_hash=effective_baseline_hash,
            verification_evidence_summary=clean_summary,
            verification_evidence_data=verification_evidence_data or {},
            notes=clean_notes,
            verified_at=now,
        )
        db.add(verification)
        db.flush()

        # State transition governance
        if outcome == VerificationOutcome.VERIFIED_FIXED:
            # Requires LEAD or ADMIN to verify closure
            if not is_lead_or_admin:
                raise PermissionError("Only Project LEAD or System ADMIN can confirm VERIFIED_FIXED closure.")

            # Legally advance finding state to VERIFIED_CLOSED
            cls._transition_to_verified_closed(
                finding=finding,
                verifier=verifier,
                verifier_role=verifier_role,
                notes=clean_notes,
                db=db,
                client_ip=client_ip,
            )
            finding.verified_at = now
            finding.verified_by_id = verifier.id
            finding.verification_notes = f"[VERIFIED_FIXED] {clean_notes}"

        elif outcome == VerificationOutcome.STILL_VULNERABLE:
            # Vulnerability persisted or recurred
            finding.recurrence_detected = True
            finding.recurrence_count = (finding.recurrence_count or 0) + 1
            if finding.status in (
                FindingLifecycleStatus.VERIFIED_CLOSED,
                FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
                FindingLifecycleStatus.REMEDIATION_ATTEMPTED,
            ):
                cls._transition_to_reopened(
                    finding=finding,
                    verifier=verifier,
                    verifier_role=verifier_role,
                    reason=f"Verification failed: vulnerability remains observable on target. {clean_notes}",
                    db=db,
                    client_ip=client_ip,
                )
            else:
                finding.verification_notes = f"[STILL_VULNERABLE] {clean_notes}"

        elif outcome == VerificationOutcome.PARTIALLY_REMEDIATED:
            # Partial remediation detected - cannot close
            if finding.status in (
                FindingLifecycleStatus.VERIFIED_CLOSED,
                FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
            ):
                cls._transition_to_reopened(
                    finding=finding,
                    verifier=verifier,
                    verifier_role=verifier_role,
                    reason=f"Partial remediation insufficient: target remains vulnerable under certain conditions. {clean_notes}",
                    db=db,
                    client_ip=client_ip,
                )
            finding.verification_notes = f"[PARTIALLY_REMEDIATED] {clean_notes}"

        elif outcome == VerificationOutcome.INCONCLUSIVE:
            # Inconclusive evidence - DO NOT CLOSE
            finding.verification_notes = f"[INCONCLUSIVE] {clean_notes}"

        AuditService.log(
            db=db,
            action="REMEDIATION_VERIFICATION_RECORDED",
            actor_id=verifier.id,
            target_resource=f"verification:{verification.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "finding_id": finding.id,
                "outcome": outcome.value,
                "verification_method": verification_method.value,
                "finding_status": finding.status.value,
                "recurrence_detected": finding.recurrence_detected,
                "recurrence_count": finding.recurrence_count,
            },
        )
        db.commit()
        db.refresh(verification)
        return verification

    @classmethod
    def _transition_to_verified_closed(
        cls,
        finding: VulnerabilityFinding,
        verifier: User,
        verifier_role: Optional[ProjectRole],
        notes: str,
        db: Session,
        client_ip: Optional[str] = None,
    ) -> None:
        """Steps through legal lifecycle states to reach VERIFIED_CLOSED."""
        current = finding.status
        if current == FindingLifecycleStatus.VERIFIED_CLOSED:
            return

        # Advance along canonical lifecycle path:
        # DETECTED/NEEDS_VALIDATION -> CONFIRMED -> REMEDIATION_PROPOSED -> REMEDIATION_APPROVED -> REMEDIATION_ATTEMPTED -> REMEDIATED_PENDING_VERIFICATION -> VERIFIED_CLOSED
        steps = []
        if current in (FindingLifecycleStatus.DETECTED, FindingLifecycleStatus.NEEDS_VALIDATION, FindingLifecycleStatus.INCONCLUSIVE):
            steps.extend([
                (FindingLifecycleStatus.CONFIRMED, "Confirmed prior to verification"),
                (FindingLifecycleStatus.REMEDIATION_PROPOSED, "Remediation proposed"),
                (FindingLifecycleStatus.REMEDIATION_APPROVED, "Remediation approved"),
                (FindingLifecycleStatus.REMEDIATION_ATTEMPTED, "Remediation attempted on target"),
                (FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION, "Submitted for independent verification"),
                (FindingLifecycleStatus.VERIFIED_CLOSED, f"Independently verified and resolved: {notes}"),
            ])
        elif current == FindingLifecycleStatus.CONFIRMED:
            steps.extend([
                (FindingLifecycleStatus.REMEDIATION_PROPOSED, "Remediation proposed"),
                (FindingLifecycleStatus.REMEDIATION_APPROVED, "Remediation approved"),
                (FindingLifecycleStatus.REMEDIATION_ATTEMPTED, "Remediation attempted on target"),
                (FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION, "Submitted for independent verification"),
                (FindingLifecycleStatus.VERIFIED_CLOSED, f"Independently verified and resolved: {notes}"),
            ])
        elif current == FindingLifecycleStatus.REMEDIATION_PROPOSED:
            steps.extend([
                (FindingLifecycleStatus.REMEDIATION_APPROVED, "Remediation approved"),
                (FindingLifecycleStatus.REMEDIATION_ATTEMPTED, "Remediation attempted on target"),
                (FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION, "Submitted for independent verification"),
                (FindingLifecycleStatus.VERIFIED_CLOSED, f"Independently verified and resolved: {notes}"),
            ])
        elif current == FindingLifecycleStatus.REMEDIATION_APPROVED:
            steps.extend([
                (FindingLifecycleStatus.REMEDIATION_ATTEMPTED, "Remediation attempted on target"),
                (FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION, "Submitted for independent verification"),
                (FindingLifecycleStatus.VERIFIED_CLOSED, f"Independently verified and resolved: {notes}"),
            ])
        elif current == FindingLifecycleStatus.REMEDIATION_ATTEMPTED:
            steps.extend([
                (FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION, "Submitted for independent verification"),
                (FindingLifecycleStatus.VERIFIED_CLOSED, f"Independently verified and resolved: {notes}"),
            ])
        elif current in (FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,):
            steps.extend([
                (FindingLifecycleStatus.VERIFIED_CLOSED, f"Independently verified and resolved: {notes}"),
            ])
        elif current in (FindingLifecycleStatus.REOPENED,):
            steps.extend([
                (FindingLifecycleStatus.CONFIRMED, "Reopened finding confirmed fixed"),
                (FindingLifecycleStatus.REMEDIATION_PROPOSED, "Remediation proposed"),
                (FindingLifecycleStatus.REMEDIATION_APPROVED, "Remediation approved"),
                (FindingLifecycleStatus.REMEDIATION_ATTEMPTED, "Remediation attempted on target"),
                (FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION, "Submitted for independent verification"),
                (FindingLifecycleStatus.VERIFIED_CLOSED, f"Independently verified and resolved: {notes}"),
            ])

        for target_status, reason in steps:
            FindingLifecycleService.transition_finding(
                finding=finding,
                to_status=target_status,
                actor=verifier,
                actor_role=verifier_role,
                reason=reason,
                db=db,
                client_ip=client_ip,
                verification_notes=notes if target_status == FindingLifecycleStatus.VERIFIED_CLOSED else None,
            )

    @classmethod
    def _transition_to_reopened(
        cls,
        finding: VulnerabilityFinding,
        verifier: User,
        verifier_role: Optional[ProjectRole],
        reason: str,
        db: Session,
        client_ip: Optional[str] = None,
    ) -> None:
        """Transitions finding to REOPENED."""
        if finding.status == FindingLifecycleStatus.REOPENED:
            return
        FindingLifecycleService.transition_finding(
            finding=finding,
            to_status=FindingLifecycleStatus.REOPENED,
            actor=verifier,
            actor_role=verifier_role,
            reason=reason,
            db=db,
            client_ip=client_ip,
        )

    @classmethod
    def execute_automated_retest(
        cls,
        project_id: str,
        finding_id: str,
        adapter_name: str,
        config: Dict[str, Any],
        notes: str,
        verifier: User,
        verifier_role: Optional[ProjectRole],
        db: Session,
        client_ip: Optional[str] = None,
    ) -> RemediationVerification:
        """
        Executes a targeted, passive re-test using an approved scanner adapter
        to independently verify whether the finding is fixed.
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

        adapter = AdapterRegistry.get_active_adapter(adapter_name)
        if not adapter:
            raise ValueError(f"Adapter '{adapter_name}' is not registered or is disabled.")

        # Execute safe adapter against finding target
        adapter_result = adapter.execute(
            target=finding.target_value,
            config=config,
        )

        # Check if the vulnerability is still observed in adapter findings
        still_present = False
        matching_finding = None
        for raw_f in adapter_result.findings:
            if finding.vuln_id and raw_f.vuln_id and finding.vuln_id.lower() == raw_f.vuln_id.lower():
                still_present = True
                matching_finding = raw_f
                break
            if raw_f.title and (raw_f.title.lower() in finding.title.lower() or finding.title.lower() in raw_f.title.lower()):
                still_present = True
                matching_finding = raw_f
                break

        if still_present:
            outcome = VerificationOutcome.STILL_VULNERABLE
            summary = (
                f"Automated re-test via '{adapter_name}' confirmed vulnerability is still present on '{finding.target_value}'. "
                f"Observed: {matching_finding.title if matching_finding else 'matching flaw'}."
            )
        else:
            outcome = VerificationOutcome.VERIFIED_FIXED
            summary = (
                f"Automated re-test via '{adapter_name}' confirmed vulnerability is resolved on '{finding.target_value}'. "
                f"No matching vulnerability signature detected in {len(adapter_result.findings)} observations."
            )

        evidence_payloads = []
        for raw_f in adapter_result.findings:
            for ev in raw_f.evidence_items:
                evidence_payloads.append({"type": ev.evidence_type, "sha256": ev.sha256_hash})

        return cls.record_verification(
            project_id=project_id,
            finding_id=finding.id,
            outcome=outcome,
            verification_criteria=f"Automated check via adapter '{adapter_name}' against target '{finding.target_value}'.",
            verification_evidence_summary=summary,
            notes=notes,
            verifier=verifier,
            verifier_role=verifier_role,
            db=db,
            verification_method=VerificationMethod.PASSIVE_SCAN,
            verification_evidence_data={
                "adapter": adapter_name,
                "evidence_count": len(evidence_payloads),
                "evidence_items": evidence_payloads,
                "execution_metadata": {
                    "success": adapter_result.success,
                    "duration_ms": adapter_result.execution_duration_ms,
                    "status_summary": adapter_result.status_summary,
                },
            },
            client_ip=client_ip,
        )

    @classmethod
    def list_verifications(
        cls,
        project_id: str,
        finding_id: Optional[str],
        db: Session,
        limit: int = 50,
        offset: int = 0,
    ) -> List[RemediationVerification]:
        query = db.query(RemediationVerification).filter(RemediationVerification.project_id == project_id)
        if finding_id:
            query = query.filter(RemediationVerification.finding_id == finding_id)
        return query.order_by(RemediationVerification.verified_at.desc()).offset(offset).limit(limit).all()

    @classmethod
    def get_verification(
        cls,
        project_id: str,
        verification_id: str,
        db: Session,
    ) -> Optional[RemediationVerification]:
        return (
            db.query(RemediationVerification)
            .filter(
                RemediationVerification.id == verification_id,
                RemediationVerification.project_id == project_id,
            )
            .first()
        )
