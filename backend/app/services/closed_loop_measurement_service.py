from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.orchestration import (
    OutcomeMeasurementStatus,
    OrchestrationWorkflowRecord,
)
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import FindingSeverity
from app.models.risk import RiskAssessment
from app.models.verification import RemediationVerification, VerificationOutcome
from app.models.base import utc_now


class ClosedLoopMeasurementService:
    """
    Closed-Loop Outcome Measurement Engine (Prompt 15 / Section 7).
    Measures whether orchestration actions actually improved security posture.
    Distinguishes:
    - Action executed successfully vs Finding independently verified as resolved.
    - Risk score decreased vs No measurable improvement vs Outcome inconclusive.
    """

    @classmethod
    def capture_project_posture_snapshot(
        cls,
        db: Session,
        project_id: str,
    ) -> Dict[str, Any]:
        """Captures a lightweight baseline or final security posture snapshot."""
        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()
        open_findings = [f for f in findings if f.status != FindingLifecycleStatus.VERIFIED_CLOSED]
        critical_count = len([f for f in open_findings if f.severity == FindingSeverity.CRITICAL])
        high_count = len([f for f in open_findings if f.severity == FindingSeverity.HIGH])
        closed_count = len([f for f in findings if f.status == FindingLifecycleStatus.VERIFIED_CLOSED])

        latest_risk = (
            db.query(RiskAssessment)
            .filter(RiskAssessment.project_id == project_id)
            .order_by(RiskAssessment.created_at.desc())
            .first()
        )
        risk_score = round(latest_risk.overall_score, 2) if latest_risk else 0.0

        return {
            "open_findings_count": len(open_findings),
            "critical_count": critical_count,
            "high_count": high_count,
            "verified_closed_count": closed_count,
            "risk_score": risk_score,
            "timestamp": utc_now().isoformat(),
        }

    @classmethod
    def evaluate_and_record_outcome(
        cls,
        db: Session,
        workflow: OrchestrationWorkflowRecord,
        initial_snapshot: Dict[str, Any],
        execution_result: Dict[str, Any],
        verification_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Calculates verified posture improvements and assigns an honest outcome status.
        """
        if now is None:
            now = utc_now()

        project_id = workflow.project_id
        final_snapshot = cls.capture_project_posture_snapshot(db=db, project_id=project_id)

        # Calculate deltas
        delta_risk = round(final_snapshot["risk_score"] - initial_snapshot.get("risk_score", 0.0), 2)
        delta_resolved = final_snapshot["verified_closed_count"] - initial_snapshot.get("verified_closed_count", 0)

        # Check verification record if provided
        verification = None
        if verification_id:
            verification = db.query(RemediationVerification).filter(RemediationVerification.id == verification_id).first()

        # Determine Outcome Status
        outcome_status = OutcomeMeasurementStatus.NO_MEASURABLE_IMPROVEMENT

        if execution_result.get("status") == "FAILED":
            outcome_status = OutcomeMeasurementStatus.FAILED
        elif verification:
            if verification.outcome == VerificationOutcome.VERIFIED_FIXED:
                outcome_status = OutcomeMeasurementStatus.FINDING_VERIFIED_RESOLVED
            elif verification.outcome == VerificationOutcome.INCONCLUSIVE:
                outcome_status = OutcomeMeasurementStatus.OUTCOME_INCONCLUSIVE
            elif verification.outcome == VerificationOutcome.STILL_VULNERABLE:
                outcome_status = OutcomeMeasurementStatus.NO_MEASURABLE_IMPROVEMENT
        elif delta_risk < 0:
            outcome_status = OutcomeMeasurementStatus.RISK_SCORE_DECREASED
        elif execution_result.get("status") in ("COMPLETED", "SUCCESS"):
            outcome_status = OutcomeMeasurementStatus.ACTION_EXECUTED_SUCCESSFULLY

        measurement_payload = {
            "initial_snapshot": initial_snapshot,
            "final_snapshot": final_snapshot,
            "posture_delta": {
                "delta_risk_score": delta_risk,
                "delta_resolved_findings": delta_resolved,
            },
            "execution_result": execution_result,
            "verification_outcome": verification.outcome.value if verification else None,
            "measured_at": now.isoformat(),
        }

        workflow.outcome_status = outcome_status
        workflow.outcome_measurement = measurement_payload
        db.commit()

        return {
            "outcome_status": outcome_status.value,
            "measurement": measurement_payload,
        }
