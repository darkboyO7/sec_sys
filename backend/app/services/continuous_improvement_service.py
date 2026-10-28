"""
Continuous Improvement Service for VAPT System.
Analyzes verified failure patterns across assessments, retests, and recoveries.
Generates advisory, non-intrusive reliability recommendations.
Strictly forbids automatic loosening of scope restrictions or security policies.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.base import utc_now
from app.models.diagnostics import FailurePatternRecord, RecoveryActionRecord, RecoveryOutcome
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.finding import VulnerabilityFinding
from app.models.verification import RemediationVerification, VerificationOutcome


class ContinuousImprovementService:
    """
    Continuous Improvement and Reliability Intelligence Engine.
    Aggregates empirical failure patterns and produces actionable advisory recommendations.
    """

    @classmethod
    def analyze_and_update_patterns(cls, db: Session, project_id: str) -> Dict[str, Any]:
        now = utc_now()
        patterns_updated = 0

        # 1. Analyze Repeated Scanner Failures by Adapter
        failed_jobs = (
            db.query(AssessmentJob.adapter_name, AssessmentJob.target_input, AssessmentJob.error_message)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.status == AssessmentStatus.FAILED,
            )
            .all()
        )

        adapter_failures: Dict[str, List[str]] = {}
        for adapter, target, err in failed_jobs:
            key = f"SCANNER_FAIL:{adapter or 'unknown'}"
            adapter_failures.setdefault(key, []).append(target or "unknown")

        for key, targets in adapter_failures.items():
            count = len(targets)
            unique_targets = list(set(targets))
            advisory = (
                f"Adapter '{key.split(':')[-1]}' encountered {count} failure(s) across {len(unique_targets)} target(s). "
                "Recommendation: Inspect target firewall/rate limits; verify worker socket network routes."
            )
            cls._upsert_pattern(
                db=db,
                project_id=project_id,
                pattern_key=key,
                category="SCANNER_ADAPTER",
                count=count,
                affected_targets=unique_targets,
                sample_error=f"{count} job failure(s) recorded.",
                advisory=advisory,
                now=now,
            )
            patterns_updated += 1

        # 2. Analyze Retests That Frequently Fail Independent Verification (STILL_VULNERABLE)
        failed_verifs = (
            db.query(VulnerabilityFinding.target_value)
            .join(RemediationVerification, VulnerabilityFinding.id == RemediationVerification.finding_id)
            .filter(
                RemediationVerification.project_id == project_id,
                RemediationVerification.outcome == VerificationOutcome.STILL_VULNERABLE,
            )
            .all()
        )
        if failed_verifs:
            targets = [v[0] for v in failed_verifs if v[0]]
            unique_targets = list(set(targets))
            cls._upsert_pattern(
                db=db,
                project_id=project_id,
                pattern_key="RETEST_PERSISTENT_FAILURE",
                category="REMEDIATION",
                count=len(failed_verifs),
                affected_targets=unique_targets,
                sample_error="Independent probe confirmed flaw remains vulnerable on target.",
                advisory=(
                    f"Observed {len(failed_verifs)} failed retests. Remediation changes deployed to targets "
                    "are not resolving the underlying vulnerability. Recommended: Conduct engineering code review."
                ),
                now=now,
            )
            patterns_updated += 1

        # 3. Analyze Inconclusive Retests
        inconclusive_verifs = (
            db.query(VulnerabilityFinding.target_value)
            .join(RemediationVerification, VulnerabilityFinding.id == RemediationVerification.finding_id)
            .filter(
                RemediationVerification.project_id == project_id,
                RemediationVerification.outcome == VerificationOutcome.INCONCLUSIVE,
            )
            .all()
        )
        if inconclusive_verifs:
            targets = [v[0] for v in inconclusive_verifs if v[0]]
            unique_targets = list(set(targets))
            cls._upsert_pattern(
                db=db,
                project_id=project_id,
                pattern_key="RETEST_INCONCLUSIVE_CLUSTER",
                category="VERIFICATION",
                count=len(inconclusive_verifs),
                affected_targets=unique_targets,
                sample_error="Verification probe was inconclusive or target timed out during retest.",
                advisory="Target unreachable during retest probe. Ensure staging/test target is running and in authorized scope.",
                now=now,
            )
            patterns_updated += 1

        # 4. Analyze Repeated Recovery Attempts
        recovery_counts = (
            db.query(RecoveryActionRecord.action_type, func.count(RecoveryActionRecord.id))
            .filter(RecoveryActionRecord.project_id == project_id)
            .group_by(RecoveryActionRecord.action_type)
            .all()
        )
        for action_type, count in recovery_counts:
            if count >= 2:
                key = f"RECOVERY_REPEATED:{action_type.value}"
                cls._upsert_pattern(
                    db=db,
                    project_id=project_id,
                    pattern_key=key,
                    category="SELF_HEALING",
                    count=count,
                    affected_targets=[],
                    sample_error=f"Recovery action '{action_type.value}' executed {count} times.",
                    advisory=f"Recurring need for recovery action '{action_type.value}'. Review underlying system stability.",
                    now=now,
                )
                patterns_updated += 1

        db.commit()

        # Query all active patterns for reporting
        patterns = (
            db.query(FailurePatternRecord)
            .filter(FailurePatternRecord.project_id == project_id)
            .order_by(FailurePatternRecord.occurrence_count.desc())
            .all()
        )

        return {
            "project_id": project_id,
            "patterns_updated": patterns_updated,
            "total_patterns": len(patterns),
            "patterns": [
                {
                    "id": p.id,
                    "pattern_key": p.pattern_key,
                    "category": p.category,
                    "occurrence_count": p.occurrence_count,
                    "first_observed_at": p.first_observed_at.isoformat(),
                    "last_observed_at": p.last_observed_at.isoformat(),
                    "affected_targets": p.affected_targets,
                    "sample_error_message": p.sample_error_message,
                    "advisory_recommendation": p.advisory_recommendation,
                }
                for p in patterns
            ],
        }

    @classmethod
    def _upsert_pattern(
        cls,
        db: Session,
        project_id: str,
        pattern_key: str,
        category: str,
        count: int,
        affected_targets: List[str],
        sample_error: str,
        advisory: str,
        now: datetime,
    ) -> None:
        rec = (
            db.query(FailurePatternRecord)
            .filter(
                FailurePatternRecord.project_id == project_id,
                FailurePatternRecord.pattern_key == pattern_key,
            )
            .first()
        )
        if rec:
            rec.occurrence_count = count
            rec.last_observed_at = now
            rec.affected_targets = affected_targets
            rec.sample_error_message = sample_error
            rec.advisory_recommendation = advisory
        else:
            rec = FailurePatternRecord(
                project_id=project_id,
                pattern_key=pattern_key,
                category=category,
                occurrence_count=count,
                first_observed_at=now,
                last_observed_at=now,
                affected_targets=affected_targets,
                sample_error_message=sample_error,
                advisory_recommendation=advisory,
            )
            db.add(rec)
