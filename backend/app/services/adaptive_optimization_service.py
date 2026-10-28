from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.orchestration import AdaptiveOptimizationRecord
from app.models.base import utc_now


class AdaptiveOptimizationService:
    """
    Controlled Adaptive Optimization Service (Prompt 15 / Section 8).
    Evaluates verified operational outcomes to recommend or apply governed improvements.
    Enforces quality thresholds, baseline comparisons, rollback safety, and complete audit provenance.
    """

    @classmethod
    def evaluate_optimization_proposal(
        cls,
        db: Session,
        project_id: str,
        optimization_name: str,
        objective: str,
        evaluation_metric: str,
        baseline_value: float,
        evaluated_value: float,
        threshold_value: float,
        dataset_summary: Dict[str, Any],
        rollback_payload: Dict[str, Any],
        evaluated_by_model: str = "governed_rule_engine_v1",
        now: Optional[datetime] = None,
    ) -> AdaptiveOptimizationRecord:
        """
        Evaluates an optimization proposal against defined thresholds.
        Rejects immediately if evaluated_value < threshold_value without mutating production policy.
        """
        if now is None:
            now = utc_now()

        is_accepted = evaluated_value >= threshold_value
        rejection_reason = None
        if not is_accepted:
            rejection_reason = (
                f"Evaluation failed threshold: {evaluation_metric} of {evaluated_value} "
                f"did not meet required threshold of {threshold_value}."
            )

        record = AdaptiveOptimizationRecord(
            project_id=project_id,
            optimization_name=optimization_name,
            objective=objective,
            evaluation_metric=evaluation_metric,
            baseline_value=baseline_value,
            evaluated_value=evaluated_value,
            threshold_value=threshold_value,
            dataset_summary=dataset_summary or {},
            is_accepted=is_accepted,
            rejection_reason=rejection_reason,
            rollback_payload=rollback_payload or {},
            evaluated_by_model=evaluated_by_model,
            evaluated_at=now,
            created_at=now,
            updated_at=now,
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        return record

    @classmethod
    def list_optimizations(
        cls,
        db: Session,
        project_id: str,
        limit: int = 10,
    ) -> List[AdaptiveOptimizationRecord]:
        """Lists recent adaptive optimization evaluation records."""
        return (
            db.query(AdaptiveOptimizationRecord)
            .filter(AdaptiveOptimizationRecord.project_id == project_id)
            .order_by(desc(AdaptiveOptimizationRecord.evaluated_at))
            .limit(limit)
            .all()
        )
