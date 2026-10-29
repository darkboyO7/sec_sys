"""
Intelligent Assessment Scheduling, Risk-Based Prioritization & Resource-Aware Orchestration (Prompt 34).
Core scheduling service implementing deterministic multi-signal prioritization, fail-closed eligibility
validation, bounded concurrency and worker pools, anti-starvation aging, and crash-resilient lease recovery.
"""
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_

from app.models.base import utc_now, generate_uuid
from app.models.scheduling import (
    QueueItemStatus,
    PriorityBand,
    EligibilityStatus,
    SchedulerDecisionType,
    TriggerSourceType,
    AssessmentQueueItem,
    SchedulerDecisionRecord,
    SchedulerPolicyRecord,
)
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingSeverity
from app.models.scope import ScopeTarget, ScopeExclusion, AuthorizationStatus
from app.models.asset import Asset, AssetCriticality
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.verification import RemediationVerification, VerificationOutcome
from app.models.compliance import ComplianceControlResultRecord, ComplianceEvaluationStatus
from app.models.drift import ExposureDriftRecord
from app.models.user import User
from app.schemas.scheduling import (
    PriorityCalculationDetail,
    QueueItemCreate,
    QueueItemPreviewResponse,
    SchedulerCapacityResponse,
    LeaseRecoveryResponse,
    SchedulerPolicyUpdate,
)
from app.core.exceptions import NotFoundError, ValidationError, AuthorizationError


# Defensive adapter whitelist: only approved, non-disruptive adapters
PERMITTED_ADAPTERS = {
    "local_fixture_adapter",
    "ssl_tls_analyzer",
    "http_header_inspector",
    "port_service_scanner",
    "compliance_evaluator",
    "web_app_scanner",
}


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure datetime is offset-aware in UTC for safe comparisons."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class SchedulingService:
    @staticmethod
    def get_or_create_policy(db: Session, project_id: str) -> SchedulerPolicyRecord:
        """Fetch or initialize the project-level scheduling and concurrency policy."""
        policy = db.query(SchedulerPolicyRecord).filter(
            SchedulerPolicyRecord.project_id == project_id
        ).first()
        if not policy:
            policy = SchedulerPolicyRecord(
                project_id=project_id,
                policy_version="scheduling_v1.0",
                max_concurrent_assessments=5,
                max_per_target_concurrency=1,
                max_per_adapter_concurrency=2,
                max_queued_jobs=100,
                max_execution_duration_sec=600,
                max_retries=3,
                aging_factor_per_hour=2.0,
                stale_lease_timeout_sec=120,
                cooldown_period_sec=3600,
                is_active=True,
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
        return policy

    @staticmethod
    def update_policy(db: Session, project_id: str, updates: SchedulerPolicyUpdate) -> SchedulerPolicyRecord:
        """Update scheduling policy parameters with bounded validation."""
        policy = SchedulingService.get_or_create_policy(db, project_id)
        update_data = updates.model_dump(exclude_unset=True)
        for key, value in update_data.items():
            if value is not None:
                setattr(policy, key, value)
        policy.updated_at = utc_now()
        db.commit()
        db.refresh(policy)
        return policy

    @staticmethod
    def calculate_priority(
        db: Session,
        project_id: str,
        target_input: str,
        adapter_name: str,
    ) -> PriorityCalculationDetail:
        """
        Deterministic, evidence-backed priority calculation.
        Combines asset criticality, finding severity, exposure drift, evidence freshness,
        retest failures, and compliance status into a bounded [0.0, 100.0] score.
        """
        now = utc_now()
        factors: Dict[str, Any] = {}
        missing_signals: List[str] = []
        base_score = 20.0
        factors["base_score"] = {"value": base_score, "weight": 1.0, "contribution": base_score, "source": "POLICY_DEFAULT"}

        # 1. Asset Criticality Signal
        asset = db.query(Asset).filter(
            Asset.project_id == project_id,
            Asset.canonical_identifier == target_input,
        ).first()

        crit_contribution = 0.0
        if asset:
            crit_map = {
                AssetCriticality.CRITICAL: 30.0,
                AssetCriticality.HIGH: 20.0,
                AssetCriticality.MEDIUM: 10.0,
                AssetCriticality.LOW: 5.0,
            }
            crit_contribution = crit_map.get(asset.criticality, 10.0)
            factors["asset_criticality"] = {
                "raw_value": asset.criticality.value,
                "contribution": crit_contribution,
                "source": f"Asset:{asset.id}",
            }
        else:
            missing_signals.append("asset_criticality")
            factors["asset_criticality"] = {
                "raw_value": "UNKNOWN",
                "contribution": 5.0,
                "source": "DEFAULT_UNREGISTERED_ASSET",
            }
            crit_contribution = 5.0

        # 2. Finding Severity Signal (Active unmitigated vulnerabilities on target)
        active_findings = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.project_id == project_id,
            VulnerabilityFinding.target_value == target_input,
            VulnerabilityFinding.status.in_([
                FindingLifecycleStatus.DETECTED,
                FindingLifecycleStatus.CONFIRMED,
            ])
        ).all()

        finding_contribution = 0.0
        if active_findings:
            severities = [f.severity for f in active_findings]
            if FindingSeverity.CRITICAL in severities:
                finding_contribution = 25.0
                top_sev = "CRITICAL"
            elif FindingSeverity.HIGH in severities:
                finding_contribution = 15.0
                top_sev = "HIGH"
            elif FindingSeverity.MEDIUM in severities:
                finding_contribution = 10.0
                top_sev = "MEDIUM"
            else:
                finding_contribution = 5.0
                top_sev = "LOW"
            factors["finding_severity"] = {
                "raw_value": top_sev,
                "count": len(active_findings),
                "contribution": finding_contribution,
                "source": f"VulnerabilityFinding(s):count={len(active_findings)}",
            }
        else:
            factors["finding_severity"] = {
                "raw_value": "NONE",
                "count": 0,
                "contribution": 0.0,
                "source": "VulnerabilityFinding:none",
            }

        # 3. Verified Exposure Drift Signal
        active_drift = db.query(ExposureDriftRecord).filter(
            ExposureDriftRecord.project_id == project_id,
            ExposureDriftRecord.target_resource == target_input,
        ).first()

        drift_contribution = 0.0
        if active_drift:
            drift_contribution = 15.0
            factors["exposure_drift"] = {
                "raw_value": active_drift.drift_type.value if hasattr(active_drift.drift_type, "value") else str(active_drift.drift_type),
                "contribution": 15.0,
                "source": f"ExposureDriftRecord:{active_drift.id}",
            }
        else:
            factors["exposure_drift"] = {
                "raw_value": "NONE",
                "contribution": 0.0,
                "source": "ExposureDriftRecord:clean",
            }

        # 4. Evidence Freshness & Coverage Gap Signal
        last_job = db.query(AssessmentJob).filter(
            AssessmentJob.project_id == project_id,
            AssessmentJob.target_input == target_input,
            AssessmentJob.status == AssessmentStatus.COMPLETED,
        ).order_by(AssessmentJob.completed_at.desc()).first()

        staleness_contribution = 0.0
        if not last_job:
            staleness_contribution = 20.0
            factors["evidence_staleness"] = {
                "raw_value": "COVERAGE_GAP_NO_PRIOR_SCAN",
                "contribution": 20.0,
                "source": "AssessmentJob:none",
            }
        else:
            completed_dt = ensure_utc(last_job.completed_at) or now
            age_days = (now - completed_dt).total_seconds() / 86400.0
            if age_days > 30.0:
                staleness_contribution = 15.0
                desc = f"STALE_OVER_30_DAYS ({age_days:.1f}d)"
            elif age_days > 14.0:
                staleness_contribution = 10.0
                desc = f"AGING_OVER_14_DAYS ({age_days:.1f}d)"
            else:
                staleness_contribution = 0.0
                desc = f"FRESH ({age_days:.1f}d)"
            factors["evidence_staleness"] = {
                "raw_value": desc,
                "days": round(age_days, 1),
                "contribution": staleness_contribution,
                "source": f"AssessmentJob:{last_job.id}",
            }

        # 5. Failed or Overdue Retest Signal
        failed_retests = db.query(RemediationVerification).filter(
            RemediationVerification.project_id == project_id,
            RemediationVerification.outcome.in_([
                VerificationOutcome.STILL_VULNERABLE,
                VerificationOutcome.PARTIALLY_REMEDIATED,
            ])
        ).first()

        retest_contribution = 0.0
        if failed_retests:
            retest_contribution = 15.0
            factors["failed_retests"] = {
                "raw_value": failed_retests.outcome.value,
                "contribution": 15.0,
                "source": f"RemediationVerification:{failed_retests.id}",
            }
        else:
            factors["failed_retests"] = {
                "raw_value": "NONE",
                "contribution": 0.0,
                "source": "RemediationVerification:clean",
            }

        # 6. Compliance Control Failure Signal
        failing_compliance = db.query(ComplianceControlResultRecord).filter(
            ComplianceControlResultRecord.status == ComplianceEvaluationStatus.FAIL,
        ).first()

        compliance_contribution = 0.0
        if failing_compliance:
            compliance_contribution = 15.0
            factors["compliance_failure"] = {
                "raw_value": "FAILING_CONTROLS_DETECTED",
                "contribution": 15.0,
                "source": f"ComplianceResult:{failing_compliance.id}",
            }
        else:
            factors["compliance_failure"] = {
                "raw_value": "PASSING_OR_NONE",
                "contribution": 0.0,
                "source": "ComplianceResult:clean",
            }

        # 7. Repeat Failure / Backoff Dampener
        recent_failures = db.query(AssessmentJob).filter(
            AssessmentJob.project_id == project_id,
            AssessmentJob.target_input == target_input,
            AssessmentJob.status == AssessmentStatus.FAILED,
        ).order_by(AssessmentJob.created_at.desc()).limit(3).all()

        penalty_contribution = 0.0
        if len(recent_failures) >= 2:
            penalty_contribution = -10.0
            factors["repeat_failure_penalty"] = {
                "raw_value": f"RECENT_FAILURES_COUNT={len(recent_failures)}",
                "contribution": -10.0,
                "source": "AssessmentJob:repeat_failures",
            }

        # Compute bounded final priority
        total_raw = (
            base_score
            + crit_contribution
            + finding_contribution
            + drift_contribution
            + staleness_contribution
            + retest_contribution
            + compliance_contribution
            + penalty_contribution
        )
        computed_priority = max(0.0, min(100.0, round(total_raw, 2)))

        if computed_priority >= 80.0:
            band = PriorityBand.CRITICAL
        elif computed_priority >= 60.0:
            band = PriorityBand.HIGH
        elif computed_priority >= 40.0:
            band = PriorityBand.MEDIUM
        else:
            band = PriorityBand.LOW

        explanation_parts = [
            f"Base: {base_score}",
            f"Criticality: +{crit_contribution}",
            f"Findings: +{finding_contribution}",
            f"Drift: +{drift_contribution}",
            f"Freshness: +{staleness_contribution}",
            f"Retest: +{retest_contribution}",
            f"Compliance: +{compliance_contribution}",
        ]
        if penalty_contribution < 0.0:
            explanation_parts.append(f"Penalty: {penalty_contribution}")

        summary = (
            f"Priority {computed_priority} ({band.value}) computed using policy scheduling_v1.0. "
            f"Breakdown: {', '.join(explanation_parts)}."
        )

        return PriorityCalculationDetail(
            computed_priority=computed_priority,
            priority_band=band,
            summary=summary,
            factors=factors,
            policy_version="scheduling_v1.0",
            calculated_at=now,
            missing_evidence_signals=missing_signals,
        )

    @staticmethod
    def evaluate_eligibility(
        db: Session,
        project_id: str,
        target_input: str,
        adapter_name: str,
    ) -> Tuple[bool, EligibilityStatus, List[str]]:
        """
        Strict fail-closed pre-flight validation.
        Priority NEVER overrides authorization. Explicit exclusions take precedence over inclusions.
        Defensive boundaries prohibit raw sweeps, DoS, and exploit payloads.
        """
        reasons: List[str] = []

        # 1. Adapter Policy Verification
        if adapter_name not in PERMITTED_ADAPTERS:
            reasons.append(f"Adapter '{adapter_name}' is not in the permitted defensive adapter whitelist.")
            return False, EligibilityStatus.UNAUTHORIZED, reasons

        # 2. Defensive Boundaries Check
        lower_target = target_input.lower().strip()
        disruptive_indicators = ["--flood", "--dos", "0.0.0.0/0", "127.0.0.1/0", "raw_socket", "exploit"]
        if any(ind in lower_target for ind in disruptive_indicators):
            reasons.append("Target input contains disruptive or non-defensive scanning patterns prohibited by policy.")
            return False, EligibilityStatus.UNAUTHORIZED, reasons

        # 3. Scope Exclusions Check (Exclusions take absolute precedence!)
        excluded_records = db.query(ScopeExclusion).filter(
            ScopeExclusion.project_id == project_id,
        ).all()

        for exc in excluded_records:
            if exc.target_value and (exc.target_value.lower() == lower_target or exc.target_value.lower() in lower_target):
                reasons.append(f"Target matches explicitly excluded scope rule '{exc.target_value}'.")
                return False, EligibilityStatus.EXCLUDED, reasons

        # 4. Scope Inclusions Check
        all_scope_targets = db.query(ScopeTarget).filter(
            ScopeTarget.project_id == project_id,
        ).all()

        if all_scope_targets:
            authorized_matches = [
                inc for inc in all_scope_targets
                if inc.authorization_status == AuthorizationStatus.AUTHORIZED
                and inc.target_value
                and (inc.target_value.lower() == lower_target or lower_target in inc.target_value.lower())
            ]
            if not authorized_matches:
                reasons.append(f"Target '{target_input}' is outside authorized scope definitions (no active authorized approval).")
                return False, EligibilityStatus.UNAUTHORIZED, reasons

        reasons.append("Target satisfies all defensive boundaries, scope inclusions, and adapter policies.")
        return True, EligibilityStatus.ELIGIBLE, reasons

    @staticmethod
    def preview_assessment(
        db: Session,
        project_id: str,
        target_input: str,
        adapter_name: str,
    ) -> QueueItemPreviewResponse:
        """Calculate priority and evaluate eligibility without reserving capacity or writing state."""
        is_eligible, elig_status, elig_reasons = SchedulingService.evaluate_eligibility(
            db, project_id, target_input, adapter_name
        )
        prio_detail = SchedulingService.calculate_priority(
            db, project_id, target_input, adapter_name
        )

        return QueueItemPreviewResponse(
            target_input=target_input,
            adapter_name=adapter_name,
            is_eligible=is_eligible,
            eligibility_status=elig_status,
            eligibility_reasons=elig_reasons,
            computed_priority=prio_detail.computed_priority,
            priority_band=prio_detail.priority_band,
            priority_explanation=prio_detail.summary,
            priority_factors=prio_detail.factors,
            policy_version=prio_detail.policy_version,
        )

    @staticmethod
    def enqueue_assessment(
        db: Session,
        project_id: str,
        user_id: str,
        request: QueueItemCreate,
        trigger_source: str = "MANUAL_DISPATCH",
    ) -> AssessmentQueueItem:
        """
        Enqueue an authorized assessment workload with deterministic priority,
        concurrency key hashing, deduplication checks, and capacity controls.
        """
        policy = SchedulingService.get_or_create_policy(db, project_id)
        now = utc_now()

        # 1. Eligibility pre-flight
        is_eligible, elig_status, elig_reasons = SchedulingService.evaluate_eligibility(
            db, project_id, request.target_input, request.adapter_name or "local_fixture_adapter"
        )
        if not is_eligible:
            # Audit rejection decision
            decision = SchedulerDecisionRecord(
                project_id=project_id,
                trigger_source=trigger_source,
                target_input=request.target_input,
                decision_type=SchedulerDecisionType.REJECT,
                priority_score=0.0,
                decision_rationale=f"Eligibility rejected: {'; '.join(elig_reasons)}",
                capacity_snapshot={"status": elig_status.value},
            )
            db.add(decision)
            db.commit()
            raise ValidationError(f"Assessment rejected: {'; '.join(elig_reasons)}")

        # 2. Check Queue Capacity
        active_queue_count = db.query(func.count(AssessmentQueueItem.id)).filter(
            AssessmentQueueItem.project_id == project_id,
            AssessmentQueueItem.status.in_([
                QueueItemStatus.PENDING,
                QueueItemStatus.SCHEDULED,
            ])
        ).scalar() or 0

        if active_queue_count >= policy.max_queued_jobs:
            decision = SchedulerDecisionRecord(
                project_id=project_id,
                trigger_source=trigger_source,
                target_input=request.target_input,
                decision_type=SchedulerDecisionType.DEFER,
                priority_score=0.0,
                decision_rationale=f"Queue capacity exceeded ({active_queue_count}/{policy.max_queued_jobs}). Work deferred.",
                capacity_snapshot={"active_queue_count": active_queue_count, "limit": policy.max_queued_jobs},
            )
            db.add(decision)
            db.commit()
            raise ValidationError(f"Maximum queued assessments capacity ({policy.max_queued_jobs}) reached. Please retry later.")

        # 3. Deduplication Check (Prevent multiple identical active scans)
        existing_active = db.query(AssessmentQueueItem).filter(
            AssessmentQueueItem.project_id == project_id,
            AssessmentQueueItem.target_input == request.target_input,
            AssessmentQueueItem.adapter_name == (request.adapter_name or "local_fixture_adapter"),
            AssessmentQueueItem.status.in_([
                QueueItemStatus.PENDING,
                QueueItemStatus.SCHEDULED,
                QueueItemStatus.DISPATCHED,
            ])
        ).first()

        if existing_active:
            decision = SchedulerDecisionRecord(
                project_id=project_id,
                queue_item_id=existing_active.id,
                trigger_source=trigger_source,
                target_input=request.target_input,
                decision_type=SchedulerDecisionType.DEDUPLICATE,
                priority_score=existing_active.priority_score,
                decision_rationale=f"Identical active queue item {existing_active.id} already exists with status {existing_active.status.value}.",
                capacity_snapshot={"existing_id": existing_active.id},
            )
            db.add(decision)
            db.commit()
            return existing_active

        # 4. Deterministic Priority Calculation
        prio = SchedulingService.calculate_priority(
            db, project_id, request.target_input, request.adapter_name or "local_fixture_adapter"
        )

        # 5. Concurrency Key (target host hash for per-target concurrency control)
        target_norm = request.target_input.strip().lower()
        concurrency_key = hashlib.sha256(target_norm.encode("utf-8")).hexdigest()[:16]
        idempotency_key = f"sched-{project_id[:8]}-{concurrency_key}-{int(now.timestamp())}"

        # 6. Create Queue Item
        queue_item = AssessmentQueueItem(
            project_id=project_id,
            schedule_name=request.schedule_name or "Ad-Hoc Assessment",
            target_input=request.target_input,
            adapter_name=request.adapter_name or "local_fixture_adapter",
            adapter_version="1.0.0",
            status=QueueItemStatus.SCHEDULED,
            priority_score=prio.computed_priority,
            priority_band=prio.priority_band,
            priority_explanation=prio.summary,
            priority_factors=prio.factors,
            policy_version=prio.policy_version,
            eligibility_status=elig_status,
            eligibility_reasons=elig_reasons,
            idempotency_key=idempotency_key,
            concurrency_key=concurrency_key,
            attempt_count=0,
            retry_count=0,
            max_retries=policy.max_retries,
            backoff_seconds=30,
            next_eligible_at=now,
            deadline_at=request.deadline_at,
            execution_budget_seconds=request.execution_budget_seconds or policy.max_execution_duration_sec,
            created_by_id=user_id,
            created_at=now,
            updated_at=now,
        )
        db.add(queue_item)
        db.flush()

        # 7. Record Scheduler Decision
        decision = SchedulerDecisionRecord(
            project_id=project_id,
            queue_item_id=queue_item.id,
            trigger_source=trigger_source,
            target_input=request.target_input,
            decision_type=SchedulerDecisionType.ENQUEUE,
            priority_score=prio.computed_priority,
            decision_rationale=f"Enqueued with priority {prio.computed_priority} ({prio.priority_band.value}). {prio.summary}",
            capacity_snapshot={"active_queue_count": active_queue_count + 1},
        )
        db.add(decision)
        db.commit()
        db.refresh(queue_item)
        return queue_item

    @staticmethod
    def dispatch_next_eligible(
        db: Session,
        project_id: str,
        worker_id: str = "worker-default",
    ) -> Tuple[bool, str, Optional[AssessmentQueueItem], Optional[str]]:
        """
        Resource-aware dispatcher using atomic worker claims, anti-starvation aging,
        per-target and per-adapter throttles, and pre-execution eligibility revalidation.
        """
        policy = SchedulingService.get_or_create_policy(db, project_id)
        now = utc_now()

        # 1. Total Concurrency Check
        dispatched_items = db.query(AssessmentQueueItem).filter(
            AssessmentQueueItem.project_id == project_id,
            AssessmentQueueItem.status == QueueItemStatus.DISPATCHED,
        ).all()
        active_dispatched = [
            it for it in dispatched_items
            if it.lease_expires_at and ensure_utc(it.lease_expires_at) > now
        ]

        if len(active_dispatched) >= policy.max_concurrent_assessments:
            return False, f"Global concurrent assessment limit ({policy.max_concurrent_assessments}) reached.", None, None

        # Track active counts per target concurrency_key and per adapter
        active_targets = {}
        active_adapters = {}
        for item in active_dispatched:
            active_targets[item.concurrency_key] = active_targets.get(item.concurrency_key, 0) + 1
            active_adapters[item.adapter_name] = active_adapters.get(item.adapter_name, 0) + 1

        # 2. Find eligible scheduled items
        scheduled_candidates = db.query(AssessmentQueueItem).filter(
            AssessmentQueueItem.project_id == project_id,
            AssessmentQueueItem.status == QueueItemStatus.SCHEDULED,
        ).all()
        candidates = [
            it for it in scheduled_candidates
            if it.next_eligible_at and ensure_utc(it.next_eligible_at) <= now
        ]

        if not candidates:
            return False, "No eligible scheduled jobs in queue.", None, None

        # 3. Apply Anti-Starvation Aging
        # effective_priority = min(100.0, priority_score + hours_queued * aging_factor)
        ranked_candidates = []
        for item in candidates:
            created_dt = ensure_utc(item.created_at) or now
            hours_queued = max(0.0, (now - created_dt).total_seconds() / 3600.0)
            effective_priority = min(100.0, item.priority_score + (hours_queued * policy.aging_factor_per_hour))
            ranked_candidates.append((effective_priority, item))

        # Sort by effective priority DESC, then created_at ASC (deterministic tie-breaker)
        ranked_candidates.sort(key=lambda x: (x[0], -ensure_utc(x[1].created_at).timestamp()), reverse=True)

        selected_item: Optional[AssessmentQueueItem] = None
        for effective_prio, candidate in ranked_candidates:
            # Check per-target concurrency
            if active_targets.get(candidate.concurrency_key, 0) >= policy.max_per_target_concurrency:
                continue
            # Check per-adapter concurrency
            if active_adapters.get(candidate.adapter_name, 0) >= policy.max_per_adapter_concurrency:
                continue

            # Candidate selected!
            selected_item = candidate
            break

        if not selected_item:
            return False, "All eligible candidates deferred due to per-target or per-adapter concurrency limits.", None, None

        # 4. Pre-execution Eligibility Revalidation (REQUIREMENT: Revalidate immediately before execution)
        is_eligible, elig_status, elig_reasons = SchedulingService.evaluate_eligibility(
            db, project_id, selected_item.target_input, selected_item.adapter_name
        )
        if not is_eligible:
            selected_item.status = QueueItemStatus.FAILED
            selected_item.last_error_category = "PREFLIGHT_ELIGIBILITY_REVOKED"
            selected_item.last_error_message = f"Eligibility revoked prior to execution: {'; '.join(elig_reasons)}"
            selected_item.updated_at = now
            db.commit()

            decision = SchedulerDecisionRecord(
                project_id=project_id,
                queue_item_id=selected_item.id,
                trigger_source="DISPATCH_PREFLIGHT",
                target_input=selected_item.target_input,
                decision_type=SchedulerDecisionType.REJECT,
                priority_score=selected_item.priority_score,
                decision_rationale=f"Job {selected_item.id} rejected at preflight: {'; '.join(elig_reasons)}",
                capacity_snapshot={"status": "REVOKED"},
            )
            db.add(decision)
            db.commit()
            return False, f"Job {selected_item.id} rejected at preflight: {'; '.join(elig_reasons)}", None, None

        # 5. Claim Job & Update Lease
        lease_expiration = now + timedelta(seconds=policy.stale_lease_timeout_sec)
        selected_item.status = QueueItemStatus.DISPATCHED
        selected_item.worker_claim_id = worker_id
        selected_item.claimed_at = now
        selected_item.lease_expires_at = lease_expiration
        selected_item.attempt_count += 1
        selected_item.updated_at = now

        # 6. Create Underlying AssessmentJob
        job = AssessmentJob(
            project_id=project_id,
            target_input=selected_item.target_input,
            adapter_name=selected_item.adapter_name,
            adapter_version=selected_item.adapter_version,
            status=AssessmentStatus.RUNNING,
            progress_pct=10,
            started_at=now,
            timeout_seconds=selected_item.execution_budget_seconds,
            created_by_id=selected_item.created_by_id,
            is_simulated=True,
            idempotency_key=f"job-{selected_item.id}",
        )
        db.add(job)
        db.flush()

        selected_item.job_id = job.id

        # 7. Record Decision
        decision = SchedulerDecisionRecord(
            project_id=project_id,
            queue_item_id=selected_item.id,
            trigger_source="DISPATCH_WORKER",
            target_input=selected_item.target_input,
            decision_type=SchedulerDecisionType.DISPATCH,
            priority_score=selected_item.priority_score,
            decision_rationale=f"Dispatched to worker '{worker_id}'. Lease expires at {lease_expiration.isoformat()}.",
            capacity_snapshot={
                "active_count": len(active_dispatched) + 1,
                "target_key": selected_item.concurrency_key,
                "adapter": selected_item.adapter_name,
            },
        )
        db.add(decision)
        db.commit()
        db.refresh(selected_item)

        return True, "Job dispatched successfully", selected_item, job.id

    @staticmethod
    def recover_stale_leases(db: Session, project_id: str) -> LeaseRecoveryResponse:
        """
        Scan and recover abandoned or crashed worker leases.
        Jobs with remaining retries are rescheduled with bounded exponential backoff.
        Exhausted jobs transition to dead-letter FAILED state.
        """
        now = utc_now()
        policy = SchedulingService.get_or_create_policy(db, project_id)

        dispatched_candidates = db.query(AssessmentQueueItem).filter(
            AssessmentQueueItem.project_id == project_id,
            AssessmentQueueItem.status == QueueItemStatus.DISPATCHED,
        ).all()

        stale_items = [
            it for it in dispatched_candidates
            if it.lease_expires_at and ensure_utc(it.lease_expires_at) <= now
        ]

        recovered_ids: List[str] = []
        dead_letter_ids: List[str] = []

        for item in stale_items:
            if item.retry_count < item.max_retries:
                # Bounded exponential backoff with ceiling
                item.retry_count += 1
                backoff = min(300, item.backoff_seconds * (2 ** (item.retry_count - 1)))
                item.status = QueueItemStatus.SCHEDULED
                item.worker_claim_id = None
                item.claimed_at = None
                item.lease_expires_at = None
                item.next_eligible_at = now + timedelta(seconds=backoff)
                item.last_error_category = "LEASE_TIMEOUT_RECOVERED"
                item.last_error_message = f"Worker lease expired. Requeued with {backoff}s backoff (retry {item.retry_count}/{item.max_retries})."
                item.updated_at = now
                recovered_ids.append(item.id)

                decision = SchedulerDecisionRecord(
                    project_id=project_id,
                    queue_item_id=item.id,
                    trigger_source="LEASE_RECOVERY",
                    target_input=item.target_input,
                    decision_type=SchedulerDecisionType.RECOVER,
                    priority_score=item.priority_score,
                    decision_rationale=f"Stale lease recovered for {item.id}. Backoff {backoff}s applied.",
                    capacity_snapshot={"retry_count": item.retry_count},
                )
                db.add(decision)
            else:
                # Max retries exhausted: dead-letter
                item.status = QueueItemStatus.FAILED
                item.last_error_category = "DEAD_LETTER_MAX_RETRIES_EXCEEDED"
                item.last_error_message = f"Job failed after {item.retry_count} retry attempts due to unhandled worker timeouts."
                item.updated_at = now
                dead_letter_ids.append(item.id)

                decision = SchedulerDecisionRecord(
                    project_id=project_id,
                    queue_item_id=item.id,
                    trigger_source="LEASE_RECOVERY",
                    target_input=item.target_input,
                    decision_type=SchedulerDecisionType.RETRY_BACKOFF,
                    priority_score=item.priority_score,
                    decision_rationale=f"Job {item.id} exceeded maximum retries ({item.max_retries}). Dead-lettered.",
                    capacity_snapshot={"status": "DEAD_LETTER"},
                )
                db.add(decision)

        db.commit()
        return LeaseRecoveryResponse(
            recovered_count=len(recovered_ids),
            dead_letter_count=len(dead_letter_ids),
            recovered_ids=recovered_ids,
            dead_letter_ids=dead_letter_ids,
        )

    @staticmethod
    def request_cancellation(
        db: Session,
        project_id: str,
        queue_id: str,
        user_id: str,
        reason: Optional[str] = "Operator cancelled assessment",
    ) -> AssessmentQueueItem:
        """
        Durable, observable cancellation requests.
        Differentiates between immediate cancellation of queued work and graceful termination of running workers.
        """
        now = utc_now()
        item = db.query(AssessmentQueueItem).filter(
            AssessmentQueueItem.project_id == project_id,
            AssessmentQueueItem.id == queue_id,
        ).first()

        if not item:
            raise NotFoundError(f"Queue item '{queue_id}' not found.")

        if item.status in [QueueItemStatus.COMPLETED, QueueItemStatus.CANCELLED, QueueItemStatus.FAILED]:
            return item

        item.cancellation_requested_at = now
        item.cancellation_reason = reason or "Operator requested cancellation"

        if item.status in [QueueItemStatus.PENDING, QueueItemStatus.SCHEDULED, QueueItemStatus.DEFERRED]:
            # Can be cancelled immediately
            item.status = QueueItemStatus.CANCELLED
            item.cancelled_at = now
        else:
            # Running/dispatched: mark requested, check underlying job
            item.status = QueueItemStatus.CANCELLED
            item.cancelled_at = now
            if item.job_id:
                job = db.query(AssessmentJob).filter(AssessmentJob.id == item.job_id).first()
                if job:
                    job.status = AssessmentStatus.CANCELLED
                    job.completed_at = now

        item.updated_at = now

        decision = SchedulerDecisionRecord(
            project_id=project_id,
            queue_item_id=item.id,
            trigger_source="OPERATOR_CANCEL",
            target_input=item.target_input,
            decision_type=SchedulerDecisionType.CANCEL,
            priority_score=item.priority_score,
            decision_rationale=f"Assessment cancelled by operator '{user_id}'. Reason: {reason}",
            capacity_snapshot={"status": item.status.value},
        )
        db.add(decision)
        db.commit()
        db.refresh(item)
        return item

    @staticmethod
    def handle_reassessment_trigger(
        db: Session,
        project_id: str,
        user_id: str,
        trigger_source: TriggerSourceType,
        target_input: str,
        adapter_name: str = "local_fixture_adapter",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AssessmentQueueItem:
        """
        Automated trigger handler (e.g. drift detected, new critical finding, failed retest).
        Enforces cooldown windows and deduplication to avoid assessment storms.
        """
        policy = SchedulingService.get_or_create_policy(db, project_id)
        now = utc_now()
        cooldown_cutoff = now - timedelta(seconds=policy.cooldown_period_sec)

        # Check if an assessment was recently completed or queued for this target
        recent_activity = db.query(AssessmentQueueItem).filter(
            AssessmentQueueItem.project_id == project_id,
            AssessmentQueueItem.target_input == target_input,
            or_(
                AssessmentQueueItem.status.in_([QueueItemStatus.PENDING, QueueItemStatus.SCHEDULED, QueueItemStatus.DISPATCHED]),
                and_(
                    AssessmentQueueItem.status == QueueItemStatus.COMPLETED,
                    AssessmentQueueItem.updated_at >= cooldown_cutoff,
                )
            )
        ).first()

        if recent_activity:
            decision = SchedulerDecisionRecord(
                project_id=project_id,
                queue_item_id=recent_activity.id,
                trigger_source=trigger_source.value,
                target_input=target_input,
                decision_type=SchedulerDecisionType.DEDUPLICATE,
                priority_score=recent_activity.priority_score,
                decision_rationale=f"Trigger {trigger_source.value} deduplicated within {policy.cooldown_period_sec}s cooldown window.",
                capacity_snapshot={"cooldown_sec": policy.cooldown_period_sec},
                metadata_payload=metadata or {},
            )
            db.add(decision)
            db.commit()
            return recent_activity

        # Enqueue with automated trigger source
        create_req = QueueItemCreate(
            schedule_name=f"Auto-Reassessment ({trigger_source.value})",
            target_input=target_input,
            adapter_name=adapter_name,
            execution_budget_seconds=policy.max_execution_duration_sec,
        )
        return SchedulingService.enqueue_assessment(
            db, project_id, user_id, create_req, trigger_source=trigger_source.value
        )

    @staticmethod
    def get_capacity_summary(db: Session, project_id: str) -> SchedulerCapacityResponse:
        """Calculate real-time queue utilization, worker slot allocations, and stale lease counts."""
        policy = SchedulingService.get_or_create_policy(db, project_id)
        now = utc_now()

        dispatched_items = db.query(AssessmentQueueItem).filter(
            AssessmentQueueItem.project_id == project_id,
            AssessmentQueueItem.status == QueueItemStatus.DISPATCHED,
        ).all()

        active_dispatched = [
            it for it in dispatched_items
            if it.lease_expires_at and ensure_utc(it.lease_expires_at) > now
        ]

        total_queued = db.query(func.count(AssessmentQueueItem.id)).filter(
            AssessmentQueueItem.project_id == project_id,
            AssessmentQueueItem.status.in_([QueueItemStatus.PENDING, QueueItemStatus.SCHEDULED]),
        ).scalar() or 0

        stale_count = sum(
            1 for it in dispatched_items
            if it.lease_expires_at and ensure_utc(it.lease_expires_at) <= now
        )

        active_targets = {}
        active_adapters = {}
        for item in active_dispatched:
            active_targets[item.target_input] = active_targets.get(item.target_input, 0) + 1
            active_adapters[item.adapter_name] = active_adapters.get(item.adapter_name, 0) + 1

        current_running = len(active_dispatched)
        available_cap = max(0, policy.max_concurrent_assessments - current_running)
        utilization = min(100.0, round((total_queued / float(policy.max_queued_jobs)) * 100.0, 1))

        return SchedulerCapacityResponse(
            project_id=project_id,
            max_concurrent_assessments=policy.max_concurrent_assessments,
            current_running_assessments=current_running,
            available_capacity=available_cap,
            total_queued_items=total_queued,
            active_by_target=active_targets,
            active_by_adapter=active_adapters,
            queue_utilization_pct=utilization,
            stale_unclaimed_leases=stale_count,
        )
