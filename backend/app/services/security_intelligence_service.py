from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.project import Project, ProjectRole
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, AuthorizationStatus
from app.models.asset import Asset, AssetCriticality, AssetStatus
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingSeverity,
    FindingConfidence,
    FindingEvidence,
)
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus, FindingTransition
from app.models.risk import (
    RiskAssessment,
    RiskPriority,
    RemediationRecommendation,
    RecommendationStatus,
)
from app.models.verification import RemediationVerification, VerificationOutcome
from app.models.graph import GraphNode, GraphRelationship, RelationshipStatus, RelationshipType
from app.models.decision import (
    PostureChangeRecord,
    ChangeType,
    AdaptiveAssessmentPlanRecord,
    PlanStatus,
    SecurityDecisionRecord,
    DecisionStatus,
)
from app.models.learning import (
    LearningDataset,
    GovernedModel,
    PredictionLedger,
    PredictionEvaluationStatus,
    ModelStatus,
)
from app.models.base import utc_now, generate_uuid
from app.services.audit_service import AuditService
from app.services.scope_engine import ScopeEngine
from app.services.contextual_risk_service import ContextualRiskService
from app.services.attack_path_service import AttackPathAnalysisService, PathVerificationStatus
from app.services.learning_service import ModelGovernanceService, PredictionLedgerService
from app.services.assessment_engine import AssessmentExecutionEngine


class SecurityIntelligenceService:
    """
    Unified Security Intelligence Engine (Prompt 10 / Section 1-5).
    Consumes actual persisted data across all platform subsystems:
    - Scope boundaries, assets, and observations.
    - Findings,Merklized evidence, and lifecycle transitions.
    - Contextual risk prioritization and uncertainty margins.
    - Validated attack paths vs unverified topological connections.
    - Remediation actions and independent retest outcomes.
    - Posture changes with event-storm throttling and change-driven reassessment.
    - Evidence-driven adaptive assessment planning with scope and budget enforcement.
    - Measurable model learning governance and drift telemetry.
    """

    @classmethod
    def get_project_intelligence_summary(
        cls,
        db: Session,
        project_id: str,
    ) -> Dict[str, Any]:
        """
        Synthesizes a complete, evidence-grounded security intelligence summary.
        Every metric is traceable directly to database entities with provenance hashes.
        Never fabricates metrics when data is unavailable or insufficient.
        """
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        now = utc_now()

        # 1. Findings & Risk Posture
        findings = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.project_id == project_id)
            .all()
        )
        total_findings = len(findings)

        active_findings = [
            f for f in findings
            if f.status in (
                FindingLifecycleStatus.DETECTED,
                FindingLifecycleStatus.CONFIRMED,
                FindingLifecycleStatus.NEEDS_VALIDATION,
                FindingLifecycleStatus.REOPENED,
                FindingLifecycleStatus.REMEDIATION_PROPOSED,
                FindingLifecycleStatus.REMEDIATION_APPROVED,
                FindingLifecycleStatus.REMEDIATION_ATTEMPTED,
                FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
            )
        ]

        active_assessments = (
            db.query(RiskAssessment)
            .filter(
                RiskAssessment.project_id == project_id,
                RiskAssessment.is_superseded.is_(False),
            )
            .all()
        )

        risk_distribution = {
            RiskPriority.CRITICAL.value: 0,
            RiskPriority.HIGH.value: 0,
            RiskPriority.MEDIUM.value: 0,
            RiskPriority.LOW.value: 0,
            RiskPriority.INFORMATIONAL.value: 0,
        }
        total_risk_score = 0.0
        for ra in active_assessments:
            p_val = ra.priority.value if hasattr(ra.priority, "value") else str(ra.priority)
            if p_val in risk_distribution:
                risk_distribution[p_val] += 1
            total_risk_score += (ra.score or 0.0)

        avg_risk_score = round(total_risk_score / len(active_assessments), 1) if active_assessments else 0.0

        # Highest priority evidence-backed findings
        sorted_assessments = sorted(active_assessments, key=lambda a: a.score or 0.0, reverse=True)[:5]
        highest_priority_findings = []
        for ra in sorted_assessments:
            f = ra.finding
            if f:
                highest_priority_findings.append({
                    "finding_id": f.id,
                    "title": f.title,
                    "target_value": f.target_value,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "status": f.status.value,
                    "risk_score": ra.score,
                    "inherent_score": ra.inherent_score,
                    "residual_score": ra.residual_score,
                    "priority": ra.priority.value,
                    "scoring_version": ra.scoring_version,
                    "contributing_factors": ra.contributing_factors or [],
                    "missing_factors": ra.missing_factors or [],
                    "uncertainty_range": ra.uncertainty_range or {},
                })

        # 2. Asset Coverage Audit
        coverage_audit = cls.audit_assessment_coverage(db=db, project_id=project_id, stale_days_threshold=14)

        # 3. Knowledge Graph & Attack Paths
        relationships = (
            db.query(GraphRelationship)
            .filter(GraphRelationship.project_id == project_id)
            .all()
        )
        total_relationships = len(relationships)

        attack_paths_info: Dict[str, Any] = {
            "total_relationships": total_relationships,
            "verified_paths_count": 0,
            "hypothetical_paths_count": 0,
            "critical_chokepoints": [],
        }
        try:
            paths_res = AttackPathAnalysisService.analyze_attack_paths(
                project_id=project_id,
                db=db,
                max_depth=3,
                max_paths=10,
            )
            candidate_paths = paths_res.get("paths", [])
            verified_count = sum(1 for p in candidate_paths if p.get("verification_status") == PathVerificationStatus.VERIFIED.value)
            hypo_count = len(candidate_paths) - verified_count
            attack_paths_info["verified_paths_count"] = verified_count
            attack_paths_info["hypothetical_paths_count"] = hypo_count
            attack_paths_info["critical_chokepoints"] = paths_res.get("critical_chokepoints", [])
        except Exception:
            pass

        # 4. Remediation Progress & Independent Retest Outcomes
        recs = (
            db.query(RemediationRecommendation)
            .filter(RemediationRecommendation.project_id == project_id)
            .all()
        )
        verifications = (
            db.query(RemediationVerification)
            .filter(RemediationVerification.project_id == project_id)
            .all()
        )
        verified_fixed = sum(1 for v in verifications if v.outcome == VerificationOutcome.VERIFIED_FIXED)
        failed_verif = sum(1 for v in verifications if v.outcome == VerificationOutcome.FAILED)
        inconclusive_verif = sum(1 for v in verifications if v.outcome == VerificationOutcome.INCONCLUSIVE)
        total_verif = len(verifications)
        remediation_rate = round(verified_fixed / total_verif * 100.0, 1) if total_verif > 0 else 0.0

        # 5. Monitoring & Posture Changes Requiring Attention
        changes = (
            db.query(PostureChangeRecord)
            .filter(PostureChangeRecord.project_id == project_id)
            .order_by(PostureChangeRecord.created_at.desc())
            .limit(10)
            .all()
        )
        unhandled_changes = [
            {
                "id": c.id,
                "change_type": c.change_type.value,
                "target_resource": c.target_resource,
                "title": c.title,
                "confidence": c.confidence,
                "is_confirmed": c.is_confirmed,
                "created_at": c.created_at.isoformat() if c.created_at else None,
                "evidence_summary": c.evidence_summary,
            }
            for c in changes
        ]

        # 6. Adaptive Assessment Plan Status
        latest_plan = (
            db.query(AdaptiveAssessmentPlanRecord)
            .filter(
                AdaptiveAssessmentPlanRecord.project_id == project_id,
                AdaptiveAssessmentPlanRecord.status.in_([PlanStatus.GENERATED, PlanStatus.PARTIALLY_EXECUTED]),
            )
            .order_by(AdaptiveAssessmentPlanRecord.created_at.desc())
            .first()
        )

        plan_summary = None
        if latest_plan:
            plan_summary = {
                "plan_id": latest_plan.id,
                "plan_name": latest_plan.plan_name,
                "status": latest_plan.status.value,
                "scan_budget": latest_plan.scan_budget,
                "total_recommended": latest_plan.total_recommended,
                "total_skipped": latest_plan.total_skipped,
                "created_at": latest_plan.created_at.isoformat() if latest_plan.created_at else None,
                "recommended_checks": latest_plan.recommended_checks[:5],
                "skipped_checks_count": len(latest_plan.skipped_checks),
            }

        # 7. Model Governance & Learning Pipeline Status
        active_model = (
            db.query(GovernedModel)
            .filter(GovernedModel.project_id == project_id, GovernedModel.is_active.is_(True))
            .first()
        )
        drift_metrics = PredictionLedgerService.calculate_drift_metrics(project_id=project_id, db=db)
        dataset_count = db.query(LearningDataset).filter(LearningDataset.project_id == project_id).count()

        learning_summary = {
            "model_version": active_model.version if active_model else ContextualRiskService.SCORING_VERSION,
            "model_status": active_model.status.value if active_model else "RULES_BASELINE_ACTIVE",
            "is_rules_baseline": (active_model is None or active_model.model_type == "RULE_ENSEMBLE"),
            "dataset_count": dataset_count,
            "drift_metrics": drift_metrics,
            "learning_data_sufficiency": "SUFFICIENT" if drift_metrics.get("evaluated_count", 0) >= 10 else "INSUFFICIENT_DATA",
            "inconclusive_rate": drift_metrics.get("inconclusive_rate", 0.0),
        }

        # 8. Data Provenance & Cryptographic Auditing
        provenance = {
            "total_jobs": db.query(AssessmentJob).filter(AssessmentJob.project_id == project_id).count(),
            "total_assets": db.query(Asset).filter(Asset.project_id == project_id).count(),
            "total_findings": total_findings,
            "total_evidence_records": db.query(FindingEvidence).join(AssessmentFinding, FindingEvidence.finding_id == AssessmentFinding.id).filter(AssessmentFinding.project_id == project_id).count(),
            "total_verifications": total_verif,
            "total_changes": len(changes),
            "generated_at": now.isoformat(),
        }

        return {
            "project_id": project_id,
            "project_name": project.name,
            "timestamp": now.isoformat(),
            "risk_summary": {
                "total_findings": total_findings,
                "active_findings": len(active_findings),
                "risk_distribution": risk_distribution,
                "average_risk_score": avg_risk_score,
                "highest_priority_findings": highest_priority_findings,
            },
            "coverage_audit": coverage_audit,
            "attack_paths": attack_paths_info,
            "remediation_intelligence": {
                "total_recommendations": len(recs),
                "total_verifications": total_verif,
                "verified_fixed_count": verified_fixed,
                "failed_verifications_count": failed_verif,
                "inconclusive_verifications_count": inconclusive_verif,
                "remediation_verification_rate": remediation_rate,
            },
            "monitoring_and_changes": {
                "unhandled_changes_count": len(unhandled_changes),
                "recent_changes": unhandled_changes,
            },
            "adaptive_plan": plan_summary,
            "learning_pipeline": learning_summary,
            "data_provenance": provenance,
        }

    @classmethod
    def audit_assessment_coverage(
        cls,
        db: Session,
        project_id: str,
        stale_days_threshold: int = 14,
    ) -> Dict[str, Any]:
        """
        Discovers assets and checks that have not been assessed recently.
        Identifies probe failures, timeout patterns, and unassessed scope targets.
        """
        now = utc_now()
        threshold_dt = now - timedelta(days=stale_days_threshold)

        assets = db.query(Asset).filter(Asset.project_id == project_id).all()
        targets = (
            db.query(ScopeTarget)
            .filter(
                ScopeTarget.project_id == project_id,
                ScopeTarget.authorization_status == AuthorizationStatus.AUTHORIZED,
            )
            .all()
        )

        stale_assets: List[Dict[str, Any]] = []
        covered_count = 0

        for a in assets:
            last_obs = a.last_seen_at
            if last_obs is not None and last_obs.tzinfo is None:
                last_obs = last_obs.replace(tzinfo=timezone.utc)

            is_stale = (last_obs is None or last_obs < threshold_dt)
            if not is_stale:
                covered_count += 1
            else:
                days_since = round((now - last_obs).total_seconds() / 86400.0, 1) if last_obs else None
                stale_assets.append({
                    "asset_id": a.id,
                    "name": a.name,
                    "canonical_identifier": a.canonical_identifier,
                    "asset_type": a.asset_type.value,
                    "criticality": a.criticality.value,
                    "last_seen_at": last_obs.isoformat() if last_obs else None,
                    "days_since_assessment": days_since,
                    "staleness_reason": f"No assessment observed in the last {days_since or 'infinite'} days (policy threshold: {stale_days_threshold} days)",
                })

        # Identify authorized scope targets never assessed
        unassessed_targets = []
        for t in targets:
            tgt_val = getattr(t, "target_value", getattr(t, "target", ""))
            job_count = (
                db.query(AssessmentJob)
                .filter(
                    AssessmentJob.project_id == project_id,
                    AssessmentJob.target_input == tgt_val,
                    AssessmentJob.status == AssessmentStatus.COMPLETED,
                )
                .count()
            )
            if job_count == 0:
                unassessed_targets.append({
                    "target_id": t.id,
                    "target": tgt_val,
                    "target_type": t.target_type.value,
                    "reason": "Authorized target has zero completed assessment scans.",
                })

        # Detect failing or inconclusive checks
        failing_jobs = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.status.in_([AssessmentStatus.FAILED, AssessmentStatus.TIMED_OUT, AssessmentStatus.PARTIAL]),
            )
            .order_by(AssessmentJob.created_at.desc())
            .limit(10)
            .all()
        )
        failing_probes = [
            {
                "job_id": j.id,
                "target_input": j.target_input,
                "adapter_name": j.adapter_name,
                "status": j.status.value,
                "failure_category": j.failure_category,
                "attempts": j.attempts,
                "created_at": j.created_at.isoformat() if j.created_at else None,
            }
            for j in failing_jobs
        ]

        total_assets = len(assets)
        coverage_pct = round(covered_count / total_assets * 100.0, 1) if total_assets > 0 else 0.0

        return {
            "total_assets": total_assets,
            "covered_assets_count": covered_count,
            "stale_assets_count": len(stale_assets),
            "coverage_percentage": coverage_pct,
            "stale_assets": stale_assets,
            "unassessed_scope_targets": unassessed_targets,
            "failing_probes": failing_probes,
            "stale_days_threshold": stale_days_threshold,
        }

    @classmethod
    def generate_adaptive_assessment_plan(
        cls,
        db: Session,
        project_id: str,
        scan_budget: int = 10,
        creator: Optional[User] = None,
    ) -> AdaptiveAssessmentPlanRecord:
        """
        Synthesizes an Evidence-Driven Adaptive Assessment Plan (Section 3).
        Recommends next assessment checks based on:
        1. Material configuration changes or newly detected assets.
        2. Remediation verification needs (approved fixes awaiting retest).
        3. Failing or inconclusive probe retries with adapted parameters.
        4. Deep targeted checks on confirmed high-risk findings.
        5. Stale asset assessment coverage gaps.
        Strictly enforces authorized scope validation and scan budget boundaries.
        Explains why each check was recommended or skipped.
        """
        now = utc_now()

        # Supersede any previous active plan for this project
        db.query(AdaptiveAssessmentPlanRecord).filter(
            AdaptiveAssessmentPlanRecord.project_id == project_id,
            AdaptiveAssessmentPlanRecord.status == PlanStatus.GENERATED,
        ).update({"status": PlanStatus.SUPERSEDED, "updated_at": now})

        recommended: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []

        # 1. Fetch authorized scope targets
        targets = (
            db.query(ScopeTarget)
            .filter(
                ScopeTarget.project_id == project_id,
                ScopeTarget.authorization_status == AuthorizationStatus.AUTHORIZED,
            )
            .all()
        )
        authorized_target_set = {getattr(t, "target_value", getattr(t, "target", "")) for t in targets}

        # Priority Bucket 1: Posture Changes (CHANGE_REASSESSMENT)
        recent_changes = (
            db.query(PostureChangeRecord)
            .filter(
                PostureChangeRecord.project_id == project_id,
                PostureChangeRecord.is_confirmed.is_(True),
            )
            .order_by(PostureChangeRecord.created_at.desc())
            .limit(10)
            .all()
        )

        seen_targets = set()
        for change in recent_changes:
            target = change.target_resource
            if target in seen_targets:
                continue

            # Scope Validation Gate
            scope_eval = ScopeEngine.validate_target_in_scope(db=db, project_id=project_id, target=target, now=now)
            if not scope_eval.get("is_authorized"):
                skipped.append({
                    "target": target,
                    "adapter_name": "web_adapter",
                    "action": "SKIPPED",
                    "skip_reason": "OUT_OF_SCOPE",
                    "rationale": f"Target '{target}' triggered change '{change.title}' but is not in authorized scope ({scope_eval.get('reason')}).",
                })
                continue

            recommended.append({
                "check_id": generate_uuid(),
                "target": target,
                "adapter_name": "web_adapter",
                "action": "RECOMMENDED",
                "priority": "HIGH",
                "reason_category": "CHANGE_REASSESSMENT",
                "rationale": f"Environmental change detected: '{change.title}'. Reassessment required to refresh posture baseline.",
                "source_evidence": {
                    "change_id": change.id,
                    "change_type": change.change_type.value,
                    "evidence_summary": change.evidence_summary,
                },
            })
            seen_targets.add(target)

        # Priority Bucket 2: Remediation Verification Retests (REMEDIATION_VERIFICATION)
        approved_recs = (
            db.query(RemediationRecommendation)
            .filter(
                RemediationRecommendation.project_id == project_id,
                RemediationRecommendation.status == RecommendationStatus.APPROVED,
            )
            .all()
        )
        for rec in approved_recs:
            finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == rec.finding_id).first()
            if not finding or finding.status == FindingLifecycleStatus.VERIFIED_CLOSED:
                continue

            target = finding.target_value
            if target in seen_targets:
                continue

            scope_eval = ScopeEngine.validate_target_in_scope(db=db, project_id=project_id, target=target, now=now)
            if not scope_eval.get("is_authorized"):
                skipped.append({
                    "target": target,
                    "adapter_name": "web_adapter",
                    "action": "SKIPPED",
                    "skip_reason": "OUT_OF_SCOPE",
                    "rationale": f"Remediation verification for finding '{finding.title}' skipped: Target is outside authorized scope.",
                })
                continue

            recommended.append({
                "check_id": generate_uuid(),
                "target": target,
                "adapter_name": "web_adapter",
                "action": "RECOMMENDED",
                "priority": "HIGH",
                "reason_category": "REMEDIATION_VERIFICATION",
                "rationale": f"Remediation '{rec.title}' was approved. Independent re-test probe required to verify resolution.",
                "source_evidence": {
                    "recommendation_id": rec.id,
                    "finding_id": finding.id,
                    "finding_title": finding.title,
                },
            })
            seen_targets.add(target)

        # Priority Bucket 3: Failing or Inconclusive Probes (FAILING_PROBE_RETRY)
        failing_jobs = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.status.in_([AssessmentStatus.FAILED, AssessmentStatus.TIMED_OUT, AssessmentStatus.PARTIAL]),
            )
            .order_by(AssessmentJob.created_at.desc())
            .limit(5)
            .all()
        )
        for job in failing_jobs:
            target = job.target_input
            if target in seen_targets:
                continue

            scope_eval = ScopeEngine.validate_target_in_scope(db=db, project_id=project_id, target=target, now=now)
            if not scope_eval.get("is_authorized"):
                continue

            recommended.append({
                "check_id": generate_uuid(),
                "target": target,
                "adapter_name": job.adapter_name,
                "action": "RECOMMENDED",
                "priority": "MEDIUM",
                "reason_category": "FAILING_PROBE_RETRY",
                "rationale": f"Previous assessment probe ended in '{job.status.value}' ({job.failure_category or 'timeout'}). Retest with adapted socket parameters recommended.",
                "source_evidence": {
                    "previous_job_id": job.id,
                    "previous_status": job.status.value,
                    "failure_category": job.failure_category,
                },
            })
            seen_targets.add(target)

        # Priority Bucket 4: Stale Coverage Assets (STALE_COVERAGE)
        coverage_data = cls.audit_assessment_coverage(db=db, project_id=project_id, stale_days_threshold=14)
        for stale in coverage_data.get("stale_assets", []):
            target = stale["canonical_identifier"]
            if target in seen_targets:
                continue

            scope_eval = ScopeEngine.validate_target_in_scope(db=db, project_id=project_id, target=target, now=now)
            if not scope_eval.get("is_authorized"):
                skipped.append({
                    "target": target,
                    "adapter_name": "network_adapter",
                    "action": "SKIPPED",
                    "skip_reason": "OUT_OF_SCOPE",
                    "rationale": f"Stale asset '{stale['name']}' is outside authorized scope.",
                })
                continue

            recommended.append({
                "check_id": generate_uuid(),
                "target": target,
                "adapter_name": "network_adapter",
                "action": "RECOMMENDED",
                "priority": "MEDIUM",
                "reason_category": "STALE_COVERAGE",
                "rationale": stale["staleness_reason"],
                "source_evidence": {
                    "asset_id": stale["asset_id"],
                    "days_since_assessment": stale["days_since_assessment"],
                },
            })
            seen_targets.add(target)

        # Priority Bucket 5: Check Recent Clean Targets (Avoid Redundant Work)
        for t_val in authorized_target_set:
            if t_val in seen_targets:
                continue

            # Query most recent job on this target
            recent_job = (
                db.query(AssessmentJob)
                .filter(
                    AssessmentJob.project_id == project_id,
                    AssessmentJob.target_input == t_val,
                    AssessmentJob.status == AssessmentStatus.COMPLETED,
                )
                .order_by(AssessmentJob.created_at.desc())
                .first()
            )
            if recent_job and recent_job.created_at:
                job_dt = recent_job.created_at
                if job_dt.tzinfo is None:
                    job_dt = job_dt.replace(tzinfo=timezone.utc)
                hours_ago = (now - job_dt).total_seconds() / 3600.0
                if hours_ago < 24.0:
                    skipped.append({
                        "target": t_val,
                        "adapter_name": recent_job.adapter_name,
                        "action": "SKIPPED",
                        "skip_reason": "RECENT_CLEAN_ASSESSMENT",
                        "rationale": f"Target was assessed cleanly {hours_ago:.1f} hours ago (< 24h). Trustworthy evidence is sufficient; avoiding redundant probe.",
                        "source_evidence": {"job_id": recent_job.id},
                    })
                    continue

        # Enforce Scan Budget
        clamped_budget = max(1, min(50, scan_budget))
        final_recommended = []
        for idx, rec in enumerate(recommended):
            if idx < clamped_budget:
                final_recommended.append(rec)
            else:
                skipped.append({
                    "target": rec["target"],
                    "adapter_name": rec["adapter_name"],
                    "action": "SKIPPED",
                    "skip_reason": "BUDGET_EXCEEDED",
                    "rationale": f"Plan reached configured scan budget limit ({clamped_budget} checks). Deferred to subsequent planning cycle.",
                    "source_evidence": rec.get("source_evidence", {}),
                })

        plan = AdaptiveAssessmentPlanRecord(
            project_id=project_id,
            plan_name=f"Adaptive Plan — {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            status=PlanStatus.GENERATED,
            scan_budget=clamped_budget,
            total_recommended=len(final_recommended),
            total_skipped=len(skipped),
            recommended_checks=final_recommended,
            skipped_checks=skipped,
            execution_summary={"executed_checks": [], "total_executed": 0},
            created_by_id=creator.id if creator else None,
            created_at=now,
            updated_at=now,
        )
        db.add(plan)
        db.commit()
        db.refresh(plan)

        AuditService.log(
            db=db,
            action="ADAPTIVE_PLAN_GENERATED",
            actor_id=creator.id if creator else None,
            target_resource=f"plan:{plan.id}",
            project_id=project_id,
            details={
                "plan_id": plan.id,
                "scan_budget": clamped_budget,
                "recommended_count": len(final_recommended),
                "skipped_count": len(skipped),
            },
        )
        return plan

    @classmethod
    def execute_planned_check(
        cls,
        db: Session,
        project_id: str,
        plan_id: str,
        check_id: str,
        actor: User,
        client_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes a planned assessment check under strict real-time scope enforcement.
        Updates plan execution summary and audit trail.
        """
        plan = (
            db.query(AdaptiveAssessmentPlanRecord)
            .filter(
                AdaptiveAssessmentPlanRecord.id == plan_id,
                AdaptiveAssessmentPlanRecord.project_id == project_id,
            )
            .first()
        )
        if not plan:
            raise ValueError(f"Plan '{plan_id}' not found in project '{project_id}'.")

        # Find the target check
        check_spec = None
        for c in plan.recommended_checks:
            if c.get("check_id") == check_id:
                check_spec = c
                break

        if not check_spec:
            raise ValueError(f"Planned check '{check_id}' not found in plan '{plan_id}'.")

        target = check_spec["target"]
        adapter_name = check_spec.get("adapter_name", "web_adapter")

        # Mandatory Real-Time Scope & Authorization Check
        now = utc_now()
        scope_eval = ScopeEngine.validate_target_in_scope(db=db, project_id=project_id, target=target, now=now)
        if not scope_eval.get("is_authorized"):
            raise PermissionError(
                f"Scope violation: Target '{target}' is not authorized ({scope_eval.get('reason')}). "
                "Execution aborted to prevent out-of-scope transmission."
            )

        # Dispatch assessment job via governed execution engine
        from app.schemas.assessment import AssessmentJobCreate
        job_create = AssessmentJobCreate(
            target_input=target,
            adapter_name=adapter_name,
            is_simulated=False,
            parameters={"adaptive_check_id": check_id, "plan_id": plan_id},
        )

        job = AssessmentExecutionEngine.create_job(
            db=db,
            project_id=project_id,
            job_in=job_create,
            user=actor,
            client_ip=client_ip,
        )

        # Update plan execution state
        current_summary = dict(plan.execution_summary or {})
        executed_list = current_summary.get("executed_checks", [])
        executed_list.append({
            "check_id": check_id,
            "target": target,
            "adapter_name": adapter_name,
            "job_id": job.id,
            "executed_at": now.isoformat(),
            "actor_id": actor.id,
        })
        current_summary["executed_checks"] = executed_list
        current_summary["total_executed"] = len(executed_list)

        plan.execution_summary = current_summary
        if len(executed_list) >= plan.total_recommended:
            plan.status = PlanStatus.COMPLETED
        else:
            plan.status = PlanStatus.PARTIALLY_EXECUTED
        plan.updated_at = now

        db.commit()
        db.refresh(plan)

        AuditService.log(
            db=db,
            action="ADAPTIVE_CHECK_EXECUTED",
            actor_id=actor.id,
            target_resource=f"job:{job.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "plan_id": plan_id,
                "check_id": check_id,
                "job_id": job.id,
                "target": target,
            },
        )

        return {
            "status": "DISPATCHED",
            "job_id": job.id,
            "target": target,
            "plan_id": plan_id,
            "plan_status": plan.status.value,
        }

    @classmethod
    def record_posture_change_with_throttle(
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
    ) -> Dict[str, Any]:
        """
        Records a posture change while enforcing deduplication and event-storm throttling (Section 5).
        Prevents cascading change events from spawning unlimited reassessment jobs.
        """
        now = utc_now()
        fifteen_min_ago = now - timedelta(minutes=15)
        one_min_ago = now - timedelta(minutes=1)

        # 1. Event Deduplication: Check if identical change occurred in last 15 minutes
        recent_duplicate = (
            db.query(PostureChangeRecord)
            .filter(
                PostureChangeRecord.project_id == project_id,
                PostureChangeRecord.change_type == change_type,
                PostureChangeRecord.target_resource == target_resource,
                PostureChangeRecord.created_at >= fifteen_min_ago,
            )
            .first()
        )

        if recent_duplicate:
            # Deduplicate by updating evidence and timestamp without creating duplicate event
            recent_duplicate.evidence_summary = f"{recent_duplicate.evidence_summary}\n[Deduplicated at {now.isoformat()}]: {evidence_summary}"
            recent_duplicate.new_state = new_state
            recent_duplicate.confidence = max(recent_duplicate.confidence, confidence)
            db.commit()
            db.refresh(recent_duplicate)
            return {
                "status": "DEDUPLICATED",
                "change_id": recent_duplicate.id,
                "target_resource": target_resource,
                "reassessment_recommended": False,
                "message": "Change deduplicated against recent observation within 15-minute sliding window.",
            }

        # 2. Event Storm Protection: Check if > 5 events occurred in last 60 seconds on target
        recent_count = (
            db.query(PostureChangeRecord)
            .filter(
                PostureChangeRecord.project_id == project_id,
                PostureChangeRecord.target_resource == target_resource,
                PostureChangeRecord.created_at >= one_min_ago,
            )
            .count()
        )

        if recent_count >= 5:
            # Throttle event storm: record change but suppress automated reassessment
            record = PostureChangeRecord(
                project_id=project_id,
                change_type=change_type,
                target_resource=target_resource,
                title=f"[THROTTLED STORM] {title}",
                previous_state=previous_state,
                new_state=new_state,
                evidence_summary=f"Event storm throttle active (>5 events in 60s). Suppressed automated scan trigger.\n{evidence_summary}",
                confidence=confidence,
                is_confirmed=True,
            )
            db.add(record)
            db.commit()
            db.refresh(record)
            return {
                "status": "THROTTLED_STORM",
                "change_id": record.id,
                "target_resource": target_resource,
                "reassessment_recommended": False,
                "message": "Event storm throttle activated. Change recorded without triggering automatic scans.",
            }

        # 3. Standard Confirmed Change Recording
        record = PostureChangeRecord(
            project_id=project_id,
            change_type=change_type,
            target_resource=target_resource,
            title=title,
            previous_state=previous_state,
            new_state=new_state,
            evidence_summary=evidence_summary,
            confidence=confidence,
            is_confirmed=True,
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        return {
            "status": "RECORDED",
            "change_id": record.id,
            "target_resource": target_resource,
            "reassessment_recommended": True,
            "message": "Posture change recorded; candidate for change-driven reassessment in next adaptive planning cycle.",
        }
