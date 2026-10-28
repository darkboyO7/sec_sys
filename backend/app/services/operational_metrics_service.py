from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.models.decision import OperationalSLOConfig
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingEvidence,
    FindingSeverity,
    FindingConfidence,
)
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
)
from app.models.asset import Asset, AssetStatus
from app.models.verification import (
    RemediationVerification,
    VerificationOutcome,
)
from app.models.risk import (
    RemediationRecommendation,
    RecommendationStatus,
)
from app.models.notification import (
    NotificationRecord,
    NotificationStatus,
)
from app.models.base import utc_now


class OperationalMetricsService:
    """
    Security Outcome and Operational SLO Reporting Service (Prompt 11 / Section 6).
    Computes rigorous, trustworthy metrics from persisted database records:
    - Avoids misleading averages or zero denominators.
    - Explicitly reports MISSING_DATA when insufficient records exist.
    - Correlates metrics against configurable project-level SLO objectives.
    """

    @classmethod
    def get_or_create_slo_config(
        cls,
        db: Session,
        project_id: str,
    ) -> OperationalSLOConfig:
        """
        Gets or initializes project SLO targets.
        """
        cfg = (
            db.query(OperationalSLOConfig)
            .filter(OperationalSLOConfig.project_id == project_id)
            .first()
        )
        if not cfg:
            cfg = OperationalSLOConfig(
                project_id=project_id,
                min_assessment_completion_rate=95.0,
                max_queue_delay_seconds=300.0,
                min_evidence_completeness_rate=90.0,
                max_inconclusive_rate=10.0,
                min_remediation_completion_rate=80.0,
                min_verification_pass_rate=85.0,
                min_asset_coverage_rate=90.0,
                coverage_stale_days=14,
            )
            db.add(cfg)
            db.commit()
            db.refresh(cfg)
        return cfg

    @classmethod
    def update_slo_config(
        cls,
        db: Session,
        project_id: str,
        update_data: Dict[str, Any],
    ) -> OperationalSLOConfig:
        """
        Updates project SLO threshold parameters.
        """
        cfg = cls.get_or_create_slo_config(db=db, project_id=project_id)
        for k, v in update_data.items():
            if hasattr(cfg, k) and k not in ("id", "project_id", "created_at"):
                setattr(cfg, k, v)
        cfg.updated_at = utc_now()
        db.commit()
        db.refresh(cfg)
        return cfg

    @classmethod
    def calculate_operational_slos(
        cls,
        db: Session,
        project_id: str,
        window_days: int = 30,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Calculates all operational metrics and compares them against target SLO objectives.
        """
        if now is None:
            now = utc_now()

        window_start = now - timedelta(days=window_days)
        slo_cfg = cls.get_or_create_slo_config(db=db, project_id=project_id)

        # ----------------------------------------------------------------------
        # 1. Assessment Operations SLO
        # ----------------------------------------------------------------------
        jobs = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.created_at >= window_start,
            )
            .all()
        )
        total_jobs = len(jobs)
        completed_jobs = len([j for j in jobs if j.status == AssessmentStatus.COMPLETED])
        failed_jobs = len([j for j in jobs if j.status in (AssessmentStatus.FAILED, AssessmentStatus.CANCELLED)])

        completion_rate = round((completed_jobs / total_jobs) * 100.0, 1) if total_jobs > 0 else None
        failure_rate = round((failed_jobs / total_jobs) * 100.0, 1) if total_jobs > 0 else None

        # Queue delay & execution duration
        queue_delays: List[float] = []
        durations: List[float] = []
        for j in jobs:
            if j.queued_at and j.started_at:
                q = (j.started_at - j.queued_at).total_seconds()
                if q >= 0:
                    queue_delays.append(q)
            if j.started_at and j.completed_at:
                d = (j.completed_at - j.started_at).total_seconds()
                if d >= 0:
                    durations.append(d)

        avg_queue_delay = round(sum(queue_delays) / len(queue_delays), 1) if queue_delays else None
        avg_duration = round(sum(durations) / len(durations), 1) if durations else None

        # ----------------------------------------------------------------------
        # 2. Evidence Completeness & Freshness SLO
        # ----------------------------------------------------------------------
        findings = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.project_id == project_id)
            .all()
        )
        total_findings = len(findings)
        
        # Count findings that have linked cryptographic evidence
        evidence_finding_ids = set(
            row[0] for row in (
                db.query(AssessmentFinding.canonical_finding_id)
                .join(FindingEvidence, FindingEvidence.finding_id == AssessmentFinding.id)
                .filter(AssessmentFinding.project_id == project_id)
                .all()
            ) if row[0]
        )
        findings_with_evidence = len([f for f in findings if f.id in evidence_finding_ids or f.status == FindingLifecycleStatus.CONFIRMED])
        evidence_completeness_rate = round((findings_with_evidence / total_findings) * 100.0, 1) if total_findings > 0 else None

        # Stale evidence
        stale_threshold = now - timedelta(days=30)
        stale_findings_count = len([
            f for f in findings
            if f.last_observed_at and (
                f.last_observed_at.replace(tzinfo=timezone.utc) if f.last_observed_at.tzinfo is None else f.last_observed_at
            ) < stale_threshold
        ])

        # ----------------------------------------------------------------------
        # 3. Finding Confirmation and Inconclusive Rates
        # ----------------------------------------------------------------------
        confirmed_count = len([f for f in findings if f.status == FindingLifecycleStatus.CONFIRMED])
        active_findings_count = len([f for f in findings if f.status in (FindingLifecycleStatus.DETECTED, FindingLifecycleStatus.CONFIRMED, FindingLifecycleStatus.REOPENED)])
        confirmation_rate = round((confirmed_count / active_findings_count) * 100.0, 1) if active_findings_count > 0 else None

        retests = (
            db.query(RemediationVerification)
            .filter(
                RemediationVerification.project_id == project_id,
                RemediationVerification.created_at >= window_start,
            )
            .all()
        )
        total_retests = len(retests)
        inconclusive_retests = len([r for r in retests if r.outcome == VerificationOutcome.INCONCLUSIVE])
        inconclusive_rate = round((inconclusive_retests / total_retests) * 100.0, 1) if total_retests > 0 else None

        # ----------------------------------------------------------------------
        # 4. Remediation & Verification Rates
        # ----------------------------------------------------------------------
        remediations = (
            db.query(RemediationRecommendation)
            .filter(RemediationRecommendation.project_id == project_id)
            .all()
        )
        total_remediations = len(remediations)
        completed_remediations = len([r for r in remediations if r.status == RecommendationStatus.APPROVED])
        remediation_completion_rate = round((completed_remediations / total_remediations) * 100.0, 1) if total_remediations > 0 else None

        passed_verifications = len([r for r in retests if r.outcome == VerificationOutcome.CONFIRMED_FIXED])
        verification_pass_rate = round((passed_verifications / total_retests) * 100.0, 1) if total_retests > 0 else None

        reopened_count = len([f for f in findings if f.status == FindingLifecycleStatus.REOPENED or f.recurrence_count > 0])
        failed_verification_count = len([r for r in retests if r.outcome == VerificationOutcome.STILL_VULNERABLE])

        # ----------------------------------------------------------------------
        # 5. Asset Assessment Coverage SLO
        # ----------------------------------------------------------------------
        assets = db.query(Asset).filter(Asset.project_id == project_id).all()
        total_assets = len(assets)
        coverage_threshold = now - timedelta(days=slo_cfg.coverage_stale_days)

        covered_assets = len([
            a for a in assets
            if a.last_seen_at and (
                a.last_seen_at.replace(tzinfo=timezone.utc) if a.last_seen_at.tzinfo is None else a.last_seen_at
            ) >= coverage_threshold
        ])
        coverage_rate = round((covered_assets / total_assets) * 100.0, 1) if total_assets > 0 else None
        overdue_assets_count = total_assets - covered_assets

        # ----------------------------------------------------------------------
        # 6. Notification Delivery SLO
        # ----------------------------------------------------------------------
        notifications = (
            db.query(NotificationRecord)
            .filter(
                NotificationRecord.project_id == project_id,
                NotificationRecord.created_at >= window_start,
            )
            .all()
        )
        total_notifications = len(notifications)
        delivered_notifications = len([n for n in notifications if n.status == NotificationStatus.DELIVERED])
        failed_notifications = len([n for n in notifications if n.status == NotificationStatus.FAILED])
        unconfigured_notifications = len([n for n in notifications if n.status == NotificationStatus.UNCONFIGURED])
        delivery_success_rate = round((delivered_notifications / total_notifications) * 100.0, 1) if total_notifications > 0 else None

        # ----------------------------------------------------------------------
        # 7. Backup and Recovery Status
        # ----------------------------------------------------------------------
        import os
        from pathlib import Path
        backup_dir = Path("D:/alt/backend/backups")
        backup_files = list(backup_dir.glob("*.db")) if backup_dir.exists() else []
        last_backup_file = max(backup_files, key=os.path.getmtime) if backup_files else None
        last_backup_at = datetime.fromtimestamp(os.path.getmtime(last_backup_file), tz=timezone.utc).isoformat() if last_backup_file else None
        last_backup_size = os.path.getsize(last_backup_file) if last_backup_file else None

        # ----------------------------------------------------------------------
        # 8. Evaluate SLO Adherence
        # ----------------------------------------------------------------------
        slos = {
            "assessment_completion": {
                "metric_name": "Assessment Job Completion Rate",
                "observed_value": completion_rate,
                "target_threshold": slo_cfg.min_assessment_completion_rate,
                "unit": "%",
                "status": "MISSING_DATA" if completion_rate is None else ("MET" if completion_rate >= slo_cfg.min_assessment_completion_rate else "BREACHED"),
            },
            "queue_delay": {
                "metric_name": "Average Assessment Queue Delay",
                "observed_value": avg_queue_delay,
                "target_threshold": slo_cfg.max_queue_delay_seconds,
                "unit": "seconds",
                "status": "MISSING_DATA" if avg_queue_delay is None else ("MET" if avg_queue_delay <= slo_cfg.max_queue_delay_seconds else "BREACHED"),
            },
            "evidence_completeness": {
                "metric_name": "Finding Evidence Completeness Rate",
                "observed_value": evidence_completeness_rate,
                "target_threshold": slo_cfg.min_evidence_completeness_rate,
                "unit": "%",
                "status": "MISSING_DATA" if evidence_completeness_rate is None else ("MET" if evidence_completeness_rate >= slo_cfg.min_evidence_completeness_rate else "BREACHED"),
            },
            "inconclusive_retests": {
                "metric_name": "Inconclusive Retest Rate",
                "observed_value": inconclusive_rate,
                "target_threshold": slo_cfg.max_inconclusive_rate,
                "unit": "%",
                "status": "MISSING_DATA" if inconclusive_rate is None else ("MET" if inconclusive_rate <= slo_cfg.max_inconclusive_rate else "BREACHED"),
            },
            "remediation_completion": {
                "metric_name": "Remediation Completion Rate",
                "observed_value": remediation_completion_rate,
                "target_threshold": slo_cfg.min_remediation_completion_rate,
                "unit": "%",
                "status": "MISSING_DATA" if remediation_completion_rate is None else ("MET" if remediation_completion_rate >= slo_cfg.min_remediation_completion_rate else "BREACHED"),
            },
            "verification_pass": {
                "metric_name": "Independent Verification Pass Rate",
                "observed_value": verification_pass_rate,
                "target_threshold": slo_cfg.min_verification_pass_rate,
                "unit": "%",
                "status": "MISSING_DATA" if verification_pass_rate is None else ("MET" if verification_pass_rate >= slo_cfg.min_verification_pass_rate else "BREACHED"),
            },
            "asset_coverage": {
                "metric_name": "Asset Assessment Coverage Rate",
                "observed_value": coverage_rate,
                "target_threshold": slo_cfg.min_asset_coverage_rate,
                "unit": "%",
                "status": "MISSING_DATA" if coverage_rate is None else ("MET" if coverage_rate >= slo_cfg.min_asset_coverage_rate else "BREACHED"),
            },
        }

        # Overall Health Score
        evaluable_slos = [s for s in slos.values() if s["status"] in ("MET", "BREACHED")]
        met_count = len([s for s in evaluable_slos if s["status"] == "MET"])
        overall_health_pct = round((met_count / len(evaluable_slos)) * 100.0, 1) if evaluable_slos else None

        return {
            "project_id": project_id,
            "window_days": window_days,
            "generated_at": now.isoformat(),
            "overall_health_pct": overall_health_pct,
            "slos": slos,
            "raw_telemetry": {
                "jobs": {
                    "total": total_jobs,
                    "completed": completed_jobs,
                    "failed": failed_jobs,
                    "avg_queue_delay_seconds": avg_queue_delay,
                    "avg_duration_seconds": avg_duration,
                },
                "evidence": {
                    "total_findings": total_findings,
                    "findings_with_evidence": findings_with_evidence,
                    "stale_evidence_count": stale_findings_count,
                },
                "findings": {
                    "active_count": active_findings_count,
                    "confirmed_count": confirmed_count,
                    "reopened_count": reopened_count,
                },
                "remediations": {
                    "total": total_remediations,
                    "completed": completed_remediations,
                    "total_retests": total_retests,
                    "passed_retests": passed_verifications,
                    "failed_retests": failed_verification_count,
                    "inconclusive_retests": inconclusive_retests,
                },
                "assets": {
                    "total": total_assets,
                    "covered": covered_assets,
                    "overdue": overdue_assets_count,
                    "stale_threshold_days": slo_cfg.coverage_stale_days,
                },
                "notifications": {
                    "total": total_notifications,
                    "delivered": delivered_notifications,
                    "failed": failed_notifications,
                    "unconfigured": unconfigured_notifications,
                },
                "backup_status": {
                    "last_backup_at": last_backup_at,
                    "last_backup_size_bytes": last_backup_size,
                    "backup_status": "AVAILABLE" if last_backup_file else "NO_BACKUPS_RECORDED",
                },
            },
        }
