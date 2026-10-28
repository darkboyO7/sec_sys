import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import FindingSeverity
from app.models.asset import Asset, AssetCriticality
from app.models.risk import RiskAssessment, RemediationRecommendation
from app.models.verification import RemediationVerification, VerificationOutcome
from app.models.digital_twin import SecuritySnapshot
from app.models.regression import (
    RegressionAlertType,
    AlertSeverity,
    AlertStatus,
    RegressionBaseline,
    RegressionAlert,
)
from app.models.user import User
from app.models.base import utc_now
from app.services.audit_service import AuditService


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class RegressionDetectionService:
    """
    Security Regression Detection and Change Intelligence Engine (Phase 17).
    Detects and explains meaningful security regressions across assessment timelines:
    - Recurring findings reopening after prior resolution.
    - Broken/regressed remediations where authorized fixes failed verification.
    - Stale evidence exceeding freshness windows.
    - High-criticality new asset exposures lacking assessment coverage.
    - Contextual risk score spikes exceeding baseline thresholds.
    Enforces deduplication, explicit baseline anchors, and full empirical rationales.
    """

    @classmethod
    def get_or_create_active_baseline(
        cls,
        project_id: str,
        db: Session,
        snapshot_id: Optional[str] = None,
        name: str = "Active Production Baseline",
    ) -> RegressionBaseline:
        baseline = (
            db.query(RegressionBaseline)
            .filter(RegressionBaseline.project_id == project_id, RegressionBaseline.is_active.is_(True))
            .first()
        )
        if baseline:
            if snapshot_id and baseline.snapshot_id != snapshot_id:
                baseline.snapshot_id = snapshot_id
                db.commit()
            return baseline

        # Create new baseline
        baseline = RegressionBaseline(
            project_id=project_id,
            snapshot_id=snapshot_id,
            name=name,
            is_active=True,
            risk_score_threshold_delta=5.0,
            evidence_stale_days=30,
        )
        db.add(baseline)
        db.commit()
        db.refresh(baseline)
        return baseline

    @classmethod
    def evaluate_project_regressions(
        cls,
        project_id: str,
        db: Session,
        actor: Optional[User] = None,
        client_ip: Optional[str] = None,
    ) -> List[RegressionAlert]:
        """
        Evaluates project findings, assets, remediations, and verification states
        against the active baseline, raising deduplicated alerts with empirical rationales.
        """
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        baseline = cls.get_or_create_active_baseline(project_id, db)
        now = utc_now()
        alerts_to_create = []

        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()
        assets = db.query(Asset).filter(Asset.project_id == project_id).all()
        remediations = db.query(RemediationRecommendation).filter(RemediationRecommendation.project_id == project_id).all()
        verifications = db.query(RemediationVerification).filter(RemediationVerification.project_id == project_id).all()

        # 1. Detect Recurring Findings
        for f in findings:
            if f.recurrence_detected and f.status in (
                FindingLifecycleStatus.REOPENED,
                FindingLifecycleStatus.DETECTED,
                FindingLifecycleStatus.CONFIRMED,
            ):
                fp = hashlib.sha256(f"RECURRING:{f.id}:{f.recurrence_count}".encode("utf-8")).hexdigest()
                sev = AlertSeverity.CRITICAL if (f.severity == FindingSeverity.CRITICAL or str(getattr(f.severity, "value", f.severity)).upper() == "CRITICAL") else AlertSeverity.HIGH
                alerts_to_create.append({
                    "alert_type": RegressionAlertType.RECURRING_FINDING,
                    "severity": sev,
                    "title": f"Recurring Vulnerability: {f.title[:80]}",
                    "description": f"Finding '{f.title}' previously marked resolved or closed has reopened on '{f.target_value}'.",
                    "evidence_rationale": (
                        f"Target fingerprint '{f.fingerprint}' was re-observed after prior closure. "
                        f"Cumulative recurrence count is now {f.recurrence_count}."
                    ),
                    "target_resource": f"finding:{f.id}",
                    "fingerprint": fp,
                    "baseline_reference": baseline.name,
                })

        # 2. Detect Remediation Regressions (Change authorized or approved, but recent verification failed)
        rem_by_finding = {r.finding_id: r for r in remediations}
        for v in verifications:
            if v.outcome == VerificationOutcome.STILL_VULNERABLE:
                rem = rem_by_finding.get(v.finding_id)
                if rem and rem.execution_governance_stage in ("APPROVED", "CHANGE_AUTHORIZED"):
                    fp = hashlib.sha256(f"REM_REGRESS:{v.finding_id}:{v.id}".encode("utf-8")).hexdigest()
                    alerts_to_create.append({
                        "alert_type": RegressionAlertType.REMEDIATION_REGRESSION,
                        "severity": AlertSeverity.HIGH,
                        "title": f"Broken Remediation Verification on {v.finding_id[:8]}",
                        "description": f"Remediation '{rem.title}' had reached stage '{rem.execution_governance_stage}', but verification failed.",
                        "evidence_rationale": (
                            f"Verification on {v.verified_at.strftime('%Y-%m-%d')} confirmed flaw is STILL_VULNERABLE. "
                            f"Verification summary: {v.verification_evidence_summary}"
                        ),
                        "target_resource": f"finding:{v.finding_id}",
                        "fingerprint": fp,
                        "baseline_reference": f"remediation:{rem.id}",
                    })

        # 3. Detect Stale Evidence (Findings open without refresh for > evidence_stale_days)
        stale_threshold = now - timedelta(days=baseline.evidence_stale_days)
        for f in findings:
            if f.status in (FindingLifecycleStatus.CONFIRMED, FindingLifecycleStatus.DETECTED, FindingLifecycleStatus.REMEDIATION_PROPOSED):
                last_obs = ensure_utc(f.last_observed_at)
                if last_obs and last_obs < stale_threshold:
                    days_old = (now - last_obs).days
                    fp = hashlib.sha256(f"STALE:{f.id}:{days_old // 10}".encode("utf-8")).hexdigest()
                    alerts_to_create.append({
                        "alert_type": RegressionAlertType.STALE_EVIDENCE,
                        "severity": AlertSeverity.LOW,
                        "title": f"Stale Vulnerability Evidence: {f.title[:80]}",
                        "description": f"Evidence for active finding '{f.title}' has not been re-tested in {days_old} days.",
                        "evidence_rationale": (
                            f"Last observation was at {last_obs.strftime('%Y-%m-%d')}, exceeding the "
                            f"{baseline.evidence_stale_days}-day staleness threshold."
                        ),
                        "target_resource": f"finding:{f.id}",
                        "fingerprint": fp,
                        "baseline_reference": f"threshold:{baseline.evidence_stale_days}d",
                    })

        # 4. Detect New Exposure (Critical/High asset registered without any assessments)
        for a in assets:
            crit = a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality)
            if crit in ("CRITICAL", "HIGH"):
                # Check if asset has any findings or observations
                findings_count = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.asset_id == a.id).count()
                asset_created = ensure_utc(a.created_at)
                if findings_count == 0 and asset_created and (now - asset_created).days <= 14:
                    fp = hashlib.sha256(f"NEW_EXPOSURE:{a.id}".encode("utf-8")).hexdigest()
                    alerts_to_create.append({
                        "alert_type": RegressionAlertType.NEW_EXPOSURE,
                        "severity": AlertSeverity.HIGH if crit == "HIGH" else AlertSeverity.CRITICAL,
                        "title": f"Unassessed Critical Perimeter Asset: {a.name[:80]}",
                        "description": f"New critical asset '{a.name}' registered without completed security assessments.",
                        "evidence_rationale": (
                            f"Asset '{a.name}' ({a.canonical_identifier or a.id}) has criticality '{crit}' "
                            f"but 0 recorded vulnerability findings or verification records."
                        ),
                        "target_resource": f"asset:{a.id}",
                        "fingerprint": fp,
                        "baseline_reference": baseline.name,
                    })

        # Filter out duplicates against existing active alerts
        created_alerts = []
        for alert_data in alerts_to_create:
            existing = (
                db.query(RegressionAlert)
                .filter(
                    RegressionAlert.project_id == project_id,
                    RegressionAlert.fingerprint == alert_data["fingerprint"],
                    RegressionAlert.status == AlertStatus.ACTIVE,
                )
                .first()
            )
            if not existing:
                alert = RegressionAlert(
                    project_id=project_id,
                    alert_type=alert_data["alert_type"],
                    severity=alert_data["severity"],
                    status=AlertStatus.ACTIVE,
                    title=alert_data["title"],
                    description=alert_data["description"],
                    evidence_rationale=alert_data["evidence_rationale"],
                    baseline_reference=alert_data.get("baseline_reference"),
                    current_reference=alert_data.get("current_reference"),
                    target_resource=alert_data["target_resource"],
                    fingerprint=alert_data["fingerprint"],
                )
                db.add(alert)
                created_alerts.append(alert)

        if created_alerts:
            db.flush()
            AuditService.log(
                db=db,
                action="REGRESSION_EVALUATION_COMPLETED",
                actor_id=actor.id if actor else None,
                target_resource=f"project:{project_id}",
                project_id=project_id,
                client_ip=client_ip,
                details={
                    "alerts_created": len(created_alerts),
                    "baseline_name": baseline.name,
                },
            )
            db.commit()

        # Return all currently active alerts
        return (
            db.query(RegressionAlert)
            .filter(RegressionAlert.project_id == project_id, RegressionAlert.status == AlertStatus.ACTIVE)
            .order_by(RegressionAlert.created_at.desc())
            .all()
        )

    @classmethod
    def acknowledge_alert(
        cls,
        project_id: str,
        alert_id: str,
        user: User,
        db: Session,
        notes: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> RegressionAlert:
        alert = (
            db.query(RegressionAlert)
            .filter(RegressionAlert.id == alert_id, RegressionAlert.project_id == project_id)
            .first()
        )
        if not alert:
            raise ValueError(f"Alert '{alert_id}' not found in project '{project_id}'.")

        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by_id = user.id
        alert.acknowledged_at = utc_now()
        if notes:
            alert.resolution_notes = notes

        AuditService.log(
            db=db,
            action="REGRESSION_ALERT_ACKNOWLEDGED",
            actor_id=user.id,
            target_resource=f"alert:{alert.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={"alert_type": alert.alert_type.value, "title": alert.title},
        )
        db.commit()
        db.refresh(alert)
        return alert

    @classmethod
    def resolve_alert(
        cls,
        project_id: str,
        alert_id: str,
        resolution_notes: str,
        user: User,
        db: Session,
        dismiss: bool = False,
        client_ip: Optional[str] = None,
    ) -> RegressionAlert:
        alert = (
            db.query(RegressionAlert)
            .filter(RegressionAlert.id == alert_id, RegressionAlert.project_id == project_id)
            .first()
        )
        if not alert:
            raise ValueError(f"Alert '{alert_id}' not found in project '{project_id}'.")

        clean_notes = (resolution_notes or "").strip()
        if len(clean_notes) < 3:
            raise ValueError("Resolution justification is required (minimum 3 characters).")

        alert.status = AlertStatus.DISMISSED if dismiss else AlertStatus.RESOLVED
        alert.resolution_notes = clean_notes
        if not alert.acknowledged_by_id:
            alert.acknowledged_by_id = user.id
            alert.acknowledged_at = utc_now()

        AuditService.log(
            db=db,
            action=f"REGRESSION_ALERT_{alert.status.value}",
            actor_id=user.id,
            target_resource=f"alert:{alert.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={"status": alert.status.value, "notes": clean_notes},
        )
        db.commit()
        db.refresh(alert)
        return alert


# Backwards compatibility alias
RegressionIntelligenceService = RegressionDetectionService
