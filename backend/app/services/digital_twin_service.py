import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus, FindingTransition
from app.models.asset import Asset
from app.models.risk import RiskAssessment, RemediationRecommendation
from app.models.verification import RemediationVerification
from app.models.digital_twin import SecuritySnapshot
from app.models.user import User
from app.models.base import utc_now
from app.services.audit_service import AuditService
from app.schemas.digital_twin import SnapshotDiffResponse, ReconstructStateResponse


class DigitalTwinService:
    """
    Historical Security Digital Twin Service (Phase 16).
    Maintains time-indexed security model of the environment.
    Provides:
    1. Point-in-time state capture and immutable snapshot manifests.
    2. Historical state reconstruction as of any timestamp using transition histories.
    3. Reproducible snapshot comparison (A vs B) detecting new, resolved, recurring, and changed findings.
    4. Asset drift tracking and risk posture trend analysis.
    """

    @classmethod
    def capture_snapshot(
        cls,
        project_id: str,
        label: str,
        user: User,
        db: Session,
        as_of_time: Optional[datetime] = None,
        client_ip: Optional[str] = None,
    ) -> SecuritySnapshot:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        target_time = as_of_time or utc_now()

        # Reconstruct or gather state as of target_time
        assets = (
            db.query(Asset)
            .filter(Asset.project_id == project_id, Asset.created_at <= target_time)
            .all()
        )
        findings = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.project_id == project_id, VulnerabilityFinding.first_detected_at <= target_time)
            .all()
        )

        asset_manifest = [
            {
                "id": a.id,
                "name": a.name,
                "asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
                "criticality": a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality),
                "status": a.status.value if hasattr(a.status, "value") else str(a.status),
            }
            for a in assets
        ]

        finding_manifest = []
        severity_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for f in findings:
            # Reconstruct status at target_time
            latest_transition = (
                db.query(FindingTransition)
                .filter(FindingTransition.finding_id == f.id, FindingTransition.created_at <= target_time)
                .order_by(FindingTransition.created_at.desc())
                .first()
            )
            reconstructed_status = (
                latest_transition.to_status.value
                if latest_transition
                else (f.status.value if hasattr(f.status, "value") else str(f.status))
            )

            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev_str in severity_dist:
                severity_dist[sev_str] += 1

            finding_manifest.append({
                "id": f.id,
                "fingerprint": f.fingerprint,
                "title": f.title,
                "severity": sev_str,
                "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                "cvss_score": f.cvss_score,
                "vuln_id": f.vuln_id,
                "target_value": f.target_value,
                "status": reconstructed_status,
                "recurrence_detected": f.recurrence_detected,
                "recurrence_count": f.recurrence_count,
                "is_simulated": f.is_simulated,
            })

        risk_summary = {
            "total_findings": len(finding_manifest),
            "severity_distribution": severity_dist,
            "critical_count": severity_dist.get("CRITICAL", 0),
            "high_count": severity_dist.get("HIGH", 0),
            "total_assets": len(asset_manifest),
        }

        state_manifest = {
            "project_id": project_id,
            "captured_at": target_time.isoformat(),
            "assets": asset_manifest,
            "findings": finding_manifest,
            "risk_summary": risk_summary,
        }

        manifest_json = json.dumps(state_manifest, sort_keys=True)
        manifest_hash = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()

        snapshot = SecuritySnapshot(
            project_id=project_id,
            snapshot_label=label.strip(),
            snapshot_timestamp=target_time,
            captured_by_id=user.id,
            assets_count=len(asset_manifest),
            findings_count=len(finding_manifest),
            risk_summary=risk_summary,
            state_manifest=state_manifest,
            manifest_sha256=manifest_hash,
        )
        db.add(snapshot)
        db.flush()

        AuditService.log(
            db=db,
            action="SECURITY_SNAPSHOT_CAPTURED",
            actor_id=user.id,
            target_resource=f"snapshot:{snapshot.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "snapshot_label": snapshot.snapshot_label,
                "findings_count": snapshot.findings_count,
                "assets_count": snapshot.assets_count,
                "manifest_sha256": snapshot.manifest_sha256,
            },
        )
        db.commit()
        db.refresh(snapshot)
        return snapshot

    @classmethod
    def reconstruct_state_as_of(
        cls,
        project_id: str,
        as_of_time: datetime,
        db: Session,
    ) -> ReconstructStateResponse:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        assets = (
            db.query(Asset)
            .filter(Asset.project_id == project_id, Asset.created_at <= as_of_time)
            .all()
        )
        findings = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.project_id == project_id, VulnerabilityFinding.first_detected_at <= as_of_time)
            .all()
        )

        asset_list = [
            {
                "id": a.id,
                "name": a.name,
                "asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
                "criticality": a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality),
            }
            for a in assets
        ]

        finding_list = []
        severity_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for f in findings:
            latest_transition = (
                db.query(FindingTransition)
                .filter(FindingTransition.finding_id == f.id, FindingTransition.created_at <= as_of_time)
                .order_by(FindingTransition.created_at.desc())
                .first()
            )
            reconstructed_status = (
                latest_transition.to_status.value
                if latest_transition
                else (f.status.value if hasattr(f.status, "value") else str(f.status))
            )
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev in severity_dist:
                severity_dist[sev] += 1

            finding_list.append({
                "id": f.id,
                "fingerprint": f.fingerprint,
                "title": f.title,
                "severity": sev,
                "status": reconstructed_status,
                "cvss_score": f.cvss_score,
                "target": f.target_value,
            })

        risk_summary = {
            "total_findings": len(finding_list),
            "severity_distribution": severity_dist,
            "total_assets": len(asset_list),
        }

        digest_corpus = json.dumps({"findings": finding_list, "assets": asset_list}, sort_keys=True)
        state_hash = hashlib.sha256(digest_corpus.encode("utf-8")).hexdigest()

        return ReconstructStateResponse(
            project_id=project_id,
            as_of_timestamp=as_of_time,
            assets=asset_list,
            findings=finding_list,
            risk_summary=risk_summary,
            state_sha256=state_hash,
        )

    @classmethod
    def compare_snapshots(
        cls,
        project_id: str,
        snapshot_a_id: str,
        snapshot_b_id: str,
        db: Session,
    ) -> SnapshotDiffResponse:
        snap_a = (
            db.query(SecuritySnapshot)
            .filter(SecuritySnapshot.id == snapshot_a_id, SecuritySnapshot.project_id == project_id)
            .first()
        )
        if not snap_a:
            raise ValueError(f"Snapshot '{snapshot_a_id}' not found in project '{project_id}'.")

        snap_b = (
            db.query(SecuritySnapshot)
            .filter(SecuritySnapshot.id == snapshot_b_id, SecuritySnapshot.project_id == project_id)
            .first()
        )
        if not snap_b:
            raise ValueError(f"Snapshot '{snapshot_b_id}' not found in project '{project_id}'.")

        # Guarantee chronological ordering (snap_a earlier than or equal to snap_b)
        if snap_a.snapshot_timestamp > snap_b.snapshot_timestamp:
            snap_a, snap_b = snap_b, snap_a

        manifest_a = snap_a.state_manifest or {}
        manifest_b = snap_b.state_manifest or {}

        findings_a = {f["fingerprint"]: f for f in manifest_a.get("findings", [])}
        findings_b = {f["fingerprint"]: f for f in manifest_b.get("findings", [])}

        new_findings = []
        resolved_findings = []
        recurring_findings = []
        changed_findings = []
        unresolved_findings = []

        # Evaluate findings in B against A
        for fp, f_b in findings_b.items():
            if fp not in findings_a:
                new_findings.append(f_b)
            else:
                f_a = findings_a[fp]
                status_a = f_a.get("status")
                status_b = f_b.get("status")

                if status_a == "VERIFIED_CLOSED" and status_b in ("REOPENED", "DETECTED", "CONFIRMED"):
                    recurring_findings.append(f_b)
                elif status_b == "VERIFIED_CLOSED" and status_a != "VERIFIED_CLOSED":
                    resolved_findings.append(f_b)
                elif status_a != status_b or f_a.get("severity") != f_b.get("severity"):
                    changed_findings.append({
                        "id": f_b.get("id"),
                        "title": f_b.get("title"),
                        "fingerprint": fp,
                        "old_status": status_a,
                        "new_status": status_b,
                        "old_severity": f_a.get("severity"),
                        "new_severity": f_b.get("severity"),
                    })
                elif status_b != "VERIFIED_CLOSED":
                    unresolved_findings.append(f_b)

        # Check for findings in A that disappeared from B
        for fp, f_a in findings_a.items():
            if fp not in findings_b and f_a.get("status") != "VERIFIED_CLOSED":
                resolved_findings.append(f_a)

        # Asset diff
        assets_a = {a["id"]: a for a in manifest_a.get("assets", [])}
        assets_b = {a["id"]: a for a in manifest_b.get("assets", [])}

        added_assets = [a for a_id, a in assets_b.items() if a_id not in assets_a]
        removed_assets = [a for a_id, a in assets_a.items() if a_id not in assets_b]

        # Posture trend calculation
        crit_a = snap_a.risk_summary.get("critical_count", 0)
        crit_b = snap_b.risk_summary.get("critical_count", 0)
        crit_diff = crit_b - crit_a
        total_diff = snap_b.findings_count - snap_a.findings_count

        if len(resolved_findings) > len(new_findings) and crit_diff <= 0:
            posture_trend = "IMPROVED"
        elif len(new_findings) > len(resolved_findings) or crit_diff > 0:
            posture_trend = "DEGRADED"
        else:
            posture_trend = "STABLE"

        return SnapshotDiffResponse(
            snapshot_a_id=snap_a.id,
            snapshot_b_id=snap_b.id,
            snapshot_a_label=snap_a.snapshot_label,
            snapshot_b_label=snap_b.snapshot_label,
            snapshot_a_timestamp=snap_a.snapshot_timestamp,
            snapshot_b_timestamp=snap_b.snapshot_timestamp,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            recurring_findings=recurring_findings,
            changed_findings=changed_findings,
            unresolved_findings=unresolved_findings,
            added_assets=added_assets,
            removed_assets=removed_assets,
            risk_drift={
                "critical_diff": crit_diff,
                "total_findings_diff": total_diff,
                "posture_trend": posture_trend,
            },
            summary={
                "new_findings_count": len(new_findings),
                "resolved_findings_count": len(resolved_findings),
                "recurring_findings_count": len(recurring_findings),
                "changed_findings_count": len(changed_findings),
                "unresolved_findings_count": len(unresolved_findings),
                "added_assets_count": len(added_assets),
                "removed_assets_count": len(removed_assets),
            },
        )
