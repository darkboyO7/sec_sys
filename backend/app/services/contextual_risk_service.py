from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.asset import Asset, AssetCriticality, AssetType
from app.models.graph import GraphRelationship, RelationshipType, RelationshipStatus
from app.models.risk import RiskAssessment, RiskPriority
from app.models.user import User
from app.services.audit_service import AuditService
from app.models.base import utc_now


class ContextualRiskService:
    """
    Explainable, deterministic Contextual Risk Engine (Scoring Version: v1.0.0).
    Evaluates vulnerability findings in their operational, topological, and lifecycle context.
    Produces a bounded 0-100 prioritization index (NOT a calibrated breach probability)
    with explicit factor decomposition, contributing rationale, and missing factor tracking.
    """

    SCORING_VERSION = "v1.0.0"

    # Base severity score bounds and defaults
    SEVERITY_BASE_SCORES: Dict[FindingSeverity, float] = {
        FindingSeverity.CRITICAL: 90.0,
        FindingSeverity.HIGH: 70.0,
        FindingSeverity.MEDIUM: 45.0,
        FindingSeverity.LOW: 20.0,
        FindingSeverity.INFO: 5.0,
    }

    CONFIDENCE_WEIGHTS: Dict[FindingConfidence, float] = {
        FindingConfidence.CERTAIN: 1.0,
        FindingConfidence.FIRM: 0.85,
        FindingConfidence.TENTATIVE: 0.65,
    }

    CRITICALITY_MULTIPLIERS: Dict[AssetCriticality, float] = {
        AssetCriticality.CRITICAL: 1.35,
        AssetCriticality.HIGH: 1.15,
        AssetCriticality.MEDIUM: 1.0,
        AssetCriticality.LOW: 0.85,
        AssetCriticality.INFO: 0.70,
    }

    LIFECYCLE_MULTIPLIERS: Dict[FindingLifecycleStatus, float] = {
        FindingLifecycleStatus.VERIFIED_CLOSED: 0.0,
        FindingLifecycleStatus.FALSE_POSITIVE: 0.0,
        FindingLifecycleStatus.ACCEPTED_RISK: 0.40,
        FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION: 0.50,
        FindingLifecycleStatus.REMEDIATION_ATTEMPTED: 0.75,
        FindingLifecycleStatus.REMEDIATION_APPROVED: 0.90,
        FindingLifecycleStatus.REMEDIATION_PROPOSED: 0.90,
        FindingLifecycleStatus.REOPENED: 1.10,
        FindingLifecycleStatus.CONFIRMED: 1.05,
        FindingLifecycleStatus.DETECTED: 1.0,
        FindingLifecycleStatus.NEEDS_VALIDATION: 1.0,
        FindingLifecycleStatus.INCONCLUSIVE: 0.85,
        FindingLifecycleStatus.EXPIRED: 1.05,
    }

    @classmethod
    def calculate_score_and_factors(
        cls,
        finding: VulnerabilityFinding,
        asset: Optional[Asset] = None,
        exposing_relationships: Optional[List[GraphRelationship]] = None,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Pure deterministic risk scoring function.
        Given a finding, optional asset, and optional relationships, returns:
        (score, priority, factor_breakdown, contributing_factors, missing_factors, input_snapshot)
        """
        current_time = now or utc_now()
        contributing_factors: List[str] = []
        missing_factors: List[str] = []

        # 1. Base Severity Score
        raw_cvss = finding.cvss_score
        base_score = cls.SEVERITY_BASE_SCORES.get(finding.severity, 45.0)
        if raw_cvss is not None and 0.0 <= raw_cvss <= 10.0:
            # Anchor around CVSS if present, clamped to reasonable severity bounds
            cvss_scaled = raw_cvss * 10.0
            if finding.severity == FindingSeverity.CRITICAL:
                base_score = max(80.0, min(100.0, cvss_scaled))
            elif finding.severity == FindingSeverity.HIGH:
                base_score = max(60.0, min(89.0, cvss_scaled))
            elif finding.severity == FindingSeverity.MEDIUM:
                base_score = max(35.0, min(65.0, cvss_scaled))
            elif finding.severity == FindingSeverity.LOW:
                base_score = max(10.0, min(39.0, cvss_scaled))
            else:
                base_score = min(15.0, cvss_scaled)
            contributing_factors.append(
                f"Base severity '{finding.severity.value}' anchored by CVSS score {raw_cvss:.1f} (base: {base_score:.1f})."
            )
        else:
            contributing_factors.append(
                f"Base severity '{finding.severity.value}' assigned default base score {base_score:.1f}."
            )
            if raw_cvss is None:
                missing_factors.append("CVSS score not provided by scanner; using categorical severity default.")

        # 2. Finding Confidence Weight
        conf_weight = cls.CONFIDENCE_WEIGHTS.get(finding.confidence, 0.85)
        contributing_factors.append(
            f"Finding confidence '{finding.confidence.value}' scales base score by {conf_weight:.2f}."
        )

        # 3. Asset Criticality Multiplier
        if asset is not None:
            crit_mult = cls.CRITICALITY_MULTIPLIERS.get(asset.criticality, 1.0)
            contributing_factors.append(
                f"Asset '{asset.name}' criticality '{asset.criticality.value}' multiplier: {crit_mult:.2f}."
            )
        else:
            crit_mult = 1.0
            missing_factors.append("Asset context not linked; asset criticality defaulted to 1.0 (MEDIUM).")

        # 4. Network Exposure / Reachability Multiplier
        exposure_mult = 1.0
        exposure_label = "INTERNAL_OR_STANDARD"
        has_exposure_edge = False
        if exposing_relationships:
            has_exposure_edge = any(
                r.relationship_type in (RelationshipType.EXPOSES, RelationshipType.CAN_ACCESS)
                for r in exposing_relationships
            )

        if asset is not None:
            if asset.asset_type in (AssetType.WEB_APP, AssetType.API_ENDPOINT) or has_exposure_edge:
                exposure_mult = 1.25
                exposure_label = "INTERNET_FACING_OR_EXPOSED"
                contributing_factors.append(
                    f"Asset is internet-facing or has verified exposing relationship ({exposure_label}): multiplier {exposure_mult:.2f}."
                )
            elif asset.asset_type in (AssetType.DATA_STORE, AssetType.SOFTWARE_COMPONENT, AssetType.SECURITY_CONTROL):
                exposure_mult = 0.85
                exposure_label = "ISOLATED_OR_RESTRICTED"
                contributing_factors.append(
                    f"Asset is backend or isolated component ({exposure_label}): multiplier {exposure_mult:.2f}."
                )
            else:
                exposure_mult = 1.0
                exposure_label = "STANDARD_NETWORK_SERVICE"
                contributing_factors.append(
                    f"Asset is standard network entity ({exposure_label}): multiplier {exposure_mult:.2f}."
                )
        else:
            exposure_mult = 1.0
            missing_factors.append("Exposure topology unknown; reachability multiplier defaulted to 1.0.")

        # 5. Evidence Freshness Multiplier
        last_obs = finding.last_observed_at
        if last_obs is not None:
            if last_obs.tzinfo is None:
                last_obs = last_obs.replace(tzinfo=timezone.utc)
            age_days = max(0, (current_time - last_obs).total_seconds() / 86400.0)
            if age_days <= 7:
                fresh_mult = 1.0
                contributing_factors.append(f"Observation is fresh ({age_days:.1f} days old): multiplier 1.00.")
            elif age_days <= 30:
                fresh_mult = 0.90
                contributing_factors.append(f"Observation is moderately recent ({age_days:.1f} days old): multiplier 0.90.")
            elif age_days <= 90:
                fresh_mult = 0.80
                contributing_factors.append(f"Observation is aging ({age_days:.1f} days old): multiplier 0.80.")
            else:
                fresh_mult = 0.70
                contributing_factors.append(f"Observation is stale ({age_days:.1f} days old): multiplier 0.70.")
        else:
            fresh_mult = 0.85
            missing_factors.append("Observation timestamp missing; freshness multiplier defaulted to 0.85.")

        # 6. Lifecycle & Mitigating Controls Multiplier
        lifecycle_mult = cls.LIFECYCLE_MULTIPLIERS.get(finding.status, 1.0)
        if finding.status == FindingLifecycleStatus.ACCEPTED_RISK:
            contributing_factors.append(
                f"Active authorized risk acceptance with documented compensating controls: multiplier {lifecycle_mult:.2f}."
            )
        elif finding.status in (FindingLifecycleStatus.VERIFIED_CLOSED, FindingLifecycleStatus.FALSE_POSITIVE):
            contributing_factors.append(
                f"Finding is resolved/dismissed ({finding.status.value}): risk score neutralized to 0.0."
            )
        elif finding.status == FindingLifecycleStatus.REOPENED:
            contributing_factors.append(
                f"Finding was previously closed but recurred on target (REOPENED): elevated urgency multiplier {lifecycle_mult:.2f}."
            )
        else:
            contributing_factors.append(
                f"Finding lifecycle state '{finding.status.value}': multiplier {lifecycle_mult:.2f}."
            )

        # 7. Composite Calculation
        effective_base = base_score * conf_weight
        raw_composite = effective_base * crit_mult * exposure_mult * fresh_mult * lifecycle_mult
        final_score = round(max(0.0, min(100.0, raw_composite)), 1)

        # 8. Priority Determination
        if final_score >= 80.0:
            priority = RiskPriority.CRITICAL
        elif final_score >= 60.0:
            priority = RiskPriority.HIGH
        elif final_score >= 40.0:
            priority = RiskPriority.MEDIUM
        elif final_score >= 15.0:
            priority = RiskPriority.LOW
        else:
            priority = RiskPriority.INFORMATIONAL

        factor_breakdown = {
            "base_score": round(base_score, 1),
            "confidence_weight": conf_weight,
            "effective_base": round(effective_base, 1),
            "criticality_multiplier": crit_mult,
            "exposure_multiplier": exposure_mult,
            "exposure_label": exposure_label,
            "freshness_multiplier": fresh_mult,
            "lifecycle_multiplier": lifecycle_mult,
            "final_score": final_score,
            "raw_composite": round(raw_composite, 2),
        }

        input_snapshot = {
            "scoring_version": cls.SCORING_VERSION,
            "finding_id": finding.id,
            "finding_severity": finding.severity.value,
            "finding_confidence": finding.confidence.value,
            "cvss_score": finding.cvss_score,
            "finding_status": finding.status.value,
            "last_observed_at": last_obs.isoformat() if last_obs else None,
            "asset_id": asset.id if asset else None,
            "asset_criticality": asset.criticality.value if asset else None,
            "asset_type": asset.asset_type.value if asset else None,
            "has_exposure_edge": has_exposure_edge,
            "calculation_time": current_time.isoformat(),
        }

        return {
            "score": final_score,
            "priority": priority,
            "factor_breakdown": factor_breakdown,
            "contributing_factors": contributing_factors,
            "missing_factors": missing_factors,
            "input_snapshot": input_snapshot,
        }

    @classmethod
    def assess_and_persist_finding_risk(
        cls,
        project_id: str,
        finding_id: str,
        db: Session,
        force_recalculate: bool = False,
        actor: Optional[User] = None,
        client_ip: Optional[str] = None,
    ) -> RiskAssessment:
        """
        Assesses a finding's contextual risk and persists it.
        Guarantees idempotency when inputs have not changed unless force_recalculate is True.
        When updated, marks previous active assessment as superseded.
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

        asset = None
        if finding.asset_id:
            asset = (
                db.query(Asset)
                .filter(
                    Asset.id == finding.asset_id,
                    Asset.project_id == project_id,
                )
                .first()
            )

        # Check for exposing relationships in knowledge graph
        exposing_rels = []
        if asset:
            # Query relationships connected to this asset
            exposing_rels = (
                db.query(GraphRelationship)
                .filter(
                    GraphRelationship.project_id == project_id,
                    GraphRelationship.relationship_type.in_([RelationshipType.EXPOSES, RelationshipType.CAN_ACCESS]),
                )
                .all()
            )

        # Check for existing active assessment
        active_assessment = (
            db.query(RiskAssessment)
            .filter(
                RiskAssessment.project_id == project_id,
                RiskAssessment.finding_id == finding_id,
                RiskAssessment.is_superseded.is_(False),
            )
            .order_by(RiskAssessment.calculated_at.desc())
            .first()
        )

        now = utc_now()
        calc = cls.calculate_score_and_factors(
            finding=finding,
            asset=asset,
            exposing_relationships=exposing_rels,
            now=now,
        )

        # If active assessment exists and not forcing recalculation, check if key inputs changed
        if active_assessment and not force_recalculate:
            prev_snapshot = active_assessment.input_snapshot or {}
            current_snapshot = calc["input_snapshot"]
            # Compare key deterministic drivers
            keys_to_compare = [
                "finding_severity",
                "finding_confidence",
                "cvss_score",
                "finding_status",
                "asset_criticality",
                "asset_type",
                "has_exposure_edge",
            ]
            if all(prev_snapshot.get(k) == current_snapshot.get(k) for k in keys_to_compare):
                # Inputs identical; return active assessment without duplicating
                return active_assessment

        # Supersede existing active assessment
        if active_assessment:
            active_assessment.is_superseded = True
            active_assessment.superseded_at = now

        # Create new assessment
        new_assessment = RiskAssessment(
            project_id=project_id,
            finding_id=finding.id,
            asset_id=asset.id if asset else None,
            score=calc["score"],
            priority=calc["priority"],
            scoring_version=cls.SCORING_VERSION,
            factor_breakdown=calc["factor_breakdown"],
            contributing_factors=calc["contributing_factors"],
            missing_factors=calc["missing_factors"],
            evidence_references=[f.id for f in (finding.raw_findings or [])] if hasattr(finding, "raw_findings") else [],
            input_snapshot=calc["input_snapshot"],
            calculated_at=now,
            is_superseded=False,
        )
        db.add(new_assessment)
        db.flush()

        # Audit event
        AuditService.log(
            db=db,
            action="RISK_ASSESSMENT_CALCULATED",
            actor_id=actor.id if actor else None,
            target_resource=f"finding:{finding.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "assessment_id": new_assessment.id,
                "score": new_assessment.score,
                "priority": new_assessment.priority.value,
                "scoring_version": new_assessment.scoring_version,
            },
        )
        db.commit()
        db.refresh(new_assessment)
        return new_assessment

    @classmethod
    def recalculate_project_risks(
        cls,
        project_id: str,
        db: Session,
        actor: Optional[User] = None,
        client_ip: Optional[str] = None,
    ) -> int:
        """
        Calculates or refreshes contextual risk assessments for all active findings in a project.
        Returns the count of findings assessed.
        """
        findings = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.project_id == project_id)
            .all()
        )
        count = 0
        for f in findings:
            cls.assess_and_persist_finding_risk(
                project_id=project_id,
                finding_id=f.id,
                db=db,
                force_recalculate=True,
                actor=actor,
                client_ip=client_ip,
            )
            count += 1
        return count
