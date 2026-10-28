import math
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

    SCORING_VERSION = "v2.0.0"

    BUSINESS_IMPACT_MULTIPLIERS: Dict[str, float] = {
        "CRITICAL": 1.25,
        "HIGH": 1.15,
        "MEDIUM": 1.00,
        "LOW": 0.85,
    }

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
        verified_attack_paths: Optional[List[Dict[str, Any]]] = None,
        prior_verification_failed: bool = False,
        now: Optional[datetime] = None,
        scoring_version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Pure deterministic risk scoring function (Prompt 10 / v2.0.0).
        Evaluates severity, confidence, exposure, business impact, exploitability,
        validated attack paths, and remediation history.
        Never infers unconfigured business impact or exploitability.
        Returns:
        (score, priority, factor_breakdown, contributing_factors, missing_factors, input_snapshot)
        """
        current_time = now or utc_now()
        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)
        contributing_factors: List[str] = []
        missing_factors: List[str] = []

        # 1. Base Severity Score & Precedence Rules
        raw_cvss = finding.cvss_score
        base_score = cls.SEVERITY_BASE_SCORES.get(finding.severity, 45.0)

        # Validate CVSS numeric validity: finite float in [0.0, 10.0]
        is_valid_cvss = (
            raw_cvss is not None
            and isinstance(raw_cvss, (int, float))
            and not math.isnan(raw_cvss)
            and not math.isinf(raw_cvss)
            and 0.0 <= raw_cvss <= 10.0
        )

        if raw_cvss is not None and not is_valid_cvss:
            missing_factors.append(
                f"CVSS score '{raw_cvss}' is non-finite or outside [0.0, 10.0]; defaulted to categorical severity '{finding.severity.value}'."
            )

        if is_valid_cvss:
            # Anchor around CVSS, with deterministic bounds per categorical severity
            cvss_scaled = float(raw_cvss) * 10.0
            if finding.severity == FindingSeverity.CRITICAL:
                min_bound, max_bound = 80.0, 100.0
            elif finding.severity == FindingSeverity.HIGH:
                min_bound, max_bound = 60.0, 89.0
            elif finding.severity == FindingSeverity.MEDIUM:
                min_bound, max_bound = 35.0, 65.0
            elif finding.severity == FindingSeverity.LOW:
                min_bound, max_bound = 10.0, 39.0
            else:  # INFO
                min_bound, max_bound = 0.0, 15.0

            base_score = max(min_bound, min(max_bound, cvss_scaled))

            # Conflict detection
            if cvss_scaled < min_bound or cvss_scaled > max_bound:
                contributing_factors.append(
                    f"Severity discrepancy detected: Finding severity '{finding.severity.value}' conflicts with CVSS score {raw_cvss:.1f}. "
                    f"Categorical bounds [{min_bound:.0f}, {max_bound:.0f}] applied (base: {base_score:.1f})."
                )
            else:
                contributing_factors.append(
                    f"Base severity '{finding.severity.value}' anchored by CVSS score {raw_cvss:.1f} (base: {base_score:.1f})."
                )
        else:
            contributing_factors.append(
                f"Base severity '{finding.severity.value}' assigned default base score {base_score:.1f}."
            )
            if raw_cvss is None:
                missing_factors.append("CVSS score not provided by scanner; using categorical severity default.")

        # 2. Finding Confidence Weight & Contradiction Discount
        raw_conf_weight = cls.CONFIDENCE_WEIGHTS.get(finding.confidence, 0.85)
        contradiction_discount = 1.0
        if getattr(finding, "has_contradictions", False):
            contradiction_discount = 0.80
            contributing_factors.append(
                f"Contradictory scanner observations detected (has_contradictions=True): confidence discounted by 20% (multiplier {contradiction_discount:.2f})."
            )
        conf_weight = raw_conf_weight * contradiction_discount
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
            if last_obs > current_time:
                age_days = 0.0
                contributing_factors.append(
                    f"Observation timestamp is future-dated ({last_obs.isoformat()}); treated as current fresh observation (0 days)."
                )
            else:
                age_days = max(0.0, (current_time - last_obs).total_seconds() / 86400.0)

            if age_days <= 7:
                fresh_mult = 1.0
                if last_obs <= current_time:
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
        exp_iso = None
        if finding.risk_accepted_expires_at:
            exp_dt = finding.risk_accepted_expires_at
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            exp_iso = exp_dt.isoformat()

        if finding.status == FindingLifecycleStatus.ACCEPTED_RISK:
            exp_str = exp_iso or "No expiration"
            approver_str = finding.risk_accepted_by_id or "Authorized Lead/Admin"
            ctrl_str = finding.compensating_controls or "Documented compensating controls"
            contributing_factors.append(
                f"Active authorized risk acceptance (Approver: {approver_str}, Expires: {exp_str}, Controls: {ctrl_str}): "
                f"residual risk multiplier {lifecycle_mult:.2f} applied."
            )
        elif finding.status == FindingLifecycleStatus.VERIFIED_CLOSED:
            v_actor = finding.verified_by_id or "Independent verification"
            contributing_factors.append(
                f"Finding resolved and verified closed (VERIFIED_CLOSED by {v_actor}): current risk score neutralized to 0.0 while preserving audit history."
            )
        elif finding.status == FindingLifecycleStatus.FALSE_POSITIVE:
            fp_actor = finding.false_positive_by_id or "Lead/Admin disposition"
            contributing_factors.append(
                f"Finding dismissed as false positive (FALSE_POSITIVE by {fp_actor}): current risk score neutralized to 0.0 while preserving audit history."
            )
        elif finding.status == FindingLifecycleStatus.REOPENED:
            contributing_factors.append(
                f"Finding was previously closed but recurred on target (REOPENED): recurrence penalty multiplier {lifecycle_mult:.2f} applied."
            )
        elif finding.status == FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION:
            contributing_factors.append(
                f"Remediation deployed but pending independent verification (REMEDIATED_PENDING_VERIFICATION): "
                f"reduced risk multiplier {lifecycle_mult:.2f} maintaining residual uncertainty."
            )
        else:
            contributing_factors.append(
                f"Finding lifecycle state '{finding.status.value}': multiplier {lifecycle_mult:.2f}."
            )

        # 7. Recurrence Multiplier (Phase 11)
        recurrence_mult = 1.0
        if getattr(finding, "recurrence_detected", False):
            rec_count = getattr(finding, "recurrence_count", 1) or 1
            recurrence_mult = 1.0 + min(0.30, 0.10 * rec_count)
            contributing_factors.append(
                f"Vulnerability recurrence detected ({rec_count} prior occurrences): recurrence multiplier {recurrence_mult:.2f}."
            )

        # 8. Evidence Quality Multiplier (Phase 11)
        quality_mult = 1.0
        ev_quality = getattr(finding, "evidence_quality_score", None)
        if ev_quality is not None and ev_quality < 1.0:
            quality_mult = round(0.80 + (0.20 * max(0.0, min(1.0, float(ev_quality)))), 2)
            contributing_factors.append(
                f"Evidence quality adjustment ({ev_quality:.2f}): multiplier {quality_mult:.2f}."
            )

        # 9. Potential Business Impact Multiplier (Operator Configured Only)
        biz_impact = None
        if asset is not None and getattr(asset, "attributes", None) and isinstance(asset.attributes, dict):
            biz_impact = asset.attributes.get("business_impact") or asset.attributes.get("business_criticality")
        if not biz_impact and getattr(finding, "attributes", None) and isinstance(finding.attributes, dict):
            biz_impact = finding.attributes.get("business_impact")

        business_impact_mult = 1.0
        if biz_impact and str(biz_impact).upper() in cls.BUSINESS_IMPACT_MULTIPLIERS:
            biz_clean = str(biz_impact).upper()
            business_impact_mult = cls.BUSINESS_IMPACT_MULTIPLIERS[biz_clean]
            contributing_factors.append(
                f"Authorized operator business impact configured as '{biz_clean}': multiplier {business_impact_mult:.2f}."
            )
        else:
            missing_factors.append("Potential business impact: UNKNOWN / NOT CONFIGURED (multiplier 1.00; not inferred).")

        # 10. Exploitability Evidence Multiplier (Evidence-Backed Only)
        has_exploit_evidence = False
        exploit_rationale = ""
        finding_meta = getattr(finding, "attributes", None) or {}
        if not isinstance(finding_meta, dict):
            finding_meta = {}
        if finding_meta.get("cisa_kev") or finding_meta.get("has_known_exploit") or finding_meta.get("in_wild_exploit"):
            has_exploit_evidence = True
            exploit_rationale = "Cataloged in CISA KEV or verified in-the-wild exploitation activity"
        elif asset is not None and getattr(asset, "attributes", None) and isinstance(asset.attributes, dict) and (asset.attributes.get("cisa_kev") or asset.attributes.get("has_known_exploit")):
            has_exploit_evidence = True
            exploit_rationale = "Cataloged in CISA KEV or verified in-the-wild exploitation activity"
        elif getattr(finding, "reproduction_steps", None) and "EXPLOIT_VERIFIED" in str(finding.reproduction_steps):
            has_exploit_evidence = True
            exploit_rationale = "Deterministic exploit payload execution confirmed during assessment"

        exploit_mult = 1.0
        if has_exploit_evidence:
            exploit_mult = 1.20
            contributing_factors.append(
                f"Reliable exploitability evidence confirmed ({exploit_rationale}): multiplier {exploit_mult:.2f}."
            )
        else:
            missing_factors.append("Exploitability evidence: NONE VERIFIED (multiplier 1.00; not inferred).")

        # 11. Validated Attack Paths Multiplier (Never infer merely because connected)
        path_mult = 1.0
        has_verified_path = False
        if verified_attack_paths:
            for p in verified_attack_paths:
                v_status = p.get("verification_status") if isinstance(p, dict) else getattr(p, "verification_status", None)
                if str(v_status) == "VERIFIED":
                    has_verified_path = True
                    break

        if has_verified_path:
            path_mult = 1.20
            contributing_factors.append(
                f"Finding is part of a verified, evidence-backed attack path: multiplier {path_mult:.2f}."
            )
        elif verified_attack_paths:
            contributing_factors.append(
                "Attack path graph connection exists topologically but path evidence is HYPOTHETICAL or unverified: multiplier 1.00 (no exploitability inferred from bare connectivity)."
            )

        # 12. Prior Remediation Failure Penalty
        remediation_failure_mult = 1.0
        if prior_verification_failed or finding.status == FindingLifecycleStatus.REOPENED:
            remediation_failure_mult = 1.20
            contributing_factors.append(
                f"Prior remediation attempt failed verification or finding recurred on target: failure penalty multiplier {remediation_failure_mult:.2f}."
            )

        # 13. Inherent vs Residual Composite Calculation
        effective_base = base_score * conf_weight
        inherent_composite = (
            effective_base
            * crit_mult
            * exposure_mult
            * business_impact_mult
            * exploit_mult
            * path_mult
        )
        inherent_score = round(max(0.0, min(100.0, inherent_composite)), 1)

        raw_composite = (
            inherent_composite
            * fresh_mult
            * lifecycle_mult
            * recurrence_mult
            * quality_mult
            * remediation_failure_mult
        )
        final_score = round(max(0.0, min(100.0, raw_composite)), 1)
        residual_score = final_score

        # 14. Contextual Heuristic Uncertainty Range (Score Margin)
        uncertainty_margin = 3.0
        if finding.confidence == FindingConfidence.TENTATIVE:
            uncertainty_margin += 7.0
        if missing_factors:
            uncertainty_margin += min(8.0, 2.0 * len(missing_factors))
        if getattr(finding, "has_contradictions", False):
            uncertainty_margin += 8.0
        if fresh_mult < 0.90:  # Stale evidence
            uncertainty_margin += 4.0

        uncertainty_range = {
            "min_score": round(max(0.0, final_score - uncertainty_margin), 1),
            "max_score": round(min(100.0, final_score + uncertainty_margin), 1),
            "uncertainty_margin": round(uncertainty_margin, 1),
            "confidence_band": "HIGH" if uncertainty_margin <= 4.0 else ("MODERATE" if uncertainty_margin <= 10.0 else "LOW"),
        }

        # 15. Priority Determination
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

        active_version = scoring_version or cls.SCORING_VERSION

        factor_breakdown = {
            "base_score": round(base_score, 1),
            "confidence_weight": round(conf_weight, 2),
            "effective_base": round(effective_base, 1),
            "criticality_multiplier": crit_mult,
            "exposure_multiplier": exposure_mult,
            "exposure_label": exposure_label,
            "business_impact_multiplier": business_impact_mult,
            "exploit_multiplier": exploit_mult,
            "attack_path_multiplier": path_mult,
            "remediation_failure_multiplier": remediation_failure_mult,
            "freshness_multiplier": fresh_mult,
            "lifecycle_multiplier": lifecycle_mult,
            "recurrence_multiplier": recurrence_mult,
            "quality_multiplier": quality_mult,
            "inherent_score": inherent_score,
            "residual_score": residual_score,
            "final_score": final_score,
            "raw_composite": round(raw_composite, 2),
            "scoring_version": active_version,
        }

        input_snapshot = {
            "scoring_version": active_version,
            "finding_id": finding.id,
            "finding_severity": finding.severity.value,
            "finding_confidence": finding.confidence.value,
            "cvss_score": finding.cvss_score if is_valid_cvss else None,
            "finding_status": finding.status.value,
            "last_observed_at": last_obs.isoformat() if last_obs else None,
            "asset_id": asset.id if asset else None,
            "asset_criticality": asset.criticality.value if asset else None,
            "asset_type": asset.asset_type.value if asset else None,
            "business_impact": biz_impact,
            "has_exploit_evidence": has_exploit_evidence,
            "has_verified_attack_path": has_verified_path,
            "prior_verification_failed": prior_verification_failed,
            "has_contradictions": getattr(finding, "has_contradictions", False),
            "has_exposure_edge": has_exposure_edge,
            "calculation_time": current_time.isoformat(),
            "risk_accepted_expires_at": exp_iso,
            "risk_accepted_by_id": finding.risk_accepted_by_id,
            "compensating_controls": finding.compensating_controls,
            "recurrence_detected": getattr(finding, "recurrence_detected", False),
            "recurrence_count": getattr(finding, "recurrence_count", 0),
            "evidence_quality_score": getattr(finding, "evidence_quality_score", None),
        }

        return {
            "score": final_score,
            "inherent_score": inherent_score,
            "residual_score": residual_score,
            "priority": priority,
            "factor_breakdown": factor_breakdown,
            "contributing_factors": contributing_factors,
            "missing_factors": missing_factors,
            "uncertainty_range": uncertainty_range,
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

        # Check for prior verification failure on this finding
        prior_verif_failed = False
        try:
            from app.models.verification import RemediationVerification, VerificationOutcome
            latest_v = (
                db.query(RemediationVerification)
                .filter(
                    RemediationVerification.project_id == project_id,
                    RemediationVerification.finding_id == finding_id,
                )
                .order_by(RemediationVerification.created_at.desc())
                .first()
            )
            if latest_v and latest_v.outcome in (VerificationOutcome.FAILED, VerificationOutcome.INCONCLUSIVE):
                prior_verif_failed = True
        except Exception:
            pass

        # Check for validated attack paths connected to this finding
        verified_paths = []
        try:
            from app.services.attack_path_service import AttackPathAnalysisService, PathVerificationStatus
            ap_res = AttackPathAnalysisService.analyze_attack_paths(
                project_id=project_id,
                db=db,
                finding_id=finding_id,
                max_depth=3,
                max_paths=3,
            )
            for p in ap_res.get("paths", []):
                if p.get("verification_status") == PathVerificationStatus.VERIFIED.value:
                    verified_paths.append(p)
        except Exception:
            pass

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
            verified_attack_paths=verified_paths,
            prior_verification_failed=prior_verif_failed,
            now=now,
        )

        # If active assessment exists and not forcing recalculation, check if key inputs changed
        if active_assessment and not force_recalculate:
            # Formula version change mandates immediate recalculation
            if active_assessment.scoring_version != cls.SCORING_VERSION:
                force_recalculate = True
            else:
                prev_snapshot = active_assessment.input_snapshot or {}
                current_snapshot = calc["input_snapshot"]
                # Compare key deterministic drivers
                keys_to_compare = [
                    "scoring_version",
                    "finding_severity",
                    "finding_confidence",
                    "cvss_score",
                    "finding_status",
                    "asset_criticality",
                    "asset_type",
                    "has_exposure_edge",
                    "risk_accepted_expires_at",
                    "business_impact",
                    "has_exploit_evidence",
                    "has_verified_attack_path",
                    "prior_verification_failed",
                    "has_contradictions",
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
            inherent_score=calc["inherent_score"],
            residual_score=calc["residual_score"],
            priority=calc["priority"],
            scoring_version=cls.SCORING_VERSION,
            factor_breakdown=calc["factor_breakdown"],
            contributing_factors=calc["contributing_factors"],
            missing_factors=calc["missing_factors"],
            uncertainty_range=calc["uncertainty_range"],
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
