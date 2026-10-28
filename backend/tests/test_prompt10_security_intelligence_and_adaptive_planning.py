import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember, ProjectRole
from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
)
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingSeverity,
    FindingConfidence,
    FindingEvidence,
)
from app.models.risk import (
    RiskAssessment,
    RiskPriority,
    RemediationRecommendation,
    RecommendationStatus,
)
from app.models.verification import RemediationVerification, VerificationOutcome
from app.models.graph import GraphRelationship, RelationshipType, RelationshipStatus
from app.models.decision import (
    PostureChangeRecord,
    ChangeType,
    AdaptiveAssessmentPlanRecord,
    PlanStatus,
)
from app.models.learning import (
    LearningDataset,
    GovernedModel,
    PredictionLedger,
    PredictionType,
    PredictionEvaluationStatus,
    ModelStatus,
)
from app.services.contextual_risk_service import ContextualRiskService
from app.services.security_intelligence_service import SecurityIntelligenceService
from app.services.learning_service import ModelGovernanceService, PredictionLedgerService
from app.services.scope_engine import ScopeEngine
from app.models.base import utc_now


# ------------------------------------------------------------------------------
# Test 1: Deterministic Risk Scoring
# ------------------------------------------------------------------------------
def test_identical_inputs_produce_identical_scores_deterministically(
    db: Session,
    test_project: Project,
    test_organization: Organization,
):
    """
    Proves that identical inputs produce 100% identical risk scores and factors
    for a fixed model version across repeated evaluations.
    """
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)

    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Deterministic Payment Gateway",
        canonical_identifier="https://pay.acme.local",
        criticality=AssetCriticality.HIGH,
        attributes={"business_impact": "HIGH"},
    )
    db.add(asset)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-p10-det-01",
        target_value="https://pay.acme.local/checkout",
        title="SQL Injection in Order ID Parameter",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        cvss_score=8.4,
        evidence_quality_score=0.95,
        last_observed_at=now - timedelta(days=2),
    )
    db.add(finding)
    db.flush()

    # Run 50 iterations with identical inputs
    baseline = ContextualRiskService.calculate_score_and_factors(
        finding=finding,
        asset=asset,
        now=now,
    )

    for i in range(50):
        iteration = ContextualRiskService.calculate_score_and_factors(
            finding=finding,
            asset=asset,
            now=now,
        )
        assert iteration["score"] == baseline["score"]
        assert iteration["inherent_score"] == baseline["inherent_score"]
        assert iteration["residual_score"] == baseline["residual_score"]
        assert iteration["priority"] == baseline["priority"]
        assert iteration["factor_breakdown"] == baseline["factor_breakdown"]
        assert iteration["contributing_factors"] == baseline["contributing_factors"]
        assert iteration["missing_factors"] == baseline["missing_factors"]
        assert iteration["uncertainty_range"] == baseline["uncertainty_range"]
        assert iteration["input_snapshot"] == baseline["input_snapshot"]


# ------------------------------------------------------------------------------
# Test 2: Risk Explanations Match Score Calculations
# ------------------------------------------------------------------------------
def test_risk_explanations_match_score_calculation(
    db: Session,
    test_project: Project,
    test_organization: Organization,
):
    """
    Proves that contributing and missing factors match the score calculation line-by-line.
    """
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)

    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Customer Portal",
        canonical_identifier="https://portal.acme.local",
        criticality=AssetCriticality.CRITICAL,
        attributes={"business_impact": "CRITICAL", "has_known_exploit": True},
    )
    db.add(asset)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-p10-expl-01",
        target_value="https://portal.acme.local/api",
        title="Remote Code Execution via File Upload",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        cvss_score=9.8,
        reproduction_steps="EXPLOIT_VERIFIED: Deterministic execution",
        last_observed_at=now - timedelta(days=1),
    )
    db.add(finding)
    db.flush()

    calc = ContextualRiskService.calculate_score_and_factors(
        finding=finding,
        asset=asset,
        prior_verification_failed=True,
        now=now,
    )

    fb = calc["factor_breakdown"]
    cf = calc["contributing_factors"]

    # 1. Base severity & CVSS
    assert any("Base severity 'CRITICAL' anchored by CVSS score 9.8" in s for s in cf)
    assert fb["base_score"] == 98.0

    # 2. Asset Criticality
    assert any("criticality 'CRITICAL' multiplier: 1.35" in s for s in cf)
    assert fb["criticality_multiplier"] == 1.35

    # 3. Business Impact
    assert any("business impact configured as 'CRITICAL': multiplier 1.25" in s for s in cf)
    assert fb["business_impact_multiplier"] == 1.25

    # 4. Exploitability Evidence
    assert any("Reliable exploitability evidence confirmed" in s for s in cf)
    assert fb["exploit_multiplier"] == 1.20

    # 5. Prior Remediation Failure Penalty
    assert any("failure penalty multiplier 1.20" in s for s in cf)
    assert fb["remediation_failure_multiplier"] == 1.20


# ------------------------------------------------------------------------------
# Test 3: Stale Evidence Cannot Silently Retain Confidence
# ------------------------------------------------------------------------------
def test_stale_evidence_cannot_silently_retain_unjustified_confidence(
    db: Session,
    test_project: Project,
    test_organization: Organization,
):
    """
    Proves that observation staleness decays the freshness multiplier, reduces confidence,
    and widens the heuristic uncertainty margin.
    """
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)

    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Stale Legacy App",
        canonical_identifier="https://legacy.acme.local",
        criticality=AssetCriticality.MEDIUM,
    )
    db.add(asset)
    db.flush()

    # Fresh Finding (1 day old)
    fresh_finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-p10-fresh-01",
        target_value="https://legacy.acme.local",
        title="Missing Content-Security-Policy",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        last_observed_at=now - timedelta(days=1),
    )
    # Stale Finding (120 days old)
    stale_finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-p10-stale-01",
        target_value="https://legacy.acme.local",
        title="Missing Content-Security-Policy",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        last_observed_at=now - timedelta(days=120),
    )
    db.add_all([fresh_finding, stale_finding])
    db.flush()

    fresh_calc = ContextualRiskService.calculate_score_and_factors(finding=fresh_finding, asset=asset, now=now)
    stale_calc = ContextualRiskService.calculate_score_and_factors(finding=stale_finding, asset=asset, now=now)

    # Fresh multiplier vs Stale multiplier
    assert fresh_calc["factor_breakdown"]["freshness_multiplier"] == 1.00
    assert stale_calc["factor_breakdown"]["freshness_multiplier"] == 0.70
    assert any("Observation is fresh" in s for s in fresh_calc["contributing_factors"])
    assert any("Observation is stale" in s for s in stale_calc["contributing_factors"])

    # Uncertainty margin must be wider on stale evidence
    assert stale_calc["uncertainty_range"]["uncertainty_margin"] > fresh_calc["uncertainty_range"]["uncertainty_margin"]


# ------------------------------------------------------------------------------
# Test 4: Unknown Business Impact is Not Inferred
# ------------------------------------------------------------------------------
def test_unknown_business_impact_is_not_treated_as_known(
    db: Session,
    test_project: Project,
    test_organization: Organization,
):
    """
    Proves that potential business impact is NEVER invented when unconfigured.
    """
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)

    # Asset with NO business impact configured
    asset_unconfigured = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Unknown Impact Service",
        canonical_identifier="https://unknown.acme.local",
        criticality=AssetCriticality.MEDIUM,
        attributes={},  # No business impact
    )
    db.add(asset_unconfigured)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset_unconfigured.id,
        fingerprint="fp-p10-no-biz-01",
        target_value="https://unknown.acme.local",
        title="Information Disclosure via Server Header",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.DETECTED,
        last_observed_at=now,
    )
    db.add(finding)
    db.flush()

    calc = ContextualRiskService.calculate_score_and_factors(finding=finding, asset=asset_unconfigured, now=now)

    # Business impact must be neutral (1.00)
    assert calc["factor_breakdown"]["business_impact_multiplier"] == 1.00
    assert calc["input_snapshot"]["business_impact"] is None

    # Must be explicitly recorded in missing_factors
    assert any("Potential business impact: UNKNOWN / NOT CONFIGURED" in s for s in calc["missing_factors"])


# ------------------------------------------------------------------------------
# Test 5: Topological Connection Alone Does Not Amplify Risk
# ------------------------------------------------------------------------------
def test_topological_connection_without_verified_exploitability_does_not_amplify_risk(
    db: Session,
    test_project: Project,
    test_organization: Organization,
):
    """
    Proves rule 5: Never infer that an attack path is exploitable merely because two assets are connected.
    """
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)

    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Connected Node",
        canonical_identifier="https://connected.acme.local",
        criticality=AssetCriticality.MEDIUM,
    )
    db.add(asset)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-p10-topo-01",
        target_value="https://connected.acme.local",
        title="Path Traversal in Static Asset Handler",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.DETECTED,
        last_observed_at=now,
    )
    db.add(finding)
    db.flush()

    # 1. Mere topological / hypothetical path
    hypothetical_paths = [{"path_id": "p-hypo-1", "verification_status": "HYPOTHETICAL"}]
    calc_hypo = ContextualRiskService.calculate_score_and_factors(
        finding=finding,
        asset=asset,
        verified_attack_paths=hypothetical_paths,
        now=now,
    )
    assert calc_hypo["factor_breakdown"]["attack_path_multiplier"] == 1.00
    assert any("no exploitability inferred from bare connectivity" in s for s in calc_hypo["contributing_factors"])

    # 2. Genuine verified attack path
    verified_paths = [{"path_id": "p-verif-1", "verification_status": "VERIFIED"}]
    calc_verif = ContextualRiskService.calculate_score_and_factors(
        finding=finding,
        asset=asset,
        verified_attack_paths=verified_paths,
        now=now,
    )
    assert calc_verif["factor_breakdown"]["attack_path_multiplier"] == 1.20
    assert any("part of a verified, evidence-backed attack path" in s for s in calc_verif["contributing_factors"])


# ------------------------------------------------------------------------------
# Test 6: Prior Remediation Failure Penalty
# ------------------------------------------------------------------------------
def test_prior_remediation_failure_increases_risk_priority(
    db: Session,
    test_project: Project,
    test_organization: Organization,
):
    """
    Proves that a prior failed remediation verification increases priority.
    """
    now = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)

    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Recurrent Vulnerability Target",
        canonical_identifier="https://app.acme.local",
        criticality=AssetCriticality.HIGH,
    )
    db.add(asset)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-p10-fail-remed-01",
        target_value="https://app.acme.local/login",
        title="Stored XSS in Comment Field",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.REOPENED,
        last_observed_at=now,
    )
    db.add(finding)
    db.flush()

    calc = ContextualRiskService.calculate_score_and_factors(
        finding=finding,
        asset=asset,
        prior_verification_failed=True,
        now=now,
    )

    assert calc["factor_breakdown"]["remediation_failure_multiplier"] == 1.20
    assert any("failure penalty multiplier 1.20" in s for s in calc["contributing_factors"])


# ------------------------------------------------------------------------------
# Test 7: Adaptive Planner Respects Scope and Budget
# ------------------------------------------------------------------------------
def test_adaptive_planner_respects_scope_and_budget(
    db: Session,
    test_project: Project,
    test_organization: Organization,
    lead_user: User,
):
    """
    Proves that the adaptive assessment planner:
    - Recommends authorized targets.
    - Rejects out-of-scope targets into skipped checks with explicit reason.
    - Clamps recommendations strictly within configured scan budget.
    """
    now = utc_now()

    # 1. Authorized target
    t1 = ScopeTarget(
        project_id=test_project.id,
        target_value="https://authorized.acme.local",
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-AUTH-001",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add(t1)

    # 2. Add an out-of-scope posture change
    c_out = PostureChangeRecord(
        project_id=test_project.id,
        change_type=ChangeType.CONFIG_CHANGED,
        target_resource="https://external-attacker.com",
        title="Unauthorized External Target Modified",
        previous_state={},
        new_state={"open_ports": [80, 443]},
        evidence_summary="Discovered on public DNS",
        is_confirmed=True,
    )
    # 3. Add an authorized posture change
    c_in = PostureChangeRecord(
        project_id=test_project.id,
        change_type=ChangeType.CONFIG_CHANGED,
        target_resource="https://authorized.acme.local",
        title="Authorized Target TLS Config Updated",
        previous_state={"tls": "1.1"},
        new_state={"tls": "1.3"},
        evidence_summary="TLS negotiation changed",
        is_confirmed=True,
    )
    db.add_all([c_out, c_in])
    db.commit()

    # Generate plan with scan budget = 1
    plan = SecurityIntelligenceService.generate_adaptive_assessment_plan(
        db=db,
        project_id=test_project.id,
        scan_budget=1,
        creator=lead_user,
    )

    # 1. Verify plan bounds
    assert plan.total_recommended <= 1
    assert len(plan.recommended_checks) <= 1

    # 2. Out-of-scope target was skipped
    skipped_targets = [s["target"] for s in plan.skipped_checks]
    assert "https://external-attacker.com" in skipped_targets
    out_of_scope_skip = next(s for s in plan.skipped_checks if s["target"] == "https://external-attacker.com")
    assert out_of_scope_skip["skip_reason"] == "OUT_OF_SCOPE"

    # 3. Recommended check is the authorized target
    assert plan.recommended_checks[0]["target"] == "https://authorized.acme.local"
    assert plan.recommended_checks[0]["reason_category"] == "CHANGE_REASSESSMENT"


# ------------------------------------------------------------------------------
# Test 8: Adaptive Planner Skips Recent Clean Work and Identifies Stale Assets
# ------------------------------------------------------------------------------
def test_adaptive_planner_recommends_stale_and_skips_recent_clean_assets(
    db: Session,
    test_project: Project,
    test_organization: Organization,
    lead_user: User,
):
    """
    Proves that recent clean assessments skip redundant scanning, while stale assets
    are flagged and prioritized for coverage recovery.
    """
    now = utc_now()

    # Target A: Fresh clean scan 2 hours ago
    t_fresh = ScopeTarget(
        project_id=test_project.id,
        target_value="https://fresh-clean.acme.local",
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-AUTH-FRESH",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    # Target B: Stale asset assessed 30 days ago
    t_stale = ScopeTarget(
        project_id=test_project.id,
        target_value="https://stale-asset.acme.local",
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-AUTH-STALE",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add_all([t_fresh, t_stale])
    db.flush()

    # Asset for stale target
    asset_stale = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Stale Service",
        canonical_identifier="https://stale-asset.acme.local",
        criticality=AssetCriticality.HIGH,
        last_seen_at=now - timedelta(days=30),
    )
    db.add(asset_stale)

    # Job for fresh target
    job_fresh = AssessmentJob(
        project_id=test_project.id,
        target_input="https://fresh-clean.acme.local",
        adapter_name="web_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
        created_at=now - timedelta(hours=2),
    )
    db.add(job_fresh)
    db.commit()

    plan = SecurityIntelligenceService.generate_adaptive_assessment_plan(
        db=db,
        project_id=test_project.id,
        scan_budget=10,
        creator=lead_user,
    )

    rec_targets = [r["target"] for r in plan.recommended_checks]
    skp_targets = [s["target"] for s in plan.skipped_checks]

    # Stale asset must be recommended
    assert "https://stale-asset.acme.local" in rec_targets

    # Fresh asset must be skipped to avoid redundant work
    assert "https://fresh-clean.acme.local" in skp_targets
    fresh_skip = next(s for s in plan.skipped_checks if s["target"] == "https://fresh-clean.acme.local")
    assert fresh_skip["skip_reason"] == "RECENT_CLEAN_ASSESSMENT"


# ------------------------------------------------------------------------------
# Test 9: Duplicate Monitoring Events and Event Storm Throttling
# ------------------------------------------------------------------------------
def test_duplicate_monitoring_events_and_storm_throttling(
    db: Session,
    test_project: Project,
):
    """
    Proves that:
    1. Duplicate events within 15 minutes are deduplicated.
    2. Rapid-fire event storms (>5 events in 60s) trigger throttle suppression.
    """
    target = "https://storm-target.acme.local"

    # 1. Initial event
    res1 = SecurityIntelligenceService.record_posture_change_with_throttle(
        db=db,
        project_id=test_project.id,
        change_type=ChangeType.CONFIG_CHANGED,
        target_resource=target,
        title="TLS Protocol Update",
        previous_state={"tls": "1.2"},
        new_state={"tls": "1.3"},
        evidence_summary="First observation",
    )
    assert res1["status"] == "RECORDED"
    assert res1["reassessment_recommended"] is True

    # 2. Duplicate event within 15 minutes
    res2 = SecurityIntelligenceService.record_posture_change_with_throttle(
        db=db,
        project_id=test_project.id,
        change_type=ChangeType.CONFIG_CHANGED,
        target_resource=target,
        title="TLS Protocol Update",
        previous_state={"tls": "1.2"},
        new_state={"tls": "1.3"},
        evidence_summary="Duplicate probe observation",
    )
    assert res2["status"] == "DEDUPLICATED"
    assert res2["reassessment_recommended"] is False

    # 3. Simulate event storm (create 5 additional unique events rapidly)
    for i in range(5):
        db.add(
            PostureChangeRecord(
                project_id=test_project.id,
                change_type=ChangeType.NEW_FINDING,
                target_resource=target,
                title=f"Rapid Storm Event {i}",
                previous_state={},
                new_state={"port": 8000 + i},
                evidence_summary="Burst telemetry",
                is_confirmed=True,
            )
        )
    db.commit()

    # Next event triggers storm throttle
    res_storm = SecurityIntelligenceService.record_posture_change_with_throttle(
        db=db,
        project_id=test_project.id,
        change_type=ChangeType.RISK_SCORE_CHANGED,
        target_resource=target,
        title="Spike in Risk",
        previous_state={},
        new_state={},
        evidence_summary="High volume event",
    )
    assert res_storm["status"] == "THROTTLED_STORM"
    assert res_storm["reassessment_recommended"] is False


# ------------------------------------------------------------------------------
# Test 10: Inconclusive Outcomes Do Not Become False Negatives
# ------------------------------------------------------------------------------
def test_inconclusive_outcomes_do_not_become_false_negatives(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """
    Proves rule: Keep inconclusive outcomes separate from confirmed negatives.
    An inconclusive test result must NEVER be recorded as VERIFIED_INACCURATE.
    """
    pred = PredictionLedgerService.record_prediction(
        project_id=test_project.id,
        target_entity_type="finding",
        target_entity_id="f-inconc-01",
        prediction_type=PredictionType.FALSE_POSITIVE_LIKELIHOOD,
        predicted_outcome="FALSE_POSITIVE",
        confidence_score=0.85,
        feature_snapshot={"title": "Potential False Positive"},
        db=db,
    )

    # Evaluate with INCONCLUSIVE outcome (e.g. host unreachable or probe timeout)
    evaluated = PredictionLedgerService.evaluate_prediction(
        prediction_id=pred.id,
        project_id=test_project.id,
        actual_outcome="INCONCLUSIVE",
        user=tester_user,
        db=db,
    )

    assert evaluated.evaluation_status == PredictionEvaluationStatus.INCONCLUSIVE
    assert evaluated.evaluation_status != PredictionEvaluationStatus.VERIFIED_INACCURATE

    # Check metrics computation
    metrics = PredictionLedgerService.calculate_drift_metrics(project_id=test_project.id, db=db)
    assert metrics["inconclusive_count"] == 1
    assert metrics["inaccurate_count"] == 0
    assert metrics["inconclusive_rate"] == 1.0


# ------------------------------------------------------------------------------
# Test 11: Unverified Findings Cannot Be Used As Confirmed Learning Labels
# ------------------------------------------------------------------------------
def test_unverified_findings_cannot_be_used_as_confirmed_learning_labels(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """
    Proves that findings in unverified states (DETECTED, NEEDS_VALIDATION)
    are strictly excluded from confirmed learning datasets.
    """
    # 1. Confirmed Finding
    f_confirmed = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p10-learn-conf",
        target_value="https://test.local",
        title="Confirmed SQLi",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
    )
    # 2. False Positive Finding
    f_fp = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p10-learn-fp",
        target_value="https://test.local",
        title="Disproved Header Alert",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.TENTATIVE,
        status=FindingLifecycleStatus.FALSE_POSITIVE,
    )
    # 3. Unverified Finding (DETECTED - NOT YET TRIAGED)
    f_unverified = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p10-learn-unverif",
        target_value="https://test.local",
        title="Unverified Candidate Alert",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.TENTATIVE,
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add_all([f_confirmed, f_fp, f_unverified])
    db.commit()

    # Curate operational dataset without synthetic padding
    dataset = ModelGovernanceService.curate_dataset(
        project_id=test_project.id,
        name="Operational Verified Dataset",
        version="v-op-2026.1",
        user=tester_user,
        db=db,
        allow_synthetic_benchmark=False,
    )

    # Only confirmed and false positive findings should be included
    records = dataset.records
    source_ids = {r.source_entity_id for r in records}

    assert f_confirmed.id in source_ids
    assert f_fp.id in source_ids
    # Unverified finding MUST NOT be in learning dataset!
    assert f_unverified.id not in source_ids
    assert dataset.total_records == 2


# ------------------------------------------------------------------------------
# Test 12: Insufficient Learning Data Produces Explicit State
# ------------------------------------------------------------------------------
def test_insufficient_learning_data_produces_explicit_state(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """
    Proves rule: If there is insufficient verified data for machine learning,
    report that the dataset is insufficient. Do not fabricate training samples.
    """
    # Project has 0 findings
    dataset = ModelGovernanceService.curate_dataset(
        project_id=test_project.id,
        name="Zero Data Test Dataset",
        version="v-zero-1",
        user=tester_user,
        db=db,
        allow_synthetic_benchmark=False,
    )

    assert dataset.total_records == 0
    assert dataset.train_count == 0
    assert dataset.test_count == 0

    # Summary reports INSUFFICIENT_DATA and rules baseline
    summary = SecurityIntelligenceService.get_project_intelligence_summary(db=db, project_id=test_project.id)
    lp = summary["learning_pipeline"]
    assert lp["learning_data_sufficiency"] == "INSUFFICIENT_DATA"
    assert lp["is_rules_baseline"] is True


# ------------------------------------------------------------------------------
# Test 13: Dashboard Aggregates Match Persisted Records
# ------------------------------------------------------------------------------
def test_dashboard_aggregates_match_persisted_records(
    db: Session,
    test_project: Project,
    test_organization: Organization,
    lead_user: User,
):
    """
    Proves that intelligence summary metrics and provenance digests exactly match
    the underlying database entity counts.
    """
    now = utc_now()

    # Add 2 assets
    a1 = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="App Alpha",
        canonical_identifier="https://alpha.acme.local",
        criticality=AssetCriticality.HIGH,
        last_seen_at=now,
    )
    a2 = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.API_ENDPOINT,
        name="API Beta",
        canonical_identifier="https://beta.acme.local",
        criticality=AssetCriticality.CRITICAL,
        last_seen_at=now,
    )
    db.add_all([a1, a2])

    # Add 1 finding with evidence
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://alpha.acme.local",
        adapter_name="web_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.flush()

    af = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        target_value="https://alpha.acme.local",
        title="SQL Injection",
        description="SQL injection vulnerability",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
    )
    db.add(af)
    db.flush()

    ev = FindingEvidence(
        finding_id=af.id,
        evidence_type="HTTP_RESPONSE",
        payload="HTTP/1.1 500 Syntax error in SQL statement",
        sha256_hash="e" * 64,
    )
    db.add(ev)

    f = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-p10-prov-01",
        target_value="https://alpha.acme.local",
        title="SQL Injection",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        last_observed_at=now,
    )
    db.add(f)
    db.flush()

    # Assess risk
    ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=f.id,
        db=db,
    )
    db.commit()

    summary = SecurityIntelligenceService.get_project_intelligence_summary(db=db, project_id=test_project.id)
    prov = summary["data_provenance"]

    assert prov["total_assets"] == 2
    assert prov["total_findings"] == 1
    assert prov["total_evidence_records"] == 1
    assert summary["risk_summary"]["total_findings"] == 1
    assert summary["risk_summary"]["active_findings"] == 1
    assert summary["coverage_audit"]["total_assets"] == 2
    assert summary["coverage_audit"]["covered_assets_count"] == 2


# ------------------------------------------------------------------------------
# Test 14: Endpoints Integration via HTTP Client
# ------------------------------------------------------------------------------
def test_intelligence_api_endpoints_integration(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_user: User,
    lead_headers: dict,
):
    """
    Verifies that the new /api/v1/projects/{project_id}/intelligence endpoints
    respond with valid JSON contracts under authenticated role access.
    """
    # 1. Overview endpoint
    res_overview = client.get(
        f"/api/v1/projects/{test_project.id}/intelligence/overview",
        headers=lead_headers,
    )
    assert res_overview.status_code == 200, res_overview.text
    ov_data = res_overview.json()
    assert ov_data["project_id"] == test_project.id
    assert "risk_summary" in ov_data
    assert "coverage_audit" in ov_data
    assert "learning_pipeline" in ov_data

    # 2. Coverage audit endpoint
    res_cov = client.get(
        f"/api/v1/projects/{test_project.id}/intelligence/coverage?stale_days=7",
        headers=lead_headers,
    )
    assert res_cov.status_code == 200, res_cov.text
    cov_data = res_cov.json()
    assert "coverage_percentage" in cov_data
    assert cov_data["stale_days_threshold"] == 7

    # 3. Generate adaptive plan endpoint
    res_plan = client.post(
        f"/api/v1/projects/{test_project.id}/intelligence/plans/generate",
        json={"scan_budget": 5},
        headers=lead_headers,
    )
    assert res_plan.status_code == 200, res_plan.text
    plan_data = res_plan.json()
    assert plan_data["project_id"] == test_project.id
    assert plan_data["scan_budget"] == 5
    assert plan_data["status"] == "GENERATED"
    assert "recommended_checks" in plan_data
    assert "skipped_checks" in plan_data

    # 4. Get latest plan endpoint
    res_latest = client.get(
        f"/api/v1/projects/{test_project.id}/intelligence/plans/latest",
        headers=lead_headers,
    )
    assert res_latest.status_code == 200, res_latest.text
    latest_data = res_latest.json()
    assert latest_data["id"] == plan_data["id"]
