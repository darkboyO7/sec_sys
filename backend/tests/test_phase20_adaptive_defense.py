import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.user import User
from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
)
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.adaptive_defense import (
    AdaptiveMorphState,
    AdaptiveTransitionTrigger,
    MorphStatePosture,
)
from app.services.adaptive_defense_service import AdaptiveDefenseService


def test_phase20_initial_posture_and_cadence_provisioning(
    db: Session,
    test_project: Project,
):
    """Verify initial project adaptive defense provisioning defaults to NORMAL with 1.0x cadence."""
    posture = AdaptiveDefenseService.get_or_create_project_posture(test_project.id, db)

    assert posture.current_state == AdaptiveMorphState.NORMAL
    assert posture.previous_state is None
    assert posture.state_version == 1
    assert posture.kill_switch_active is False
    assert posture.monitoring_cadence_multiplier == 1.0
    assert len(posture.active_recommendations) >= 1
    assert len(posture.history) >= 1
    assert posture.history[0].trigger == AdaptiveTransitionTrigger.INITIAL_PROVISIONING


def test_phase20_empirical_signal_evaluation_and_escalation(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify multiple critical findings escalate state to CONTAINMENT_RECOMMENDED with increased cadence."""
    # Create 2 unmitigated critical findings
    f1 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase20-crit-01",
        target_value="https://edge.corp.net/auth",
        title="Critical Auth Bypass in Gateway",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        is_simulated=True,
    )
    f2 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase20-crit-02",
        target_value="https://edge.corp.net/admin",
        title="Remote Code Execution via Deserialization",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        is_simulated=True,
    )
    db.add_all([f1, f2])
    db.commit()

    # Initial evaluation from NORMAL transitions to ELEVATED / CONTAINMENT
    # First evaluate to ELEVATED_MONITORING if step-wise, or direct CONTAINMENT if legal:
    # NORMAL -> ELEVATED_MONITORING -> CONTAINMENT_RECOMMENDED
    # Let's verify evaluate_adaptive_posture handles transitions
    posture = AdaptiveDefenseService.get_or_create_project_posture(test_project.id, db)
    
    # Step transition to ELEVATED_MONITORING first
    AdaptiveDefenseService.execute_transition(
        posture=posture,
        target_state=AdaptiveMorphState.ELEVATED_MONITORING,
        trigger=AdaptiveTransitionTrigger.CRITICAL_FINDING_DETECTED,
        rationale="Initial exposure detected.",
        db=db,
    )

    # Now evaluate signals: 2 criticals trigger transition to CONTAINMENT_RECOMMENDED
    evaluated = AdaptiveDefenseService.evaluate_adaptive_posture(test_project.id, db, actor=tester_user)
    assert evaluated.current_state == AdaptiveMorphState.CONTAINMENT_RECOMMENDED
    assert evaluated.monitoring_cadence_multiplier == 4.0
    assert evaluated.previous_state == AdaptiveMorphState.ELEVATED_MONITORING
    assert len(evaluated.recovery_prerequisites) >= 1


def test_phase20_emergency_kill_switch_and_disengage(
    db: Session,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    """Verify emergency kill switch halts automation and locks to MANUAL_REVIEW_REQUIRED."""
    posture = AdaptiveDefenseService.get_or_create_project_posture(test_project.id, db)

    # 1. Engage kill switch
    engaged = AdaptiveDefenseService.engage_kill_switch(
        project_id=test_project.id,
        reason="Suspected false telemetry loop in perimeter monitors.",
        user=tester_user,
        db=db,
    )
    assert engaged.kill_switch_active is True
    assert engaged.current_state == AdaptiveMorphState.MANUAL_REVIEW_REQUIRED
    assert engaged.monitoring_cadence_multiplier == 0.5
    assert engaged.kill_switch_engaged_by_id == tester_user.id
    assert "telemetry loop" in engaged.kill_switch_reason

    # 2. Evaluations while kill switch is active remain locked in MANUAL_REVIEW_REQUIRED
    locked = AdaptiveDefenseService.evaluate_adaptive_posture(test_project.id, db)
    assert locked.current_state == AdaptiveMorphState.MANUAL_REVIEW_REQUIRED
    assert locked.kill_switch_active is True

    # 3. Disengage kill switch (Lead user gate)
    disengaged = AdaptiveDefenseService.disengage_kill_switch(
        project_id=test_project.id,
        justification="Root cause identified as benign scanner benchmark. Telemetry verified.",
        user=lead_user,
        db=db,
    )
    assert disengaged.kill_switch_active is False
    assert disengaged.current_state == AdaptiveMorphState.NORMAL
    assert disengaged.monitoring_cadence_multiplier == 1.0


def test_phase20_illegal_transitions_rejected(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify state machine strictly rejects illegal or non-sequential transitions."""
    posture = AdaptiveDefenseService.get_or_create_project_posture(test_project.id, db)
    assert posture.current_state == AdaptiveMorphState.NORMAL

    # Direct illegal leap from NORMAL to RECOVERY_COMPLETE is forbidden
    with pytest.raises(ValueError, match="Illegal posture transition"):
        AdaptiveDefenseService.execute_transition(
            posture=posture,
            target_state=AdaptiveMorphState.RECOVERY_COMPLETE,
            trigger=AdaptiveTransitionTrigger.VERIFICATION_PASSED,
            rationale="Attempting unverified leap to recovery complete",
            db=db,
            actor=tester_user,
        )


def test_phase20_api_endpoints_and_cross_project_isolation(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_headers: dict,
    tester_headers: dict,
):
    """Verify HTTP API endpoints for adaptive posture, evaluation, kill-switch, and history."""
    # 1. Get posture via API
    get_res = client.get(
        f"/api/v1/projects/{test_project.id}/adaptive-defense/posture",
        headers=tester_headers,
    )
    assert get_res.status_code == 200
    posture_data = get_res.json()
    assert posture_data["current_state"] == "NORMAL"
    assert posture_data["kill_switch_active"] is False

    # 2. Evaluate posture via API
    eval_res = client.post(
        f"/api/v1/projects/{test_project.id}/adaptive-defense/evaluate",
        headers=tester_headers,
    )
    assert eval_res.status_code == 200
    assert eval_res.json()["current_state"] in ("NORMAL", "ELEVATED_MONITORING")

    # 3. Engage kill switch via API
    kill_res = client.post(
        f"/api/v1/projects/{test_project.id}/adaptive-defense/kill-switch/engage",
        headers=tester_headers,
        json={"reason": "Emergency security hold ordered by CISO."},
    )
    assert kill_res.status_code == 200
    assert kill_res.json()["kill_switch_active"] is True
    assert kill_res.json()["current_state"] == "MANUAL_REVIEW_REQUIRED"

    # 4. Disengage kill switch via API using Lead headers
    dis_res = client.post(
        f"/api/v1/projects/{test_project.id}/adaptive-defense/kill-switch/disengage",
        headers=lead_headers,
        json={"justification": "Incident investigation complete. Cleared for normal operation."},
    )
    assert dis_res.status_code == 200
    assert dis_res.json()["kill_switch_active"] is False
    assert dis_res.json()["current_state"] == "NORMAL"

    # 5. Get transition history via API
    hist_res = client.get(
        f"/api/v1/projects/{test_project.id}/adaptive-defense/history",
        headers=tester_headers,
    )
    assert hist_res.status_code == 200
    history = hist_res.json()
    assert len(history) >= 2

    # 6. Cross-project isolation: non-existent project returns 404
    iso_res = client.get(
        "/api/v1/projects/00000000-0000-0000-0000-000000000000/adaptive-defense/posture",
        headers=tester_headers,
    )
    assert iso_res.status_code == 404
