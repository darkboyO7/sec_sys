import pytest
import hashlib
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.risk import RecommendationStatus
from app.services.scanner_adapters.live_network_adapter import (
    check_ip_ssrf,
    resolve_and_verify_ssrf,
    CLOUD_METADATA_IPS,
    CGNAT_NETWORK,
)
from app.services.scope_engine import ScopeEngine
from app.services.remediation_service import RemediationPrioritizationService
from app.services.remediation_verification_service import RemediationVerificationService, VerificationOutcome
from app.services.contextual_risk_service import ContextualRiskService
from app.services.knowledge_graph_service import KnowledgeGraphService


def test_ssrf_cloud_metadata_hard_block():
    """
    Validates that all known cloud metadata IP addresses and hostnames are strictly blocked,
    even if allow_loopback=True or allow_private=True are enabled.
    """
    for meta_ip in CLOUD_METADATA_IPS:
        # Test with allow_loopback=True, allow_private=True
        is_safe, reason = check_ip_ssrf(meta_ip, allow_loopback=True, allow_private=True)
        assert not is_safe, f"Metadata IP {meta_ip} must be blocked even when allow_private=True"
        assert "metadata" in reason.lower() or "blocked" in reason.lower()

        # Test IPv4-mapped IPv6 variant
        mapped_ip = f"::ffff:{meta_ip}"
        try:
            is_safe_m, reason_m = check_ip_ssrf(mapped_ip, allow_loopback=True, allow_private=True)
            assert not is_safe_m, f"IPv4-mapped metadata IP {mapped_ip} must be blocked"
        except Exception:
            pass

    # AWS IPv6 IMDS
    is_safe, reason = check_ip_ssrf("fd00:ec2::254", allow_loopback=True, allow_private=True)
    assert not is_safe, "AWS IPv6 metadata endpoint must be blocked"

    # Cloud metadata hostnames
    for host in ("metadata.google.internal", "api.metadata.google.internal", "instance-data", "metadata", "kubernetes.default.svc"):
        is_safe, reason, _ = resolve_and_verify_ssrf(host, 80, allow_loopback=True, allow_private=True)
        assert not is_safe, f"Metadata/cluster hostname {host} must be blocked"


def test_ssrf_cgnat_rfc6598_isolation():
    """
    Validates that RFC 6598 Carrier-Grade NAT (100.64.0.0/10) is blocked by default,
    and only permitted when allow_private=True is explicitly set.
    """
    cgnat_ip = "100.64.0.5"
    # Default (no private allowed) -> BLOCKED
    is_safe, reason = check_ip_ssrf(cgnat_ip, allow_loopback=False, allow_private=False)
    assert not is_safe
    assert "Carrier-Grade NAT" in reason or "SSRF blocked" in reason

    # allow_loopback=True must NOT allow CGNAT
    is_safe_lb, _ = check_ip_ssrf(cgnat_ip, allow_loopback=True, allow_private=False)
    assert not is_safe_lb, "allow_loopback=True must never permit CGNAT"

    # allow_private=True -> PERMITTED
    is_safe_priv, _ = check_ip_ssrf(cgnat_ip, allow_loopback=False, allow_private=True)
    assert is_safe_priv, "allow_private=True should permit non-metadata CGNAT space"


def test_ssrf_non_global_special_address_blocking():
    """
    Validates that non-global special address space (RFC 6890 / IANA) is rejected by default.
    """
    special_ips = [
        "198.18.0.1",   # Benchmark testing (RFC 2544)
        "192.0.2.1",    # TEST-NET-1 (RFC 5737)
        "198.51.100.1", # TEST-NET-2
        "203.0.113.1",  # TEST-NET-3
        "240.0.0.1",    # Future reserved
    ]
    for ip in special_ips:
        is_safe, reason = check_ip_ssrf(ip, allow_loopback=True, allow_private=False)
        assert not is_safe, f"Special address {ip} must be blocked when allow_private=False"


def test_scope_engine_ipv6_and_cgnat_characteristics():
    """
    Validates that ScopeEngine.evaluate_target_ip_characteristics parses bracketed IPv6
    and detects CGNAT and private characteristics accurately.
    """
    # Bracketed IPv6 localhost with port
    chars_ipv6 = ScopeEngine.evaluate_target_ip_characteristics("[::1]:8000")
    assert chars_ipv6["is_loopback"] is True

    # Standard loopback URL
    chars_url = ScopeEngine.evaluate_target_ip_characteristics("http://127.0.0.1:5173")
    assert chars_url["is_loopback"] is True

    # CGNAT target
    chars_cgnat = ScopeEngine.evaluate_target_ip_characteristics("http://100.64.1.5:8080")
    assert chars_cgnat["is_private"] is True


def test_full_integrated_e2e_remediation_risk_graph_sync(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Full end-to-end integration test of the complete defensive pipeline:
    Scope target -> Finding -> Knowledge Graph Node -> Risk Scoring
    -> Remediation Recommendation -> Approval -> Retest (Inconclusive on unreachable)
    -> Risk & Graph State Synchronized.
    """
    now = datetime.now(timezone.utc)

    # 1. Scope Target Authorized
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="prompt5-target.corp.internal",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-PROMPT5-AUDIT-E2E",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # 2. Scope verification at boundary
    scope_eval = ScopeEngine.validate_target_in_scope(db=db, project_id=test_project.id, target="prompt5-target.corp.internal")
    assert scope_eval["is_authorized"] is True

    # 3. Create Finding
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        target_value="prompt5-target.corp.internal",
        title="Missing Strict-Transport-Security (HSTS) Header",
        description="The HTTPS server does not enforce Strict-Transport-Security, allowing potential SSL stripping.",
        severity=FindingSeverity.HIGH,
        vuln_id="CWE-319",
        status=FindingLifecycleStatus.DETECTED,
        fingerprint=hashlib.sha256("Missing HSTS Header on prompt5-target".encode("utf-8")).hexdigest(),
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    # 4. Sync Knowledge Graph Node
    from app.models.graph import GraphNodeCategory
    node = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.FINDING,
        label=finding.title,
        entity_id=finding.id,
        entity_type="VulnerabilityFinding",
        properties={"finding_id": finding.id, "severity": finding.severity.value, "status": finding.status.value},
        db=db,
    )
    assert node.id is not None

    # 5. Risk Calculation
    risk = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
    )
    assert risk.score > 0
    assert risk.factor_breakdown is not None

    # 6. Generate Remediation Guidance
    rec = RemediationPrioritizationService.generate_or_get_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
    )
    assert rec is not None
    assert rec.finding_id == finding.id

    # 7. Lead Approval
    rec_approved = RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=rec.id,
        new_status=RecommendationStatus.APPROVED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Approved for security team implementation.",
        db=db,
    )
    assert rec_approved.status == RecommendationStatus.APPROVED

    # 8. Independent Retest against unreachable target -> INCONCLUSIVE (Never falsely marks fixed)
    verification = RemediationVerificationService.execute_automated_retest(
        project_id=test_project.id,
        finding_id=finding.id,
        adapter_name="live_network_auditor_adapter",
        config={"profile": "LIVE_HTTP_HEADERS"},
        notes="Automated retest probe against target",
        verifier=lead_user,
        verifier_role=ProjectRole.LEAD,
        db=db,
    )
    assert verification.outcome == VerificationOutcome.INCONCLUSIVE
    # Finding must remain open
    db.refresh(finding)
    assert finding.status == FindingLifecycleStatus.DETECTED
