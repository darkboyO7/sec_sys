import pytest
from datetime import datetime, timedelta, timezone
from app.services.scope_engine import ScopeEngine, ScopeTargetParseException
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.project import Project
from app.models.user import User


def test_target_normalization_valid_types():
    # IPv4
    t_type, norm = ScopeEngine.normalize_target("192.168.1.100")
    assert t_type == TargetType.IP_ADDRESS
    assert norm == "192.168.1.100"

    # IPv6
    t_type, norm = ScopeEngine.normalize_target("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert t_type == TargetType.IP_ADDRESS
    assert norm == "2001:db8:85a3::8a2e:370:7334"

    # CIDR
    t_type, norm = ScopeEngine.normalize_target("10.0.0.0/16")
    assert t_type == TargetType.CIDR
    assert norm == "10.0.0.0/16"

    # Domain
    t_type, norm = ScopeEngine.normalize_target("API.SECURITY.CORP")
    assert t_type == TargetType.DOMAIN
    assert norm == "api.security.corp"

    # Wildcard Domain
    t_type, norm = ScopeEngine.normalize_target("*.SUB.EXAMPLE.COM")
    assert t_type == TargetType.DOMAIN
    assert norm == "*.sub.example.com"

    # URL
    t_type, norm = ScopeEngine.normalize_target("HTTPS://App.Example.Com:8443/v1/api?query=1")
    assert t_type == TargetType.URL
    assert norm == "https://app.example.com:8443/v1/api?query=1"


def test_target_normalization_invalid_types():
    with pytest.raises(ScopeTargetParseException):
        ScopeEngine.normalize_target("999.999.999.999")

    with pytest.raises(ScopeTargetParseException):
        ScopeEngine.normalize_target("ftp://unsupported-scheme.com")

    with pytest.raises(ScopeTargetParseException):
        ScopeEngine.normalize_target("")

    with pytest.raises(ScopeTargetParseException):
        ScopeEngine.normalize_target("not a valid target --!!")


def test_exclusions_preempt_authorized_inclusions(db, test_project: Project, lead_user: User):
    # Register authorized CIDR: 192.168.10.0/24
    authorized_net = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.CIDR,
        target_value="192.168.10.0/24",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-SEC-2026-001 Signed by CISO",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(authorized_net)

    # Register exclusion for Default Gateway / Core Router: 192.168.10.1
    exclusion = ScopeExclusion(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="192.168.10.1",
        reason="Core internal switch gateway - Strictly out of scope",
        created_by_id=lead_user.id,
    )
    db.add(exclusion)
    db.commit()

    # Evaluating the excluded host must be strictly DENIED
    eval_excl = ScopeEngine.validate_target_in_scope(db, test_project.id, "192.168.10.1")
    assert eval_excl["is_authorized"] is False
    assert eval_excl["status"] == "EXCLUDED"
    assert "Core internal switch gateway" in eval_excl["reason"]
    assert eval_excl["matched_exclusion"] is not None

    # Evaluating a non-excluded host in the same subnet must be ALLOWED
    eval_host = ScopeEngine.validate_target_in_scope(db, test_project.id, "192.168.10.55")
    assert eval_host["is_authorized"] is True
    assert eval_host["status"] == "AUTHORIZED"
    assert eval_host["matched_rule"]["target_value"] == "192.168.10.0/24"


def test_domain_wildcards_and_subdomain_exclusion(db, test_project: Project, lead_user: User):
    # Authorized wildcard: *.payments.local
    authorized_wildcard = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="*.payments.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-PCI-DSS-Assessment",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(authorized_wildcard)

    # Excluded subdomain: hsm.payments.local (Hardware Security Module)
    exclusion = ScopeExclusion(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="hsm.payments.local",
        reason="Production HSM key vault - Out of scope",
        created_by_id=lead_user.id,
    )
    db.add(exclusion)
    db.commit()

    # Allowed subdomains
    eval_api = ScopeEngine.validate_target_in_scope(db, test_project.id, "api.payments.local")
    assert eval_api["is_authorized"] is True
    assert eval_api["status"] == "AUTHORIZED"

    # Excluded subdomain
    eval_hsm = ScopeEngine.validate_target_in_scope(db, test_project.id, "hsm.payments.local")
    assert eval_hsm["is_authorized"] is False
    assert eval_hsm["status"] == "EXCLUDED"


def test_pending_revoked_and_expired_states(db, test_project: Project, lead_user: User):
    now = datetime.now(timezone.utc)

    # 1. Target registered but PENDING
    pending_target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="pending.corp.local",
        authorization_status=AuthorizationStatus.PENDING,
        created_by_id=lead_user.id,
    )
    # 2. Target REVOKED
    revoked_target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="revoked.corp.local",
        authorization_status=AuthorizationStatus.REVOKED,
        revocation_reason="Emergency operational freeze",
        created_by_id=lead_user.id,
    )
    # 3. Target EXPIRED
    expired_target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="expired.corp.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="Past authorization",
        expires_at=now - timedelta(hours=1),
        created_by_id=lead_user.id,
    )
    db.add_all([pending_target, revoked_target, expired_target])
    db.commit()

    # Pending check
    eval_pending = ScopeEngine.validate_target_in_scope(db, test_project.id, "pending.corp.local")
    assert eval_pending["is_authorized"] is False
    assert eval_pending["status"] == "PENDING_APPROVAL"

    # Revoked check
    eval_revoked = ScopeEngine.validate_target_in_scope(db, test_project.id, "revoked.corp.local")
    assert eval_revoked["is_authorized"] is False
    assert eval_revoked["status"] == "REVOKED"
    assert "Emergency operational freeze" in eval_revoked["reason"]

    # Expired check
    eval_expired = ScopeEngine.validate_target_in_scope(db, test_project.id, "expired.corp.local")
    assert eval_expired["is_authorized"] is False
    assert eval_expired["status"] == "EXPIRED"

    # Completely unmapped target fails closed
    eval_unmapped = ScopeEngine.validate_target_in_scope(db, test_project.id, "external-target.com")
    assert eval_unmapped["is_authorized"] is False
    assert eval_unmapped["status"] == "NOT_IN_SCOPE"
