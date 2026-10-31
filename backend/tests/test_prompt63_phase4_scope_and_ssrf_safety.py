"""
VAPT Platform — Scope Safety, SSRF & DNS Rebinding Hardening Tests (Phase 4).
Validates:
1. Pure scope validation is separated from network DNS resolution.
2. Cloud metadata service endpoints are strictly rejected (fails closed).
3. Exclusions strictly take precedence over inclusions.
4. Pre-connection destination revalidation blocks SSRF, link-local, and unauthorized internal IP escapes.
5. Obfuscated IP and IPv4-mapped IPv6 representations are unwrapped and blocked when pointing to metadata.
"""
import pytest
from sqlalchemy.orm import Session

from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.project import Project
from app.models.user import User
from app.services.scope_engine import ScopeEngine


def test_cloud_metadata_endpoints_strictly_rejected(db: Session, test_project: Project):
    """Ensure cloud metadata endpoints (169.254.169.254, etc.) are strictly rejected by scope engine."""
    metadata_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "169.254.169.254",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://169.254.0.2/opc/v1/instance/",
        "http://[::ffff:169.254.169.254]/",
    ]

    for target in metadata_targets:
        res = ScopeEngine.validate_target_in_scope(
            db=db,
            project_id=test_project.id,
            target=target,
            allow_dns_resolution=False,
        )
        assert res["is_authorized"] is False
        assert res["status"] in ("PROHIBITED_METADATA", "INVALID_TARGET", "EXCLUDED")


def test_exclusions_strictly_override_inclusions(db: Session, test_project: Project, admin_user: User):
    """Ensure that an exclusion rule strictly overrides an authorized wildcard inclusion rule."""
    # 1. Authorize *.example.com
    target_rule = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="*.example.com",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-APPROVED-2026",
        description="Approved penetration test engagement scope",
        created_by_id=admin_user.id,
    )
    # 2. Exclude critical admin portal
    exclusion_rule = ScopeExclusion(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="admin.example.com",
        reason="Third-party managed SSO portal - Strictly out of scope",
        created_by_id=admin_user.id,
    )
    db.add(target_rule)
    db.add(exclusion_rule)
    db.commit()

    # Subdomain in scope
    res_allowed = ScopeEngine.validate_target_in_scope(
        db=db,
        project_id=test_project.id,
        target="api.example.com",
        allow_dns_resolution=False,
    )
    assert res_allowed["is_authorized"] is True

    # Excluded subdomain MUST be rejected
    res_blocked = ScopeEngine.validate_target_in_scope(
        db=db,
        project_id=test_project.id,
        target="admin.example.com",
        allow_dns_resolution=False,
    )
    assert res_blocked["is_authorized"] is False
    assert res_blocked["status"] == "EXCLUDED"


def test_pre_connection_destination_revalidation_blocks_ssrf_and_metadata():
    """Ensure revalidate_destination_before_connection detects metadata, loopback, and unpermitted IPs."""
    # 1. Cloud metadata
    safe, err, resolved = ScopeEngine.revalidate_destination_before_connection("169.254.169.254")
    assert safe is False
    assert "metadata" in err.lower()

    # 2. Hostname pointing to metadata
    safe2, err2, resolved2 = ScopeEngine.revalidate_destination_before_connection("metadata.google.internal")
    assert safe2 is False
    assert "metadata" in err2.lower()

    # 3. Localhost loopback rejected when allow_loopback=False
    safe3, err3, resolved3 = ScopeEngine.revalidate_destination_before_connection("127.0.0.1", allow_loopback=False)
    assert safe3 is False
    assert "loopback" in err3.lower()

    # 4. Localhost loopback permitted when allow_loopback=True
    safe4, err4, resolved4 = ScopeEngine.revalidate_destination_before_connection("127.0.0.1", allow_loopback=True)
    assert safe4 is True
    assert resolved4 == "127.0.0.1"

    # 5. Private IP rejected when allow_private=False
    safe5, err5, resolved5 = ScopeEngine.revalidate_destination_before_connection("10.0.0.1", allow_private=False)
    assert safe5 is False
    assert "private" in err5.lower()
