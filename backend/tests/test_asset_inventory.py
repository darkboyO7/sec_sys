import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.asset import (
    Asset,
    AssetObservation,
    AssetType,
    AssetCriticality,
    AssetStatus,
)
from app.services.asset_reconciliation_service import AssetReconciliationService

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture
def db_session():
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def setup_env(db_session):
    org = Organization(name="Defense Org", slug="defense-org")
    user = User(
        email="lead@defense.local",
        hashed_password="pw",
        full_name="Defense Lead",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    db_session.add_all([org, user])
    db_session.flush()

    project = Project(
        name="Asset Lab",
        organization_id=org.id,
        description="Asset testing",
    )
    db_session.add(project)
    db_session.flush()

    mem = ProjectMember(project_id=project.id, user_id=user.id, role=ProjectRole.LEAD)
    db_session.add(mem)
    db_session.commit()

    return {"org": org, "user": user, "project": project}


def test_type_specific_identifier_normalization():
    # 1. URL / Web Application normalization (strips default ports 80/443 and trailing slashes)
    t1, c1, n1 = AssetReconciliationService.classify_and_normalize("HTTPS://Api.Bank.Corp:443/login/")
    assert t1 == AssetType.API_ENDPOINT
    assert c1 == "https://api.bank.corp/login"
    assert n1 == "api.bank.corp"

    t2, c2, n2 = AssetReconciliationService.classify_and_normalize("http://web.corp:80/")
    assert t2 == AssetType.WEB_APP
    assert c2 == "http://web.corp"

    # 2. IP Address normalization (IPv4 and IPv6 compression)
    t3, c3, _ = AssetReconciliationService.classify_and_normalize("  192.168.001.050  ")
    assert t3 == AssetType.IP_ADDRESS
    assert c3 == "192.168.1.50"

    t4, c4, _ = AssetReconciliationService.classify_and_normalize("2001:0db8:0000:0000:0000:0000:0000:0001")
    assert t4 == AssetType.IP_ADDRESS
    assert c4 == "2001:db8::1"

    # 3. Domain & Hostname normalization
    t5, c5, _ = AssetReconciliationService.classify_and_normalize("Sub.Domain.Example.Com.")
    assert t5 == AssetType.DOMAIN
    assert c5 == "sub.domain.example.com"

    t6, c6, _ = AssetReconciliationService.classify_and_normalize("localhost")
    assert t6 == AssetType.HOSTNAME
    assert c6 == "localhost"

    # 4. Service Host:Port normalization
    t7, c7, _ = AssetReconciliationService.classify_and_normalize("10.0.0.1:8443")
    assert t7 == AssetType.SERVICE
    assert c7 == "tcp://10.0.0.1:8443"


def test_asset_creation_and_observation_preservation(db_session, setup_env):
    env = setup_env
    org = env["org"]
    project = env["project"]

    # Ingestion 1
    asset1 = AssetReconciliationService.reconcile_or_create_asset(
        project_id=project.id,
        organization_id=org.id,
        asset_type=AssetType.DOMAIN,
        canonical_identifier="api.payment.corp",
        name="Payment Gateway API",
        criticality=AssetCriticality.HIGH,
        attributes={"os": "Linux", "cloud": "AWS"},
        db=db_session,
    )
    assert asset1.id is not None
    assert asset1.name == "Payment Gateway API"
    assert asset1.criticality == AssetCriticality.HIGH

    # Record observation 1
    obs1 = AssetReconciliationService.record_observation(
        asset=asset1,
        project_id=project.id,
        observation_source="fixture_scan",
        observed_attributes={"port_443": "nginx/1.18"},
        confidence=1.0,
        db=db_session,
    )
    assert obs1.id is not None

    # Ingestion 2 from subsequent scan with conflicting attributes
    asset2 = AssetReconciliationService.reconcile_or_create_asset(
        project_id=project.id,
        organization_id=org.id,
        asset_type=AssetType.DOMAIN,
        canonical_identifier="api.payment.corp",
        attributes={"os": "Debian Linux"},
        db=db_session,
    )
    # Must resolve to the exact same canonical asset
    assert asset2.id == asset1.id
    # Conflicting attribute is preserved in conflict history without data loss
    assert "_conflict_os" in asset2.attributes

    # Record observation 2
    obs2 = AssetReconciliationService.record_observation(
        asset=asset2,
        project_id=project.id,
        observation_source="secondary_probe",
        observed_attributes={"port_443": "nginx/1.20"},
        confidence=0.9,
        db=db_session,
    )
    db_session.commit()

    # Verify both observations are preserved in history
    observations = (
        db_session.query(AssetObservation)
        .filter(AssetObservation.asset_id == asset1.id)
        .order_by(AssetObservation.observed_at.asc())
        .all()
    )
    assert len(observations) == 2
    assert observations[0].observed_attributes["port_443"] == "nginx/1.18"
    assert observations[1].observed_attributes["port_443"] == "nginx/1.20"


def test_ambiguity_tracking_and_resolution(db_session, setup_env):
    env = setup_env
    org = env["org"]
    project = env["project"]

    asset = AssetReconciliationService.reconcile_or_create_asset(
        project_id=project.id,
        organization_id=org.id,
        asset_type=AssetType.HOST,
        canonical_identifier="internal-gw-01",
        is_ambiguous=True,
        ambiguity_reason="Observed on multiple overlapping private subnets without distinct MAC",
        db=db_session,
    )
    assert asset.is_ambiguous is True
    assert "overlapping" in asset.ambiguity_reason

    # Resolve ambiguity
    asset.is_ambiguous = False
    attrs = dict(asset.attributes or {})
    attrs["_resolution"] = "Confirmed distinct gateway via BGP routing table inspection."
    asset.attributes = attrs
    asset.ambiguity_reason = None
    db_session.commit()

    db_session.refresh(asset)
    assert asset.is_ambiguous is False
    assert asset.ambiguity_reason is None
    assert "_resolution" in asset.attributes
