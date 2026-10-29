import uuid
import json
from datetime import datetime, timezone
import pytest
from fastapi import status

from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.connector import (
    ConnectorCapability,
    ConnectorStatus,
    SyncStatus,
    ImplementationStatus,
    ConnectorConfiguration,
    ConnectorSyncEvent,
)
from app.core.security import create_access_token, hash_password
from app.services.connector_service import ConnectorService
from app.services.integrations.connector_framework import (
    CONNECTOR_REGISTRY,
    ProviderErrorCategory,
    mask_sensitive_settings,
    WebhookAlertConnectorAdapter,
)
from app.schemas.connector import ConnectorConfigCreate, ConnectorConfigUpdate


def auth_header_for_user(user: User) -> dict:
    token = create_access_token(
        subject=user.id,
        claims={"role": user.system_role.value, "email": user.email},
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def conn_org(db):
    org = Organization(name="Integration Framework Org", slug=f"conn-org-{uuid.uuid4().hex[:6]}")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@pytest.fixture
def conn_project(db, conn_org):
    project = Project(
        name="Integration Security Project",
        description="Enterprise connector testing and data sync",
        organization_id=conn_org.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@pytest.fixture
def conn_admin(db, conn_org, conn_project):
    admin = User(
        email=f"conn_admin_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Connector Admin",
        hashed_password=hash_password("SuperSecret123!"),
        system_role=SystemRole.ADMIN,
        is_active=True,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    member = ProjectMember(
        project_id=conn_project.id,
        user_id=admin.id,
        role=ProjectRole.LEAD,
    )
    db.add(member)
    db.commit()
    return admin


def test_connector_inventory_discovery(client, conn_project, conn_admin):
    """Req 1, 4, 28: Discover inventory and verify implementation status, capabilities, and limitations."""
    headers = auth_header_for_user(conn_admin)
    res = client.get(f"/api/v1/projects/{conn_project.id}/connectors/inventory", headers=headers)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert len(data) >= 8

    # Verify implementation statuses
    status_map = {item["provider_type"]: item for item in data}
    assert "CISA_KEV" in status_map
    assert status_map["CISA_KEV"]["implementation_status"] == "IMPLEMENTED"
    assert "PULL_THREAT_INTEL" in status_map["CISA_KEV"]["supported_capabilities"]

    assert "CLOUD_ASSET_INVENTORY" in status_map
    assert status_map["CLOUD_ASSET_INVENTORY"]["implementation_status"] == "IMPLEMENTED"
    assert "PULL_ASSETS" in status_map["CLOUD_ASSET_INVENTORY"]["supported_capabilities"]

    assert "QUALYS_VM_MOCK" in status_map
    assert status_map["QUALYS_VM_MOCK"]["implementation_status"] == "SIMULATED"
    assert "Simulated sandbox" in status_map["QUALYS_VM_MOCK"]["limitations"]

    assert "TENABLE_IO" in status_map
    assert status_map["TENABLE_IO"]["implementation_status"] == "UNVERIFIED"

    assert "CROWDSTRIKE_FALCON" in status_map
    assert status_map["CROWDSTRIKE_FALCON"]["implementation_status"] == "DISABLED"


def test_connector_registration_and_capability_validation(db, conn_project, conn_admin):
    """Req 2, 4: Register connector with explicit capabilities and reject unsupported ones."""
    # Attempt to declare unsupported capability (PUSH_ALERTS on CLOUD_ASSET_INVENTORY)
    invalid_data = ConnectorConfigCreate(
        name="Invalid Cloud Connector",
        provider_type="CLOUD_ASSET_INVENTORY",
        capabilities=["PULL_ASSETS", "PUSH_ALERTS"],  # PUSH_ALERTS unsupported!
        settings={"cloud_provider": "AWS", "api_endpoint": "https://ec2.amazonaws.com"},
    )
    with pytest.raises(ValueError, match="not supported"):
        ConnectorService.create_connector(db, conn_project.id, invalid_data)

    # Valid configuration
    valid_data = ConnectorConfigCreate(
        name="Production AWS Inventory",
        provider_type="CLOUD_ASSET_INVENTORY",
        capabilities=["PULL_ASSETS", "TEST_CONNECTIVITY"],
        settings={
            "cloud_provider": "AWS",
            "api_endpoint": "https://ec2.us-east-1.amazonaws.com",
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
        rate_limit_per_minute=60,
        timeout_seconds=15.0,
    )
    conn = ConnectorService.create_connector(db, conn_project.id, valid_data)
    assert conn.id is not None
    assert conn.name == "Production AWS Inventory"
    assert conn.provider_type == "CLOUD_ASSET_INVENTORY"
    assert "PULL_ASSETS" in conn.capabilities


def test_credential_masking_and_storage_security(client, conn_project, conn_admin):
    """Req 5, 12: Secrets are recursively masked and never returned in cleartext in read APIs."""
    headers = auth_header_for_user(conn_admin)
    payload = {
        "name": "Secure Webhook Integration",
        "provider_type": "WEBHOOK_NOTIFIER",
        "capabilities": ["PUSH_ALERTS", "TEST_CONNECTIVITY"],
        "settings": {
            "webhook_url": "https://siem-collector.corp.internal/v1/webhook",
            "secret_token": "super_secret_hmac_key_998877",
            "api_key": "live_prod_key_11223344",
        },
    }
    create_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors", json=payload, headers=headers)
    assert create_res.status_code == status.HTTP_201_CREATED
    data = create_res.json()

    # Verify settings_masked masks secret keys
    masked = data["settings_masked"]
    assert masked["secret_token"] != "super_secret_hmac_key_998877"
    assert "super_secret_hmac_key_998877" not in json.dumps(data)
    assert "live_prod_key_11223344" not in json.dumps(data)
    assert "****" in masked["secret_token"]
    assert "****" in masked["api_key"]


def test_ssrf_protection_and_destination_policy(client, conn_project, conn_admin):
    """Req 11: Protect outbound HTTP integrations against SSRF, loopback, and metadata endpoints."""
    headers = auth_header_for_user(conn_admin)

    # 1. Loopback attack attempt
    loopback_payload = {
        "name": "SSRF Loopback Target",
        "provider_type": "WEBHOOK_NOTIFIER",
        "capabilities": ["PUSH_ALERTS", "TEST_CONNECTIVITY"],
        "settings": {"webhook_url": "https://127.0.0.1:8000/internal-admin"},
    }
    c_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors", json=loopback_payload, headers=headers)
    conn_id = c_res.json()["id"]

    test_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors/{conn_id}/test", headers=headers)
    assert test_res.status_code == status.HTTP_200_OK
    test_data = test_res.json()
    assert test_data["status"] == "ERROR"
    assert test_data["error_category"] == "SSRF_DETECTED"
    assert "rejected destination" in test_data["message"]

    # 2. Cloud metadata attack attempt (169.254.169.254)
    meta_payload = {
        "name": "SSRF Cloud Metadata Target",
        "provider_type": "WEBHOOK_NOTIFIER",
        "capabilities": ["PUSH_ALERTS", "TEST_CONNECTIVITY"],
        "settings": {"webhook_url": "https://169.254.169.254/latest/meta-data"},
    }
    meta_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors", json=meta_payload, headers=headers)
    meta_conn_id = meta_res.json()["id"]

    test_meta = client.post(f"/api/v1/projects/{conn_project.id}/connectors/{meta_conn_id}/test", headers=headers)
    assert test_meta.json()["status"] == "ERROR"
    assert test_meta.json()["error_category"] == "SSRF_DETECTED"


def test_asset_synchronization_and_scope_isolation(db, client, conn_project, conn_admin):
    """Req 7, 8, 10: Sync imported assets with cryptographic digest, strictly enforcing is_scoped=False."""
    headers = auth_header_for_user(conn_admin)
    payload = {
        "name": "AWS EC2 Syncer",
        "provider_type": "CLOUD_ASSET_INVENTORY",
        "capabilities": ["PULL_ASSETS", "TEST_CONNECTIVITY"],
        "settings": {
            "cloud_provider": "AWS",
            "api_endpoint": "https://ec2.us-east-1.amazonaws.com",
            "access_key": "AKIA...",
        },
    }
    c_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors", json=payload, headers=headers)
    conn_id = c_res.json()["id"]

    # Trigger Sync
    sync_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors/{conn_id}/sync", headers=headers)
    assert sync_res.status_code == status.HTTP_200_OK
    sync_data = sync_res.json()
    assert sync_data["status"] == "SUCCESS"
    assert sync_data["records_pulled"] == 3
    assert sync_data["raw_payload_digest"] is not None

    # Check imported assets in DB
    assets = db.query(Asset).filter(Asset.project_id == conn_project.id).all()
    assert len(assets) >= 2

    for a in assets:
        # CRITICAL SAFETY REQUIREMENT: External connector assets MUST NOT be auto-scoped!
        assert a.attributes is not None
        assert a.attributes.get("is_scoped") is False
        assert a.attributes["approval_status"] == "PENDING_OPERATOR_APPROVAL"
        assert len(a.attributes["raw_digest"]) == 64


def test_source_deletion_distinguished_from_unavailability(db, client, conn_project, conn_admin):
    """Req 9: Distinguish source deletion (tombstone) from temporary source unavailability."""
    headers = auth_header_for_user(conn_admin)

    # 1. First sync ingests running instances and handles terminated instance
    payload = {
        "name": "Lifecycle Deletion Test Connector",
        "provider_type": "CLOUD_ASSET_INVENTORY",
        "capabilities": ["PULL_ASSETS", "TEST_CONNECTIVITY"],
        "settings": {"cloud_provider": "AWS", "api_endpoint": "https://ec2.us-east-1.amazonaws.com"},
    }
    c_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors", json=payload, headers=headers)
    conn_id = c_res.json()["id"]

    # Pre-create the legacy VPN asset to verify tombstone deactivation
    vpn_asset = Asset(
        project_id=conn_project.id,
        organization_id=conn_project.organization_id,
        name="legacy-vpn-concentrator.internal.corp",
        canonical_identifier="host:legacy-vpn-concentrator.internal.corp",
        asset_type=AssetType.HOST,
        criticality=AssetCriticality.LOW,
        status=AssetStatus.ACTIVE,
        attributes={"is_scoped": False},
    )
    db.add(vpn_asset)
    db.commit()

    # Trigger sync - instance 3 is marked 'terminated' in MOCK_INSTANCES
    sync_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors/{conn_id}/sync", headers=headers)
    assert sync_res.status_code == status.HTTP_200_OK
    sync_data = sync_res.json()
    assert sync_data["records_tombstoned"] >= 1

    # Verify that terminated instance is now deactivated (status=DECOMMISSIONED)
    db.refresh(vpn_asset)
    assert vpn_asset.status == AssetStatus.DECOMMISSIONED

    # 2. Simulate Temporary Network Outage (503 / Timeout)
    # Temporary unavailability MUST NOT delete or tombstone other active assets!
    active_assets_before = db.query(Asset).filter(Asset.project_id == conn_project.id, Asset.status == AssetStatus.ACTIVE).count()

    # Patch adapter to simulate temporary outage
    adapter = CONNECTOR_REGISTRY["CLOUD_ASSET_INVENTORY"]
    orig_pull = adapter.pull_data

    def failing_pull(*args, **kwargs):
        raise ConnectionError("503 Service Unavailable: Remote cloud gateway timeout")

    adapter.pull_data = failing_pull
    try:
        outage_sync = client.post(f"/api/v1/projects/{conn_project.id}/connectors/{conn_id}/sync", headers=headers)
        assert outage_sync.status_code == status.HTTP_200_OK
        outage_data = outage_sync.json()
        assert outage_data["status"] == "FAILED"
        assert outage_data["records_tombstoned"] == 0

        # Verify active assets are PRESERVED and untouched
        active_assets_after = db.query(Asset).filter(Asset.project_id == conn_project.id, Asset.status == AssetStatus.ACTIVE).count()
        assert active_assets_after == active_assets_before
    finally:
        adapter.pull_data = orig_pull


def test_idempotent_synchronization_and_watermarks(client, conn_project, conn_admin):
    """Req 8: Synchronization is idempotent; subsequent runs with watermarks do not re-ingest duplicate records."""
    headers = auth_header_for_user(conn_admin)
    payload = {
        "name": "CISA KEV Watermark Syncer",
        "provider_type": "CISA_KEV",
        "capabilities": ["PULL_THREAT_INTEL", "TEST_CONNECTIVITY"],
        "settings": {"feed_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    }
    c_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors", json=payload, headers=headers)
    conn_id = c_res.json()["id"]

    # First sync - pulls all records
    sync1 = client.post(f"/api/v1/projects/{conn_project.id}/connectors/{conn_id}/sync", headers=headers).json()
    assert sync1["status"] == "SUCCESS"
    assert sync1["records_pulled"] == 4
    watermark_1 = sync1["next_watermark"]
    assert watermark_1 is not None

    # Second sync immediately after - watermark advances and pulls 0 new records
    sync2 = client.post(f"/api/v1/projects/{conn_project.id}/connectors/{conn_id}/sync", headers=headers).json()
    assert sync2["status"] == "SUCCESS"
    assert sync2["records_pulled"] == 0


def test_unsupported_and_disabled_connector_rejection(client, conn_project, conn_admin):
    """Req 1, 28: Test disabled and unverified connector handling."""
    headers = auth_header_for_user(conn_admin)

    # 1. Disabled connector (Crowdstrike)
    dis_payload = {
        "name": "Policy Disabled Connector",
        "provider_type": "CROWDSTRIKE_FALCON",
        "capabilities": ["PULL_ASSETS"],
        "settings": {},
    }
    c_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors", json=dis_payload, headers=headers)
    # Validation should reject creation because adapter validate_configuration returns False
    assert c_res.status_code == status.HTTP_400_BAD_REQUEST
    assert "disabled by platform policy" in c_res.json()["detail"]


def test_sync_history_audit_and_provenance(client, conn_project, conn_admin):
    """Req 7, 14: Verify sync run execution history and cryptographic provenance records."""
    headers = auth_header_for_user(conn_admin)
    payload = {
        "name": "Scanner History Connector",
        "provider_type": "VULNERABILITY_SCANNER",
        "capabilities": ["PULL_FINDINGS", "TEST_CONNECTIVITY"],
        "settings": {"scanner_url": "https://scanner.internal.corp/api/v2"},
    }
    c_res = client.post(f"/api/v1/projects/{conn_project.id}/connectors", json=payload, headers=headers)
    conn_id = c_res.json()["id"]

    # Run sync
    client.post(f"/api/v1/projects/{conn_project.id}/connectors/{conn_id}/sync", headers=headers)

    # Fetch history
    h_res = client.get(f"/api/v1/projects/{conn_project.id}/connectors/{conn_id}/history", headers=headers)
    assert h_res.status_code == status.HTTP_200_OK
    history = h_res.json()
    assert len(history) == 1
    event = history[0]
    assert event["connector_id"] == conn_id
    assert event["status"] == "SUCCESS"
    assert event["records_pulled"] == 2
    assert len(event["raw_payload_digest"]) == 64
