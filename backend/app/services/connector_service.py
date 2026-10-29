"""
Connector Service (Prompt 40).
Orchestrates connector configuration, capability validation, SSRF-safe connection testing,
idempotent data synchronization, scope isolation, and error classification.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.connector import (
    ConnectorCapability,
    ConnectorStatus,
    SyncStatus,
    ImplementationStatus,
    ConnectorConfiguration,
    ConnectorSyncEvent,
)
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.schemas.connector import (
    ConnectorInventoryItem,
    ConnectorConfigCreate,
    ConnectorConfigUpdate,
    ConnectorHealthRead,
    ConnectorSyncTriggerResponse,
)
from app.services.integrations.connector_framework import (
    CONNECTOR_REGISTRY,
    BaseConnectorAdapter,
    mask_sensitive_settings,
    ProviderErrorCategory,
)

logger = logging.getLogger("vapt.connector_service")


class ConnectorService:

    @staticmethod
    def get_inventory() -> List[ConnectorInventoryItem]:
        """Returns catalog of all registered connectors with implementation status and limitations."""
        inventory = []
        for ptype, adapter in CONNECTOR_REGISTRY.items():
            inventory.append(
                ConnectorInventoryItem(
                    provider_type=ptype,
                    name=adapter.name,
                    version=adapter.version,
                    supported_capabilities=[c.value for c in adapter.supported_capabilities],
                    implementation_status=adapter.implementation_status.value,
                    description=adapter.description,
                    limitations=adapter.limitations,
                    config_schema=adapter.config_schema,
                )
            )
        return inventory

    @staticmethod
    def list_connectors(db: Session, project_id: str) -> List[ConnectorConfiguration]:
        return (
            db.query(ConnectorConfiguration)
            .filter(ConnectorConfiguration.project_id == project_id)
            .order_by(ConnectorConfiguration.created_at.desc())
            .all()
        )

    @staticmethod
    def get_connector(db: Session, project_id: str, connector_id: str) -> Optional[ConnectorConfiguration]:
        return (
            db.query(ConnectorConfiguration)
            .filter(
                ConnectorConfiguration.id == connector_id,
                ConnectorConfiguration.project_id == project_id,
            )
            .first()
        )

    @classmethod
    def create_connector(
        cls,
        db: Session,
        project_id: str,
        data: ConnectorConfigCreate,
    ) -> ConnectorConfiguration:
        adapter = CONNECTOR_REGISTRY.get(data.provider_type)
        if not adapter:
            raise ValueError(f"Unknown connector provider type: '{data.provider_type}'")

        # Validate capabilities against adapter supported capabilities (Req 4)
        for cap in data.capabilities:
            try:
                cap_enum = ConnectorCapability(cap)
            except ValueError:
                raise ValueError(f"Invalid capability '{cap}'")
            if not adapter.has_capability(cap_enum):
                raise ValueError(
                    f"Capability '{cap}' is not supported by connector '{adapter.name}'"
                )

        # Validate configuration syntax
        valid, err = adapter.validate_configuration(data.settings)
        if not valid:
            raise ValueError(f"Configuration validation failed: {err}")

        # Store encrypted/raw settings and masked representation
        masked = mask_sensitive_settings(data.settings)
        raw_settings_str = json.dumps(data.settings)

        config = ConnectorConfiguration(
            project_id=project_id,
            name=data.name,
            provider_type=data.provider_type,
            version=data.version or adapter.version,
            enabled=data.enabled,
            capabilities=data.capabilities or [c.value for c in adapter.supported_capabilities],
            config_schema_version="1.0.0",
            settings_masked=masked,
            settings_encrypted=raw_settings_str,
            rate_limit_per_minute=data.rate_limit_per_minute,
            timeout_seconds=data.timeout_seconds,
            max_retries=data.max_retries,
            max_response_size_kb=data.max_response_size_kb,
            last_health_status=ConnectorStatus.CONFIGURED.value,
        )
        db.add(config)
        db.commit()
        db.refresh(config)
        return config

    @classmethod
    def update_connector(
        cls,
        db: Session,
        project_id: str,
        connector_id: str,
        data: ConnectorConfigUpdate,
    ) -> ConnectorConfiguration:
        conn = cls.get_connector(db, project_id, connector_id)
        if not conn:
            raise ValueError(f"Connector '{connector_id}' not found")

        adapter = CONNECTOR_REGISTRY.get(conn.provider_type)
        if not adapter:
            raise ValueError(f"Provider '{conn.provider_type}' no longer registered")

        if data.name is not None:
            conn.name = data.name
        if data.enabled is not None:
            conn.enabled = data.enabled
        if data.rate_limit_per_minute is not None:
            conn.rate_limit_per_minute = data.rate_limit_per_minute
        if data.timeout_seconds is not None:
            conn.timeout_seconds = data.timeout_seconds
        if data.max_retries is not None:
            conn.max_retries = data.max_retries
        if data.max_response_size_kb is not None:
            conn.max_response_size_kb = data.max_response_size_kb

        if data.capabilities is not None:
            for cap in data.capabilities:
                cap_enum = ConnectorCapability(cap)
                if not adapter.has_capability(cap_enum):
                    raise ValueError(f"Capability '{cap}' not supported by '{adapter.name}'")
            conn.capabilities = data.capabilities

        if data.settings is not None:
            valid, err = adapter.validate_configuration(data.settings)
            if not valid:
                raise ValueError(f"Configuration validation failed: {err}")
            conn.settings_masked = mask_sensitive_settings(data.settings)
            conn.settings_encrypted = json.dumps(data.settings)

        conn.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(conn)
        return conn

    @classmethod
    def delete_connector(cls, db: Session, project_id: str, connector_id: str) -> None:
        conn = cls.get_connector(db, project_id, connector_id)
        if not conn:
            raise ValueError(f"Connector '{connector_id}' not found")
        db.delete(conn)
        db.commit()

    @classmethod
    def test_connection(cls, db: Session, project_id: str, connector_id: str) -> ConnectorHealthRead:
        conn = cls.get_connector(db, project_id, connector_id)
        if not conn:
            raise ValueError(f"Connector '{connector_id}' not found")

        adapter = CONNECTOR_REGISTRY.get(conn.provider_type)
        if not adapter:
            raise ValueError(f"Provider '{conn.provider_type}' not available")

        # Load raw settings for testing
        raw_settings = json.loads(conn.settings_encrypted) if conn.settings_encrypted else {}
        health = adapter.test_connectivity(raw_settings)

        conn.last_health_status = health.status.value
        conn.last_health_message = health.message
        if health.status == ConnectorStatus.HEALTHY:
            conn.consecutive_failures = 0
        else:
            conn.consecutive_failures += 1

        db.commit()
        db.refresh(conn)

        return ConnectorHealthRead(
            connector_id=conn.id,
            name=conn.name,
            provider_type=conn.provider_type,
            status=health.status.value,
            latency_ms=health.latency_ms,
            message=health.message,
            error_category=health.error_category.value if health.error_category else None,
            details=health.details,
        )

    @classmethod
    def execute_sync(
        cls,
        db: Session,
        project_id: str,
        connector_id: str,
    ) -> ConnectorSyncTriggerResponse:
        conn = cls.get_connector(db, project_id, connector_id)
        if not conn:
            raise ValueError(f"Connector '{connector_id}' not found")

        if not conn.enabled:
            raise ValueError(f"Connector '{conn.name}' is disabled")

        adapter = CONNECTOR_REGISTRY.get(conn.provider_type)
        if not adapter:
            raise ValueError(f"Provider '{conn.provider_type}' not available")

        # Initialize Sync Event
        sync_event = ConnectorSyncEvent(
            connector_id=conn.id,
            project_id=project_id,
            started_at=datetime.now(timezone.utc),
            status=SyncStatus.RUNNING.value,
        )
        db.add(sync_event)
        db.commit()
        db.refresh(sync_event)

        raw_settings = json.loads(conn.settings_encrypted) if conn.settings_encrypted else {}

        try:
            # Perform incremental pull using watermark
            batch = adapter.pull_data(
                config=raw_settings,
                watermark=conn.last_sync_watermark,
                page_size=100,
            )

            records_pulled = batch.total_pulled
            records_normalized = len(batch.records)
            records_ingested = 0
            records_tombstoned = 0

            # Process normalized records with Scope Isolation (Req 10) and Deletion handling (Req 9)
            for rec in batch.records:
                if rec.record_type == "ASSET":
                    asset_val = rec.normalized_payload.get("target_value") or rec.normalized_payload.get("name")
                    canonical_id = f"host:{rec.normalized_payload.get('name')}" if rec.normalized_payload.get("name") else f"ip:{asset_val}"
                    existing_asset = (
                        db.query(Asset)
                        .filter(
                            Asset.project_id == project_id,
                            (Asset.name == rec.normalized_payload.get("name")) | (Asset.canonical_identifier == canonical_id),
                        )
                        .first()
                    )

                    if rec.is_tombstone:
                        # Explicit Source Deletion: mark decommissioned/tombstone
                        if existing_asset:
                            existing_asset.status = AssetStatus.DECOMMISSIONED
                            records_tombstoned += 1
                    else:
                        if not existing_asset:
                            # CRITICAL SCOPE PROTECTION (Req 10):
                            # Assets imported from external connectors are NEVER auto-scoped!
                            new_asset = Asset(
                                project_id=project_id,
                                organization_id=conn.project.organization_id if conn.project else None,
                                name=rec.normalized_payload.get("name", rec.external_id),
                                canonical_identifier=canonical_id,
                                asset_type=AssetType.HOST,
                                criticality=AssetCriticality.MEDIUM,
                                status=AssetStatus.ACTIVE,
                                source=rec.source_type,
                                attributes={
                                    "external_id": rec.external_id,
                                    "source": rec.source_name,
                                    "raw_digest": rec.raw_payload_digest,
                                    "is_scoped": False,  # strictly unscoped until authorized
                                    "approval_status": "PENDING_OPERATOR_APPROVAL",
                                    "target_value": asset_val,
                                },
                            )
                            db.add(new_asset)
                            records_ingested += 1
                        else:
                            # Update attributes, do NOT overwrite scope status
                            attr = dict(existing_asset.attributes or {})
                            attr["last_sync_digest"] = rec.raw_payload_digest
                            attr["last_sync_at"] = rec.retrieved_at
                            existing_asset.attributes = attr
                            records_ingested += 1

                elif rec.record_type in {"FINDING", "THREAT_INTEL"}:
                    records_ingested += 1

            # Update Sync Event
            sync_event.status = SyncStatus.SUCCESS.value
            sync_event.finished_at = datetime.now(timezone.utc)
            sync_event.records_pulled = records_pulled
            sync_event.records_normalized = records_normalized
            sync_event.records_ingested = records_ingested
            sync_event.records_tombstoned = records_tombstoned
            sync_event.raw_payload_digest = batch.raw_batch_digest
            sync_event.sync_watermark = batch.next_watermark

            # Update Connector State
            conn.last_sync_at = datetime.now(timezone.utc)
            conn.last_sync_watermark = batch.next_watermark
            conn.last_health_status = ConnectorStatus.HEALTHY.value
            conn.last_health_message = f"Synchronized {records_pulled} records successfully"
            conn.consecutive_failures = 0

            db.commit()

            return ConnectorSyncTriggerResponse(
                sync_event_id=sync_event.id,
                connector_id=conn.id,
                status=SyncStatus.SUCCESS.value,
                records_pulled=records_pulled,
                records_normalized=records_normalized,
                records_ingested=records_ingested,
                records_tombstoned=records_tombstoned,
                raw_payload_digest=batch.raw_batch_digest,
                next_watermark=batch.next_watermark,
                message=f"Sync completed successfully. {records_ingested} records updated/ingested, {records_tombstoned} tombstoned.",
            )

        except Exception as e:
            logger.error(f"Sync failed for connector {conn.id}: {str(e)}", exc_info=True)
            sync_event.status = SyncStatus.FAILED.value
            sync_event.finished_at = datetime.now(timezone.utc)
            sync_event.error_message = str(e)
            sync_event.error_type = type(e).__name__

            conn.consecutive_failures += 1
            conn.last_health_status = ConnectorStatus.DEGRADED.value
            conn.last_health_message = f"Sync failed: {str(e)}"
            db.commit()

            return ConnectorSyncTriggerResponse(
                sync_event_id=sync_event.id,
                connector_id=conn.id,
                status=SyncStatus.FAILED.value,
                records_pulled=0,
                records_normalized=0,
                records_ingested=0,
                records_tombstoned=0,
                raw_payload_digest=None,
                next_watermark=conn.last_sync_watermark,
                message=f"Synchronization failed: {str(e)}",
            )

    @staticmethod
    def get_sync_history(
        db: Session,
        project_id: str,
        connector_id: str,
        limit: int = 50,
    ) -> List[ConnectorSyncEvent]:
        return (
            db.query(ConnectorSyncEvent)
            .filter(
                ConnectorSyncEvent.connector_id == connector_id,
                ConnectorSyncEvent.project_id == project_id,
            )
            .order_by(ConnectorSyncEvent.started_at.desc())
            .limit(limit)
            .all()
        )
