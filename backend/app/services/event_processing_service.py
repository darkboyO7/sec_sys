import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.orchestration import (
    OrchestrationEventRecord,
    OrchestrationEventType,
    EventProcessingStatus,
)
from app.models.decision import AutonomousPolicyRecord
from app.models.base import utc_now


class EventProcessingService:
    """
    Event Deduplication and Ingestion Pipeline (Prompt 15 / Section 5).
    Computes deterministic SHA-256 deduplication signatures, coalesces matching events,
    enforces rate and queue bounds, and prevents event storms.
    """

    DEFAULT_DEDUP_WINDOW_SECONDS = 300  # 5 minutes
    MAX_PROJECT_QUEUED_EVENTS = 50

    @classmethod
    def compute_dedup_key(
        cls,
        project_id: str,
        event_type: OrchestrationEventType,
        target_resource: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Computes a stable deterministic SHA-256 deduplication key.
        Normalizes target and serializes deterministic JSON payload keys.
        """
        norm_target = str(target_resource or "").strip().lower()
        payload_repr = json.dumps(payload or {}, sort_keys=True, default=str)
        payload_digest = hashlib.sha256(payload_repr.encode("utf-8")).hexdigest()[:16]

        raw_str = f"{project_id}:{event_type.value}:{norm_target}:{payload_digest}"
        return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

    @classmethod
    def ingest_event(
        cls,
        db: Session,
        project_id: str,
        event_type: OrchestrationEventType,
        target_resource: str,
        payload: Optional[Dict[str, Any]] = None,
        event_source: str = "ORCHESTRATOR",
        dedup_window_seconds: int = DEFAULT_DEDUP_WINDOW_SECONDS,
        now: Optional[datetime] = None,
    ) -> Tuple[OrchestrationEventRecord, bool, str]:
        """
        Ingests an incoming operational event:
        - Calculates stable deduplication key.
        - Detects duplicate delivery within window; coalesces if compatible.
        - Rejects/defers if project event queue is saturated.
        - Returns (event_record, is_new_work, message).
        """
        if now is None:
            now = utc_now()

        payload = payload or {}
        dedup_key = cls.compute_dedup_key(
            project_id=project_id,
            event_type=event_type,
            target_resource=target_resource,
            payload=payload,
        )

        # 1. Check for duplicate/coalesceable event within sliding window
        window_start = now - timedelta(seconds=dedup_window_seconds)
        existing = (
            db.query(OrchestrationEventRecord)
            .filter(
                OrchestrationEventRecord.project_id == project_id,
                OrchestrationEventRecord.dedup_key == dedup_key,
                OrchestrationEventRecord.received_at >= window_start,
                OrchestrationEventRecord.status.in_([
                    EventProcessingStatus.RECEIVED,
                    EventProcessingStatus.PROCESSED,
                ]),
            )
            .order_by(desc(OrchestrationEventRecord.received_at))
            .first()
        )

        if existing:
            existing.coalesced_count += 1
            existing.updated_at = now
            db.commit()
            db.refresh(existing)
            return (
                existing,
                False,
                f"Duplicate event coalesced (count={existing.coalesced_count}) within {dedup_window_seconds}s window."
            )

        # 2. Check project queue saturation to prevent event storms
        active_queued_count = (
            db.query(OrchestrationEventRecord)
            .filter(
                OrchestrationEventRecord.project_id == project_id,
                OrchestrationEventRecord.status == EventProcessingStatus.RECEIVED,
            )
            .count()
        )

        if active_queued_count >= cls.MAX_PROJECT_QUEUED_EVENTS:
            rejected_event = OrchestrationEventRecord(
                project_id=project_id,
                event_type=event_type,
                event_source=event_source,
                dedup_key=dedup_key,
                target_resource=target_resource,
                payload=payload,
                status=EventProcessingStatus.REJECTED,
                coalesced_count=1,
                received_at=now,
                processed_at=now,
                rejection_reason=f"Event queue saturated ({active_queued_count}/{cls.MAX_PROJECT_QUEUED_EVENTS}). Event rejected to prevent storm.",
            )
            db.add(rejected_event)
            db.commit()
            db.refresh(rejected_event)
            return (
                rejected_event,
                False,
                "Event rejected: Project event queue capacity exceeded."
            )

        # 3. Create new valid event record
        new_event = OrchestrationEventRecord(
            project_id=project_id,
            event_type=event_type,
            event_source=event_source,
            dedup_key=dedup_key,
            target_resource=target_resource,
            payload=payload,
            status=EventProcessingStatus.RECEIVED,
            coalesced_count=1,
            received_at=now,
        )
        db.add(new_event)
        db.commit()
        db.refresh(new_event)

        return (new_event, True, "Event successfully ingested and queued for orchestration.")

    @classmethod
    def mark_event_processed(
        cls,
        db: Session,
        event: OrchestrationEventRecord,
        now: Optional[datetime] = None,
    ) -> OrchestrationEventRecord:
        """Marks an event as successfully consumed by a workflow."""
        if now is None:
            now = utc_now()
        event.status = EventProcessingStatus.PROCESSED
        event.processed_at = now
        event.updated_at = now
        db.commit()
        db.refresh(event)
        return event

    @classmethod
    def mark_event_failed(
        cls,
        db: Session,
        event: OrchestrationEventRecord,
        reason: str,
        now: Optional[datetime] = None,
    ) -> OrchestrationEventRecord:
        """Marks an event as failed during processing with an explicit reason."""
        if now is None:
            now = utc_now()
        event.status = EventProcessingStatus.FAILED
        event.processed_at = now
        event.rejection_reason = reason
        event.updated_at = now
        db.commit()
        db.refresh(event)
        return event
