import json
import hashlib
import threading
from typing import Any, Dict, Optional, Tuple, List
from datetime import datetime, timezone, timedelta
import logging
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.models.audit import AuditEvent, AuditChainHead
from app.core.config import settings

logger = logging.getLogger("vapt.audit")


class AuditPersistenceError(RuntimeError):
    """Raised when audit event serialization or persistence fails under strict audit policy."""
    pass


SENSITIVE_KEYS = {
    "password", "secret", "token", "access_token", "refresh_token",
    "authorization", "api_key", "cookie", "credentials", "private_key"
}


def sanitize_audit_details(data: Any) -> Any:
    """Recursively scrub sensitive keys and credential patterns from audit metadata."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if any(sens in k.lower() for sens in SENSITIVE_KEYS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_audit_details(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_audit_details(item) for item in data]
    return data


def compute_audit_event_hash(
    prev_hash: Optional[str],
    timestamp: datetime,
    actor_id: Optional[str],
    action: str,
    target_type: str,
    target_id: Optional[str],
    project_id: Optional[str],
    outcome: str,
    details: Dict[str, Any],
) -> str:
    """
    Computes deterministic SHA-256 hash for an audit event, binding it to the previous event hash.
    """
    canonical_details = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    if timestamp.tzinfo is None:
        ts_utc = timestamp.replace(tzinfo=timezone.utc)
    else:
        ts_utc = timestamp.astimezone(timezone.utc)
    ts_str = ts_utc.isoformat()
    raw = (
        f"{prev_hash or 'GENESIS'}|"
        f"{ts_str}|"
        f"{actor_id or 'ANONYMOUS'}|"
        f"{action}|"
        f"{target_type}|"
        f"{target_id or ''}|"
        f"{project_id or ''}|"
        f"{outcome}|"
        f"{canonical_details}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AuditService:
    _chain_lock = threading.Lock()

    @classmethod
    def record_event(
        cls,
        db: Session,
        action: str,
        target_type: str,
        outcome: str,
        actor_id: Optional[str] = None,
        actor_email: Optional[str] = None,
        target_id: Optional[str] = None,
        project_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditEvent:
        """
        Record an immutable audit log entry with multi-process serialized hash-chaining.
        Uses partition chain head records (AuditChainHead) to serialize concurrent writers,
        preventing chain forks even when the audit ledger starts out empty.
        Fails closed on any serialization or persistence error under strict audit policy.
        """
        clean_details = sanitize_audit_details(details or {})
        now = datetime.now(timezone.utc)
        proj_str = str(project_id) if project_id is not None else None
        target_id_str = str(target_id) if target_id is not None else None
        partition_key = proj_str or "__GLOBAL__"

        with cls._chain_lock:
            try:
                bind = db.get_bind()
                is_pg = bind and getattr(bind.dialect, "name", "") == "postgresql"

                # 1. Fetch partition chain head with row-level lock on PostgreSQL
                query = db.query(AuditChainHead).filter(AuditChainHead.partition_key == partition_key)
                if is_pg:
                    query = query.with_for_update()
                head = query.first()

                if not head:
                    # Head record does not exist yet: check historical records for this partition
                    hist_query = db.query(AuditEvent)
                    if proj_str:
                        hist_query = hist_query.filter(AuditEvent.project_id == proj_str)
                    else:
                        hist_query = hist_query.filter(AuditEvent.project_id.is_(None))

                    latest_hist = hist_query.order_by(
                        AuditEvent.sequence_number.desc().nullslast(),
                        AuditEvent.timestamp.desc(),
                        AuditEvent.id.desc(),
                    ).first()

                    init_seq = latest_hist.sequence_number if (latest_hist and latest_hist.sequence_number is not None) else 0
                    init_hash = latest_hist.event_hash if latest_hist else None
                    init_ts = latest_hist.timestamp if latest_hist else None

                    # Insert head record atomically
                    try:
                        with db.begin_nested():
                            head = AuditChainHead(
                                partition_key=partition_key,
                                last_sequence_number=init_seq,
                                last_event_hash=init_hash,
                                last_event_timestamp=init_ts,
                                updated_at=now,
                            )
                            db.add(head)
                            db.flush()
                    except IntegrityError:
                        # Another process created the head row concurrently
                        query = db.query(AuditChainHead).filter(AuditChainHead.partition_key == partition_key)
                        if is_pg:
                            query = query.with_for_update()
                        head = query.first()

                if not head:
                    raise AuditPersistenceError(f"Failed to acquire audit chain head for partition '{partition_key}'.")

                last_seq = head.last_sequence_number or 0
                prev_hash = head.last_event_hash
                next_seq = last_seq + 1

                if head.last_event_timestamp:
                    last_ts = head.last_event_timestamp
                    if last_ts.tzinfo is None:
                        last_ts = last_ts.replace(tzinfo=timezone.utc)
                    if last_ts >= now:
                        now = last_ts + timedelta(microseconds=1)

            except Exception as e:
                logger.error(f"Audit chain head serialization failure: {e}", exc_info=True)
                if getattr(settings, "AUDIT_LOG_STRICT", True):
                    raise AuditPersistenceError(f"Audit log write failed under strict security policy: failed to serialize audit chain: {e}") from e
                raise e

            # 2. Compute cryptographically bound hash
            event_hash = compute_audit_event_hash(
                prev_hash=prev_hash,
                timestamp=now,
                actor_id=actor_id,
                action=action,
                target_type=target_type,
                target_id=target_id_str,
                project_id=proj_str,
                outcome=outcome,
                details=clean_details,
            )

            # 3. Create AuditEvent and update AuditChainHead atomically
            try:
                event = AuditEvent(
                    timestamp=now,
                    sequence_number=next_seq,
                    actor_id=actor_id,
                    actor_email=actor_email,
                    action=action,
                    target_type=target_type,
                    target_id=target_id_str,
                    project_id=proj_str,
                    ip_address=ip_address,
                    outcome=outcome,
                    details=clean_details,
                    prev_event_hash=prev_hash,
                    event_hash=event_hash,
                )
                with db.begin_nested():
                    db.add(event)
                    head.last_sequence_number = next_seq
                    head.last_event_hash = event_hash
                    head.last_event_timestamp = now
                    head.updated_at = now
                    db.flush()

                if not db.in_nested_transaction():
                    db.commit()
                    db.refresh(event)

                logger.info(
                    f"AUDIT: seq={next_seq} action={action} actor={actor_email or actor_id} target={target_type}:{target_id} outcome={outcome}"
                )
                return event
            except Exception as e:
                logger.error(f"AUDIT FAILURE: Could not record audit event {action}: {e}", exc_info=True)
                if getattr(settings, "AUDIT_LOG_STRICT", True):
                    raise AuditPersistenceError(f"Audit log write failed under strict security policy: {e}") from e
                raise e

    @classmethod
    def log(
        cls,
        db: Session,
        action: str,
        target_resource: str = "system",
        actor_id: Optional[str] = None,
        project_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        outcome: str = "SUCCESS",
    ) -> AuditEvent:
        parts = target_resource.split(":", 1)
        target_type = parts[0]
        target_id = parts[1] if len(parts) > 1 else None
        return cls.record_event(
            db=db,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            actor_id=actor_id,
            project_id=project_id,
            ip_address=client_ip,
            details=details,
        )

    @classmethod
    def verify_chain_integrity(
        cls,
        db: Session,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Walks the audit ledger and validates hash chain continuity and cryptographic integrity.
        Verifies that every event's prev_event_hash matches the previous event's event_hash,
        recomputes SHA-256 event hashes from details payload to detect in-place tampering,
        and ensures zero tampering, zero forks, and monotonic ordering.
        """
        proj_str = str(project_id) if project_id is not None else None
        query = db.query(AuditEvent)
        if proj_str is not None:
            query = query.filter(AuditEvent.project_id == proj_str)
        else:
            query = query.filter(AuditEvent.project_id.is_(None))

        events = query.order_by(AuditEvent.timestamp.asc(), AuditEvent.id.asc()).all()

        valid = True
        broken_count = 0
        expected_prev_hash = None
        discrepancies: List[str] = []

        for idx, evt in enumerate(events):
            if idx == 0:
                expected_prev_hash = None
            if evt.prev_event_hash != expected_prev_hash:
                valid = False
                broken_count += 1
                discrepancies.append(
                    f"Chain link broken at event '{evt.id}' (seq={evt.sequence_number}): "
                    f"expected prev_hash='{expected_prev_hash}', recorded='{evt.prev_event_hash}'"
                )

            # Sequence number monotonicity verification
            if evt.sequence_number is None or evt.sequence_number <= 0:
                valid = False
                broken_count += 1
                discrepancies.append(
                    f"Invalid non-positive or null sequence number at event '{evt.id}': {evt.sequence_number}"
                )
            elif idx > 0 and events[idx - 1].sequence_number is not None:
                if evt.sequence_number <= events[idx - 1].sequence_number:
                    valid = False
                    broken_count += 1
                    discrepancies.append(
                        f"Non-monotonic sequence order at event '{evt.id}': current={evt.sequence_number}, previous={events[idx - 1].sequence_number}"
                    )

            recomputed = compute_audit_event_hash(
                prev_hash=evt.prev_event_hash,
                timestamp=evt.timestamp,
                actor_id=evt.actor_id,
                action=evt.action,
                target_type=evt.target_type,
                target_id=evt.target_id,
                project_id=evt.project_id,
                outcome=evt.outcome,
                details=evt.details,
            )
            if recomputed != evt.event_hash:
                valid = False
                broken_count += 1
                discrepancies.append(
                    f"Hash integrity failed at event '{evt.id}' (seq={evt.sequence_number}): "
                    f"recorded='{evt.event_hash}', recomputed='{recomputed}'"
                )

            expected_prev_hash = evt.event_hash

        return {
            "valid": valid,
            "total_events": len(events),
            "broken_links": broken_count,
            "forks": 0 if valid else broken_count,
            "discrepancies": discrepancies,
        }
