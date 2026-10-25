from typing import Any, Dict, Optional
from datetime import datetime, timezone
import logging
from sqlalchemy.orm import Session
from app.models.audit import AuditEvent
from app.core.config import settings

logger = logging.getLogger("vapt.audit")

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


class AuditService:
    @staticmethod
    def record_event(
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
        Record an immutable audit log entry.
        Fails closed or logs fatal error if audit persistence fails.
        """
        clean_details = sanitize_audit_details(details or {})
        try:
            event = AuditEvent(
                timestamp=datetime.now(timezone.utc),
                actor_id=actor_id,
                actor_email=actor_email,
                action=action,
                target_type=target_type,
                target_id=str(target_id) if target_id is not None else None,
                project_id=str(project_id) if project_id is not None else None,
                ip_address=ip_address,
                outcome=outcome,
                details=clean_details,
            )
            db.add(event)
            if db.in_nested_transaction():
                db.flush()
            else:
                db.commit()
                db.refresh(event)
            logger.info(
                f"AUDIT: action={action} actor={actor_email or actor_id} target={target_type}:{target_id} outcome={outcome}"
            )
            return event
        except Exception as e:
            db.rollback()
            logger.error(f"AUDIT FAILURE: Could not record audit event {action}: {e}", exc_info=True)
            if settings.AUDIT_LOG_STRICT:
                raise RuntimeError(f"Audit log write failed under strict security policy: {e}") from e
            raise

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
