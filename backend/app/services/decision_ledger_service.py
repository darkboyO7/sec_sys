from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.decision import (
    SecurityDecisionLedgerRecord,
    DecisionLedgerType,
)
from app.models.user import User


class DecisionLedgerService:
    """
    Auditable Security Decision Ledger Service (Prompt 11 / Section 3).
    Maintains a persistent, append-only ledger for all significant operational decisions:
    - Assessment scheduling
    - Target acceptance/rejection
    - Finding prioritization
    - Remediation recommendations and execution
    - Finding resolution and reopening
    - Governed learning acceptance/rejection
    - Autonomy suspension and cancellation
    """

    REDACTED_KEYS = {"password", "secret", "token", "auth", "api_key", "credential", "private_key"}

    @classmethod
    def record_decision(
        cls,
        db: Session,
        project_id: str,
        decision_type: DecisionLedgerType,
        decision_outcome: str,
        initiating_event: str,
        target_type: str,
        reason: str,
        target_id: Optional[str] = None,
        target_resource: Optional[str] = None,
        policy_version: str = "v1.0.0",
        evidence_references: Optional[List[Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None,
        actor_id: Optional[str] = None,
    ) -> SecurityDecisionLedgerRecord:
        """
        Records an immutable decision entry into the ledger with sensitive data redaction.
        """
        clean_evidence = [cls._sanitize_payload(e) for e in (evidence_references or [])]
        clean_details = cls._sanitize_payload(details or {})

        entry = SecurityDecisionLedgerRecord(
            project_id=project_id,
            decision_type=decision_type,
            decision_outcome=decision_outcome,
            initiating_event=initiating_event,
            target_type=target_type,
            target_id=target_id,
            target_resource=target_resource,
            policy_version=policy_version,
            reason=reason,
            evidence_references=clean_evidence,
            details=clean_details,
            actor_id=actor_id,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry

    @classmethod
    def query_ledger(
        cls,
        db: Session,
        project_id: str,
        decision_type: Optional[DecisionLedgerType] = None,
        decision_outcome: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Queries ledger records strictly within project boundary.
        """
        query = db.query(SecurityDecisionLedgerRecord).filter(
            SecurityDecisionLedgerRecord.project_id == project_id
        )
        if decision_type:
            query = query.filter(SecurityDecisionLedgerRecord.decision_type == decision_type)
        if decision_outcome:
            query = query.filter(SecurityDecisionLedgerRecord.decision_outcome == decision_outcome)
        if target_type:
            query = query.filter(SecurityDecisionLedgerRecord.target_type == target_type)
        if target_id:
            query = query.filter(SecurityDecisionLedgerRecord.target_id == target_id)

        total_count = query.count()
        records = (
            query.order_by(desc(SecurityDecisionLedgerRecord.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )

        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "records": records,
        }

    @classmethod
    def get_audit_trail_for_entity(
        cls,
        db: Session,
        project_id: str,
        target_id: str,
    ) -> List[SecurityDecisionLedgerRecord]:
        """
        Retrieves the complete historical decision sequence for a specific target entity.
        """
        return (
            db.query(SecurityDecisionLedgerRecord)
            .filter(
                SecurityDecisionLedgerRecord.project_id == project_id,
                SecurityDecisionLedgerRecord.target_id == target_id,
            )
            .order_by(SecurityDecisionLedgerRecord.created_at.asc())
            .all()
        )

    @classmethod
    def _sanitize_payload(cls, data: Any) -> Any:
        """
        Recursively redacts sensitive keys from payload structures.
        """
        if isinstance(data, dict):
            clean = {}
            for k, v in data.items():
                if any(sec in k.lower() for sec in cls.REDACTED_KEYS):
                    clean[k] = "[REDACTED]"
                else:
                    clean[k] = cls._sanitize_payload(v)
            return clean
        elif isinstance(data, list):
            return [cls._sanitize_payload(item) for item in data]
        return data
