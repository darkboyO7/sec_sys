import hashlib
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Type
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.authorization import TokenRevocationRecord, AccessDenialAuditRecord
from app.core.permissions import (
    Permission,
    SYSTEM_ROLE_PERMISSIONS,
    PROJECT_ROLE_PERMISSIONS,
)
from app.core.security import decode_access_token


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def redact_sensitive_strings(text: str) -> str:
    """Redact sensitive authorization tokens, private keys, or passwords from strings."""
    if not text:
        return ""
    # Redact Bearer JWT tokens
    text = re.sub(r"Bearer\s+eyJ[a-zA-Z0-9_\-\.]+", "Bearer [REDACTED_JWT]", text)
    # Redact raw passwords
    text = re.sub(r'("password"|"current_password"|"new_password")\s*:\s*"[^"]+"', r'\1: "[REDACTED]"', text)
    return text


class AuthorizationService:

    @staticmethod
    def record_access_denial(
        db: Session,
        endpoint: str,
        http_method: str,
        required_privilege: str,
        denial_reason: str,
        user_id: Optional[str] = None,
        user_email: Optional[str] = None,
        project_id: Optional[str] = None,
        held_privilege: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> AccessDenialAuditRecord:
        """
        Record attributable access denial entry with zero sensitive token or credential leakage.
        """
        clean_endpoint = redact_sensitive_strings(endpoint)
        clean_reason = redact_sensitive_strings(denial_reason)

        record = AccessDenialAuditRecord(
            user_id=user_id,
            user_email=user_email,
            project_id=project_id,
            endpoint=clean_endpoint,
            http_method=http_method.upper(),
            required_privilege=required_privilege,
            held_privilege=held_privilege or "NONE",
            denial_reason=clean_reason,
            client_ip=client_ip,
            denied_at=datetime.now(timezone.utc),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def revoke_token(
        db: Session,
        token: str,
        user_id: str,
        reason: str = "USER_LOGOUT",
    ) -> str:
        """
        Add token to cryptographic revocation blocklist.
        """
        try:
            payload = decode_access_token(token)
            jti = payload.get("jti")
            exp = payload.get("exp")
            if exp:
                expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
            else:
                expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        except Exception:
            # If token cannot be decoded, hash the token string itself
            jti = hashlib.sha256(token.encode("utf-8")).hexdigest()
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        if not jti:
            jti = hashlib.sha256(token.encode("utf-8")).hexdigest()

        # Idempotent record
        existing = db.query(TokenRevocationRecord).filter(
            TokenRevocationRecord.token_jti == jti
        ).first()

        if not existing:
            rev_record = TokenRevocationRecord(
                token_jti=jti,
                user_id=user_id,
                revoked_at=datetime.now(timezone.utc),
                expires_at=expires_at,
                reason=reason,
            )
            db.add(rev_record)
            db.commit()

        return jti

    @staticmethod
    def is_token_revoked(
        db: Session,
        token: str,
        user: User,
        payload: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Verify whether token is globally invalidated or in revocation blocklist.
        """
        if not payload:
            try:
                payload = decode_access_token(token)
            except Exception:
                return True

        # 1. Global User Invalidation Check (token_revoked_before)
        if user.token_revoked_before:
            revoked_before = ensure_utc(user.token_revoked_before)
            iat_precise = payload.get("iat_precise")
            if iat_precise is not None:
                token_time = datetime.fromtimestamp(iat_precise, tz=timezone.utc)
                if token_time <= revoked_before:
                    return True
            else:
                iat = payload.get("iat")
                if iat:
                    iat_dt = datetime.fromtimestamp(iat, tz=timezone.utc)
                    if iat_dt < revoked_before.replace(microsecond=0):
                        return True

        # 2. Blocklist Check
        jti = payload.get("jti")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        filters = [TokenRevocationRecord.token_jti == token_hash]
        if jti:
            filters.append(TokenRevocationRecord.token_jti == jti)

        revoked = db.query(TokenRevocationRecord).filter(or_(*filters)).first()
        return revoked is not None

    @staticmethod
    def revoke_all_user_tokens(db: Session, user_id: str) -> datetime:
        """
        Invalidate all active sessions for user by updating token_revoked_before.
        """
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        now = datetime.now(timezone.utc)
        user.token_revoked_before = now
        db.commit()
        return now

    @staticmethod
    def verify_resource_ownership(
        db: Session,
        model_class: Type,
        resource_id: str,
        project_id: str,
        resource_name: str = "Resource",
    ) -> Any:
        """
        Object-level authorization check.
        Ensures that the requested entity belongs to the specified project.
        Fails closed with 404 to avoid leaking cross-tenant resource identities.
        """
        obj = db.query(model_class).filter(model_class.id == resource_id).first()
        if not obj:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"{resource_name} not found",
            )

        obj_project_id = getattr(obj, "project_id", None)
        if obj_project_id is not None and obj_project_id != project_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,  # Fail closed
                detail=f"{resource_name} not found in this project",
            )

        return obj

    @staticmethod
    def get_permission_matrix() -> Dict[str, Any]:
        """
        Retrieve structured catalog of permissions across all system and project roles.
        """
        system_items = []
        for s_role in SystemRole:
            perms = [p.value for p in SYSTEM_ROLE_PERMISSIONS.get(s_role, set())]
            desc = {
                SystemRole.ADMIN: "Full platform-wide administrative authority",
                SystemRole.SECURITY_LEAD: "Platform security oversight, approvals, and policy management",
                SystemRole.SECURITY_TESTER: "Assessment execution, verification, and technical analysis",
                SystemRole.AUDITOR: "Read-only compliance, audit log, and reporting access",
                SystemRole.VIEWER: "Read-only inspection of visible project state",
            }.get(s_role, "Custom role")
            system_items.append({
                "role": s_role.value,
                "role_type": "SYSTEM",
                "description": desc,
                "granted_permissions": sorted(perms),
            })

        project_items = []
        for p_role in ProjectRole:
            perms = [p.value for p in PROJECT_ROLE_PERMISSIONS.get(p_role, set())]
            desc = {
                ProjectRole.LEAD: "Project team lead with approval, SoD, and policy authority",
                ProjectRole.TESTER: "Active penetration tester and assessment operator",
                ProjectRole.VIEWER: "Read-only project auditor and observer",
            }.get(p_role, "Custom project role")
            project_items.append({
                "role": p_role.value,
                "role_type": "PROJECT",
                "description": desc,
                "granted_permissions": sorted(perms),
            })

        return {
            "available_permissions": sorted([p.value for p in Permission]),
            "system_roles": system_items,
            "project_roles": project_items,
        }
