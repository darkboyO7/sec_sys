from typing import List, Optional, Any
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import decode_access_token
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme),
) -> User:
    """Validate Bearer JWT, check session validity & revocation, and return authenticated User."""
    payload = decode_access_token(token)
    user_id: str = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )

    # Check if token is on revocation blocklist or invalidated by user-level revocation timestamp
    from app.services.authorization_service import AuthorizationService
    if AuthorizationService.is_token_revoked(db, token, user, payload):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_system_roles(allowed_roles: List[SystemRole]):
    """Enforce system-level role requirements with auditable access denial logging."""
    def role_checker(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        if current_user.system_role not in allowed_roles and current_user.system_role != SystemRole.ADMIN:
            from app.services.authorization_service import AuthorizationService
            req_str = ", ".join(r.value for r in allowed_roles)
            AuthorizationService.record_access_denial(
                db=db,
                endpoint="/system-action",
                http_method="UNKNOWN",
                required_privilege=req_str,
                held_privilege=current_user.system_role.value,
                denial_reason=f"Operation requires one of system roles: [{req_str}], held: '{current_user.system_role.value}'",
                user_id=current_user.id,
                user_email=current_user.email,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of the following roles: {[r.value for r in allowed_roles]}",
            )
        return current_user
    return role_checker


def get_client_ip(request: Request) -> Optional[str]:
    """Extract client IP from request headers or client socket."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def verify_project_access(
    project_id: str,
    user: User,
    db: Session,
    required_project_roles: Optional[List[ProjectRole]] = None,
) -> Project:
    """
    Verify that user has authorized access to the project.
    Admins have global oversight.
    Other users must have an active membership in the project.
    Fails closed with 404/403 to maintain tenant/project isolation and logs auditable access denials.
    """
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )

    # Admin bypass for oversight
    if user.system_role == SystemRole.ADMIN:
        return project

    membership = (
        db.query(ProjectMember)
        .filter(ProjectMember.project_id == project_id, ProjectMember.user_id == user.id)
        .first()
    )

    if not membership:
        from app.services.authorization_service import AuthorizationService
        AuthorizationService.record_access_denial(
            db=db,
            endpoint=f"/projects/{project_id}",
            http_method="UNKNOWN",
            required_privilege="PROJECT_MEMBER",
            held_privilege="NONE",
            denial_reason=f"User '{user.email}' is not an authorized member of project '{project_id}'",
            user_id=user.id,
            user_email=user.email,
            project_id=project_id,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,  # Fail closed: do not leak existence of unauthorized projects
            detail="Project not found",
        )

    if required_project_roles and membership.role not in required_project_roles:
        from app.services.authorization_service import AuthorizationService
        req_str = ", ".join(r.value for r in required_project_roles)
        AuthorizationService.record_access_denial(
            db=db,
            endpoint=f"/projects/{project_id}",
            http_method="UNKNOWN",
            required_privilege=req_str,
            held_privilege=membership.role.value,
            denial_reason=f"Project operation requires one of: [{req_str}], held role: '{membership.role.value}'",
            user_id=user.id,
            user_email=user.email,
            project_id=project_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Project operation requires one of: [{req_str}]",
        )

    return project


def verify_resource_ownership(
    model_class: Any,
    resource_id: str,
    project_id: str,
    db: Session,
    resource_name: str = "Resource",
) -> Any:
    """Object-level authorization check enforcing project boundary containment."""
    from app.services.authorization_service import AuthorizationService
    return AuthorizationService.verify_resource_ownership(db, model_class, resource_id, project_id, resource_name)
