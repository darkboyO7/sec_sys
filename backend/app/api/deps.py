from typing import List, Optional
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
    """Validate Bearer JWT and return authenticated User."""
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
    return user


def require_system_roles(allowed_roles: List[SystemRole]):
    """Enforce system-level role requirements."""
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.system_role not in allowed_roles and current_user.system_role != SystemRole.ADMIN:
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
    Fails closed with 404/403 to maintain tenant/project isolation.
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,  # Fail closed: do not leak existence of unauthorized projects
            detail="Project not found",
        )

    if required_project_roles and membership.role not in required_project_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Project operation requires one of: {[r.value for r in required_project_roles]}",
        )

    return project
