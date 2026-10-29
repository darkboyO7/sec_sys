from typing import List
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import hash_password, verify_password, create_access_token
from app.core.config import settings
from app.models.user import User, SystemRole
from app.schemas.auth import UserCreate, UserResponse, LoginRequest, TokenResponse
from app.services.audit_service import AuditService
from app.services.rate_limit_service import rate_limiter
from app.api.deps import get_current_user, get_client_ip

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    user_in: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Register a new user account.
    First user registered in an empty database is automatically assigned ADMIN role for bootstrap.
    """
    client_ip = get_client_ip(request)
    existing_user = db.query(User).filter(User.email == user_in.email.lower()).first()
    if existing_user:
        AuditService.record_event(
            db=db,
            action="AUTH_REGISTER_FAIL",
            target_type="user",
            outcome="FAILURE",
            actor_email=user_in.email.lower(),
            ip_address=client_ip,
            details={"reason": "Email already registered"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists",
        )

    # Check if this is the first user
    user_count = db.query(User).count()
    assigned_role = SystemRole.ADMIN if user_count == 0 else (user_in.system_role or SystemRole.SECURITY_TESTER)

    new_user = User(
        email=user_in.email.lower(),
        hashed_password=hash_password(user_in.password),
        full_name=user_in.full_name.strip(),
        system_role=assigned_role,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    AuditService.record_event(
        db=db,
        action="AUTH_REGISTER_SUCCESS",
        target_type="user",
        target_id=new_user.id,
        actor_id=new_user.id,
        actor_email=new_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={"assigned_role": assigned_role.value, "is_bootstrap_admin": user_count == 0},
    )

    return new_user


@router.post("/login", response_model=TokenResponse)
def login(
    login_in: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Authenticate credentials and issue a short-lived signed JWT bearer token.
    Records audit entry for both successful and denied attempts.
    """
    client_ip = get_client_ip(request)

    # Defend against brute force login storms
    allowed, remaining, retry_after = rate_limiter.is_allowed(
        key=client_ip or "unknown",
        bucket="AUTH_LOGIN",
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many authentication attempts. Please retry after {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

    user = db.query(User).filter(User.email == login_in.email.lower()).first()

    if not user or not verify_password(login_in.password, user.hashed_password):
        AuditService.record_event(
            db=db,
            action="AUTH_LOGIN_FAILED",
            target_type="user",
            target_id=user.id if user else None,
            actor_email=login_in.email.lower(),
            outcome="DENIED",
            ip_address=client_ip,
            details={"reason": "Invalid credentials"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        AuditService.record_event(
            db=db,
            action="AUTH_LOGIN_INACTIVE",
            target_type="user",
            target_id=user.id,
            actor_id=user.id,
            actor_email=user.email,
            outcome="DENIED",
            ip_address=client_ip,
            details={"reason": "Account is inactive"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Contact platform administrator.",
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        subject=user.id,
        claims={"email": user.email, "role": user.system_role.value},
        expires_delta=access_token_expires,
    )

    AuditService.record_event(
        db=db,
        action="AUTH_LOGIN_SUCCESS",
        target_type="user",
        target_id=user.id,
        actor_id=user.id,
        actor_email=user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={"role": user.system_role.value},
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    """Retrieve profile of currently authenticated actor."""
    return current_user


@router.get("/users", response_model=List[UserResponse])
def list_organization_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve registered users in organization for access governance."""
    users = db.query(User).filter(User.is_active == True).order_by(User.full_name).all()
    return users
