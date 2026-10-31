from typing import List
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.core.database import get_db
from app.core.security import hash_password, verify_password, create_access_token
from app.core.config import settings
from app.models.base import generate_uuid, utc_now
from app.models.user import User, SystemRole, SystemBootstrapState
from app.schemas.auth import UserCreate, UserResponse, LoginRequest, TokenResponse, AdminUserCreate
from app.services.audit_service import AuditService
from app.services.rate_limit_service import rate_limiter
from app.api.deps import get_current_user, get_client_ip, require_system_roles

router = APIRouter()

PRIVILEGED_SYSTEM_ROLES = {SystemRole.ADMIN, SystemRole.SECURITY_LEAD, SystemRole.AUDITOR}


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    user_in: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Register a new user account with strict privilege escalation defense and race-safe bootstrap.
    - Initial administrator bootstrap is protected by a database-enforced singleton lock (SystemBootstrapState).
    - Concurrent bootstrap attempts are physically serialized at the database level; losers safely fall back.
    - Public registration never accepts or assigns privileged roles (ADMIN, SECURITY_LEAD, AUDITOR).
    - Unauthenticated privilege escalation attempts are logged to the audit ledger and blocked.
    - Duplicate email registrations are handled race-safely via database unique constraints.
    """
    client_ip = get_client_ip(request)
    email_clean = user_in.email.lower().strip()

    # 1. Early check for existing registered email
    existing_user = db.query(User).filter(User.email == email_clean).first()
    if existing_user:
        AuditService.record_event(
            db=db,
            action="AUTH_REGISTER_FAIL",
            target_type="user",
            outcome="FAILURE",
            actor_email=email_clean,
            ip_address=client_ip,
            details={"reason": "Email already registered"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists",
        )

    # 2. Strict Privilege Escalation Defense: Log unauthorized role requests
    if user_in.system_role in PRIVILEGED_SYSTEM_ROLES:
        AuditService.record_event(
            db=db,
            action="AUTH_PRIVILEGE_ESCALATION_ATTEMPT",
            target_type="user",
            outcome="DENIED",
            actor_email=email_clean,
            ip_address=client_ip,
            details={
                "requested_role": user_in.system_role.value if user_in.system_role else None,
                "reason": "Unauthenticated registration cannot request privileged role",
            },
        )

    # 3. Race-safe atomic bootstrap lock
    # Check if bootstrap has already occurred
    bootstrap_state = db.query(SystemBootstrapState).filter(SystemBootstrapState.id == 1).first()
    is_bootstrap_admin = False
    new_user = None

    if not bootstrap_state:
        # Check if database has zero users (fresh deployment)
        user_count = db.query(User).count()
        if user_count == 0:
            # Attempt atomic insert of bootstrap singleton record alongside initial admin user
            try:
                with db.begin_nested():
                    new_user_id = generate_uuid()
                    new_user = User(
                        id=new_user_id,
                        email=email_clean,
                        hashed_password=hash_password(user_in.password),
                        full_name=user_in.full_name.strip(),
                        system_role=SystemRole.ADMIN,
                        is_active=True,
                    )
                    db.add(new_user)
                    b_state = SystemBootstrapState(
                        id=1,
                        is_bootstrapped=True,
                        bootstrap_user_id=new_user_id,
                        bootstrapped_at=utc_now(),
                    )
                    db.add(b_state)
                    db.flush()
                is_bootstrap_admin = True
            except IntegrityError:
                # Concurrent request won the bootstrap race or email collided
                db.rollback()
                if db.query(User).filter(User.email == email_clean).first():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="A user with this email address already exists",
                    )
                is_bootstrap_admin = False
                new_user = None
        else:
            # Existing installation with users: permanently close bootstrap
            try:
                with db.begin_nested():
                    b_state = SystemBootstrapState(
                        id=1,
                        is_bootstrapped=True,
                        bootstrap_user_id="LEGACY_INSTALLATION",
                        bootstrapped_at=utc_now(),
                    )
                    db.add(b_state)
                    db.flush()
            except IntegrityError:
                pass
            is_bootstrap_admin = False

    if not is_bootstrap_admin:
        # Standard unprivileged user registration
        assigned_role = SystemRole.SECURITY_TESTER
        new_user = User(
            email=email_clean,
            hashed_password=hash_password(user_in.password),
            full_name=user_in.full_name.strip(),
            system_role=assigned_role,
            is_active=True,
        )
        db.add(new_user)

    try:
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists",
        )

    AuditService.record_event(
        db=db,
        action="AUTH_REGISTER_SUCCESS",
        target_type="user",
        target_id=new_user.id,
        actor_id=new_user.id,
        actor_email=new_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={"assigned_role": new_user.system_role.value, "is_bootstrap_admin": is_bootstrap_admin},
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
    current_user: User = Depends(require_system_roles([
        SystemRole.ADMIN,
        SystemRole.SECURITY_LEAD,
        SystemRole.AUDITOR,
    ])),
):
    """
    Retrieve registered users in organization for access governance.
    Strictly role-gated to administrative, security lead, and auditor personnel.
    """
    users = db.query(User).filter(User.is_active == True).order_by(User.full_name).all()
    return users


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_privileged_user(
    user_in: AdminUserCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN])),
):
    """
    Authorized Administrator endpoint to provision user accounts with designated system roles.
    Guarded strictly by ADMIN system role requirement.
    """
    client_ip = get_client_ip(request)
    existing_user = db.query(User).filter(User.email == user_in.email.lower()).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists",
        )

    new_user = User(
        email=user_in.email.lower(),
        hashed_password=hash_password(user_in.password),
        full_name=user_in.full_name.strip(),
        system_role=user_in.system_role,
        is_active=user_in.is_active,
    )
    db.add(new_user)
    try:
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists",
        )

    AuditService.record_event(
        db=db,
        action="ADMIN_CREATE_USER",
        target_type="user",
        target_id=new_user.id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={"assigned_role": user_in.system_role.value, "provisioned_by_admin": current_user.email},
    )

    return new_user


@router.post("/logout")
def logout_user(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Revoke the current authentication token and terminate session immediately.
    """
    from app.services.authorization_service import AuthorizationService
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    revoked_id = None
    if token:
        revoked_id = AuthorizationService.revoke_token(
            db=db,
            token=token,
            user_id=current_user.id,
            reason="USER_LOGOUT",
        )

    AuditService.record_event(
        db=db,
        action="AUTH_LOGOUT",
        target_type="user",
        target_id=current_user.id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=get_client_ip(request),
        details={"revoked_token_id": revoked_id},
    )

    return {"status": "SUCCESS", "message": "Session terminated and token revoked successfully"}


@router.post("/revoke-all")
def revoke_all_sessions(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Invalidate all issued tokens for the current user across all devices.
    """
    from app.services.authorization_service import AuthorizationService
    cutoff = AuthorizationService.revoke_all_user_tokens(db, current_user.id)

    AuditService.record_event(
        db=db,
        action="AUTH_REVOKE_ALL_SESSIONS",
        target_type="user",
        target_id=current_user.id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=get_client_ip(request),
        details={"revoked_before": cutoff.isoformat()},
    )

    return {
        "status": "SUCCESS",
        "message": "All active sessions revoked successfully",
        "revoked_before": cutoff.isoformat(),
    }


@router.post("/change-password")
def change_user_password(
    payload: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Change user password with validation, session invalidation, and zero credential leakage.
    """
    from app.services.authorization_service import AuthorizationService

    current_pw = payload.get("current_password", "")
    new_pw = payload.get("new_password", "")

    if not current_pw or not new_pw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current and new password are required",
        )

    if len(new_pw) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters in length",
        )

    if not verify_password(current_pw, current_user.hashed_password):
        AuditService.record_event(
            db=db,
            action="AUTH_CHANGE_PASSWORD_FAIL",
            target_type="user",
            target_id=current_user.id,
            actor_id=current_user.id,
            actor_email=current_user.email,
            outcome="FAILURE",
            ip_address=get_client_ip(request),
            details={"reason": "Invalid current password"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid current password",
        )

    # Update password and revoke all existing sessions
    current_user.hashed_password = hash_password(new_pw)
    cutoff = AuthorizationService.revoke_all_user_tokens(db, current_user.id)
    db.commit()

    AuditService.record_event(
        db=db,
        action="AUTH_CHANGE_PASSWORD_SUCCESS",
        target_type="user",
        target_id=current_user.id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=get_client_ip(request),
        details={"sessions_invalidated": True},
    )

    return {
        "status": "SUCCESS",
        "message": "Password changed successfully. All previous sessions have been invalidated.",
    }
