from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, ScopeExclusion
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectResponse, ProjectMemberAdd, ProjectMemberResponse
from app.services.audit_service import AuditService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


def get_or_create_default_org(db: Session) -> Organization:
    org = db.query(Organization).first()
    if not org:
        org = Organization(name="Default Organization", slug="default-org", is_active=True)
        db.add(org)
        db.commit()
        db.refresh(org)
    return org


@router.get("/", response_model=List[ProjectResponse])
def list_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List projects accessible to the authenticated actor.
    Admins can view all projects. Standard users see only projects where they are registered members.
    """
    if current_user.system_role == SystemRole.ADMIN:
        projects = db.query(Project).all()
    else:
        projects = (
            db.query(Project)
            .join(ProjectMember, ProjectMember.project_id == Project.id)
            .filter(ProjectMember.user_id == current_user.id)
            .all()
        )

    results = []
    for p in projects:
        m_count = db.query(ProjectMember).filter(ProjectMember.project_id == p.id).count()
        t_count = db.query(ScopeTarget).filter(ScopeTarget.project_id == p.id).count()
        e_count = db.query(ScopeExclusion).filter(ScopeExclusion.project_id == p.id).count()
        resp = ProjectResponse.model_validate(p)
        resp.member_count = m_count
        resp.scope_target_count = t_count
        resp.scope_exclusion_count = e_count
        results.append(resp)

    return results


@router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
def create_project(
    project_in: ProjectCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Create a new project workspace.
    The creator is automatically assigned as Project LEAD.
    """
    client_ip = get_client_ip(request)
    org_id = project_in.organization_id
    if not org_id:
        default_org = get_or_create_default_org(db)
        org_id = default_org.id
    else:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")

    new_project = Project(
        name=project_in.name.strip(),
        description=project_in.description or "",
        organization_id=org_id,
        is_active=True,
    )
    db.add(new_project)
    db.commit()
    db.refresh(new_project)

    # Assign creator as Project LEAD
    membership = ProjectMember(
        project_id=new_project.id,
        user_id=current_user.id,
        role=ProjectRole.LEAD,
    )
    db.add(membership)
    db.commit()

    AuditService.record_event(
        db=db,
        action="PROJECT_CREATE",
        target_type="project",
        target_id=new_project.id,
        project_id=new_project.id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={"name": new_project.name, "organization_id": org_id},
    )

    resp = ProjectResponse.model_validate(new_project)
    resp.member_count = 1
    resp.scope_target_count = 0
    resp.scope_exclusion_count = 0
    return resp


@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch project details with server-side isolation check."""
    project = verify_project_access(project_id, current_user, db)
    m_count = db.query(ProjectMember).filter(ProjectMember.project_id == project.id).count()
    t_count = db.query(ScopeTarget).filter(ScopeTarget.project_id == project.id).count()
    e_count = db.query(ScopeExclusion).filter(ScopeExclusion.project_id == project.id).count()

    resp = ProjectResponse.model_validate(project)
    resp.member_count = m_count
    resp.scope_target_count = t_count
    resp.scope_exclusion_count = e_count
    return resp


@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: str,
    project_in: ProjectUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update project metadata. Requires project LEAD or system ADMIN."""
    client_ip = get_client_ip(request)
    project = verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])

    changes = {}
    if project_in.name is not None and project_in.name.strip():
        changes["name"] = {"old": project.name, "new": project_in.name.strip()}
        project.name = project_in.name.strip()
    if project_in.description is not None:
        changes["description"] = {"old": project.description, "new": project_in.description}
        project.description = project_in.description
    if project_in.is_active is not None:
        changes["is_active"] = {"old": project.is_active, "new": project_in.is_active}
        project.is_active = project_in.is_active

    db.commit()
    db.refresh(project)

    AuditService.record_event(
        db=db,
        action="PROJECT_UPDATE",
        target_type="project",
        target_id=project.id,
        project_id=project.id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={"changes": changes},
    )

    m_count = db.query(ProjectMember).filter(ProjectMember.project_id == project.id).count()
    t_count = db.query(ScopeTarget).filter(ScopeTarget.project_id == project.id).count()
    e_count = db.query(ScopeExclusion).filter(ScopeExclusion.project_id == project.id).count()

    resp = ProjectResponse.model_validate(project)
    resp.member_count = m_count
    resp.scope_target_count = t_count
    resp.scope_exclusion_count = e_count
    return resp


@router.get("/{project_id}/members", response_model=List[ProjectMemberResponse])
def list_project_members(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List members of a project."""
    verify_project_access(project_id, current_user, db)
    members = db.query(ProjectMember).filter(ProjectMember.project_id == project_id).all()
    results = []
    for m in members:
        user = db.query(User).filter(User.id == m.user_id).first()
        results.append(
            ProjectMemberResponse(
                id=m.id,
                user_id=m.user_id,
                role=m.role,
                created_at=m.created_at,
                user_email=user.email if user else None,
                user_full_name=user.full_name if user else None,
            )
        )
    return results


@router.post("/{project_id}/members", response_model=ProjectMemberResponse, status_code=status.HTTP_201_CREATED)
def add_project_member(
    project_id: str,
    member_in: ProjectMemberAdd,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Add a member to a project. Requires project LEAD or system ADMIN."""
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])

    target_user = db.query(User).filter(User.id == member_in.user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    existing = (
        db.query(ProjectMember)
        .filter(ProjectMember.project_id == project_id, ProjectMember.user_id == member_in.user_id)
        .first()
    )
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is already a member of this project")

    member = ProjectMember(
        project_id=project_id,
        user_id=member_in.user_id,
        role=member_in.role,
    )
    db.add(member)
    db.commit()
    db.refresh(member)

    AuditService.record_event(
        db=db,
        action="PROJECT_MEMBER_ADD",
        target_type="project_member",
        target_id=member.id,
        project_id=project_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={"user_id": member_in.user_id, "role": member_in.role.value},
    )

    return ProjectMemberResponse(
        id=member.id,
        user_id=member.user_id,
        role=member.role,
        created_at=member.created_at,
        user_email=target_user.email,
        user_full_name=target_user.full_name,
    )
