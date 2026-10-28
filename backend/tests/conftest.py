import os
import pytest
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.core.database import Base, get_db
from app.core.security import hash_password, create_access_token
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.main import app

# Use a distinct test database file
TEST_DB_PATH = "./data/vapt_test.db"
TEST_DATABASE_URL = f"sqlite:///{TEST_DB_PATH}"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30.0},
)

@event.listens_for(test_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create test database schema once for the test session and clean up after."""
    os.makedirs("./data", exist_ok=True)
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except Exception:
            pass


@pytest.fixture
def db() -> Generator[Session, None, None]:
    """Provide a clean transactional session for each test."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db: Session) -> Generator[TestClient, None, None]:
    """Test client with db dependency override."""
    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_organization(db: Session) -> Organization:
    org = Organization(name="ACME Defense Corp", slug="acme-defense", is_active=True)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@pytest.fixture
def admin_user(db: Session) -> User:
    user = User(
        email="admin@acme-defense.local",
        hashed_password=hash_password("SuperSecretAdminPass123!"),
        full_name="Global Security Admin",
        system_role=SystemRole.ADMIN,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def lead_user(db: Session) -> User:
    user = User(
        email="lead@acme-defense.local",
        hashed_password=hash_password("LeadPass12345!"),
        full_name="Security Lead Officer",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def tester_user(db: Session) -> User:
    user = User(
        email="tester@acme-defense.local",
        hashed_password=hash_password("TesterPass12345!"),
        full_name="Penetration Tester",
        system_role=SystemRole.SECURITY_TESTER,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def auditor_user(db: Session) -> User:
    user = User(
        email="auditor@acme-defense.local",
        hashed_password=hash_password("AuditorPass12345!"),
        full_name="Compliance Auditor",
        system_role=SystemRole.AUDITOR,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def outsider_user(db: Session) -> User:
    user = User(
        email="outsider@acme-defense.local",
        hashed_password=hash_password("OutsiderPass12345!"),
        full_name="Unassigned Contractor",
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def auth_header_for_user(user: User) -> dict:
    token = create_access_token(subject=user.id, claims={"email": user.email, "role": user.system_role.value})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers(admin_user: User) -> dict:
    return auth_header_for_user(admin_user)


@pytest.fixture
def lead_headers(lead_user: User) -> dict:
    return auth_header_for_user(lead_user)


@pytest.fixture
def tester_headers(tester_user: User) -> dict:
    return auth_header_for_user(tester_user)


@pytest.fixture
def auditor_headers(auditor_user: User) -> dict:
    return auth_header_for_user(auditor_user)


@pytest.fixture
def outsider_headers(outsider_user: User) -> dict:
    return auth_header_for_user(outsider_user)


@pytest.fixture
def test_project(db: Session, test_organization: Organization, lead_user: User, tester_user: User) -> Project:
    project = Project(
        name="Project Apex Assessment",
        description="Core banking API penetration test",
        organization_id=test_organization.id,
        is_active=True,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    # Lead membership
    db.add(ProjectMember(project_id=project.id, user_id=lead_user.id, role=ProjectRole.LEAD))
    # Tester membership
    db.add(ProjectMember(project_id=project.id, user_id=tester_user.id, role=ProjectRole.TESTER))
    db.commit()
    return project
