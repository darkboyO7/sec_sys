import os
import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from app.core.database import Base
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.core.security import hash_password


def test_sqlite_persistence_across_engine_restart(tmp_path):
    # Use a persistent SQLite file in tmp_path
    db_file = tmp_path / "persistent_vapt.db"
    db_url = f"sqlite:///{db_file}"

    # Engine 1: Create schema and insert data
    engine1 = create_engine(db_url)

    @event.listens_for(engine1, "connect")
    def set_pragma1(dbapi_con, con_record):
        cur = dbapi_con.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.close()

    Base.metadata.create_all(bind=engine1)
    Session1 = sessionmaker(bind=engine1)
    session1 = Session1()

    org = Organization(name="Persistent Bank", slug="persistent-bank")
    session1.add(org)
    session1.commit()

    user = User(
        email="lead@persistent.local",
        hashed_password=hash_password("LeadPass123!"),
        full_name="Lead Analyst",
        system_role=SystemRole.SECURITY_LEAD,
    )
    session1.add(user)
    session1.commit()

    project = Project(name="Core Vault Audit", organization_id=org.id)
    session1.add(project)
    session1.commit()

    target = ScopeTarget(
        project_id=project.id,
        target_type=TargetType.DOMAIN,
        target_value="vault.persistent.local",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-992-PERMANENT",
        created_by_id=user.id,
    )
    session1.add(target)
    session1.commit()

    saved_proj_id = project.id
    saved_target_id = target.id

    # Close and dispose engine 1 completely
    session1.close()
    engine1.dispose()

    # Engine 2: Re-open the database as if the application restarted
    engine2 = create_engine(db_url)

    @event.listens_for(engine2, "connect")
    def set_pragma2(dbapi_con, con_record):
        cur = dbapi_con.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Session2 = sessionmaker(bind=engine2)
    session2 = Session2()

    # Verify data exists and WAL mode was preserved
    wal_check = session2.execute(text("PRAGMA journal_mode;")).scalar()
    assert wal_check.lower() == "wal"

    reloaded_project = session2.query(Project).filter(Project.id == saved_proj_id).first()
    assert reloaded_project is not None
    assert reloaded_project.name == "Core Vault Audit"

    reloaded_target = session2.query(ScopeTarget).filter(ScopeTarget.id == saved_target_id).first()
    assert reloaded_target is not None
    assert reloaded_target.target_value == "vault.persistent.local"
    assert reloaded_target.authorization_status == AuthorizationStatus.AUTHORIZED

    session2.close()
    engine2.dispose()


def test_sqlite_foreign_key_enforcement(tmp_path):
    db_file = tmp_path / "fk_test.db"
    engine = create_engine(f"sqlite:///{db_file}")

    @event.listens_for(engine, "connect")
    def set_pragma(dbapi_con, con_record):
        cur = dbapi_con.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Attempt to insert ProjectMember with non-existent project_id and user_id
    invalid_member = ProjectMember(
        project_id="non-existent-proj-uuid",
        user_id="non-existent-user-uuid",
        role=ProjectRole.TESTER,
    )
    session.add(invalid_member)

    with pytest.raises(IntegrityError):
        session.commit()

    session.rollback()
    session.close()
    engine.dispose()
