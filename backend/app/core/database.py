import os
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.engine import make_url
from app.core.config import settings, Settings


def get_effective_database_url(s: Settings = settings) -> str:
    """Returns the effective database URL, redirecting working DB in testing profile (Prompt 49)."""
    url = s.DATABASE_URL
    if s.ENVIRONMENT == "testing" and "vapt.db" in url and not url.endswith("vapt_test.db"):
        backend_dir = Path(__file__).resolve().parent.parent.parent
        test_db_file = (backend_dir / "data" / "vapt_test.db").resolve().as_posix()
        return f"sqlite:///{test_db_file}"
    return url


# Prompt 49: Guard against test execution mutating the user's working database
effective_db_url = get_effective_database_url(settings)

# Ensure sqlite data directory exists if local sqlite path is used
if effective_db_url.startswith("sqlite"):
    # Strip prefix to extract path
    db_path = effective_db_url.replace("sqlite:///", "").replace("sqlite://", "")
    if db_path != ":memory:":
        parent_dir = Path(db_path).parent
        if parent_dir and not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)


def get_engine_kwargs(db_url: str = effective_db_url) -> dict:
    """Return engine configuration arguments based on dialect."""
    kwargs = {
        "pool_pre_ping": True,
        "echo": settings.DEBUG,
    }
    if db_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30.0}
    elif db_url.startswith("postgresql"):
        kwargs["pool_size"] = getattr(settings, "POSTGRES_POOL_SIZE", 20)
        kwargs["max_overflow"] = getattr(settings, "POSTGRES_MAX_OVERFLOW", 10)
        kwargs["pool_timeout"] = getattr(settings, "POSTGRES_POOL_TIMEOUT", 30)
        kwargs["pool_recycle"] = getattr(settings, "POSTGRES_POOL_RECYCLE", 1800)
    return kwargs


def get_masked_database_url(url: str = effective_db_url) -> str:
    """Return database URL with sensitive credentials redacted."""
    try:
        parsed = make_url(url)
        return parsed.render_as_string(hide_password=True)
    except Exception:
        return "<redacted>"


engine_kwargs = get_engine_kwargs(effective_db_url)
engine = create_engine(
    effective_db_url,
    **engine_kwargs,
)

# Apply SQLite specific pragmas for WAL mode and Foreign Key enforcement
if effective_db_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA wal_autocheckpoint=1000")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Provide a transactional database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
