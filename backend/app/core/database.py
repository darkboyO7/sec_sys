import os
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.engine import make_url
from app.core.config import settings

# Ensure sqlite data directory exists if local sqlite path is used
if settings.DATABASE_URL.startswith("sqlite"):
    # Strip prefix to extract path
    db_path = settings.DATABASE_URL.replace("sqlite:///", "").replace("sqlite://", "")
    if db_path != ":memory:":
        parent_dir = Path(db_path).parent
        if parent_dir and not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)


def get_engine_kwargs(db_url: str = settings.DATABASE_URL) -> dict:
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


def get_masked_database_url(url: str = settings.DATABASE_URL) -> str:
    """Return database URL with sensitive credentials redacted."""
    try:
        parsed = make_url(url)
        return parsed.render_as_string(hide_password=True)
    except Exception:
        return "<redacted>"


engine_kwargs = get_engine_kwargs(settings.DATABASE_URL)
engine = create_engine(
    settings.DATABASE_URL,
    **engine_kwargs,
)

# Apply SQLite specific pragmas for WAL mode and Foreign Key enforcement
if settings.DATABASE_URL.startswith("sqlite"):
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
