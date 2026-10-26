import os
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings

# Ensure sqlite data directory exists if local sqlite path is used
if settings.DATABASE_URL.startswith("sqlite"):
    # Strip prefix to extract path
    db_path = settings.DATABASE_URL.replace("sqlite:///", "").replace("sqlite://", "")
    if db_path != ":memory:":
        parent_dir = Path(db_path).parent
        if parent_dir and not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)

connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,
    "echo": settings.DEBUG,
}

if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    engine_kwargs["connect_args"] = connect_args
elif settings.DATABASE_URL.startswith("postgresql"):
    # Production-ready PostgreSQL connection pool configuration
    engine_kwargs["pool_size"] = getattr(settings, "POSTGRES_POOL_SIZE", 20)
    engine_kwargs["max_overflow"] = getattr(settings, "POSTGRES_MAX_OVERFLOW", 10)
    engine_kwargs["pool_timeout"] = getattr(settings, "POSTGRES_POOL_TIMEOUT", 30)
    engine_kwargs["pool_recycle"] = getattr(settings, "POSTGRES_POOL_RECYCLE", 1800)

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
