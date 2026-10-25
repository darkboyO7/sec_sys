import os
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.database import get_db, Base
from app.core.config import settings
from app.schemas.health import HealthResponse, ReadinessResponse, ReadinessCheck

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def liveness_check():
    """Liveness probe: verifies that the control plane process is responsive."""
    return HealthResponse(
        status="ok",
        version="1.0.0",
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/ready", response_model=ReadinessResponse)
def readiness_check(db: Session = Depends(get_db)):
    """Readiness probe: validates database connectivity, schema tables, and disk writability."""
    db_ok = False
    migrations_ok = False
    storage_ok = False
    details = {}

    # Check Database connection
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
        details["database"] = "reachable"
    except Exception as e:
        details["database"] = f"error: {str(e)}"

    # Check Schema tables exist
    try:
        # Check users table presence
        db.execute(text("SELECT count(*) FROM users"))
        migrations_ok = True
        details["schema"] = "initialized"
    except Exception as e:
        details["schema"] = f"tables_missing_or_unmigrated: {str(e)}"

    # Check Storage writability (data directory or temp)
    try:
        test_file = Path("./data/_readiness_test.tmp")
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("ok")
        if test_file.exists():
            test_file.unlink()
        storage_ok = True
        details["storage"] = "writable"
    except Exception as e:
        details["storage"] = f"unwritable: {str(e)}"

    is_ready = db_ok and migrations_ok and storage_ok
    status_code = status.HTTP_200_OK if is_ready else status.HTTP_503_SERVICE_UNAVAILABLE

    response_data = ReadinessResponse(
        status="ready" if is_ready else "not_ready",
        timestamp=datetime.now(timezone.utc),
        checks=ReadinessCheck(
            database=db_ok,
            migrations=migrations_ok,
            storage_writable=storage_ok,
            details=details,
        ),
    )

    if not is_ready:
        raise HTTPException(status_code=status_code, detail=response_data.model_dump())

    return response_data
