import time
import random
import logging
from typing import Callable, TypeVar, Any, Optional
from functools import wraps
from sqlalchemy.orm import Session
from sqlalchemy.exc import DBAPIError, OperationalError
from app.core.config import settings

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Standard transient DB error indicators (PostgreSQL & SQLite)
TRANSIENT_SQLSTATE_CODES = {
    "40001",  # serialization_failure
    "40P01",  # deadlock_detected
    "55P03",  # lock_not_available
}


def is_transient_db_error(exc: Exception) -> bool:
    """Detect transient database lock or serialization conflict."""
    if isinstance(exc, (OperationalError, DBAPIError)):
        orig = getattr(exc, "orig", None)
        if orig:
            # Check for PostgreSQL SQLSTATE
            sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
            if sqlstate in TRANSIENT_SQLSTATE_CODES:
                return True
            err_msg = str(orig).lower()
            if "deadlock" in err_msg or "database is locked" in err_msg or "lock timeout" in err_msg:
                return True
        err_msg = str(exc).lower()
        if "database is locked" in err_msg or "deadlock" in err_msg:
            return True
    return False


def with_transaction_retry(
    max_retries: Optional[int] = None,
    base_delay: Optional[float] = None,
    backoff_factor: float = 2.0,
    jitter: bool = True,
):
    """
    Decorator that retries database transactions on transient serialization or deadlock errors.
    """
    retries = max_retries if max_retries is not None else settings.DB_RETRY_MAX_ATTEMPTS
    delay = base_delay if base_delay is not None else settings.DB_RETRY_BASE_DELAY_SECONDS

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            attempt = 0
            current_delay = delay
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    attempt += 1
                    if attempt > retries or not is_transient_db_error(exc):
                        raise
                    
                    sleep_time = current_delay
                    if jitter:
                        sleep_time += random.uniform(0, current_delay * 0.5)
                    
                    logger.warning(
                        "Transient DB conflict detected in %s (attempt %d/%d). Retrying in %.3fs: %s",
                        func.__name__,
                        attempt,
                        retries,
                        sleep_time,
                        exc,
                    )
                    time.sleep(sleep_time)
                    current_delay *= backoff_factor

        return wrapper

    return decorator


def get_dialect_name(session_or_engine: Any) -> str:
    """Return normalized dialect name (e.g. 'postgresql' or 'sqlite')."""
    if hasattr(session_or_engine, "bind") and session_or_engine.bind:
        return session_or_engine.bind.dialect.name
    if hasattr(session_or_engine, "dialect") and session_or_engine.dialect:
        return session_or_engine.dialect.name
    return "sqlite"
