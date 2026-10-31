"""
Enterprise Database Transaction & Concurrency Management.
Supports safe transaction retries with exponential backoff and full jitter
for both PostgreSQL (SQLSTATE 40001, 40P01, 55P03) and SQLite (busy/locked).
Guarantees that non-idempotent operations are never retried unsafely.
"""
import time
import random
import logging
from typing import Callable, TypeVar, Any, Optional
from functools import wraps
from sqlalchemy.orm import Session
from sqlalchemy.exc import DBAPIError, OperationalError, IntegrityError, DataError, ProgrammingError
from app.core.config import settings

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Standard transient DB error indicators (PostgreSQL & SQLite)
TRANSIENT_SQLSTATE_CODES = {
    "40001",  # serialization_failure
    "40P01",  # deadlock_detected
    "55P03",  # lock_not_available
    "08006",  # connection_failure (transient network blip)
    "57P01",  # admin_shutdown
}

# Non-retryable error classes: semantic or schema violations that cannot succeed on retry
FATAL_DB_EXCEPTIONS = (
    IntegrityError,     # Unique violation, FK failure (retrying will not fix a duplicate key)
    DataError,          # Type overflow, string truncation, invalid datetime
    ProgrammingError,   # Syntax error, missing column, table not found
)


def is_transient_db_error(exc: Exception) -> bool:
    """
    Detects whether an exception represents a transient concurrency conflict or lock.
    Returns True for PostgreSQL deadlocks/serialization failures and SQLite busy/locked states.
    Returns False for schema violations, constraint violations, or logic errors.
    """
    # Fatal errors should never be retried
    if isinstance(exc, FATAL_DB_EXCEPTIONS):
        return False

    if isinstance(exc, (OperationalError, DBAPIError)):
        orig = getattr(exc, "orig", None)
        if orig:
            # Check for PostgreSQL SQLSTATE
            sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
            if sqlstate in TRANSIENT_SQLSTATE_CODES:
                return True
            err_msg = str(orig).lower()
            if any(marker in err_msg for marker in ("deadlock", "database is locked", "lock timeout", "sqlite_busy")):
                return True
        err_msg = str(exc).lower()
        if any(marker in err_msg for marker in ("database is locked", "deadlock", "could not obtain lock", "sqlite_busy")):
            return True

    return False


def with_transaction_retry(
    max_retries: Optional[int] = None,
    base_delay: Optional[float] = None,
    backoff_factor: float = 2.0,
    jitter: bool = True,
    is_idempotent: bool = True,
):
    """
    Decorator that retries database transactions on transient serialization or deadlock errors.
    If is_idempotent=False, the decorator refuses to retry to prevent duplicate mutations.
    """
    retries = max_retries if max_retries is not None else settings.DB_RETRY_MAX_ATTEMPTS
    delay = base_delay if base_delay is not None else settings.DB_RETRY_BASE_DELAY_SECONDS

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            if not is_idempotent:
                # Non-idempotent operation: do not retry automatically to prevent duplicate records
                return func(*args, **kwargs)

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


# Alias for explicit enterprise codebases
with_safe_transaction_retry = with_transaction_retry


def execute_with_safe_retry(
    action_fn: Callable[[], T],
    max_retries: Optional[int] = None,
    base_delay: Optional[float] = None,
    is_idempotent: bool = True,
) -> T:
    """
    Executes a callable block with safe transaction retry semantics.
    """
    wrapped = with_transaction_retry(
        max_retries=max_retries,
        base_delay=base_delay,
        is_idempotent=is_idempotent,
    )(action_fn)
    return wrapped()


def get_dialect_name(session_or_engine: Any) -> str:
    """Return normalized dialect name (e.g. 'postgresql' or 'sqlite')."""
    if hasattr(session_or_engine, "bind") and session_or_engine.bind:
        return session_or_engine.bind.dialect.name
    if hasattr(session_or_engine, "dialect") and session_or_engine.dialect:
        return session_or_engine.dialect.name
    return "sqlite"
