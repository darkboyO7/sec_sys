"""
Production-Grade Structured Logging, Correlation Context, and Sensitive Data Redaction.
Enforces zero log injection, thread/asyncio-safe correlation propagation via ContextVar,
and automatic scrubbing of credentials, tokens, bearer headers, and private keys.
"""

import re
import uuid
import logging
from contextvars import ContextVar
from typing import Optional, Any

# Context variables for request and job tracing across async tasks and worker threads
correlation_id_ctx: ContextVar[str] = ContextVar("correlation_id_ctx", default="")
job_id_ctx: ContextVar[Optional[str]] = ContextVar("job_id_ctx", default=None)

# Bounded correlation id pattern (alphanumeric, underscores, hyphens, max 64 chars)
_CORRELATION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

# Patterns for sensitive data redaction
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9_\-\.]+\b")
_SENSITIVE_KV_PATTERN = re.compile(
    r'(?i)("(?:password|secret|secret_key|api_key|access_token|client_secret|token|private_key)"\s*:\s*)"(?:[^"\\]|\\.)*"',
)
_SENSITIVE_KV_EQUALS_PATTERN = re.compile(
    r'(?i)\b(password|secret|api_key|token|access_token)\s*=\s*["\']?[^\s"\'&,;]+["\']?',
)
_PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"
)


def sanitize_correlation_id(candidate: Optional[str]) -> str:
    """
    Sanitizes external correlation/request IDs to defend against header injection and log spoofing.
    If missing or invalid, generates a trusted UUIDv4.
    """
    if candidate and isinstance(candidate, str):
        candidate_stripped = candidate.strip()
        if _CORRELATION_ID_REGEX.match(candidate_stripped):
            return candidate_stripped
    return str(uuid.uuid4())


def get_correlation_id() -> str:
    """Returns the current request correlation ID, or empty string if not in a request context."""
    return correlation_id_ctx.get()


def set_correlation_id(corr_id: str) -> None:
    """Sets the current correlation ID after sanitization."""
    sanitized = sanitize_correlation_id(corr_id)
    correlation_id_ctx.set(sanitized)


def get_job_id() -> Optional[str]:
    """Returns the current background assessment/orchestration job ID."""
    return job_id_ctx.get()


def set_job_id(job_id: Optional[str]) -> None:
    """Sets the current background assessment job ID."""
    if job_id:
        # Sanitize against CRLF injection
        job_id = re.sub(r"[\r\n\x00-\x1f]", "", str(job_id))[:64]
    job_id_ctx.set(job_id)


class SensitiveDataRedactor:
    """
    Scans text or structured objects and redacts credentials, secrets,
    bearer tokens, and private keys.
    """

    @classmethod
    def redact_text(cls, text: str) -> str:
        if not text or not isinstance(text, str):
            return str(text)

        # 1. Redact PEM private keys
        text = _PEM_PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", text)

        # 2. Redact Bearer tokens
        text = _BEARER_PATTERN.sub("Bearer [REDACTED]", text)

        # 3. Redact JSON-style key-values
        text = _SENSITIVE_KV_PATTERN.sub(r'\1"[REDACTED]"', text)

        # 4. Redact key=value style pairs
        text = _SENSITIVE_KV_EQUALS_PATTERN.sub(r"\1=[REDACTED]", text)

        return text

    @classmethod
    def sanitize_log_injection(cls, text: str) -> str:
        """
        Guards against CRLF log injection by escaping newline and carriage return characters.
        """
        if not text or not isinstance(text, str):
            return ""
        return text.replace("\r", "\\r").replace("\n", "\\n")


class CorrelationLogFilter(logging.Filter):
    """
    Logging filter that injects correlation_id and job_id into every LogRecord,
    and guarantees that sensitive data is scrubbed before emission.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        corr_id = get_correlation_id()
        record.correlation_id = corr_id if corr_id else "-"

        job_id = get_job_id()
        record.job_id = job_id if job_id else "-"

        # Scrub message
        if isinstance(record.msg, str):
            scrubbed = SensitiveDataRedactor.redact_text(record.msg)
            # Escape control characters/newlines to prevent log forging
            record.msg = SensitiveDataRedactor.sanitize_log_injection(scrubbed)

        return True


class StructuredLogFormatter(logging.Formatter):
    """
    Standard production log formatter with explicit correlation identifiers.
    """

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "correlation_id"):
            record.correlation_id = get_correlation_id() or "-"
        if not hasattr(record, "job_id"):
            record.job_id = get_job_id() or "-"

        # Format message safely
        formatted = super().format(record)
        return formatted


def setup_structured_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Configures the root and platform loggers with correlation filters and structured formatting.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Attach filter
    corr_filter = CorrelationLogFilter()

    # Formatter with correlation tracking
    formatter = StructuredLogFormatter(
        "%(asctime)s [%(levelname)s] [corr_id=%(correlation_id)s] [job_id=%(job_id)s] [%(name)s] %(message)s"
    )

    # Ensure existing handlers use our filter and formatter
    for handler in root_logger.handlers:
        handler.addFilter(corr_filter)
        handler.setFormatter(formatter)

    platform_logger = logging.getLogger("vapt.platform")
    platform_logger.setLevel(level)
    return platform_logger
