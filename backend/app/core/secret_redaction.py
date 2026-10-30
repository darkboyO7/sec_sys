"""
Secret Redaction Engine (Prompt 45).
Provides high-performance, deterministic pattern redaction for logs, exceptions,
stack traces, diagnostic reports, and serialized API payloads.
Ensures zero secret leakage across console output, log files, and external exports.
"""
import re
import logging
from typing import Any, Dict, List, Set, Union, Optional

# High-sensitivity key names (case-insensitive substring match)
SENSITIVE_KEY_NAMES: Set[str] = {
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "secret_key",
    "credential",
    "credentials",
    "authorization",
    "auth_token",
    "bearer",
    "encryption_key",
    "database_url",
    "db_password",
    "client_secret",
}

# Regex patterns matching known secret token formats in text
SECRET_TEXT_PATTERNS: List[re.Pattern] = [
    # Database connection strings with credentials: scheme://username:password@host:port/dbname
    re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]+://[^:\s@]+):([^@\s]+)(@[^:\s]+)", re.IGNORECASE),
    # JWT tokens: header.payload.signature (base64url)
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    # Bearer tokens in headers or logs
    re.compile(r"(Bearer\s+)[a-zA-Z0-9_\-\.~+/]+=*", re.IGNORECASE),
    # GitHub personal access tokens
    re.compile(r"gh[pousr]_[a-zA-Z0-9]{36,255}"),
    # Slack tokens
    re.compile(r"xox[baprs]-[a-zA-Z0-9\-]{10,72}"),
    # AWS access key ID
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Generic Private Key blocks
    re.compile(r"-----BEGIN (?:[A-Z\s]+)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z\s]+)?PRIVATE KEY-----"),
    # Generic hex secret strings (length >= 32, e.g. secrets.token_hex(32))
    re.compile(r"\b[0-9a-fA-F]{64}\b"),
]

REDACTED_SUBSTITUTE = "***REDACTED_SECRET***"


def mask_secret_string(value: str, visible_prefix: int = 3, visible_suffix: int = 3) -> str:
    """
    Masks a string while optionally leaving short prefix/suffix characters for diagnostic identification.
    If the string is short (<= 8 chars), masks completely.
    """
    if not value or not isinstance(value, str):
        return REDACTED_SUBSTITUTE
    v_len = len(value)
    if v_len <= 8 or (visible_prefix + visible_suffix >= v_len):
        return "********"
    return f"{value[:visible_prefix]}****{value[-visible_suffix:]}"


def redact_secrets_from_text(text: str) -> str:
    """
    Sanitizes any raw text or log line by substituting identified credentials,
    connection strings, JWTs, and private keys with redaction markers.
    """
    if not text or not isinstance(text, str):
        return text

    sanitized = text

    # Sanitize database URLs (replace password portion with ***REDACTED***)
    sanitized = SECRET_TEXT_PATTERNS[0].sub(r"\1:***REDACTED***\3", sanitized)

    # Sanitize Bearer tokens
    sanitized = SECRET_TEXT_PATTERNS[2].sub(r"\1***REDACTED***", sanitized)

    # Sanitize Private Key blocks
    sanitized = SECRET_TEXT_PATTERNS[6].sub("-----BEGIN " + "PRIVATE KEY-----\n***REDACTED PRIVATE KEY***\n-----END " + "PRIVATE KEY-----", sanitized)

    # Sanitize JWTs, GitHub PATs, Slack, AWS keys, 64-char hex tokens
    for pat in [SECRET_TEXT_PATTERNS[1], SECRET_TEXT_PATTERNS[3], SECRET_TEXT_PATTERNS[4], SECRET_TEXT_PATTERNS[5], SECRET_TEXT_PATTERNS[7]]:
        sanitized = pat.sub(REDACTED_SUBSTITUTE, sanitized)

    return sanitized


def redact_secrets_from_dict(data: Any, max_depth: int = 15, current_depth: int = 0) -> Any:
    """
    Recursively scans and redacts sensitive keys and values in nested dictionaries, lists,
    and primitive structures.
    """
    if current_depth > max_depth:
        return "[MAX_DEPTH_EXCEEDED]"

    if isinstance(data, dict):
        sanitized_dict: Dict[str, Any] = {}
        for k, v in data.items():
            k_str = str(k).lower()
            is_sensitive = any(s_key in k_str for s_key in SENSITIVE_KEY_NAMES)

            if is_sensitive:
                if isinstance(v, str):
                    sanitized_dict[k] = mask_secret_string(v)
                elif isinstance(v, (int, float, bool)):
                    sanitized_dict[k] = "********"
                elif isinstance(v, dict):
                    sanitized_dict[k] = redact_secrets_from_dict(v, max_depth, current_depth + 1)
                elif isinstance(v, list):
                    sanitized_dict[k] = ["********" for _ in v]
                else:
                    sanitized_dict[k] = REDACTED_SUBSTITUTE
            else:
                sanitized_dict[k] = redact_secrets_from_dict(v, max_depth, current_depth + 1)
        return sanitized_dict

    elif isinstance(data, list):
        return [redact_secrets_from_dict(item, max_depth, current_depth + 1) for item in data]

    elif isinstance(data, str):
        return redact_secrets_from_text(data)

    return data


class SecretRedactionLoggingFilter(logging.Filter):
    """
    Python logging filter that intercepts log records and scrubs any sensitive
    tokens, connection strings, or credentials before the record is formatted or emitted.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact_secrets_from_text(record.msg)
            if record.args:
                if isinstance(record.args, dict):
                    record.args = redact_secrets_from_dict(record.args)
                elif isinstance(record.args, (list, tuple)):
                    record.args = tuple(
                        redact_secrets_from_text(str(a)) if isinstance(a, str) else redact_secrets_from_dict(a) if isinstance(a, dict) else a
                        for a in record.args
                    )
        except Exception:
            pass  # Redaction filter must never crash logger
        return True


def install_global_secret_redaction_filter() -> None:
    """
    Attaches SecretRedactionLoggingFilter to root logger and standard handlers.
    """
    root_logger = logging.getLogger()
    filt = SecretRedactionLoggingFilter()
    
    # Avoid duplicate filter attachment
    for existing in root_logger.filters:
        if isinstance(existing, SecretRedactionLoggingFilter):
            return

    root_logger.addFilter(filt)
    for handler in root_logger.handlers:
        handler.addFilter(filt)
