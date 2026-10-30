"""
Fault Injection and Resilience Verification Framework (Prompt 52).

Provides deterministic fault-injection hooks exclusively for automated testing and resilience verification.
STRICT FAIL-CLOSED SECURITY GUARD:
Fault injection is strictly prohibited and structurally blocked in production and staging environments.
Attempting to enable or register fault injection hooks in production/staging environments
raises an immediate FaultInjectionSecurityError.
"""
import enum
import logging
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable

from app.core.config import settings

logger = logging.getLogger("vapt.fault_injection")


class FaultType(str, enum.Enum):
    DATABASE_INTERRUPTION = "DATABASE_INTERRUPTION"
    WORKER_TERMINATION = "WORKER_TERMINATION"
    ADAPTER_TIMEOUT = "ADAPTER_TIMEOUT"
    PROVIDER_OUTAGE = "PROVIDER_OUTAGE"
    DISK_WRITE_FAILURE = "DISK_WRITE_FAILURE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    INTERRUPTED_BACKGROUND_TASK = "INTERRUPTED_BACKGROUND_TASK"


class FaultInjectionSecurityError(RuntimeError):
    """Raised when fault injection is attempted in an unauthorized environment (production/staging)."""
    pass


class DatabaseInterruptionError(Exception):
    """Simulated transient database connection loss or transactional commit interruption."""
    pass


class WorkerTerminationError(Exception):
    """Simulated abrupt worker crash, SIGKILL, or OOM termination."""
    pass


class AdapterTimeoutError(TimeoutError):
    """Simulated scanner adapter execution deadline exhaustion."""
    pass


class ProviderOutageError(Exception):
    """Simulated external webhook, notification provider, or threat feed 503 outage."""
    pass


class DiskWriteFailureError(IOError):
    """Simulated disk full, read-only filesystem, or I/O failure during artifact write."""
    pass


class MalformedResponseError(ValueError):
    """Simulated corrupted, truncated, or invalid JSON payload returned by an external tool/provider."""
    pass


class InterruptedBackgroundTaskError(Exception):
    """Simulated cooperative cancellation or worker preemption during background batch processing."""
    pass


@dataclass
class FaultRule:
    fault_type: FaultType
    trigger_point: str
    error_message: str = "Simulated fault injection"
    count: int = 1  # -1 for unlimited
    injected_count: int = 0
    params: Dict[str, Any] = field(default_factory=dict)
    filter_fn: Optional[Callable[[Dict[str, Any]], bool]] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_active(self) -> bool:
        if self.count == -1:
            return True
        return self.injected_count < self.count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fault_type": self.fault_type.value,
            "trigger_point": self.trigger_point,
            "error_message": self.error_message,
            "count": self.count,
            "injected_count": self.injected_count,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
        }


class FaultInjector:
    """
    Thread-safe controller governing deterministic fault injection hooks.
    Active ONLY in testing and development profiles when explicitly enabled.
    """
    _lock = threading.Lock()
    _active_rules: List[FaultRule] = []
    _injected_history: List[Dict[str, Any]] = []

    @classmethod
    def is_injection_permitted(cls) -> bool:
        """
        Fail-closed security guard.
        Fault injection is completely disallowed in production and staging environments.
        """
        env = (settings.ENVIRONMENT or "").lower().strip()
        if env in ("production", "staging"):
            return False
        if not getattr(settings, "FAULT_INJECTION_ENABLED", False):
            return False
        return True

    @classmethod
    def register_rule(cls, rule: FaultRule) -> FaultRule:
        """
        Registers a deterministic fault injection rule.
        Fails closed with FaultInjectionSecurityError if called in production or when disabled.
        """
        env = (settings.ENVIRONMENT or "").lower().strip()
        if env in ("production", "staging"):
            raise FaultInjectionSecurityError(
                f"Security violation: Fault injection is strictly prohibited in '{env}' environment."
            )
        if not getattr(settings, "FAULT_INJECTION_ENABLED", False):
            raise FaultInjectionSecurityError(
                "Fault injection is disabled. Set FAULT_INJECTION_ENABLED=True in test configuration."
            )

        with cls._lock:
            cls._active_rules.append(rule)
            logger.warning(
                f"[FAULT_INJECTION_REGISTERED] Type: {rule.fault_type.value}, "
                f"Trigger: {rule.trigger_point}, Count: {rule.count}"
            )
            return rule

    @classmethod
    def remove_rule(cls, rule: FaultRule) -> None:
        with cls._lock:
            if rule in cls._active_rules:
                cls._active_rules.remove(rule)

    @classmethod
    def clear(cls) -> None:
        with cls._lock:
            cls._active_rules.clear()
            cls._injected_history.clear()

    @classmethod
    def get_active_rules(cls) -> List[Dict[str, Any]]:
        with cls._lock:
            return [r.to_dict() for r in cls._active_rules if r.is_active]

    @classmethod
    def get_history(cls) -> List[Dict[str, Any]]:
        with cls._lock:
            return list(cls._injected_history)

    @classmethod
    def maybe_inject(cls, trigger_point: str, context: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        """
        Checks if an active fault rule matches the given trigger point.
        Executes fault action (raises exception or returns malformed payload) if matched.
        """
        if not cls.is_injection_permitted():
            return None

        ctx = context or {}
        matched_rule: Optional[FaultRule] = None

        with cls._lock:
            for rule in cls._active_rules:
                if rule.is_active and rule.trigger_point == trigger_point:
                    if rule.filter_fn is None or rule.filter_fn(ctx):
                        matched_rule = rule
                        rule.injected_count += 1
                        cls._injected_history.append({
                            "fault_type": rule.fault_type.value,
                            "trigger_point": trigger_point,
                            "injected_at": datetime.now(timezone.utc).isoformat(),
                            "context": {k: str(v) for k, v in ctx.items() if "secret" not in k.lower() and "token" not in k.lower()},
                            "message": rule.error_message,
                        })
                        break

        if not matched_rule:
            return None

        logger.warning(
            f"[FAULT_INJECTED] Injected {matched_rule.fault_type.value} at '{trigger_point}': {matched_rule.error_message}"
        )

        # Dispatch the injected fault
        if matched_rule.fault_type == FaultType.DATABASE_INTERRUPTION:
            raise DatabaseInterruptionError(matched_rule.error_message)

        elif matched_rule.fault_type == FaultType.WORKER_TERMINATION:
            raise WorkerTerminationError(matched_rule.error_message)

        elif matched_rule.fault_type == FaultType.ADAPTER_TIMEOUT:
            raise AdapterTimeoutError(matched_rule.error_message)

        elif matched_rule.fault_type == FaultType.PROVIDER_OUTAGE:
            raise ProviderOutageError(matched_rule.error_message)

        elif matched_rule.fault_type == FaultType.DISK_WRITE_FAILURE:
            raise DiskWriteFailureError(matched_rule.error_message)

        elif matched_rule.fault_type == FaultType.MALFORMED_RESPONSE:
            if "raw_payload" in matched_rule.params:
                return matched_rule.params["raw_payload"]
            raise MalformedResponseError(matched_rule.error_message)

        elif matched_rule.fault_type == FaultType.INTERRUPTED_BACKGROUND_TASK:
            raise InterruptedBackgroundTaskError(matched_rule.error_message)

        return None


@contextmanager
def fault_injection_context(
    fault_type: FaultType,
    trigger_point: str,
    error_message: str = "Simulated fault injection",
    count: int = 1,
    params: Optional[Dict[str, Any]] = None,
    filter_fn: Optional[Callable[[Dict[str, Any]], bool]] = None,
):
    """
    Context manager for safely registering and auto-cleaning a test fault injection rule.
    Enables FAULT_INJECTION_ENABLED temporarily for the duration of the test block.
    """
    original_enabled = getattr(settings, "FAULT_INJECTION_ENABLED", False)
    settings.FAULT_INJECTION_ENABLED = True

    rule = FaultRule(
        fault_type=fault_type,
        trigger_point=trigger_point,
        error_message=error_message,
        count=count,
        params=params or {},
        filter_fn=filter_fn,
    )
    try:
        FaultInjector.register_rule(rule)
        yield rule
    finally:
        FaultInjector.remove_rule(rule)
        settings.FAULT_INJECTION_ENABLED = original_enabled
