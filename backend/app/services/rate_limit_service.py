"""
VAPT Platform — API Abuse & Rate Limiting Service (Prompt 24).
Provides thread-safe sliding window rate limiting for sensitive operations
such as authentication, assessment dispatch, report generation, and disaster restore.
"""
import time
import threading
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger("vapt.rate_limit")


class RateLimitService:
    """
    In-memory sliding window rate limiter designed for single-node / local mode operation.
    Enforces distinct operational limits across security-sensitive endpoint buckets.
    """

    # Pre-configured bucket profiles: (max_requests, window_seconds)
    BUCKET_PROFILES: Dict[str, Tuple[int, int]] = {
        "AUTH_LOGIN": (30, 60),          # 30 login attempts per minute
        "JOB_CREATION": (60, 60),        # 60 scan jobs per minute
        "RECOVERY_LIVE": (50, 60),       # 50 recovery operations per minute
        "REPORT_EXPORT": (40, 60),       # 40 exports per minute
        "DISCOVERY_INGEST": (100, 60),   # 100 asset ingestion calls per minute
        "DEFAULT": (500, 60),            # 500 general requests per minute
    }

    def __init__(self):
        self._lock = threading.Lock()
        # Storage format: { (bucket, key): [timestamp1, timestamp2, ...] }
        self._records: Dict[Tuple[str, str], List[float]] = {}

    def is_allowed(
        self,
        key: str,
        bucket: str = "DEFAULT",
        custom_limit: Optional[int] = None,
        custom_window: Optional[int] = None,
    ) -> Tuple[bool, int, int]:
        """
        Evaluates whether a request from 'key' under 'bucket' is allowed.

        Returns:
            Tuple of:
            - is_allowed (bool): True if under limit, False if exceeded
            - remaining (int): Count of remaining allowed requests in current window
            - retry_after (int): Seconds until window resets (0 if allowed)
        """
        now = time.time()
        max_requests, window = self.BUCKET_PROFILES.get(bucket, self.BUCKET_PROFILES["DEFAULT"])
        if custom_limit is not None:
            max_requests = custom_limit
        if custom_window is not None:
            window = custom_window

        bucket_key = (bucket, key)

        with self._lock:
            timestamps = self._records.get(bucket_key, [])
            # Evict timestamps outside sliding window
            cutoff = now - window
            valid_timestamps = [t for t in timestamps if t > cutoff]

            if len(valid_timestamps) >= max_requests:
                # Limit exceeded; calculate retry_after from oldest timestamp in window
                oldest_in_window = valid_timestamps[0]
                retry_after = max(1, int(oldest_in_window + window - now))
                self._records[bucket_key] = valid_timestamps
                logger.warning(
                    f"Rate limit exceeded: bucket={bucket} key={key} count={len(valid_timestamps)} max={max_requests}"
                )
                return False, 0, retry_after

            # Within limits; record timestamp
            valid_timestamps.append(now)
            self._records[bucket_key] = valid_timestamps
            remaining = max(0, max_requests - len(valid_timestamps))
            return True, remaining, 0

    def reset(self) -> None:
        """Clears all in-memory rate-limiting counters (used primarily by test fixtures)."""
        with self._lock:
            self._records.clear()


# Global singleton instance
rate_limiter = RateLimitService()
