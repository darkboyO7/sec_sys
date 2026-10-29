"""
Bounded Query Cache and Database Aggregation Service (Prompt 41).
Provides thread-safe, bounded-capacity LRU caching with strict multi-tenant
workspace and role isolation, TTL expiration, and direct SQL aggregations.
"""
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List
from collections import OrderedDict
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
)
from app.models.assessment import FindingSeverity


class CacheEntry:
    def __init__(self, value: Any, expires_at: float):
        self.value = value
        self.expires_at = expires_at


class BoundedQueryCache:
    """
    Thread-safe, memory-bounded LRU cache with strict workspace and role isolation.
    Guarantees that cached entries never leak across projects or privilege levels.
    """

    def __init__(self, max_capacity: int = 1000, default_ttl_seconds: float = 30.0):
        self.max_capacity = max_capacity
        self.default_ttl_seconds = default_ttl_seconds
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.invalidations = 0

    @staticmethod
    def build_key(project_id: str, user_role: str, namespace: str, sub_key: str) -> str:
        """
        Builds a canonical cache key enforcing multi-tenant project and role boundaries.
        """
        return f"proj:{project_id}:role:{user_role}:{namespace}:{sub_key}"

    def _build_key(self, project_id: str, user_role: str, namespace: str, sub_key: str) -> str:
        return self.build_key(project_id, user_role, namespace, sub_key)

    def get(self, project_id: str, user_role: str, namespace: str, sub_key: str) -> Optional[Any]:
        key = self._build_key(project_id, user_role, namespace, sub_key)
        now = time.monotonic()
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if entry.expires_at < now:
                    # Expired entry - purge and count as miss
                    del self._cache[key]
                    self.misses += 1
                    return None
                # Move to end (most recently used)
                self._cache.move_to_end(key)
                self.hits += 1
                return entry.value
            self.misses += 1
            return None

    def set(
        self,
        project_id: str,
        user_role: str,
        namespace: str,
        sub_key: str,
        value: Any,
        ttl_seconds: Optional[float] = None,
    ) -> None:
        key = self._build_key(project_id, user_role, namespace, sub_key)
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        expires_at = time.monotonic() + ttl

        with self._lock:
            # If key already exists, refresh and move to end
            if key in self._cache:
                self._cache[key] = CacheEntry(value, expires_at)
                self._cache.move_to_end(key)
                return

            # Check capacity and evict least recently used if necessary
            if len(self._cache) >= self.max_capacity:
                self._cache.popitem(last=False)
                self.evictions += 1

            self._cache[key] = CacheEntry(value, expires_at)

    def invalidate_project(self, project_id: str, namespace: Optional[str] = None) -> int:
        """
        Invalidates all cached entries for a given project, optionally scoped to a namespace.
        """
        prefix = f"proj:{project_id}:"
        ns_filter = f":{namespace}:" if namespace else None
        removed_count = 0

        with self._lock:
            keys_to_remove = [
                k for k in self._cache.keys()
                if k.startswith(prefix) and (ns_filter is None or ns_filter in k)
            ]
            for k in keys_to_remove:
                del self._cache[k]
                removed_count += 1
            self.invalidations += removed_count

        return removed_count

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self.invalidations += 1

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            total_requests = self.hits + self.misses
            hit_ratio = (self.hits / total_requests) if total_requests > 0 else 0.0
            return {
                "total_cached_items": len(self._cache),
                "max_capacity": self.max_capacity,
                "hits": self.hits,
                "misses": self.misses,
                "hit_ratio": round(hit_ratio, 4),
                "evictions": self.evictions,
                "invalidations": self.invalidations,
            }


# Global singleton cache instance
query_cache = BoundedQueryCache(max_capacity=1000, default_ttl_seconds=30.0)


class DatabaseOptimizationService:
    """
    Provides optimized SQL aggregation queries and cache management.
    """

    @staticmethod
    def get_finding_stats_optimized(
        db: Session,
        project_id: str,
        user_role: str,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        Computes finding statistics using efficient SQL GROUP BY queries rather than
        loading thousands of full entity rows into application memory.
        Enforces tenant and role cache isolation.
        """
        if use_cache:
            cached = query_cache.get(project_id, user_role, "FINDING_STATS", "summary")
            if cached is not None:
                return cached

        # 1. SQL Group By status counts
        status_counts_raw = (
            db.query(VulnerabilityFinding.status, func.count(VulnerabilityFinding.id))
            .filter(VulnerabilityFinding.project_id == project_id)
            .group_by(VulnerabilityFinding.status)
            .all()
        )
        status_map = {row[0].value if hasattr(row[0], "value") else str(row[0]): row[1] for row in status_counts_raw}

        # 2. SQL Group By severity counts
        sev_counts_raw = (
            db.query(VulnerabilityFinding.severity, func.count(VulnerabilityFinding.id))
            .filter(VulnerabilityFinding.project_id == project_id)
            .group_by(VulnerabilityFinding.severity)
            .all()
        )
        sev_map = {row[0].value if hasattr(row[0], "value") else str(row[0]): row[1] for row in sev_counts_raw}

        # 3. Direct count for contradictions
        contradiction_count = (
            db.query(func.count(VulnerabilityFinding.id))
            .filter(
                VulnerabilityFinding.project_id == project_id,
                VulnerabilityFinding.has_contradictions == True,
            )
            .scalar()
            or 0
        )

        # 4. Fill complete enums
        by_status = {s.value: status_map.get(s.value, 0) for s in FindingLifecycleStatus}
        by_severity = {s.value: sev_map.get(s.value, 0) for s in FindingSeverity}

        unresolved_statuses = {
            FindingLifecycleStatus.DETECTED.value,
            FindingLifecycleStatus.NEEDS_VALIDATION.value,
            FindingLifecycleStatus.CONFIRMED.value,
            FindingLifecycleStatus.INCONCLUSIVE.value,
            FindingLifecycleStatus.REOPENED.value,
            FindingLifecycleStatus.REMEDIATION_PROPOSED.value,
            FindingLifecycleStatus.REMEDIATION_APPROVED.value,
            FindingLifecycleStatus.REMEDIATION_ATTEMPTED.value,
            FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION.value,
            FindingLifecycleStatus.EXPIRED.value,
        }

        unresolved_count = sum(by_status.get(s, 0) for s in unresolved_statuses)
        total_findings = sum(by_status.values())
        reopened_count = by_status.get(FindingLifecycleStatus.REOPENED.value, 0)
        accepted_risk_count = by_status.get(FindingLifecycleStatus.ACCEPTED_RISK.value, 0)

        result = {
            "total": total_findings,
            "by_status": by_status,
            "by_severity": by_severity,
            "unresolved_count": unresolved_count,
            "reopened_count": reopened_count,
            "accepted_risk_count": accepted_risk_count,
            "contradiction_count": contradiction_count,
        }

        if use_cache:
            query_cache.set(project_id, user_role, "FINDING_STATS", "summary", result, ttl_seconds=30.0)

        return result

    @staticmethod
    def invalidate_project_findings(project_id: str) -> None:
        """Called upon finding state transitions or new discoveries to invalidate stale stats."""
        query_cache.invalidate_project(project_id, namespace="FINDING_STATS")
