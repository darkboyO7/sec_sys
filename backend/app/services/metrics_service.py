"""
Thread-Safe In-Memory Operational Metrics Collector for VAPT System.
Enforces strict label cardinality bounds (no raw URLs, UUIDs, or user inputs),
tracks API latencies, worker states, database contention, and recovery events,
and renders Prometheus text format (v0.0.4) and structured JSON.
"""

import time
import threading
from typing import Dict, Any, List, Tuple, Optional


class MetricsService:
    """
    Thread-safe operational telemetry collector.
    Guarantees bounded label cardinality to prevent memory leak and metric explosion.
    """

    _instance = None
    _lock = threading.Lock()

    # Fixed histogram buckets for latency in milliseconds
    LATENCY_BUCKETS_MS = [5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0]

    # Bounded endpoint prefixes
    KNOWN_ENDPOINT_GROUPS = [
        "/health",
        "/ready",
        "/metrics",
        "/api/v1/auth",
        "/api/v1/projects",
        "/api/v1/scopes",
        "/api/v1/assessments",
        "/api/v1/findings",
        "/api/v1/assets",
        "/api/v1/graph",
        "/api/v1/risk",
        "/api/v1/audit",
        "/api/v1/integrity",
        "/api/v1/verification",
        "/api/v1/reports",
        "/api/v1/digital-twin",
        "/api/v1/regression",
        "/api/v1/ai-analyst",
        "/api/v1/learning",
        "/api/v1/adaptive-defense",
        "/api/v1/lifecycle",
        "/api/v1/integrations",
        "/api/v1/monitoring",
        "/api/v1/decisions",
        "/api/v1/intelligence",
        "/api/v1/operations",
        "/api/v1/diagnostics",
        "/api/v1/orchestration",
    ]

    def __init__(self):
        self._mutex = threading.Lock()
        self.reset()

    @classmethod
    def get_instance(cls) -> "MetricsService":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def reset(self):
        """Resets all metrics (useful for testing)."""
        with getattr(self, "_mutex", threading.Lock()):
            self._start_time = time.time()
            # Counters: name -> {(label_tuple): count}
            self._counters: Dict[str, Dict[Tuple[Tuple[str, str], ...], float]] = {
                "api_requests_total": {},
                "worker_lease_expirations_total": {},
                "db_contention_events_total": {},
                "evidence_verification_failures_total": {},
                "recovery_events_total": {},
                "jobs_by_status_total": {},
                "stuck_jobs_detected_total": {},
            }
            # Gauges: name -> {(label_tuple): value}
            self._gauges: Dict[str, Dict[Tuple[Tuple[str, str], ...], float]] = {
                "active_assessments": {},
                "database_connections_active": {},
            }
            # Histograms: name -> {(label_tuple): {"count": n, "sum": s, "buckets": {bucket: c}}}
            self._histograms: Dict[str, Dict[Tuple[Tuple[str, str], ...], Dict[str, Any]]] = {
                "api_request_duration_ms": {},
            }

    @classmethod
    def normalize_endpoint(cls, path: str) -> str:
        """
        Normalizes any arbitrary request URL path into bounded endpoint groups.
        Never outputs raw IDs, query params, or unknown paths.
        """
        if not path:
            return "other"
        # Strip query string and trailing slashes
        clean_path = path.split("?")[0].rstrip("/")
        if not clean_path:
            clean_path = "/"

        for group in cls.KNOWN_ENDPOINT_GROUPS:
            if clean_path == group or clean_path.startswith(group + "/"):
                return group

        return "other"

    @classmethod
    def get_status_class(cls, status_code: int) -> str:
        """Categorizes HTTP status codes into bounded classes."""
        if 100 <= status_code < 200:
            return "1xx"
        elif 200 <= status_code < 300:
            return "2xx"
        elif 300 <= status_code < 400:
            return "3xx"
        elif 400 <= status_code < 500:
            return "4xx"
        elif 500 <= status_code < 600:
            return "5xx"
        return "other"

    def _labels_to_key(self, labels: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
        # Filter and sanitize labels
        safe_labels = {}
        for k, v in labels.items():
            # Bound label values to 64 chars and remove newlines
            safe_k = str(k)[:32]
            safe_v = str(v).replace("\n", "").replace('"', "")[:64]
            safe_labels[safe_k] = safe_v
        return tuple(sorted(safe_labels.items()))

    # --------------------------------------------------------------------------
    # Observation Methods
    # --------------------------------------------------------------------------
    def record_api_request(self, method: str, path: str, status_code: int, duration_ms: float):
        """Records an HTTP request counter and latency histogram observation with bounded labels."""
        bounded_method = method.upper() if method.upper() in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] else "OTHER"
        endpoint_group = self.normalize_endpoint(path)
        status_class = self.get_status_class(status_code)

        labels = {"method": bounded_method, "endpoint_group": endpoint_group, "status_class": status_class}
        key = self._labels_to_key(labels)

        with self._mutex:
            # Increment request counter
            counters = self._counters["api_requests_total"]
            counters[key] = counters.get(key, 0.0) + 1.0

            # Record in histogram
            hist_labels = {"endpoint_group": endpoint_group}
            hist_key = self._labels_to_key(hist_labels)
            histograms = self._histograms["api_request_duration_ms"]

            if hist_key not in histograms:
                histograms[hist_key] = {
                    "count": 0.0,
                    "sum": 0.0,
                    "buckets": {b: 0.0 for b in self.LATENCY_BUCKETS_MS},
                }

            entry = histograms[hist_key]
            entry["count"] += 1.0
            entry["sum"] += duration_ms

            for b in self.LATENCY_BUCKETS_MS:
                if duration_ms <= b:
                    entry["buckets"][b] += 1.0

    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Thread-safe counter increment."""
        if labels is None:
            labels = {}
        key = self._labels_to_key(labels)
        with self._mutex:
            if name not in self._counters:
                self._counters[name] = {}
            self._counters[name][key] = self._counters[name].get(key, 0.0) + value

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Thread-safe gauge update."""
        if labels is None:
            labels = {}
        key = self._labels_to_key(labels)
        with self._mutex:
            if name not in self._gauges:
                self._gauges[name] = {}
            self._gauges[name][key] = float(value)

    def record_lease_expiration(self, worker_type: str = "orchestration"):
        """Records a worker concurrency lease expiration."""
        self.increment_counter("worker_lease_expirations_total", 1.0, {"worker_type": str(worker_type)[:32]})

    def record_db_contention(self, operation: str = "transaction"):
        """Records a database concurrency lock or busy contention event."""
        self.increment_counter("db_contention_events_total", 1.0, {"operation": str(operation)[:32]})

    def record_evidence_verification_failure(self, verifier: str = "crypto_merkle"):
        """Records an evidence digest verification mismatch."""
        self.increment_counter("evidence_verification_failures_total", 1.0, {"verifier": str(verifier)[:32]})

    def record_recovery_event(self, trigger: str, status: str):
        """Records an automated or operator recovery action."""
        self.increment_counter("recovery_events_total", 1.0, {
            "trigger": str(trigger)[:32],
            "status": str(status)[:16],
        })

    def record_job_status(self, status: str):
        """Records a job state transition event."""
        self.increment_counter("jobs_by_status_total", 1.0, {"status": str(status).lower()[:24]})

    def record_stuck_job_detected(self, recovery_action: str):
        """Records detection of an orphaned or stuck job."""
        self.increment_counter("stuck_jobs_detected_total", 1.0, {"recovery_action": str(recovery_action)[:32]})

    # --------------------------------------------------------------------------
    # Output Formats
    # --------------------------------------------------------------------------
    def to_prometheus_text(self) -> str:
        """
        Renders all collected metrics in Prometheus text exposition format (version 0.0.4).
        Includes # HELP, # TYPE, accurate buckets and labels.
        """
        lines: List[str] = []
        with self._mutex:
            # Uptime Gauge
            uptime = time.time() - self._start_time
            lines.append("# HELP process_uptime_seconds Total seconds elapsed since process start.")
            lines.append("# TYPE process_uptime_seconds gauge")
            lines.append(f"process_uptime_seconds {uptime:.2f}")

            # 1. Counters
            help_texts = {
                "api_requests_total": "Total number of HTTP requests processed by endpoint group and status class.",
                "worker_lease_expirations_total": "Total number of worker concurrency lease expirations.",
                "db_contention_events_total": "Total number of database lock contention and retry events.",
                "evidence_verification_failures_total": "Total cryptographic evidence integrity verification failures.",
                "recovery_events_total": "Total automated and operator recovery execution attempts.",
                "jobs_by_status_total": "Total count of assessment and orchestration jobs partitioned by terminal state.",
                "stuck_jobs_detected_total": "Total orphaned or stuck jobs detected by self-diagnostics.",
            }

            for name, entries in self._counters.items():
                help_msg = help_texts.get(name, f"Counter metric {name}")
                lines.append(f"# HELP {name} {help_msg}")
                lines.append(f"# TYPE {name} counter")
                if not entries:
                    lines.append(f"{name} 0")
                else:
                    for key, val in entries.items():
                        if key:
                            label_str = ",".join(f'{k}="{v}"' for k, v in key)
                            lines.append(f"{name}{{{label_str}}} {val}")
                        else:
                            lines.append(f"{name} {val}")

            # 2. Gauges
            gauge_help = {
                "active_assessments": "Current count of active (QUEUED or RUNNING) assessment jobs.",
                "database_connections_active": "Current active database connections.",
            }
            for name, entries in self._gauges.items():
                help_msg = gauge_help.get(name, f"Gauge metric {name}")
                lines.append(f"# HELP {name} {help_msg}")
                lines.append(f"# TYPE {name} gauge")
                if not entries:
                    lines.append(f"{name} 0")
                else:
                    for key, val in entries.items():
                        if key:
                            label_str = ",".join(f'{k}="{v}"' for k, v in key)
                            lines.append(f"{name}{{{label_str}}} {val}")
                        else:
                            lines.append(f"{name} {val}")

            # 3. Histograms
            hist_help = {
                "api_request_duration_ms": "HTTP request duration latency in milliseconds.",
            }
            for name, entries in self._histograms.items():
                help_msg = hist_help.get(name, f"Histogram metric {name}")
                lines.append(f"# HELP {name} {help_msg}")
                lines.append(f"# TYPE {name} histogram")
                for key, data in entries.items():
                    base_labels = dict(key)
                    # Bucket lines
                    for bucket in sorted(data["buckets"].keys()):
                        b_labels = dict(base_labels)
                        b_labels["le"] = str(bucket)
                        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(b_labels.items()))
                        lines.append(f"{name}_bucket{{{label_str}}} {data['buckets'][bucket]}")

                    # +Inf bucket
                    inf_labels = dict(base_labels)
                    inf_labels["le"] = "+Inf"
                    label_str = ",".join(f'{k}="{v}"' for k, v in sorted(inf_labels.items()))
                    lines.append(f"{name}_bucket{{{label_str}}} {data['count']}")

                    # Sum and Count
                    sum_label_str = ",".join(f'{k}="{v}"' for k, v in sorted(base_labels.items()))
                    lines.append(f"{name}_sum{{{sum_label_str}}} {data['sum']:.2f}")
                    lines.append(f"{name}_count{{{sum_label_str}}} {data['count']}")

        return "\n".join(lines) + "\n"

    def to_dict(self) -> Dict[str, Any]:
        """Renders all metrics in a structured dictionary suitable for JSON responses."""
        with self._mutex:
            counters_dict = {}
            for name, entries in self._counters.items():
                counters_dict[name] = [
                    {"labels": dict(k), "value": v} for k, v in entries.items()
                ]

            gauges_dict = {}
            for name, entries in self._gauges.items():
                gauges_dict[name] = [
                    {"labels": dict(k), "value": v} for k, v in entries.items()
                ]

            hist_dict = {}
            for name, entries in self._histograms.items():
                hist_dict[name] = [
                    {
                        "labels": dict(k),
                        "count": v["count"],
                        "sum": round(v["sum"], 2),
                        "buckets": v["buckets"],
                    }
                    for k, v in entries.items()
                ]

            return {
                "uptime_seconds": round(time.time() - self._start_time, 2),
                "counters": counters_dict,
                "gauges": gauges_dict,
                "histograms": hist_dict,
            }


metrics_service = MetricsService.get_instance()
