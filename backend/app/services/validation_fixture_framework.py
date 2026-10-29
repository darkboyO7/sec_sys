"""
Deterministic Validation Fixture Framework (Prompt 19).
Provides isolated, reproducible, loopback-only HTTP fixtures and ground-truth evaluation
to measure detection quality, precision, recall, false-positive rate, and false-negative rate.

Strictly bound to 127.0.0.1 on ephemeral ports (port 0). Zero external network egress.
"""

import http.server
import threading
import time
import socket
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional, Tuple, Set
from contextlib import contextmanager


class PositiveExposedHandler(http.server.BaseHTTPRequestHandler):
    """Serves responses with intentionally seeded, reproducible security exposures."""

    def log_message(self, format, *args):
        pass  # Suppress console logging during benchmarks

    def do_GET(self):
        self.send_response(200)
        # Seeded exposures:
        # 1. Server banner and version disclosure
        self.send_header("Server", "Apache/2.4.41 (Ubuntu) PHP/7.4.3")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        # 2. Insecure cookie without Secure, HttpOnly, SameSite
        self.send_header("Set-Cookie", "sessionid=insecure_token_123; path=/")
        # 3. Missing Strict-Transport-Security (HSTS)
        # 4. Missing Content-Security-Policy (CSP)
        # 5. Missing X-Frame-Options
        # 6. Missing X-Content-Type-Options
        self.send_header("Content-Type", "text/html; charset=utf-8")
        body = b"<!DOCTYPE html><html><body>Controlled Positive Exposed Fixture</body></html>"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class NegativeCleanHandler(http.server.BaseHTTPRequestHandler):
    """Serves responses with fully hardened, defense-in-depth headers and zero vulnerabilities."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        # Hardened headers:
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        self.send_header("Server", "HardenedGateway")  # Obfuscated banner
        self.send_header("Set-Cookie", "sessionid=token_xyz; Secure; HttpOnly; SameSite=Strict; Path=/")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        body = b"<!DOCTYPE html><html><body>Controlled Negative Clean Fixture</body></html>"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AmbiguousHandler(http.server.BaseHTTPRequestHandler):
    """Serves inconsistent / alternating responses to test handling of ambiguous edge cases."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        controller = getattr(self.server, "fixture_controller", None)
        req_count = controller.request_count if controller else 0
        if controller:
            controller.request_count += 1

        if req_count % 2 == 0:
            # First request: Appears clean
            self.send_response(200)
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("Content-Type", "text/html")
            body = b"Ambiguous: Clean state"
        else:
            # Second request: Appears vulnerable / server error
            self.send_response(500)
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.send_header("Content-Type", "text/html")
            body = b"Ambiguous: Error state"

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RemediatedHandler(http.server.BaseHTTPRequestHandler):
    """Dynamic fixture toggled between vulnerable state and remediated state."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        controller = getattr(self.server, "fixture_controller", None)
        is_remediated = controller.is_remediated if controller else False

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")

        if is_remediated:
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Server", "RemediatedGateway")
            self.send_header("Set-Cookie", "sessionid=secure_token; Secure; HttpOnly; SameSite=Strict; Path=/")
            body = b"Remediated State: Hardened"
        else:
            self.send_header("Server", "Apache/2.4.41 (Ubuntu) PHP/7.4.3")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.send_header("Set-Cookie", "sessionid=insecure_token; path=/")
            body = b"Initial State: Vulnerable"

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class BaseValidationFixture:
    """Base controller for managing an ephemeral loopback HTTP fixture."""

    def __init__(self, handler_class, host: str = "127.0.0.1"):
        self.host = host
        self.handler_class = handler_class
        self.server: Optional[http.server.HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.port: Optional[int] = None
        self.request_count = 0
        self.is_remediated = False

    def start(self):
        self.server = http.server.HTTPServer((self.host, 0), self.handler_class)
        self.server.fixture_controller = self
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
            self.thread = None

    @property
    def url(self) -> str:
        if not self.port:
            raise RuntimeError("Fixture server is not running.")
        return f"http://{self.host}:{self.port}"


class PositiveExposedFixture(BaseValidationFixture):
    def __init__(self):
        super().__init__(PositiveExposedHandler)


class NegativeCleanFixture(BaseValidationFixture):
    def __init__(self):
        super().__init__(NegativeCleanHandler)


class AmbiguousFixture(BaseValidationFixture):
    def __init__(self):
        super().__init__(AmbiguousHandler)


class RemediatedFixture(BaseValidationFixture):
    def __init__(self):
        super().__init__(RemediatedHandler)

    def remediate(self):
        self.is_remediated = True

    def revert(self):
        self.is_remediated = False


class UnavailableFixture:
    """
    Simulates an unavailable or non-responsive service by claiming an ephemeral port
    and immediately closing the socket.
    """

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, 0))
        self.port = s.getsockname()[1]
        s.close()

    def start(self):
        pass

    def stop(self):
        pass

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


# Ground Truth Definitions for Detection Quality Evaluation
FIXTURE_GROUND_TRUTH = {
    "positive_exposed": {
        "true_positives": [
            "MISSING_HSTS",
            "MISSING_CSP",
            "SERVER_BANNER_DISCLOSURE",
            "INSECURE_COOKIE",
            "MISSING_FRAME_PROTECTION",
            "MISSING_CONTENT_TYPE_OPTIONS",
        ],
        "true_negatives": [],
        "expected_validation_status": "CONFIRMED_TRUE_POSITIVE",
        "description": "Known-vulnerable service with 6 true positive security header exposures.",
    },
    "negative_clean": {
        "true_positives": [],
        "true_negatives": [
            "MISSING_HSTS",
            "MISSING_CSP",
            "SERVER_BANNER_DISCLOSURE",
            "INSECURE_COOKIE",
            "MISSING_FRAME_PROTECTION",
            "MISSING_CONTENT_TYPE_OPTIONS",
        ],
        "expected_validation_status": "CONFIRMED_FALSE_POSITIVE",
        "description": "Clean, fully hardened service with 0 vulnerabilities and 6 true negatives.",
    },
    "unavailable": {
        "true_positives": [],
        "true_negatives": [],
        "expected_validation_status": "UNABLE_TO_VERIFY",
        "description": "Unavailable service. Must produce UNABLE_TO_VERIFY, never false positives.",
    },
    "ambiguous": {
        "true_positives": [],
        "true_negatives": [],
        "expected_validation_status": "INCONCLUSIVE",
        "description": "Inconsistent alternating service. Must produce INCONCLUSIVE validation state.",
    },
    "remediated": {
        "initial_true_positives": [
            "MISSING_HSTS",
            "MISSING_CSP",
            "SERVER_BANNER_DISCLOSURE",
            "INSECURE_COOKIE",
        ],
        "remediated_true_positives": [],
        "expected_validation_status": "RESOLVED_AFTER_RETEST",
        "description": "Dynamic service transitioning from vulnerable to verified fixed.",
    },
}


class DeterministicFixtureFramework:
    """
    Deterministic Validation Fixture Management & Quality Evaluation Engine.
    Executes controlled benchmark scenarios against known ground-truth targets.
    """

    VERSION = "1.0.0"

    @classmethod
    def create_fixture(cls, fixture_type: str):
        ft = fixture_type.lower()
        if ft in ("positive_exposed", "positive", "vulnerable"):
            return PositiveExposedFixture()
        elif ft in ("negative_clean", "negative", "clean", "hardened"):
            return NegativeCleanFixture()
        elif ft in ("unavailable", "offline", "timeout"):
            return UnavailableFixture()
        elif ft in ("ambiguous", "flaky", "inconsistent"):
            return AmbiguousFixture()
        elif ft in ("remediated", "fix_verification"):
            return RemediatedFixture()
        else:
            raise ValueError(f"Unknown validation fixture type: '{fixture_type}'.")

    @classmethod
    @contextmanager
    def managed_fixture(cls, fixture_type: str):
        fixture = cls.create_fixture(fixture_type)
        fixture.start()
        try:
            yield fixture
        finally:
            fixture.stop()

    @classmethod
    def evaluate_detection_results(
        cls,
        fixture_type: str,
        detected_categories: List[str],
        reported_validation_status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates detected findings against ground truth.
        Computes TP, FP, TN, FN, Precision, Recall, FPR, FNR with explicit denominator disclosures.
        """
        ft = fixture_type.lower()
        if ft not in FIXTURE_GROUND_TRUTH:
            raise ValueError(f"No ground truth registered for fixture type: '{fixture_type}'.")

        gt = FIXTURE_GROUND_TRUTH[ft]
        expected_tp_set = set(gt.get("true_positives", []))
        expected_tn_set = set(gt.get("true_negatives", []))
        detected_set = set(detected_categories)

        # Handle unavailable and ambiguous edge cases
        if ft == "unavailable":
            is_valid_failure_handling = (
                reported_validation_status in ("UNABLE_TO_VERIFY", "ERROR")
                and len(detected_set) == 0
            )
            return {
                "fixture_type": ft,
                "fixture_version": cls.VERSION,
                "is_synthetic": True,
                "ground_truth_status": gt["expected_validation_status"],
                "reported_validation_status": reported_validation_status,
                "valid_failure_handling": is_valid_failure_handling,
                "true_positives": 0,
                "false_positives": len(detected_set),
                "true_negatives": 0,
                "false_negatives": 0,
                "precision": 0.0 if detected_set else 1.0,
                "recall": 1.0,
                "false_positive_rate": 1.0 if detected_set else 0.0,
                "false_negative_rate": 0.0,
                "denominators": {
                    "total_detected": len(detected_set),
                    "total_expected": 0,
                },
                "notes": "Unavailable service testbed; zero false positives expected.",
            }

        if ft == "ambiguous":
            is_valid_ambiguity_handling = reported_validation_status == "INCONCLUSIVE"
            return {
                "fixture_type": ft,
                "fixture_version": cls.VERSION,
                "is_synthetic": True,
                "ground_truth_status": gt["expected_validation_status"],
                "reported_validation_status": reported_validation_status,
                "valid_ambiguity_handling": is_valid_ambiguity_handling,
                "notes": "Ambiguous service testbed; validation engine must classify as INCONCLUSIVE.",
            }

        # Calculate metrics for positive and negative fixtures
        tp_matches = detected_set.intersection(expected_tp_set)
        fp_matches = detected_set.difference(expected_tp_set)
        fn_matches = expected_tp_set.difference(detected_set)
        tn_matches = expected_tn_set.difference(detected_set)

        tp = len(tp_matches)
        fp = len(fp_matches)
        fn = len(fn_matches)
        tn = len(tn_matches)

        # Honest mathematical metrics calculation
        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if len(expected_tp_set) == 0 and fp == 0 else 0.0)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if len(expected_tp_set) == 0 and fn == 0 else 0.0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0

        return {
            "fixture_type": ft,
            "fixture_version": cls.VERSION,
            "is_synthetic": True,
            "sample_size": tp + fp + tn + fn,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "matched_true_positives": sorted(list(tp_matches)),
            "unmatched_false_positives": sorted(list(fp_matches)),
            "missed_false_negatives": sorted(list(fn_matches)),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "denominators": {
                "precision_denominator_tp_plus_fp": tp + fp,
                "recall_denominator_tp_plus_fn": tp + fn,
                "fpr_denominator_fp_plus_tn": fp + tn,
            },
            "ground_truth_status": gt["expected_validation_status"],
        }

    @classmethod
    def execute_live_header_audit(cls, target_url: str, timeout: float = 3.0) -> Tuple[List[str], Dict[str, str], Optional[str]]:
        """
        Passive, loopback-only HTTP header inspection against a running test fixture.
        Extracts headers and tags detection categories without external network access.
        """
        detected_categories = []
        headers_dict = {}
        error_detail = None

        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "VAPT-Validation-Benchmark/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers_dict = {k.lower(): v for k, v in resp.headers.items()}
        except (urllib.error.URLError, socket.error, TimeoutError) as e:
            error_detail = str(e)
            return [], {}, error_detail

        # 1. HSTS Check
        if "strict-transport-security" not in headers_dict:
            detected_categories.append("MISSING_HSTS")

        # 2. CSP Check
        if "content-security-policy" not in headers_dict:
            detected_categories.append("MISSING_CSP")

        # 3. Server Banner Disclosure
        server_val = headers_dict.get("server", "")
        x_powered = headers_dict.get("x-powered-by", "")
        if any(c in server_val for c in ("/", "(", "Ubuntu", "Apache", "PHP")) or x_powered:
            detected_categories.append("SERVER_BANNER_DISCLOSURE")

        # 4. Cookie Security Check
        set_cookie = headers_dict.get("set-cookie", "")
        if set_cookie:
            sc_lower = set_cookie.lower()
            if "secure" not in sc_lower or "httponly" not in sc_lower:
                detected_categories.append("INSECURE_COOKIE")

        # 5. Frame Protection
        if "x-frame-options" not in headers_dict and "frame-ancestors" not in headers_dict.get("content-security-policy", ""):
            detected_categories.append("MISSING_FRAME_PROTECTION")

        # 6. Content Type Options
        if headers_dict.get("x-content-type-options", "").lower() != "nosniff":
            detected_categories.append("MISSING_CONTENT_TYPE_OPTIONS")

        return detected_categories, headers_dict, None

    @classmethod
    def run_benchmark_scenario(cls, fixture_type: str) -> Dict[str, Any]:
        """
        End-to-end execution of a deterministic validation benchmark scenario.
        Starts ephemeral fixture, performs passive inspection, evaluates metrics against ground truth.
        """
        ft = fixture_type.lower()
        if ft == "unavailable":
            fix = cls.create_fixture("unavailable")
            url = fix.url
            detected, _, error = cls.execute_live_header_audit(url, timeout=0.5)
            status = "UNABLE_TO_VERIFY" if error else "DETECTED"
            return cls.evaluate_detection_results("unavailable", detected, reported_validation_status=status)

        with cls.managed_fixture(ft) as fixture:
            url = fixture.url
            if ft == "ambiguous":
                # Make two calls to observe conflicting responses
                det1, _, _ = cls.execute_live_header_audit(url)
                det2, _, _ = cls.execute_live_header_audit(url)
                status = "INCONCLUSIVE" if det1 != det2 else "DETECTED"
                return cls.evaluate_detection_results("ambiguous", det1, reported_validation_status=status)

            detected, _, _ = cls.execute_live_header_audit(url)
            return cls.evaluate_detection_results(ft, detected)
