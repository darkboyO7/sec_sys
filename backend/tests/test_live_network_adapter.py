import pytest
import http.server
import threading
import socket
from app.services.scanner_adapters.live_network_adapter import LiveNetworkAuditorAdapter
from app.services.scanner_adapters.base import AdapterRegistry


@pytest.fixture(scope="module")
def local_test_http_server():
    """Spins up a lightweight in-process HTTP test server on an ephemeral localhost port."""
    class TestHandler(http.server.BaseHTTPRequestHandler):
        server_version = "TestServer/1.0.0"
        sys_version = ""

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            # Intentionally omit HSTS, CSP, and X-Content-Type-Options
            self.end_headers()
            self.wfile.write(b"<html><body>VAPT Defensive Test Target</body></html>")

        def log_message(self, format, *args):
            pass  # Silence stderr in tests

    server = http.server.HTTPServer(("127.0.0.1", 0), TestHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_live_network_auditor_adapter_registration():
    adapter = AdapterRegistry.get("live_network_auditor_adapter")
    assert adapter is not None
    assert adapter.name == "live_network_auditor_adapter"
    assert adapter.version == "1.0.0"
    assert adapter.status == "ACTIVE"
    assert "LIVE_HTTP_HEADER_INSPECTION" in adapter.declared_capabilities
    assert "LIVE_TLS_CERTIFICATE_AUDIT" in adapter.declared_capabilities
    assert "LIVE_TCP_SERVICE_BANNER_GRAB" in adapter.declared_capabilities


def test_live_network_auditor_preflight_and_validation():
    adapter = LiveNetworkAuditorAdapter()
    
    # Valid preflight
    pf = adapter.preflight_check("http://localhost:8000", {"profile": "LIVE_HTTP_HEADERS"})
    assert pf.is_ready is True
    assert pf.target_type == "URL"
    assert pf.mode == "LIVE_NETWORK"

    # Empty target
    pf_empty = adapter.preflight_check("", {"profile": "LIVE_HTTP_HEADERS"})
    assert pf_empty.is_ready is False
    assert "Target cannot be empty" in pf_empty.preflight_error

    # Invalid profile
    valid, err = adapter.validate_config({"profile": "UNKNOWN_PROFILE"})
    assert valid is False
    assert "is not supported" in err

    # Invalid port
    valid_port, err_port = adapter.validate_config({"profile": "LIVE_TCP_BANNER", "target_port": 99999})
    assert valid_port is False
    assert "between 1 and 65535" in err_port


def test_live_network_auditor_genuine_http_execution(local_test_http_server):
    adapter = LiveNetworkAuditorAdapter()
    res = adapter.execute(
        target=local_test_http_server,
        config={"profile": "LIVE_HTTP_HEADERS", "timeout_seconds": 5},
    )

    assert res.success is True
    assert res.is_simulated is False, "Live network adapter must flag is_simulated as False"
    assert res.adapter_name == "live_network_auditor_adapter"
    assert len(res.findings) > 0

    # Verify real findings detected from local HTTP server
    finding_titles = [f.title for f in res.findings]
    assert any("Content-Security-Policy" in t for t in finding_titles)
    assert any("X-Content-Type-Options" in t for t in finding_titles)
    assert any("Server Banner" in t for t in finding_titles)

    # Verify byte-level evidence and cryptographic hash
    ev = res.findings[0].evidence_items[0]
    assert ev.evidence_type == "HTTP_RESPONSE_HEADERS"
    assert "Server:" in ev.payload
    assert len(ev.sha256_hash) == 64


def test_live_network_auditor_honest_connection_failure():
    """Verify that attempting to connect to an unreachable port produces an honest failure without fabricating findings."""
    adapter = LiveNetworkAuditorAdapter()
    # Find an unused local port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        unused_port = s.getsockname()[1]

    res = adapter.execute(
        target=f"http://127.0.0.1:{unused_port}",
        config={"profile": "LIVE_HTTP_HEADERS", "timeout_seconds": 1},
    )

    assert res.success is False
    assert res.is_simulated is False
    assert len(res.findings) == 0, "Failed connection must not fabricate artificial findings"
    assert len(res.errors) > 0
    assert "Network error" in res.errors[0]
    assert res.failure_category == "CONNECTION_FAILED"


def test_live_network_auditor_cancellation():
    adapter = LiveNetworkAuditorAdapter()
    res = adapter.execute(
        target="http://127.0.0.1:8000",
        config={"profile": "LIVE_HTTP_HEADERS"},
        cancellation_check=lambda: True,
    )

    assert res.success is False
    assert res.failure_category == "JOB_CANCELLED"
    assert "cancelled" in res.status_summary.lower()
