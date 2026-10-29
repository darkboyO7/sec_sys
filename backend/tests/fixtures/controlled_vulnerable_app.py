"""
Isolated Controlled Vulnerable Test Application Fixture for VAPT Acceptance Testing.
Runs strictly on 127.0.0.1 on an ephemeral port.
Zero external network access, deterministic seeded findings, reversible remediation state.
"""

import http.server
import threading
import time
from typing import Optional, List, Dict, Any


class ControlledVulnerableHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP handler serving deterministic responses representing an application
    in either VULNERABLE or REMEDIATED state.
    """

    def log_message(self, format, *args):
        # Silence default stderr logging during automated testing
        pass

    @property
    def fixture_server(self):
        return self.server.fixture_controller

    def do_GET(self):
        self.fixture_server.record_request("GET", self.path, dict(self.headers))
        is_remediated = self.fixture_server.is_remediated

        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            content = b"User-agent: *\nDisallow: /admin\n" if is_remediated else b"User-agent: *\nDisallow: /admin\nDisallow: /internal_backup.sql\n"
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        if self.path.startswith("/api/v1/user/secret"):
            if not is_remediated:
                # Vulnerability: Unauthenticated sensitive endpoint disclosure
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                body = b'{"status": "ok", "api_key": "insecure_dev_key_12345", "role": "admin"}'
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            else:
                # Remediated: Requires authentication
                auth = self.headers.get("Authorization")
                if not auth or "Bearer verified_token" not in auth:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    body = b'{"detail": "Unauthorized access to privileged endpoint."}'
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(200)
                body = b'{"status": "ok", "authenticated": true}'
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

        # Default landing page
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")

        if is_remediated:
            # Remediated: strict security headers, obfuscated server banner, secure cookie
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Server", "ProtectedGateway/1.0")
            self.send_header("Set-Cookie", "sessionid=secure_token_abc; Secure; HttpOnly; SameSite=Strict")
            body = b"<!DOCTYPE html><html><head><title>Hardened Secure App</title></head><body>Hardened</body></html>"
        else:
            # Vulnerable: missing all modern security headers, reveals version, insecure cookie
            self.send_header("Server", "Apache/2.4.41 (Ubuntu) PHP/7.4.3")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.send_header("Set-Cookie", "sessionid=insecure_token_123; path=/")
            body = b"<!DOCTYPE html><html><head><title>Vulnerable App</title></head><body>Vulnerable Target</body></html>"

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ControlledVulnerableApp:
    """
    Manages the lifecycle of an isolated controlled vulnerable target application.
    Enforces deterministic behavior and reversible remediation states.
    """

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.port: Optional[int] = None
        self.is_remediated = False
        self.requests_log: List[Dict[str, Any]] = []
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def record_request(self, method: str, path: str, headers: Dict[str, str]):
        with self._lock:
            self.requests_log.append({
                "method": method,
                "path": path,
                "headers": headers,
                "timestamp": time.time(),
            })

    def start(self) -> str:
        """Starts the server on 127.0.0.1 with an OS-allocated ephemeral port."""
        self._server = http.server.HTTPServer((self.host, 0), ControlledVulnerableHandler)
        self._server.fixture_controller = self
        self.port = self._server.server_port

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    @property
    def base_url(self) -> str:
        if not self.port:
            raise RuntimeError("ControlledVulnerableApp has not been started.")
        return f"http://{self.host}:{self.port}"

    def remediate(self):
        """Switches the application state to REMEDIATED."""
        with self._lock:
            self.is_remediated = True

    def roll_back(self):
        """Switches the application state back to VULNERABLE."""
        with self._lock:
            self.is_remediated = False

    def stop(self):
        """Stops the server and cleans up threads."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
            self._thread = None
