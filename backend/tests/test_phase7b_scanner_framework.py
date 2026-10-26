import os
import json
import hashlib
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.services.scanner_adapters.base import (
    BaseScannerAdapter,
    AdapterRegistry,
    AdapterResult,
    RawAdapterFinding,
    RawAdapterEvidence,
    PreflightResult,
)
from app.services.scanner_adapters.local_fixture_adapter import LocalFixtureAdapter
from app.services.scanner_adapters.passive_header_adapter import PassiveHeaderAuditAdapter
from app.services.scanner_adapters.ssl_cipher_adapter import SslTlsCipherAuditAdapter
from app.services.subprocess_worker_runner import SubprocessWorkerRunner
from app.worker.ipc_schemas import WorkerIPCRequest


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture(autouse=True)
def ensure_adapters_registered():
    """Ensure standard adapters are registered before each test."""
    AdapterRegistry.register(LocalFixtureAdapter(), allow_override=True)
    AdapterRegistry.register(PassiveHeaderAuditAdapter(), allow_override=True)
    AdapterRegistry.register(SslTlsCipherAuditAdapter(), allow_override=True)
    yield
    AdapterRegistry.register(LocalFixtureAdapter(), allow_override=True)
    AdapterRegistry.register(PassiveHeaderAuditAdapter(), allow_override=True)
    AdapterRegistry.register(SslTlsCipherAuditAdapter(), allow_override=True)


# ==============================================================================
# 1. Adapter Contract Conformance
# ==============================================================================

def test_registered_adapters_contract_conformance():
    """
    Verifies that all registered adapters adhere strictly to the Phase 7B
    BaseScannerAdapter contract (properties, schema, timeout policies, health).
    """
    adapters = [
        LocalFixtureAdapter(),
        PassiveHeaderAuditAdapter(),
        SslTlsCipherAuditAdapter(),
    ]

    for adapter in adapters:
        assert isinstance(adapter, BaseScannerAdapter)
        assert len(adapter.name) > 0
        assert len(adapter.version) > 0
        assert len(adapter.declared_capabilities) > 0
        assert len(adapter.supported_profiles) > 0
        assert len(adapter.permitted_check_categories) > 0
        assert len(adapter.supported_target_types) > 0
        assert len(adapter.required_permissions) > 0

        # Timeouts: 0 < min <= default <= max
        assert adapter.min_timeout_seconds > 0
        assert adapter.min_timeout_seconds <= adapter.default_timeout_seconds
        assert adapter.default_timeout_seconds <= adapter.max_timeout_seconds

        # Lifecycle status
        assert adapter.status in ("ACTIVE", "DEPRECATED", "DISABLED")

        # Health
        health = adapter.get_health()
        assert health["status"] == "HEALTHY"
        assert health["network_scanning_enabled"] is False

        # Preflight
        preflight = adapter.preflight_check("example.internal-defense.corp", {})
        assert isinstance(preflight, PreflightResult)
        assert preflight.mode == "SIMULATED_FIXTURE"
        assert preflight.adapter_name == adapter.name
        # Dict access compatibility
        assert preflight["mode"] == "SIMULATED_FIXTURE"


# ==============================================================================
# 2. Adapter Registry Governance & Validation
# ==============================================================================

def test_adapter_registry_governance_and_lifecycle():
    """
    Verifies AdapterRegistry rejects invalid adapters, prevents unauthorized
    overwrites, and supports capability querying.
    """
    # 1. Reject non-adapter instance
    with pytest.raises(TypeError):
        AdapterRegistry.register(dict(name="fake"))  # type: ignore

    # 2. Reject adapter with invalid characters in name
    class BadNameAdapter(BaseScannerAdapter):
        @property
        def name(self): return "bad adapter name!"
        @property
        def version(self): return "1.0.0"
        @property
        def declared_capabilities(self): return ["CAP"]
        @property
        def supported_profiles(self): return ["PROF"]
        @property
        def permitted_check_categories(self): return ["CAT"]
        def validate_config(self, config): return True, None
        def preflight_check(self, target, config):
            return PreflightResult(adapter_name=self.name, adapter_version=self.version, target=target, is_ready=True)
        def execute(self, target, config, cancellation_check=None): pass
        def get_health(self): return {}

    with pytest.raises(ValueError, match="invalid characters"):
        AdapterRegistry.register(BadNameAdapter())

    # 3. Reject duplicate registration without allow_override
    class DummyAdapter(BaseScannerAdapter):
        @property
        def name(self): return "dummy_custom_adapter"
        @property
        def version(self): return "1.0.0"
        @property
        def declared_capabilities(self): return ["CUSTOM_CAP"]
        @property
        def supported_profiles(self): return ["CUSTOM_PROF"]
        @property
        def permitted_check_categories(self): return ["CONFIGURATION"]
        def validate_config(self, config): return True, None
        def preflight_check(self, target, config):
            return PreflightResult(adapter_name=self.name, adapter_version=self.version, target=target, is_ready=True)
        def execute(self, target, config, cancellation_check=None):
            return AdapterResult(adapter_name=self.name, adapter_version=self.version, target=target, success=True, status_summary="ok")
        def get_health(self): return {"status": "HEALTHY", "network_scanning_enabled": False}

    dummy = DummyAdapter()
    AdapterRegistry.register(dummy, allow_override=True)
    assert AdapterRegistry.is_approved("dummy_custom_adapter") is True

    # Re-registering with different instance should raise without allow_override
    with pytest.raises(ValueError, match="already registered"):
        AdapterRegistry.register(DummyAdapter(), allow_override=False)

    # 4. Capability querying
    by_cap = AdapterRegistry.get_by_capability("CUSTOM_CAP")
    assert any(a.name == "dummy_custom_adapter" for a in by_cap)

    # 5. Target type querying
    by_type = AdapterRegistry.get_by_target_type("URL")
    assert any(a.name == "passive_header_adapter" for a in by_type)

    # 6. Unregister
    removed = AdapterRegistry.unregister("dummy_custom_adapter")
    assert removed is True
    assert AdapterRegistry.is_approved("dummy_custom_adapter") is False


# ==============================================================================
# 3. API Adapter Listing Includes Phase 7B Metadata
# ==============================================================================

def test_api_adapter_listing_includes_contract_metadata(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
):
    """
    Verifies GET /projects/{project_id}/assessments/adapters returns all registered
    adapters with complete Phase 7B contract metadata.
    """
    res = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/adapters",
        headers=tester_headers,
    )
    assert res.status_code == 200
    adapters = res.json()
    assert len(adapters) >= 3

    adapter_names = [a["name"] for a in adapters]
    assert "local_fixture_adapter" in adapter_names
    assert "passive_header_adapter" in adapter_names
    assert "ssl_cipher_adapter" in adapter_names

    # Verify metadata fields on passive_header_adapter
    header_adapter = next(a for a in adapters if a["name"] == "passive_header_adapter")
    assert header_adapter["version"] == "1.0.0"
    assert "URL" in header_adapter["supported_target_types"]
    assert "DOMAIN" in header_adapter["supported_target_types"]
    assert header_adapter["default_timeout_seconds"] == 60
    assert header_adapter["min_timeout_seconds"] == 5
    assert header_adapter["max_timeout_seconds"] == 600
    assert header_adapter["status"] == "ACTIVE"
    assert header_adapter["health"]["network_scanning_enabled"] is False


# ==============================================================================
# 4. API Rejects Unregistered and Disabled Adapters
# ==============================================================================

def test_api_rejects_unregistered_and_disabled_adapters(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
):
    """
    Verifies that create_assessment_job rejects unknown or disabled adapters with 400 Bad Request.
    """
    # 1. Authorize target scope
    st = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="auth.internal-defense.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="Lead authorized",
        created_by_id=tester_user.id,
    )
    db.add(st)
    db.commit()

    # 2. Reject unregistered adapter
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        headers=tester_headers,
        json={
            "target_input": "auth.internal-defense.corp",
            "adapter_name": "unregistered_exploit_scanner",
        },
    )
    assert res.status_code == 400
    assert "not registered" in res.json()["detail"]

    # 3. Reject disabled adapter
    class DisabledMockAdapter(BaseScannerAdapter):
        @property
        def name(self): return "mock_disabled_adapter"
        @property
        def version(self): return "1.0.0"
        @property
        def declared_capabilities(self): return ["CAP"]
        @property
        def supported_profiles(self): return ["PROF"]
        @property
        def permitted_check_categories(self): return ["CAT"]
        @property
        def status(self): return "DISABLED"
        def validate_config(self, config): return True, None
        def preflight_check(self, target, config):
            return PreflightResult(adapter_name=self.name, adapter_version=self.version, target=target, is_ready=True)
        def execute(self, target, config, cancellation_check=None): pass
        def get_health(self): return {"status": "DISABLED", "network_scanning_enabled": False}

    AdapterRegistry.register(DisabledMockAdapter(), allow_override=True)
    try:
        res = client.post(
            f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
            headers=tester_headers,
            json={
                "target_input": "auth.internal-defense.corp",
                "adapter_name": "mock_disabled_adapter",
            },
        )
        assert res.status_code == 400
        assert "disabled" in res.json()["detail"].lower()
    finally:
        AdapterRegistry.unregister("mock_disabled_adapter")


# ==============================================================================
# 5. API Rejects Unsupported Target Types
# ==============================================================================

def test_api_rejects_unsupported_target_types(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
):
    """
    Verifies that create_assessment_job rejects targets whose type is unsupported
    by the requested adapter (e.g. passive_header_adapter on a CIDR subnet).
    """
    # Authorize a CIDR subnet
    st = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.CIDR,
        target_value="172.16.0.0/24",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="CIDR authorization",
        created_by_id=tester_user.id,
    )
    db.add(st)
    db.commit()

    # Attempt to run passive_header_adapter against CIDR
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        headers=tester_headers,
        json={
            "target_input": "172.16.0.0/24",
            "adapter_name": "passive_header_adapter",
        },
    )
    assert res.status_code == 400
    assert "not supported by adapter 'passive_header_adapter'" in res.json()["detail"]


# ==============================================================================
# 6. API Rejects Invalid Configuration & Out-of-Bounds Timeout
# ==============================================================================

def test_api_rejects_invalid_configuration_and_timeout(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
):
    """
    Verifies that configuration schema violations return 422 Unprocessable Entity
    and timeout violations return 400 Bad Request.
    """
    st = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="cfg.internal-defense.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="Authorized",
        created_by_id=tester_user.id,
    )
    db.add(st)
    db.commit()

    # 1. Invalid profile for ssl_cipher_adapter -> 422
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        headers=tester_headers,
        json={
            "target_input": "cfg.internal-defense.corp",
            "adapter_name": "ssl_cipher_adapter",
            "fixture_profile": "INVALID_TLS_PROFILE",
        },
    )
    assert res.status_code == 422
    assert "Invalid configuration" in res.json()["detail"]

    # 2. Invalid port in config for ssl_cipher_adapter -> 422
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        headers=tester_headers,
        json={
            "target_input": "cfg.internal-defense.corp",
            "adapter_name": "ssl_cipher_adapter",
            "fixture_profile": "TLS_MODERN_CIPHERS",
            "config": {"port": 70000},  # port > 65535
        },
    )
    assert res.status_code == 422
    assert "Port must be an integer between 1 and 65535" in res.json()["detail"]

    # 3. Timeout exceeds adapter max_timeout_seconds (600s for passive_header_adapter) -> 400
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        headers=tester_headers,
        json={
            "target_input": "cfg.internal-defense.corp",
            "adapter_name": "passive_header_adapter",
            "timeout_seconds": 1200,
        },
    )
    assert res.status_code == 400
    assert "outside permitted range" in res.json()["detail"]


# ==============================================================================
# 7. Passive Header Adapter Execution and Finding Verification
# ==============================================================================

def test_passive_header_adapter_execution_and_findings(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
):
    """
    Verifies end-to-end execution of passive_header_adapter, including finding
    generation, evidence hashing, and simulation transparency.
    """
    st = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="web.internal-defense.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="Web audit authorized",
        created_by_id=tester_user.id,
    )
    db.add(st)
    db.commit()

    # Create and execute job
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=true",
        headers=tester_headers,
        json={
            "target_input": "web.internal-defense.corp",
            "adapter_name": "passive_header_adapter",
            "fixture_profile": "OWASP_SECURE_HEADERS",
            "timeout_seconds": 60,
        },
    )
    assert res.status_code == 201
    job = res.json()
    assert job["status"] == "COMPLETED"
    assert job["adapter_name"] == "passive_header_adapter"
    assert job["is_simulated"] is True

    # Inspect findings
    res_findings = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/{job['id']}/findings",
        headers=tester_headers,
    )
    assert res_findings.status_code == 200
    findings = res_findings.json()
    assert len(findings) >= 2

    titles = [f["title"] for f in findings]
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)

    for f in findings:
        assert f["is_simulated"] is True
        assert len(f["evidence_items"]) > 0
        for ev in f["evidence_items"]:
            # Verify SHA-256 evidence integrity
            expected_hash = hashlib.sha256(ev["payload"].encode("utf-8")).hexdigest()
            assert ev["sha256_hash"] == expected_hash


# ==============================================================================
# 8. SSL/TLS Cipher Adapter Execution and Finding Verification
# ==============================================================================

def test_ssl_cipher_adapter_execution_and_findings(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user: User,
    tester_headers: dict,
):
    """
    Verifies end-to-end execution of ssl_cipher_adapter with legacy cipher detection.
    """
    st = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="tls.internal-defense.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="TLS audit authorized",
        created_by_id=tester_user.id,
    )
    db.add(st)
    db.commit()

    # Create and execute job
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=true",
        headers=tester_headers,
        json={
            "target_input": "tls.internal-defense.corp",
            "adapter_name": "ssl_cipher_adapter",
            "fixture_profile": "LEGACY_DEPRECATION_AUDIT",
            "config": {"port": 8443},
            "timeout_seconds": 120,
        },
    )
    assert res.status_code == 201
    job = res.json()
    assert job["status"] == "COMPLETED"
    assert job["adapter_name"] == "ssl_cipher_adapter"
    assert job["is_simulated"] is True

    # Inspect findings
    res_findings = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/{job['id']}/findings",
        headers=tester_headers,
    )
    assert res_findings.status_code == 200
    findings = res_findings.json()
    assert len(findings) >= 2

    titles = [f["title"] for f in findings]
    assert any("Deprecated TLS 1.0" in t for t in titles)
    assert any("3DES" in t for t in titles)

    for f in findings:
        assert f["is_simulated"] is True
        assert len(f["evidence_items"]) > 0
        for ev in f["evidence_items"]:
            assert ev["evidence_type"] in ("HANDSHAKE_TRANSCRIPT", "CONFIG_AUDIT")
            expected_hash = hashlib.sha256(ev["payload"].encode("utf-8")).hexdigest()
            assert ev["sha256_hash"] == expected_hash


# ==============================================================================
# 9. Subprocess Worker Multi-Adapter Execution
# ==============================================================================

def test_subprocess_worker_executes_phase7b_adapters_out_of_process(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """
    Verifies that the isolated OS subprocess worker runner can execute both
    Phase 7B adapters out-of-process and deserialize results properly.
    """
    runner = SubprocessWorkerRunner()

    # Test 1: passive_header_adapter out of process
    req_header = WorkerIPCRequest(
        job_id="test-job-header-001",
        project_id=test_project.id,
        worker_id="runner-phase7b-01",
        adapter_name="passive_header_adapter",
        target_input="https://subproc.internal-defense.corp",
        config={"fixture_profile": "OWASP_SECURE_HEADERS"},
        timeout_seconds=30,
        attempt_count=1,
    )

    res_header = runner.run_job(request=req_header)
    assert res_header.success is True
    assert res_header.adapter_name == "passive_header_adapter"
    assert len(res_header.findings) >= 2
    assert res_header.is_simulated is True

    # Test 2: ssl_cipher_adapter out of process
    req_tls = WorkerIPCRequest(
        job_id="test-job-tls-002",
        project_id=test_project.id,
        worker_id="runner-phase7b-02",
        adapter_name="ssl_cipher_adapter",
        target_input="subproc.internal-defense.corp",
        config={"fixture_profile": "LEGACY_DEPRECATION_AUDIT", "port": 443},
        timeout_seconds=30,
        attempt_count=1,
    )

    res_tls = runner.run_job(request=req_tls)
    assert res_tls.success is True
    assert res_tls.adapter_name == "ssl_cipher_adapter"
    assert len(res_tls.findings) >= 2
    assert res_tls.is_simulated is True
