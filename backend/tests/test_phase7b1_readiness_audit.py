import threading
import hashlib
import pytest
from typing import Dict, Any, List
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.project import Project
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.services.scanner_adapters.base import (
    BaseScannerAdapter,
    AdapterRegistry,
    AdapterResult,
    RawAdapterFinding,
    RawAdapterEvidence,
    PreflightResult,
    MAX_EVIDENCE_PAYLOAD_BYTES,
    MAX_FINDINGS_PER_JOB,
    MAX_JOB_EVIDENCE_TOTAL_BYTES,
    truncate_utf8_to_bytes,
)
from app.services.scanner_adapters.local_fixture_adapter import LocalFixtureAdapter
from app.services.scanner_adapters.passive_header_adapter import PassiveHeaderAuditAdapter
from app.services.scanner_adapters.ssl_cipher_adapter import SslTlsCipherAuditAdapter
from app.models.assessment import FindingSeverity, FindingConfidence


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture(autouse=True)
def restore_registry_after_test():
    """Ensure standard adapters remain intact after adversarial test runs."""
    yield
    AdapterRegistry.register(LocalFixtureAdapter(), allow_override=True)
    AdapterRegistry.register(PassiveHeaderAuditAdapter(), allow_override=True)
    AdapterRegistry.register(SslTlsCipherAuditAdapter(), allow_override=True)


# ==============================================================================
# 1. Concurrent Registry Access Thread Safety
# ==============================================================================

def test_concurrent_registry_access_thread_safety():
    """
    Spawns multiple threads concurrently registering, querying, listing,
    and unregistering adapters to ensure zero race conditions or
    'dictionary changed size during iteration' errors.
    """
    errors: List[Exception] = []
    num_threads = 20
    iterations_per_thread = 50

    def worker_task(thread_id: int):
        try:
            for i in range(iterations_per_thread):
                adapter_name = f"threaded_adapter_{thread_id}_{i}"

                # 1. Create and register dynamic adapter
                class ThreadedAdapter(BaseScannerAdapter):
                    @property
                    def name(self): return adapter_name
                    @property
                    def version(self): return "1.0.0"
                    @property
                    def declared_capabilities(self): return ["CONCURRENT_AUDIT"]
                    @property
                    def supported_profiles(self): return ["CONCURRENT_PROFILE"]
                    @property
                    def permitted_check_categories(self): return ["CONFIGURATION"]
                    def validate_config(self, config): return True, None
                    def preflight_check(self, target, config):
                        return PreflightResult(adapter_name=self.name, adapter_version=self.version, target=target, is_ready=True)
                    def execute(self, target, config, cancellation_check=None): pass
                    def get_health(self): return {"status": "HEALTHY", "network_scanning_enabled": False}

                adapter_inst = ThreadedAdapter()
                AdapterRegistry.register(adapter_inst, allow_override=True)

                # 2. Query registry concurrently
                _ = AdapterRegistry.get(adapter_name)
                _ = AdapterRegistry.is_approved(adapter_name)
                caps = AdapterRegistry.list_capabilities()
                assert len(caps) >= 1

                # 3. Query by capability and target type
                _ = AdapterRegistry.get_by_capability("CONCURRENT_AUDIT")
                _ = AdapterRegistry.get_by_target_type("URL")

                # 4. Clean up
                AdapterRegistry.unregister(adapter_name)
        except Exception as ex:
            errors.append(ex)

    threads = [threading.Thread(target=worker_task, args=(tid,)) for tid in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Thread safety errors observed: {errors}"


# ==============================================================================
# 2. Multibyte UTF-8 Boundary Truncation Integrity
# ==============================================================================

def test_evidence_truncation_preserves_multibyte_utf8():
    """
    Tests that a payload with 4-byte UTF-8 characters (emojis, complex scripts)
    straddling the 64 KB truncation boundary is safely decoded without producing
    replacement characters or malformed codepoint cuts.
    """
    # 4-byte unicode character: 🔥 (0xF0 0x9F 0x94 0xA5)
    char = "🔥"
    char_bytes = char.encode("utf-8")
    assert len(char_bytes) == 4

    # Build string that exactly crosses 64KB boundary
    suffix = "... [TRUNCATED_AT_64KB]"
    max_payload = MAX_EVIDENCE_PAYLOAD_BYTES  # 65536
    allowed_bytes = max_payload - len(suffix.encode("utf-8"))

    # Pad with ASCII then place multibyte character right across boundary
    base_ascii = "A" * (allowed_bytes - 2)
    # Adding a 4-byte character here will cause it to straddle allowed_bytes
    adversarial_payload = base_ascii + char + ("B" * 5000)

    safe_text, was_truncated = truncate_utf8_to_bytes(adversarial_payload, max_bytes=max_payload)
    assert was_truncated is True
    assert len(safe_text.encode("utf-8")) <= max_payload
    # Ensure replacement character (\ufffd) was NOT injected due to corrupted byte cut
    assert "\ufffd" not in safe_text

    # Verify model validator on RawAdapterEvidence
    evidence = RawAdapterEvidence(
        evidence_type="HTTP_RESPONSE_HEADERS",
        payload=adversarial_payload,
    )
    assert evidence.is_truncated is True
    assert len(evidence.payload.encode("utf-8")) <= max_payload
    assert evidence.raw_sha256_hash == hashlib.sha256(adversarial_payload.encode("utf-8")).hexdigest()
    assert evidence.sha256_hash == hashlib.sha256(evidence.payload.encode("utf-8")).hexdigest()
    assert evidence.raw_sha256_hash != evidence.sha256_hash


# ==============================================================================
# 3. Findings Clamp and Aggregate Evidence Limit
# ==============================================================================

def test_adapter_result_enforces_findings_clamp_and_total_evidence_cap():
    """
    Verifies that AdapterResult strictly clamps findings to MAX_FINDINGS_PER_JOB (50)
    and fails closed if total aggregate evidence exceeds MAX_JOB_EVIDENCE_TOTAL_BYTES (1MB).
    """
    # 1. Clamping findings to 50
    findings = [
        RawAdapterFinding(
            title=f"Synthetic Finding {i}",
            severity=FindingSeverity.LOW,
            confidence=FindingConfidence.FIRM,
        )
        for i in range(80)
    ]
    result = AdapterResult(
        adapter_name="test_adapter",
        adapter_version="1.0.0",
        target="target.internal-defense.corp",
        success=True,
        status_summary="Clamped findings test",
        findings=findings,
    )
    assert len(result.findings) == MAX_FINDINGS_PER_JOB

    # 2. Exceeding 1MB aggregate evidence raises ValueError
    oversized_findings = []
    # 25 findings each with ~50KB evidence = 1.25MB total
    for i in range(25):
        oversized_findings.append(
            RawAdapterFinding(
                title=f"Oversized Finding {i}",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.CERTAIN,
                evidence_items=[
                    RawAdapterEvidence(
                        evidence_type="HTTP_RESPONSE_HEADERS",
                        payload="X" * 50000,
                    )
                ],
            )
        )

    with pytest.raises(ValueError, match="Total evidence payload exceeds maximum job limit of 1MB"):
        AdapterResult(
            adapter_name="test_adapter",
            adapter_version="1.0.0",
            target="target.internal-defense.corp",
            success=True,
            status_summary="Aggregate evidence failure test",
            findings=oversized_findings,
        )


# ==============================================================================
# 4. Target Type Evasion & Canonicalization Matrix
# ==============================================================================

def test_target_type_evasion_normalization():
    """
    Verifies validate_target_type handles case variations, whitespace,
    and IP_ADDRESS / IPV4 canonical equivalence.
    """
    adapter = PassiveHeaderAuditAdapter()
    assert adapter.supported_target_types == ["URL", "DOMAIN"]

    # Valid types with varying case and whitespace
    assert adapter.validate_target_type("url")[0] is True
    assert adapter.validate_target_type("  URL  ")[0] is True
    assert adapter.validate_target_type("Domain")[0] is True

    # Incompatible target types rejected
    valid, err = adapter.validate_target_type("CIDR")
    assert valid is False
    assert "not supported by adapter 'passive_header_adapter'" in err

    valid, err = adapter.validate_target_type("IP_ADDRESS")
    assert valid is False

    # SSL Cipher adapter accepts IP_ADDRESS and IPV4 equivalently
    ssl_adapter = SslTlsCipherAuditAdapter()
    assert ssl_adapter.validate_target_type("IP_ADDRESS")[0] is True
    assert ssl_adapter.validate_target_type("IPV4")[0] is True
    assert ssl_adapter.validate_target_type("ipv4")[0] is True
    assert ssl_adapter.validate_target_type("DOMAIN")[0] is True


# ==============================================================================
# 5. Extreme and Deeply Nested Configuration Handling
# ==============================================================================

def test_extreme_and_deeply_nested_config_handling():
    """
    Verifies that adapters handle extreme configuration parameters
    (null bytes, nested objects, unicode) safely without unhandled exceptions.
    """
    adapter = PassiveHeaderAuditAdapter()

    # Extreme config with unicode and null characters
    extreme_config = {
        "fixture_profile": "OWASP_SECURE_HEADERS",
        "nested": {"level1": {"level2": {"param": "value" * 1000}}},
        "unicode_field": "🛡️ 安全 🚨 \x00\x01\x02",
        "array_field": [1, 2, 3, "test", None],
    }

    valid, err = adapter.validate_config(extreme_config)
    assert valid is True
    assert err is None

    # Preflight check handles extreme config safely
    preflight = adapter.preflight_check("https://target.internal-defense.corp", extreme_config)
    assert preflight.is_ready is True
    assert preflight.mode == "SIMULATED_FIXTURE"


# ==============================================================================
# 6. PreflightResult Access Interfaces & Immutability
# ==============================================================================

def test_preflight_result_access_interfaces():
    """
    Verifies PreflightResult provides both object and dictionary interfaces
    for full backward and forward compatibility.
    """
    res = PreflightResult(
        adapter_name="test_adapter",
        adapter_version="1.0.0",
        target="web.internal-defense.corp",
        target_type="DOMAIN",
        is_ready=True,
        mode="SIMULATED_FIXTURE",
        metadata={"custom_flag": True},
    )

    # Object access
    assert res.adapter_name == "test_adapter"
    assert res.is_ready is True
    assert res.mode == "SIMULATED_FIXTURE"

    # Dict access
    assert res["adapter_name"] == "test_adapter"
    assert res["is_ready"] is True
    assert res["mode"] == "SIMULATED_FIXTURE"

    # .get() access
    assert res.get("target_type") == "DOMAIN"
    assert res.get("non_existent", "default_val") == "default_val"
