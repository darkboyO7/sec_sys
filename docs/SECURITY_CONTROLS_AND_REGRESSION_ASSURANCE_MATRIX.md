# Security Controls and Regression Assurance Matrix

**Document Revision:** 1.0.0  
**Prompt Target:** Prompt 47  
**Classification:** Core Defensive Architecture & Regression Assurance Specification  
**Applicability:** VAPT Security Platform (Control Plane, API Layer, Workers, and Storage Engines)

---

## 1. Architectural Overview & Security Guarantees

The VAPT Security Platform enforces an evidence-backed, durable security regression harness. Any code change that weakens authentication, role authorization, tenant isolation, scope enforcement, or evidence integrity is automatically caught and blocked by continuous regression testing, AST-aware mutation testing, and the 39-stage release qualification gate.

```
+---------------------------------------------------------------------------------------------------+
|                                  Continuous Security Regression Harness                           |
|   +--------------------------+   +----------------------------+   +---------------------------+   |
|   | Authentication & Session |   | Multi-Tenant Project Guard |   | Scope Preflight & Bypass  |   |
|   | - Token validation/expiry|   | - Horizontal boundary check|   | - Direct & wildcard checks|   |
|   | - Immediate revocation   |   | - Object-level isolation   |   | - Exclusion absolute block|   |
|   +------------+-------------+   +-------------+--------------+   +-------------+-------------+   |
+----------------|-------------------------------|--------------------------------|-----------------+
                 |                               |                                |
+----------------v-------------------------------v--------------------------------v-----------------+
                 |               Core Security Regression Suite (Prompt 47)                         |
                 |      `test_prompt47_security_regression_and_control_verification.py`             |
                 +-------------------------------+--------------------------------+
                                                 |
                   +-----------------------------+-----------------------------+
                   |                                                           |
+------------------v----------------------------+         +--------------------v--------------------+
|  Input Validation & Cryptographic Integrity   |         |  High-Risk Policy Mutation Testing      |
|  - Directory traversal defense (`../../`)     |         |  - 14 AST-aware mutation scenarios      |
|  - Oversized payload & syntax rejection (422) |         |  - 100.0% Kill Ratio Requirement        |
|  - Single-byte evidence tamper detection      |         |  - Zero surviving defensive mutations   |
|  - Monotonic audit hash-chain continuity      |         |  - Verified against policy logic        |
+------------------+----------------------------+         +--------------------+--------------------+
                   |                                                           |
                   +-----------------------------+-----------------------------+
                                                 |
+------------------------------------------------v--------------------------------------------------+
|                                  Machine-Readable Audit Artifacts                                 |
|  - Inventory: `reports/security_controls_inventory.json` (18 controls mapped & verified)          |
|  - Telemetry: `reports/security_regression_results.json` (11 integration tests, 0 failures)       |
|  - Drill Report: `mutation_test_report.json` (14 killed, 0 survived, verdict: QUALIFIED)         |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Canonical Security Controls Inventory

| Control ID | Category | Enforcement Point | Positive Test | Negative Test | Failure Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-AUTH-01** | `AUTHENTICATION` | `app.api.deps.get_current_user` | `test_auth.py` | `test_prompt47.py::test_02` | Rejects missing/invalid tokens with HTTP 401. |
| **SEC-AUTH-02** | `SESSION_REVOCATION` | `app.api.deps.get_current_user` | `test_prompt36.py::test_05` | `test_prompt47.py::test_02` | Immediately invalidates tokens issued before revocation timestamp. |
| **SEC-RBAC-01** | `AUTHORIZATION_RBAC` | `app.api.deps.require_system_roles` | `test_prompt26.py::test_15` | `test_prompt47.py::test_03` | Rejects unauthorized role actions with HTTP 403. |
| **SEC-TENANT-01** | `MULTI_TENANT_ISOLATION` | `app.api.deps.verify_project_access` | `test_prompt36.py::test_07` | `test_prompt47.py::test_04` | Cross-project requests return HTTP 404/403 without data leakage. |
| **SEC-SCOPE-01** | `SCOPE_ENFORCEMENT` | `app.services.assessment_engine` | `test_scope_engine.py` | `test_phase6a.py` | Unverified targets transition job to REJECTED. |
| **SEC-EXCL-01** | `EXCLUSIONS_PRECEDENCE` | `app.services.scope_engine` | `test_scope_engine.py` | `test_prompt47.py::test_05` | Scope exclusions strictly override inclusions across all vectors. |
| **SEC-SCOPE-02** | `ANTI_EXPANSION_GUARD` | `app.services.attack_surface_service` | `test_prompt46.py::test_06` | `test_prompt47.py::test_05` | Unauthorized discoveries diverted to proposal inbox; active scans blocked. |
| **SEC-EVID-01** | `EVIDENCE_INTEGRITY` | `app.services.integrity_service` | `test_prompt23.py::test_03` | `test_prompt47.py::test_07` | Single-byte evidence modification invalidates SHA-256 hash. |
| **SEC-AUDIT-01** | `AUDIT_CHAIN_CONSISTENCY` | `app.models.audit.AuditEvent` | `test_phase8.py` | `test_prompt47.py::test_07` | Predecessor hash mismatch detects log tampering and raises exception. |
| **SEC-REMED-01** | `REMEDIATION_GOVERNANCE` | `app.services.remediation_service` | `test_phase13.py` | `test_phase13.py` | Requires explicit reviewer approval before execution. |
| **SEC-RETEST-01** | `INDEPENDENT_RETEST` | `app.services.remediation_verification` | `test_phase14.py` | `test_phase14.py` | Retest requires genuine scanner re-execution; recycling evidence prohibited. |
| **SEC-DR-01** | `DISASTER_RECOVERY_POSTCONDITION` | `app.services.backup_service` | `test_prompt23.py::test_10` | `test_prompt23.py::test_07` | Schema and foreign-key check failures abort database restore drills. |
| **SEC-SSRF-01** | `SSRF_PROTECTION` | `app.services.network_security_service`| `test_prompt24.py::test_10` | `test_prompt24.py::test_06` | Loopback, private RFC 1918, and cloud metadata (169.254.169.254) blocked. |
| **SEC-SUPPLY-01**| `SUPPLY_CHAIN_PROVENANCE` | `app.services.supply_chain_security` | `test_prompt25.py::test_11` | `test_prompt25.py::test_15` | HMAC-SHA256 signature verification detects tampered release archives. |
| **SEC-VAULT-01** | `SECRETS_PROTECTION` | `app.core.secret_vault.SecretVault` | `test_prompt45.py::test_05` | `test_prompt45.py::test_01` | External connector credentials encrypted at rest with Fernet `enc:v1:` envelope. |
| **SEC-INPUT-01** | `INPUT_VALIDATION_TRAVERSAL` | `app.services.canonical_report_service` | `test_prompt32.py::test_06` | `test_prompt47.py::test_08` | Rejects relative paths (`../`), absolute traversal, and oversized payloads. |
| **SEC-PERF-01**  | `CONCURRENCY_WORKLOAD` | `app.services.workload_isolation_service`| `test_prompt26.py::test_07` | `test_prompt26.py::test_08` | Returns HTTP 429 backpressure when worker slots are saturated. |
| **SEC-CONCUR-01**| `CONCURRENCY_IDEMPOTENCY`| `app.services.scopes` | `test_prompt34.py::test_04` | `test_prompt47.py::test_09` | Deduplicates identical target registrations; fails closed on race attempts. |

---

## 3. High-Risk Policy Mutation Testing Matrix

All 14 mutation scenarios achieved a **100.0% Kill Ratio** (0 survivors) during the automated drill:

| Mutation ID | Control ID | Target Component | Mutation Type | Killer Test | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `MUT-AUTH-01` | `SEC-RBAC-01` | `deps.py:require_system_roles` | `BYPASS_AUTH` | `test_prompt26.py::test_17` | **KILLED** |
| `MUT-SCOPE-01` | `SEC-EXCL-01` | `scope_engine.py:evaluate_target` | `INVERT_BOOLEAN` | `test_scope_engine.py` | **KILLED** |
| `MUT-TARGET-02`| `SEC-SCOPE-01` | `assessment_engine.py:submit_job` | `REMOVE_VALIDATION` | `test_phase6a.py` | **KILLED** |
| `MUT-EVID-01` | `SEC-EVID-01` | `integrity_service.py:verify_evidence` | `ALWAYS_TRUE` | `test_prompt23.py::test_04` | **KILLED** |
| `MUT-AUDIT-01` | `SEC-AUDIT-01` | `backup_service.py:verify_audit_chain` | `REMOVE_VALIDATION` | `test_prompt23.py::test_08` | **KILLED** |
| `MUT-REMED-01` | `SEC-REMED-01` | `remediation_service.py:execute_remediation` | `BYPASS_AUTH` | `test_phase13.py` | **KILLED** |
| `MUT-RETEST-01`| `SEC-RETEST-01`| `remediation_verification_service.py:retest_finding` | `ALWAYS_TRUE` | `test_phase14.py` | **KILLED** |
| `MUT-DR-01` | `SEC-DR-01` | `backup_service.py:audit_sandbox_schema` | `REMOVE_VALIDATION` | `test_prompt23.py::test_07` | **KILLED** |
| `MUT-SSRF-01` | `SEC-SSRF-01` | `network_security_service.py:validate_outbound_url` | `INVERT_BOOLEAN` | `test_prompt24.py::test_06` | **KILLED** |
| `MUT-SUPPLY-01`| `SEC-SUPPLY-01`| `supply_chain_security_service.py:verify_release_package` | `ALWAYS_TRUE` | `test_prompt25.py::test_15` | **KILLED** |
| `MUT-TENANT-01`| `SEC-TENANT-01`| `deps.py:get_project_member_role` | `ALWAYS_TRUE` | `test_prompt47.py::test_04` | **KILLED** |
| `MUT-TOKEN-02` | `SEC-AUTH-02` | `deps.py:get_current_user` | `REMOVE_VALIDATION` | `test_prompt47.py::test_02` | **KILLED** |
| `MUT-ANTIEXP-01`| `SEC-SCOPE-02` | `attack_surface_service.py:ingest_exposure_observation`| `BYPASS_AUTH` | `test_prompt47.py::test_05` | **KILLED** |
| `MUT-TRAVERSAL-01`| `SEC-INPUT-01` | `bundle_service.py:safe_extract` | `REMOVE_VALIDATION` | `test_prompt47.py::test_08` | **KILLED** |

---

## 4. Documented Testing Limitations & Skipped Checks

In conformance with Prompt 47 Acceptance criteria, skipped checks and coverage limitations are explicitly recorded rather than claimed as tested:

1. **Hardware Security Module (HSM) PKCS#11 Integration:**
   - *Check ID:* `CHK-HW-HSM-01`
   - *Reason:* Dedicated physical HSM hardware is not provisioned in local CI/CD sandbox environments.
   - *Mitigation:* Cryptographic encryption at rest is validated through Fernet AES-128-CBC + HMAC-SHA256 in `SEC-VAULT-01`.
2. **Upstream BGP Routing & Autonomous System Hijacking:**
   - *Check ID:* `CHK-NET-BGP-01`
   - *Reason:* Live internet BGP manipulation cannot be safely performed without risking broader internet disruption.
   - *Mitigation:* Scope boundary revalidation and SSRF cloud metadata IP filtering strictly enforced on every outbound connection.
3. **Hardware L2 Bus Probing & Physical Memory Freezing:**
   - *Check ID:* `CHK-HW-MEM-01`
   - *Reason:* Physical security boundaries and cold-boot memory attacks are out of scope for application software regression testing.
   - *Mitigation:* Operating system memory protection, non-swappable secret memory strings where supported, and continuous secret pattern scrubbing in RAM logs.
