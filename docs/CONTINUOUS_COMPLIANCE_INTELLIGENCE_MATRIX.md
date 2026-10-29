# Continuous Compliance Intelligence, Security Baselines & Configuration Drift Governance Matrix (Prompt 33)

## 1. Overview & Architecture

Prompt 33 establishes an integrated continuous compliance intelligence and security-baseline capability for the VAPT Platform. It provides a versioned, normalized security requirements catalog, configurable baseline profiles, deterministic evidence evaluation, idempotent configuration and evidence drift tracking, and time-bounded exception governance enforcing Separation of Duties.

```
+-------------------------------------------------------------------------------------------------+
|                                     VAPT COMPLIANCE SYSTEM                                      |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|   +--------------------------+        +---------------------------+        +----------------+   |
|   | Controls Catalog         |        | Baseline Profiles         |        | Evidence Store |   |
|   | - CMP-TLS-01 (v1.0.0)    |        | - web-app-defensive-v1    |        | - Findings     |   |
|   | - CMP-AUTH-01 (v1.0.0)   |------->| - perimeter-exposure-v1   |------->| - Retests      |   |
|   | - CMP-VULN-01 (v1.0.0)   |        | (Configurable parameters) |        | - Banners/TLS  |   |
|   | - CMP-REMED-01 (v1.0.0)  |        +---------------------------+        | - Audit Logs   |   |
|   | - CMP-AUDIT-01 (v1.0.0)  |                      |                      +----------------+   |
|   | - CMP-EXPOSURE-01 (v1.0) |                      v                               |           |
|   +--------------------------+        +---------------------------+                 |           |
|                                       | Deterministic Evaluator   |<----------------+           |
|                                       +---------------------------+                             |
|                                                     |                                           |
|                     +-------------------------------+-------------------------------+           |
|                     v                               v                               v           |
|        +-------------------------+    +-------------------------+     +--------------------+    |
|        | Provenance Digest Run   |    | Idempotent Drift Engine |     | Exception Manager  |    |
|        | - PASS / FAIL / PARTIAL |    | - REGRESSION_FAIL       |     | - SoD Enforcement  |    |
|        | - UNKNOWN / N/A / ERROR |    | - EVIDENCE_DISAPPEARED  |     | - Auto-Expiry      |    |
|        | - Zero fabricated pass  |    | - REMEDIATED_PASS       |     | - Proof Linking    |    |
|        +-------------------------+    +-------------------------+     +--------------------+    |
|                                                                                                 |
+-------------------------------------------------------------------------------------------------+
```

---

## 2. Security Controls Catalog

| Control ID | Version | Category | Title | Framework & Ref | Required Evidence | Evaluation Rule | Severity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `CMP-TLS-01` | `1.0.0` | `TRANSPORT_SECURITY` | Enforce Strong TLS & Transport Cryptography | NIST CSF 2.0 PR.DS-02 | `NETWORK_PORT_BANNER`, `HTTP_RESPONSE` | `verify_tls_posture` | `HIGH` |
| `CMP-AUTH-01` | `1.0.0` | `IDENTITY_AND_ACCESS` | Robust Authentication & Session Management | OWASP ASVS v4.0 V2.1-V2.8 | `HTTP_RESPONSE`, `HEADER_ANALYSIS` | `verify_auth_mechanisms` | `CRITICAL` |
| `CMP-VULN-01` | `1.0.0` | `VULNERABILITY_MANAGEMENT` | Zero Unmitigated Critical & High Vulnerabilities | NIST CSF 2.0 ID.RA-01 | `VULNERABILITY_PROOF` | `verify_no_critical_findings` | `CRITICAL` |
| `CMP-REMED-01` | `1.0.0` | `REMEDIATION_INTEGRITY` | Independent Verification of Remediated Findings | NIST CSF 2.0 RS.MI-01 | `RETEST_EXECUTION` | `verify_remediation_attestation` | `MEDIUM` |
| `CMP-AUDIT-01` | `1.0.0` | `AUDIT_INTEGRITY` | Cryptographic Audit Ledger & Immutability | NIST CSF 2.0 PR.PS-08 | `AUDIT_RECORD` | `verify_audit_log_chain` | `HIGH` |
| `CMP-EXPOSURE-01` | `1.0.0` | `EXPOSURE_MANAGEMENT` | Authorized Scope & Perimeter Completeness | NIST CSF 2.0 PR.AC-05 | `ASSET_DISCOVERY` | `verify_asset_inventory_completeness` | `MEDIUM` |

---

## 3. Truthful Evaluation Decision States

The platform strictly rejects the anti-pattern of inferring security from missing evidence:
- **`PASS`**: Valid, cryptographically grounded evidence directly satisfies the requirement statement.
- **`FAIL`**: Valid evidence proves an unmitigated violation or active vulnerability.
- **`PARTIAL`**: Evidence satisfies part of the requirement (e.g., 1 of 2 resolved findings has retest proof). Never treated as a pass.
- **`UNKNOWN`**: Incomplete evidence or missing observations. Recorded with explicit `missing_evidence_types`. Never promoted to pass.
- **`NOT_APPLICABLE`**: Documented applicability criteria establish the control is out of scope (e.g. no resolved findings to retest).
- **`ERROR`**: Catalog definition missing or unhandled evaluation failure.

---

## 4. Idempotent Drift Detection

Transitions between successive evaluation runs for a project and profile are tracked idempotently:
- **`REGRESSION_FAIL`**: Prior PASS drifted to FAIL due to new vulnerability or configuration change.
- **`EVIDENCE_DISAPPEARED_UNKNOWN`**: Prior PASS transitioned to UNKNOWN due to missing observation or sensor loss.
- **`NEW_CONTROL_UNSATISFIED`**: New control added by profile revision that is not yet satisfied.
- **`REMEDIATED_PASS`**: Prior FAIL transitioned to PASS following independently verified remediation.
- **`Deduplication Hash`**: SHA-256(`project_id:control_id:asset_id:drift_type:current_run_id`) guarantees that repeated evaluations with identical inputs never flood the database with duplicate events.

---

## 5. Controlled Exceptions & Separation of Duties

- **Time-Bounded**: Every exception requires a mandatory future `expires_at` timestamp.
- **Auto-Cleansing**: Expired exceptions (`utc_now() > expires_at`) automatically transition to `EXPIRED` during evaluation preflight, losing exception protection.
- **Separation of Duties (SoD)**: The requester cannot self-approve their own exception request. Server-side verification strictly enforces `requester_id != approver_id` and rejects self-approval with `403 Forbidden` (`AuthorizationError`).
- **Truthful Outcomes**: Exceptions never falsify underlying control outcomes; `status` remains evaluated truthfully while `has_exception=True` and `exception_id` are linked for governance transparency.

---

## 6. REST API Endpoints & Permissions

| Method | Endpoint | Description | Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/compliance/controls` | List versioned requirements catalog | Authenticated User |
| `GET` | `/api/v1/compliance/controls/{control_id}` | Retrieve specific control details | Authenticated User |
| `POST` | `/api/v1/compliance/controls` | Publish new control or version | System `ADMIN` |
| `GET` | `/api/v1/projects/{project_id}/compliance/baselines` | List project baseline profiles | Project Member |
| `GET` | `/api/v1/projects/{project_id}/compliance/baselines/{profile_id}` | Get baseline profile details | Project Member |
| `POST` | `/api/v1/projects/{project_id}/compliance/baselines` | Create baseline profile | Project `LEAD` / `ADMIN` |
| `PUT` | `/api/v1/projects/{project_id}/compliance/baselines/{profile_id}` | Update baseline parameters/controls | Project `LEAD` / `ADMIN` |
| `POST` | `/api/v1/projects/{project_id}/compliance/evaluate` | Run deterministic evaluation | Project Member |
| `GET` | `/api/v1/projects/{project_id}/compliance/evaluations` | List historical evaluation runs | Project Member |
| `GET` | `/api/v1/projects/{project_id}/compliance/evaluations/{run_id}` | Get evaluation run with results | Project Member |
| `GET` | `/api/v1/projects/{project_id}/compliance/compare` | Compare two evaluation runs | Project Member |
| `GET` | `/api/v1/projects/{project_id}/compliance/drift` | List configuration drift events | Project Member |
| `GET` | `/api/v1/projects/{project_id}/compliance/exceptions` | List baseline exceptions | Project Member |
| `POST` | `/api/v1/projects/{project_id}/compliance/exceptions` | Request baseline exception | Project Member |
| `POST` | `/api/v1/projects/{project_id}/compliance/exceptions/{id}/review` | Review/Approve/Reject (SoD) | Project `LEAD` / `ADMIN` |
| `POST` | `/api/v1/projects/{project_id}/compliance/exceptions/{id}/revoke` | Revoke approved exception | Project `LEAD` / `ADMIN` |

---

## 7. Verification Evidence & Quality Assurance

- **Alembic Revision**: `c1d2e3f4a5b6_prompt33_continuous_compliance_intelligence.py` (applied cleanly to head).
- **Pytest Suite**: `backend/tests/test_prompt33_continuous_compliance_intelligence.py` (19/19 passed in 1.66s).
- **Vitest Suite**: `frontend/src/tests/compliance.test.ts` (5/5 passed; 108/108 vitest passed in 916ms).
- **Frontend Distribution Build**: `tsc -b && vite build` (clean in 1.03s).
- **API Contract Verification**: `234/234 verified` against 266 OpenAPI endpoints.
