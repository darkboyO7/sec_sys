# VAPT Platform — Test Strategy, Inventory & Automation Runbook

## 1. Testing Philosophy & Non-Negotiable Invariants

The VAPT Platform follows rigorous, defensive test engineering standards:
1. **Deterministic Synthetic Fixtures**: All network payloads, scanner responses, and vulnerability detections are generated deterministically in memory.
2. **Zero Live Network Calls**: Tests **never** emit raw network probes, open physical TCP sockets to target hosts, or attempt external exploitation.
3. **Isolated Disposable Databases**: Pytest runs against an isolated SQLite test database (`backend/data/vapt_test.db`), configured with WAL mode and transaction rollback between test cases.
4. **Complete Codebase Verification**: Every phase release requires 100% test pass rate across backend and frontend suites.

---

## 2. Test Suite Inventory

The platform test suite comprises over **200 automated backend tests** and a dedicated frontend Vitest test suite.

| Functional Area | Primary Test Files | Coverage & Verification Focus |
| :--- | :--- | :--- |
| **Authentication & RBAC** | `test_auth.py`<br>`test_projects_isolation.py`<br>`test_audit_ledger.py` | Password hashing, JWT token validation, 404 tenant isolation, audit record creation and key scrubbing. |
| **Scope Governance** | `test_scope_engine.py`<br>`test_scope_api_lifecycle.py` | Normalization, exclusion precedence over inclusions, dual-key authorization barriers. |
| **Assessment & Findings** | `test_assessment_api.py`<br>`test_assessment_state_machine.py`<br>`test_finding_api.py`<br>`test_finding_deduplication.py`<br>`test_finding_state_machine.py` | State machine transitions, finding deduplication fingerprints, contradictory observation preservation. |
| **Asset & Knowledge Graph** | `test_asset_inventory.py`<br>`test_knowledge_graph.py`<br>`test_phase10_knowledge_graph.py` | USKG node/relationship indexing, cross-project graph isolation, BFS/DFS traversal bounds. |
| **Worker Subprocess Sandbox** | `test_phase6a_execution_boundary.py`<br>`test_phase6b_worker_reliability.py`<br>`test_phase7a_worker_isolation.py`<br>`test_phase7b_scanner_framework.py` | Windows Job Object memory caps, clean environment sanitization, JSON-RPC pipe transport, timeout kill. |
| **Evidence & Tamper Detection** | `test_phase8_evidence_integrity.py` | SHA-256 evidence hashing, binary Merkle tree proofs, audit hash chaining, external trust anchors. |
| **Validation & Contextual Risk** | `test_phase9_advanced_validation.py`<br>`test_phase11_contextual_risk.py`<br>`test_phase12_attack_path_analysis.py` | Corroboration scoring, risk formula v1.1.0, heuristic uncertainty margins, attack path fingerprints. |
| **Remediation & Governance** | `test_phase13_remediation_governance.py`<br>`test_phase14_remediation_verification.py`<br>`test_phase15_reporting_and_export.py` | SLA tracking, independent verification state space, executive report generation, CSV formula defense. |
| **Digital Twin & Regression** | `test_phase16_digital_twin.py`<br>`test_phase17_regression_intelligence.py` | Point-in-time state diff engine, regression alert vectors, baseline anchoring. |
| **AI Analyst & Model ML** | `test_phase18_ai_analyst.py`<br>`test_phase19_learning_governance.py` | Prompt injection quarantine, grounded citations, empirical precision/recall thresholds, rollback. |
| **Adaptive Defense & Postgres** | `test_phase20_adaptive_defense.py`<br>`test_phase22_postgres_readiness.py`<br>`test_phase23_performance_resilience.py` | 8-state posture transitions, kill-switch, PostgreSQL connection pooling AST, composite indexes. |
| **Backup & Release Audit** | `test_phase24_backup_recovery.py`<br>`test_phase25_deployment_hardening.py`<br>`test_phase26_final_security_assessment.py` | Online SQLite backup, sandbox restore check, production secrets validator, 8-gate final security audit. |
| **Frontend Web Client** | `frontend/src/tests/api.test.ts` | Vitest API client contracts, authentication bearer injection, error interceptors. |

---

## 3. Test Execution Runbook

### 3.1. Running the Full Backend Test Suite
To execute all backend tests safely within Windows native PowerShell:
```powershell
cd D:\alt\backend

# Run complete test suite with coverage
..\.venv\Scripts\python -m pytest -v
```

### 3.2. Running Grouped Test Batches
For rapid iteration, tests can be run in functional groups:
```powershell
# Core Architecture & Scope
..\.venv\Scripts\python -m pytest tests/test_auth.py tests/test_projects_isolation.py tests/test_scope_engine.py tests/test_scope_api_lifecycle.py tests/test_audit_ledger.py

# Worker Isolation & Evidence Integrity
..\.venv\Scripts\python -m pytest tests/test_phase7a_worker_isolation.py tests/test_phase7b_scanner_framework.py tests/test_phase8_evidence_integrity.py

# Knowledge Graph & Risk Engine
..\.venv\Scripts\python -m pytest tests/test_phase10_knowledge_graph.py tests/test_phase11_contextual_risk.py tests/test_phase12_attack_path_analysis.py

# Backup, Hardening & Final Release
..\.venv\Scripts\python -m pytest tests/test_phase24_backup_recovery.py tests/test_phase25_deployment_hardening.py tests/test_phase26_final_security_assessment.py
```

### 3.3. Disposable Database Migration Test
Validates that migrations cleanly upgrade, downgrade, and re-upgrade:
```powershell
cd D:\alt\backend
$env:DATABASE_URL="sqlite:///./data/disposable_test.db"
..\.venv\Scripts\python -m alembic upgrade head
..\.venv\Scripts\python -m alembic downgrade -1
..\.venv\Scripts\python -m alembic upgrade head
Remove-Item .\data\disposable_test.db -Force
Remove-Item env:DATABASE_URL
```

### 3.4. Frontend Vitest & Production Build
```powershell
cd D:\alt\frontend

# Run Vitest unit tests
npm test

# Verify production compilation
npm run build
```
