# VAPT SYSTEM — CROSS-SUBSYSTEM INTEGRATION TESTS
## Specification and Verification of 14 Complex Failure Scenarios (Prompt 13)

---

## 1. Overview & Test Harness Architecture

To prove that the **VAPT Defensive Security Platform** functions as an integrated, resilient system rather than a set of isolated components, 14 cross-subsystem failure scenarios were implemented in `backend/tests/test_prompt13_cross_system_integrity_and_validation.py`.

The integration harness utilizes disposable, transaction-isolated SQLite databases with WAL mode enabled, foreign key integrity constraints, and strict dependency overrides.

---

## 2. Detailed Failure Scenario Specifications

### Scenario 1: Target Authorized, Then Excluded Before Queued Job Starts
- **Subsystems Involved:** Scope Engine, Assessment Engine, Worker Execution Boundary, Audit Ledger.
- **Precondition:** Target `192.168.100.50` is enrolled and authorized in `ScopeTarget`. An assessment job is queued with a scope snapshot digest.
- **Fault Injection:** Before worker claims the job, an emergency exclusion for `192.168.100.50` is registered in `ScopeExclusion`.
- **Observed Behavior:**
  - `AssessmentExecutionEngine.preflight_and_claim_job` re-evaluates scope at runtime.
  - Scope evaluation returns `is_authorized: False`, `status: EXCLUDED`.
  - Job transitions to `REJECTED` with `failure_category = "SCOPE_AUTHORIZATION_DENIED"`.
  - An audit event `ASSESSMENT_PREFLIGHT_DENIED` is committed to the Merkle audit ledger.
- **Status:** **PASSED** (Verified in `test_scenario_1`).

---

### Scenario 2: Worker Process Crashes After Evidence Collection
- **Subsystems Involved:** Background Workers, Central Health Engine, Diagnostics Engine, Controlled Recovery Engine.
- **Precondition:** An assessment job was claimed by a worker node, transitioned to `RUNNING`, and inserted raw evidence.
- **Fault Injection:** The worker process terminates abruptly (simulated by a 45-minute heartbeat timeout).
- **Observed Behavior:**
  - `DiagnosticsEngineService.run_project_diagnostics` flags check `DIAG_STUCK_JOBS` as a `CONFIRMED` defect.
  - `RecoveryEngineService.execute_recovery` executes `RECOVER_STUCK_JOB`.
  - Job transitions to `CANCELLED` with diagnostic error message `"Recovered by diagnostic action: ..."`.
  - Worker concurrency slot is released; pre-collected evidence is preserved without corruption.
- **Status:** **PASSED** (Verified in `test_scenario_2`).

---

### Scenario 3: Two Workers Attempt to Claim the Same Job Concurrently
- **Subsystems Involved:** Assessment State Machine, Database Transaction Boundary, Concurrency Control.
- **Precondition:** Assessment job sits in `QUEUED` state.
- **Fault Injection:** Two independent worker routines (`worker-alpha` and `worker-beta`) invoke `preflight_and_claim_job` simultaneously.
- **Observed Behavior:**
  - Atomic SQL conditional update (`status == QUEUED` $\to$ `PREFLIGHT`) succeeds for `worker-alpha` (`rows_updated == 1`).
  - `worker-beta`'s query updates 0 rows (`rows_updated == 0`).
  - `worker-beta` receives the job already owned by `worker-alpha` and aborts execution.
  - Job transitions cleanly from `PREFLIGHT` to `RUNNING` under `worker-alpha` without double execution.
- **Status:** **PASSED** (Verified in `test_scenario_3`).

---

### Scenario 4: Evidence Altered After Finding and Risk Score Recorded
- **Subsystems Involved:** Evidence Storage, Cryptographic Integrity Service, Merkle Proof Engine.
- **Precondition:** An assessment job recorded an insecure header finding with raw evidence and its SHA-256 digest.
- **Fault Injection:** An attacker or rogue process directly mutates `FindingEvidence.payload` in the database without updating `sha256_hash`.
- **Observed Behavior:**
  - `IntegrityService.verify_evidence_integrity` re-hashes payload bytes.
  - Detects hash mismatch (`actual_hash != ev.sha256_hash`).
  - Returns `is_valid: False` and adds the exact evidence ID to `corrupted_evidence_ids`.
- **Status:** **PASSED** (Verified in `test_scenario_4`).

---

### Scenario 5: Graph Relationship Change Invalidates Attack Path
- **Subsystems Involved:** Universal Security Knowledge Graph, Attack Path Synthesis Engine, Risk Prioritization.
- **Precondition:** A 3-node graph chain ($A \to B \to C$) has active `VERIFIED` relationships yielding a verified attack path.
- **Fault Injection:** Relationship $B \to C$ status is changed to `STALE` due to firewall rule changes or expired credentials.
- **Observed Behavior:**
  - `AttackPathAnalysisService.analyze_attack_paths` re-evaluates the topology.
  - The path is categorized with `path_verification_status = "STALE"`.
  - Generates explicit `missing_evidence` entry: `"Relationship 'Web Server' --[CAN_ACCESS]--> 'Database' is STALE. Evidence has expired..."`.
- **Status:** **PASSED** (Verified in `test_scenario_5`).

---

### Scenario 6: Reopened Finding Triggers Risk Recurrence Penalty
- **Subsystems Involved:** Finding Lifecycle FSM, Contextual Risk Engine, Audit Ledger.
- **Precondition:** A finding was marked `VERIFIED_CLOSED` (risk score neutralized to 0.0).
- **Fault Injection:** Security tester transitions finding from `VERIFIED_CLOSED` to `REOPENED` with recurrence flags set.
- **Observed Behavior:**
  - `ContextualRiskService.calculate_score_and_factors` detects `status == REOPENED` and prior failure.
  - Applies recurrence multiplier ($1.10\times$) and remediation failure penalty ($1.20\times$).
  - Residual score jumps back above 60.0 with explicit contributing factor warnings in output.
- **Status:** **PASSED** (Verified in `test_scenario_6`).

---

### Scenario 7: Model Update Failing Quality Gate Rejected; Baseline Preserved
- **Subsystems Involved:** Model Governance Service, Empirical Evaluation Gate, Machine Learning Storage.
- **Precondition:** An active baseline model `fp_classifier` v1.0 is currently deployed in production.
- **Fault Injection:** A candidate model v2.0 with precision $0.45 < 0.60$ is submitted for Lead approval.
- **Observed Behavior:**
  - `ModelGovernanceService.approve_model` evaluates metrics against empirical threshold.
  - Raises `ValueError: Model fails minimum quality thresholds (precision=0.45, recall=0.85)`.
  - Candidate status remains `EVALUATED` (not `APPROVED`), deployment is blocked, active v1.0 baseline remains untouched.
- **Status:** **PASSED** (Verified in `test_scenario_7`).

---

### Scenario 8: Recovery Action Fails Closed on Unmet Preconditions
- **Subsystems Involved:** Controlled Recovery Engine, Two-Phase Verification, Security Decision Ledger.
- **Precondition:** An assessment job has already finished in terminal status `COMPLETED`.
- **Fault Injection:** An operator invokes `RECOVER_STUCK_JOB` against this completed job.
- **Observed Behavior:**
  - Pre-condition inspection detects `job.status == COMPLETED`.
  - Action aborts without modifying job state; outcome is marked `INCONCLUSIVE`.
  - Verification notes record: `"Job was already in terminal state 'COMPLETED'"`.
- **Status:** **PASSED** (Verified in `test_scenario_8`).

---

### Scenario 9: Sandbox Restore Verifies Evidence and Diagnostics Integrity
- **Subsystems Involved:** Backup & Recovery Service, Data Lifecycle Manager, Cryptographic Verifier.
- **Precondition:** Database is restored into an isolated sandbox environment.
- **Fault Injection:** One evidence record has an invalid SHA-256 digest representing corrupted disk data.
- **Observed Behavior:**
  - `IntegrityService.verify_evidence_integrity` flags the corrupted evidence ID.
  - Sandbox verification fails and logs the defect before promoting the backup to production.
- **Status:** **PASSED** (Verified in `test_scenario_9`).

---

### Scenario 10: Cross-Tenant Isolation Denies Outsider Access (HTTP 404)
- **Subsystems Involved:** Authentication Dependency, Project Membership RBAC, Diagnostics Router.
- **Precondition:** Project Apex belongs to Tenant Organization A. Outsider user belongs to Organization B.
- **Fault Injection:** Outsider user sends authenticated requests to run diagnostics, read run history, or execute recovery actions in Project Apex.
- **Observed Behavior:**
  - `verify_project_access` verifies project membership.
  - Fails closed with **HTTP 404 Not Found** on all endpoints (preventing confirmation of project existence).
- **Status:** **PASSED** (Verified in `test_scenario_10`).

---

### Scenario 11: Duplicate Monitoring Event Deduplication
- **Subsystems Involved:** Continuous Monitoring Engine, Finding Deduplication Service.
- **Precondition:** Finding with fingerprint $F_1$ exists in project database with `occurrence_count = 1`.
- **Fault Injection:** Ingestion pipeline delivers the exact same finding observation a second time.
- **Observed Behavior:**
  - Query detects existing fingerprint match.
  - Total finding count remains 1 (no duplicate rows created).
  - Existing finding's `occurrence_count` increments to 2, and `last_observed_at` updates.
- **Status:** **PASSED** (Verified in `test_scenario_11`).

---

### Scenario 12: Optimistic Concurrency Conflict on Finding Transition (HTTP 409)
- **Subsystems Involved:** Finding API Router, Finding Lifecycle Service, Concurrency Manager.
- **Precondition:** Finding status is `CONFIRMED`.
- **Fault Injection:** Client attempts to transition finding to `REMEDIATION_PROPOSED` but provides `expected_status: DETECTED` (simulating a race condition with a concurrent update).
- **Observed Behavior:**
  - API endpoint compares `finding.status` to `transition_in.expected_status`.
  - Discrepancy detected; API raises **HTTP 409 Conflict** with detail: `"Concurrent transition conflict: Expected finding status 'DETECTED' but current status is 'CONFIRMED'"`.
  - Finding state is not modified.
- **Status:** **PASSED** (Verified in `test_scenario_12`).

---

### Scenario 13: Audit Hash Chain Strictly Monotonic Under Rapid Sequential Calls
- **Subsystems Involved:** Audit Ledger Service, Merkle Hash Chain Engine, Concurrency Lock.
- **Precondition:** Project audit ledger has an active root.
- **Fault Injection:** 5 rapid sequential audit log entries are generated in tight loop within sub-millisecond windows.
- **Observed Behavior:**
  - Internal `_chain_lock` serializes event generation.
  - Microsecond timestamp adjuster guarantees strictly non-decreasing timestamps.
  - Every event's `prev_event_hash` matches its immediate predecessor's `event_hash`.
  - `IntegrityService.verify_audit_ledger_integrity` confirms `chain_status = "VALID"` with 0 broken links.
- **Status:** **PASSED** (Verified in `test_scenario_13`).

---

### Scenario 14: SSRF & DNS Rebinding Outbound Boundary Protection
- **Subsystems Involved:** Live Network Auditor Adapter, Safe Connection Sockets, SSRF Validator.
- **Precondition:** Network auditor configured to probe target URLs.
- **Fault Injection:** Assessment is targeted at cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`), link-local IPs, or internal private RFC1918 space without explicit authorization.
- **Observed Behavior:**
  - `check_ip_ssrf` and `resolve_and_verify_ssrf` evaluate target host and all resolved DNS A/AAAA records.
  - Requests are blocked before socket creation with descriptive SSRF denial reasons.
- **Status:** **PASSED** (Verified in `test_scenario_14`).

---

## 3. Automated Test Execution Summary

```
D:\alt\.venv\Scripts\pytest D:\alt\backend\tests\test_prompt13_cross_system_integrity_and_validation.py -v
==================================== 14 passed in 7.09s ====================================
```
