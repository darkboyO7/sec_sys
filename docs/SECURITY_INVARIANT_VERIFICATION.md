# VAPT SYSTEM — SECURITY INVARIANT VERIFICATION
## Comprehensive End-to-End Cryptographic, Scope, Lifecycle, and Governance Verification (Prompt 13)

---

## 1. Executive Security Verification Summary

This report documents the rigorous, independent verification of all primary security invariants across the **VAPT Defensive Security Platform**. Every invariant was evaluated against active source code, database foreign keys, cryptographic algorithms, state machine transitions, and executable adversarial failure tests.

---

## 2. Invariant A — Authorization and Scope Enclosure

### Core Guarantees & Verification Results
1. **Independent Dual-Key Approvals:**
   - *Implementation:* `app/services/scope_engine.py` requires target records in `ScopeTarget` to hold `authorization_status = AuthorizationStatus.AUTHORIZED` and explicit `authorized_by_id`.
   - *Verification:* Verified in `test_scope_engine.py`. Targets in `PENDING` state fail closed with reason `"Target is registered in scope but pending authorization approval"`.
2. **Exclusion Precedence Over Inclusions:**
   - *Implementation:* `ScopeEngine.validate_target_in_scope` executes Step 2 (Exclusions) *before* Step 3 (Inclusions). If any exclusion rule matches, the target is immediately rejected.
   - *Verification:* Proved in `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_1`. A candidate IP within an authorized CIDR matching an exclusion returns `is_authorized: False`, `status: EXCLUDED`.
3. **Execution-Time Boundary Re-Validation:**
   - *Implementation:* `AssessmentExecutionEngine.preflight_and_claim_job` re-invokes `ScopeEngine.validate_target_in_scope` at the exact moment a worker claims a queued job.
   - *Verification:* Proved in `test_scenario_1`. If an exclusion is created while a job sits in `QUEUED`, the job is rejected at preflight with `failure_category: SCOPE_AUTHORIZATION_DENIED`.
4. **SSRF, DNS Rebinding & Socket Pinning:**
   - *Implementation:* `LiveNetworkAuditorAdapter` uses `check_ip_ssrf` and `SafeHTTPConnection` / `SafeHTTPSConnection` to resolve DNS once, verify destination IP safety, and pin the socket directly to the verified IP (`connect_host = self.verified_ip`).
   - *Blocked Targets:* Cloud metadata (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`), link-local (`169.254.0.0/16`), Carrier-Grade NAT (`100.64.0.0/10`), multicast (`224.0.0.0/4`), IPv4-mapped IPv6, and internal metadata hostnames (`metadata.google.internal`).
   - *Verification:* Proved in `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_14`.
5. **Cross-Tenant Fail-Closed Isolation:**
   - *Implementation:* `verify_project_access` dependency checks project membership. Requests from non-members fail closed with HTTP 404 (preventing project existence leakage).
   - *Verification:* Proved in `test_scenario_10`. Diagnostic sweeps, recent run listings, and recovery action triggers from an unassigned outsider return HTTP 404.

---

## 3. Invariant B — Evidence Provenance and Audit Integrity

### Cryptographic Evidence Integrity
- **Byte Representation:** Evidence hashes are computed using canonical SHA-256 over UTF-8 encoded payloads:
  $$\text{SHA256}(\text{payload.encode('utf-8')})$$
- **Payload Clamping & Truncation:** Payloads exceeding `MAX_EVIDENCE_PAYLOAD_BYTES` (1MB) are truncated with an explicit notice; `FindingEvidence` tracks both `sha256_hash` (truncated payload) and `raw_sha256_hash` (original stream).
- **Independent Verification:** `IntegrityService.verify_evidence_integrity` rehashes all evidence items belonging to an assessment job, compares them to stored digests, and builds a binary Merkle tree.
- *Verification Evidence:* Proved in `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_4`. Mutating payload bytes causes instant validation failure and flags the corrupted record ID.

### Merkle Audit Ledger Chaining
- **Hash Binding Formula:**
  $$\text{event\_hash} = \text{SHA256}(\text{prev\_hash} \mid \text{timestamp} \mid \text{actor\_id} \mid \text{action} \mid \text{target\_type} \mid \text{target\_id} \mid \text{project\_id} \mid \text{outcome} \mid \text{canonical\_json\_details})$$
- **Monotonicity & Concurrency Protection:** `AuditService` implements an internal `_chain_lock` and timestamp adjuster:
  ```python
  with cls._chain_lock:
      last_event = query.order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc()).first()
      if last_event and last_event.timestamp >= now:
          now = last_event.timestamp + timedelta(microseconds=1)
      event_hash = compute_audit_event_hash(prev_hash=last_event.event_hash, timestamp=now, ...)
  ```
- *Verification Evidence:* Proved in `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_13`. Rapid sequential audit events generate strictly non-decreasing timestamps, unbroken links, and `chain_status = "VALID"`.

### Threat Model & Cryptographic Limitations
> [!WARNING] Cryptographic Security Boundary & Threat Model
> The internal Merkle hash chain guarantees **tamper evidence against unprivileged application users and standard attackers who modify rows via SQL injection or application vulnerabilities**. Any inserted, updated, or deleted audit record breaks the forward cryptographic hash links.
> 
> **Defined Cryptographic Limitation:** An attacker who achieves **full database superuser access AND control over the server environment** could hypothetically recompute all forward hashes from the point of alteration. To defend against full host compromise, the platform provides `AppendOnlyArchiveTrustAnchor` and `ExternalTrustAnchor` interfaces (Phase 8), which commit Merkle roots to an out-of-band external append-only archive with isolated signing keys or an external RFC 3161 timestamping authority. An internal hash chain alone must never be described as "tamper-proof" against a compromised database root.

---

## 4. Invariant C — Finding Lifecycle and Epistemic Knowledge Graph

### State Machine Constraints & Optimistic Concurrency
- **13-State Finite State Machine:** Managed by `FindingLifecycleService`. Prohibits illegal transitions (e.g. `DETECTED` cannot jump directly to `VERIFIED_CLOSED`).
- **Optimistic Concurrency Control:** `POST /findings/{id}/transition` accepts an optional `expected_status`. If another user or worker modified the finding state in the interim, the API immediately rejects the update with **HTTP 409 Conflict** (`Concurrent transition conflict`), preventing silent state overwrites.
- *Verification Evidence:* Proved in `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_12`.

### Epistemic Graph Rigor
- **Multi-Scanner Contradiction Preservation:** When scanners disagree (e.g. Scanner A flags an outdated library while Scanner B observes patched headers), the finding is preserved with `has_contradictions = True` and a 20% confidence discount ($0.80\times$), rather than discarding contradictory telemetry.
- **Topological Reachability vs Exploitability:** The graph differentiates observed structural edges (`RUNS_ON`, `EXPOSES`) from verified exploit chains.
- *Verification Evidence:* Proved in `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_5`. Attack path analysis explicitly tags unverified paths as `HYPOTHETICAL` or `STALE` and outputs required missing evidence instead of falsely asserting exploitability.

---

## 5. Invariant D — Contextual Risk and Model Governance

### Determinism and Statistical Basis of Uncertainty Margin
- **Deterministic Risk Scoring:** For identical finding, asset, and topology inputs, `ContextualRiskService.calculate_score_and_factors` yields identical scores to one decimal place.
- **Score Margin Clarification:**
  > [!IMPORTANT] Statistical Interpretation of Uncertainty Margin
  > The platform's score margin ($\text{score} \pm \Delta$) is an **empirical heuristic uncertainty interval**, derived deterministically from:
  > - Base finding confidence (`TENTATIVE` adds $+7.0$)
  > - Missing context attributes ($+2.0$ per missing factor up to $+8.0$)
  > - Contradictory scanner observations ($+8.0$)
  > - Stale evidence age ($+4.0$)
  > 
  > This represents input completeness and observation confidence. It is **NOT** a frequentist Gaussian or Student-t 95% confidence interval over sampled breach events. Describing it as a "95% CI" was an architectural shorthand; the actual metric is a bounded heuristic uncertainty band.

### Governed Model Learning & Empirical Gates
- **Dataset Splitting:** Data is partitioned into strictly deterministic splits (70% TRAIN, 15% VAL, 15% TEST) hashed with SHA-256. Unverified findings cannot serve as confirmed training labels.
- **Offline Quality Gates:** Candidate models must achieve **Precision $\ge 0.60$ and Recall $\ge 0.60$** on the held-out TEST partition.
- **Baseline Comparison & Rejection:** If a candidate model has a lower F1 score or higher Brier error than the active baseline model, it is automatically rejected.
- *Verification Evidence:* Proved in `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_7`.

---

## 6. Invariant E — Remediation, Retesting, and Controlled Recovery

### Independent Verification
- A remediation cannot be verified closed by relying on the original assessment observation.
- `RemediationVerification` dispatches fresh retest probes across 4 distinct outcomes:
  1. `VERIFIED_RESOLVED`
  2. `STILL_VULNERABLE`
  3. `PARTIALLY_REMEDIATED`
  4. `REINTRODUCED`
- *Inconclusive Safety:* Retests yielding `INCONCLUSIVE` are strictly forbidden from transitioning a finding to `VERIFIED_CLOSED`.

### Controlled Self-Healing & Recovery Boundaries
- All 8 recovery actions enforce strict boundaries:
  1. **Authorization:** Restricted to `SystemRole.ADMIN` or `ProjectRole.LEAD`.
  2. **Scope Validation:** Out-of-scope targets fail closed immediately.
  3. **Two-Phase Verification:** Pre-condition snapshot $\to$ action $\to$ post-condition snapshot $\to$ cryptographic audit ledger logging.
  4. **Unmet Preconditions:** If an entity is already in a terminal state (e.g. recovering a `COMPLETED` job), the recovery engine marks outcome `INCONCLUSIVE` and aborts without mutating records.
  5. **Policy Invariant:** Recovery actions **never** expand scope, loosen security policies, or disable authentication.
- *Verification Evidence:* Proved in `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_2` and `test_scenario_8`.
