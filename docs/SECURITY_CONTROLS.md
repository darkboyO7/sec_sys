# VAPT Platform — Security Controls & Invariant Verification Matrix

**Document Version:** 1.0.0
**Classification:** Core Governance & Architecture Standard
**Last Verified Commit:** `bfeaf15`
**Governing Standard:** NIST SP 800-53 Rev. 5 / OWASP ASVS 4.0 / CWE Top 25

---

## 1. Architectural Security Principles

The VAPT Platform implements defense-in-depth across six core security tiers:
1. **Zero-Trust Scope Invariant:** No target is scanned without cryptographic authorization. Exclusions strictly preempt inclusions.
2. **Fail-Closed Execution Frontier:** Preflight boundary re-validation immediately before worker process launch.
3. **Hardware-Level Process Containment:** Win32 Job Object sandbox limits worker memory to 512 MB and automatically terminates all descendant processes upon exit.
4. **Non-Intrusive Safety Standard:** All scanner adapters operate strictly under `is_simulated = True` by default. Intrusive network scanning is disabled.
5. **Cryptographic Proof of Evidence:** Byte-level SHA-256 evidence hashing, monotonic audit hash chaining, binary Merkle tree proofs, and out-of-band append-only trust anchor.
6. **Model & Automation Governance:** Dual-party human approval gates for model promotion and remediation execution; immutable prediction ledger; emergency kill switch.

---

## 2. Complete Security Controls & Verification Matrix

| Control ID | Control Name | Threat Addressed | Implementation Location | Verified Invariant | Test Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Multi-Tenant Isolation | Cross-tenant data leakage / IDOR | `app/api/deps.py`, `app/models/project.py` | All queries strictly filter by `project_id`. Unauthorized requests receive HTTP 404. | `test_projects_isolation.py` |
| **SEC-02** | Dual-Key Authorization | Unauthorized critical operations | `app/api/deps.py`, `app/core/security.py` | Destructive operations (purge, scan launch, model approval) mandate Lead role authorization. | `test_auth.py`, `test_phase6b1_security_audit.py` |
| **SEC-03** | Scope Exclusion Precedence | Scope boundary violation / SSRF | `app/services/scope_engine.py` | Exclusions strictly override inclusions. Subnets, IPs, and hostnames match deterministically. | `test_scope_engine.py` (5 tests) |
| **SEC-04** | Fail-Closed Preflight Boundary | Race condition scope expansion | `app/services/assessment_engine.py` | Targets re-validated against current scope snapshot at execution time; aborts if invalid. | `test_phase6a_execution_boundary.py` (16 tests) |
| **SEC-05** | Win32 Job Object Sandbox | Memory exhaustion / Fork bomb / Process escape | `app/services/subprocess_worker_runner.py` | Memory ceiling clamped to 512 MB; `KILL_ON_JOB_CLOSE` destroys all child processes. | `test_phase7a_worker_isolation.py` (8 tests) |
| **SEC-06** | Bounded Stdio IPC | Buffer overflow / JSON memory DoS | `app/worker/process_worker.py` | Stdio output clamped to 10 MB total; findings capped at 50 per execution; multibyte safe truncation. | `test_phase7a1_security_review.py` (5 tests) |
| **SEC-07** | Restricted Scanner Invariant | Unauthorized active exploitation | `app/services/scanner_adapters/` | `is_simulated = True` strictly enforced; pure-Python passive adapters only. | `test_phase7b_scanner_framework.py` (9 tests) |
| **SEC-08** | Scanner Readiness Gate | Command injection / Path traversal | `app/services/assessment_engine.py` | 8-stage readiness gate validates binary paths, argument whitelists, and target reachability. | `test_phase7b1_readiness_audit.py` (6 tests) |
| **SEC-09** | Byte-Level Evidence Hashing | Evidence tampering / Evidence fabrication | `app/services/integrity_service.py` | Every evidence item computed with byte-level SHA-256 digest (`evidence_hash`) at insertion time. | `test_phase8_evidence_integrity.py` (9 tests) |
| **SEC-10** | Monotonic Audit Hash Chaining | Audit ledger modification / Deletion | `app/services/integrity_service.py`, `app/models/audit.py` | Monotonic sequence IDs; each event embeds SHA-256 digest of previous event (`prev_entry_hash`). | `test_phase8_evidence_integrity.py` |
| **SEC-11** | Binary Merkle Tree Proofs | Selective audit tampering | `app/services/integrity_service.py` | Merkle tree generation over audit records; individual inclusion proofs verified against root hash. | `test_phase8_evidence_integrity.py` |
| **SEC-12** | External Trust Anchor | Whole-database rollback / DBA tampering | `app/services/integrity_service.py` | `AppendOnlyArchiveTrustAnchor` with out-of-band persistent sequencing, key rotation, and rollback detection. | `test_phase8_evidence_integrity.py` |
| **SEC-13** | CSV Formula Injection Defense | Spreadsheet code execution (CWE-1236) | `app/services/report_service.py` | Auto-prepends single quote (`'`) to cells beginning with `=`, `+`, `-`, `@`. | `test_phase15_reporting_and_export.py` |
| **SEC-14** | HTML Output Sanitization | Stored XSS in reports | `app/services/report_service.py` | Jinja2 autoescaping and `html.escape()` enforced across all generated reports. | `test_phase15_reporting_and_export.py` |
| **SEC-15** | AI Prompt Injection Quarantine | LLM manipulation / Jailbreak | `app/services/ai_analyst_service.py` | Strict XML tag wrapping, delimiter stripping, grounded citations, advisory-only outputs. | `test_phase18_ai_analyst.py` (5 tests) |
| **SEC-16** | Controlled Model Governance | Model poisoning / Unauthorized self-modification | `app/services/learning_service.py` | Privacy sanitization, Train/Val/Test splits, human approval gate, atomic rollback to previous model. | `test_phase19_learning_governance.py` (7 tests) |
| **SEC-17** | Persistent Prediction Ledger | Epistemic bias / Unmonitored drift | `app/services/learning_service.py` | Immutable feature snapshots, asynchronous outcome evaluation, Brier calibration score, drift alert. | `test_phase19_learning_governance.py` |
| **SEC-18** | Morph-State Emergency Kill Switch | Runaway automated execution | `app/services/adaptive_defense_service.py` | Instantaneous emergency kill switch pauses all scans and workers; immutable audit record. | `test_phase20_adaptive_defense.py` (5 tests) |
| **SEC-19** | OWASP Security Headers | Clickjacking, MIME sniffing, XSS | `app/main.py` | Enforces `CSP`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `HSTS`. | `test_phase25_deployment_hardening.py` |
| **SEC-20** | API Cache Disablement | Sensitive data browser caching | `app/main.py` | Sets `Cache-Control: no-store, no-cache, must-revalidate, private` on all API responses. | `test_phase25_deployment_hardening.py` |
| **SEC-21** | Production Secret Key Policy | Weak credentials / Session forgery | `app/main.py`, `app/core/security.py` | Fail-closed check: aborts startup in production if `SECRET_KEY` is weak, default, or $< 32$ chars. | `test_phase25_deployment_hardening.py` |
| **SEC-22** | Webhook HMAC-SHA256 Signing | Webhook tampering / Replay attacks | `app/services/integrations/webhook_notifier.py` | Computes HMAC-SHA256 over timestamp + payload; verifies signature in `X-VAPT-Signature`. | `test_integrations.py` (4 tests) |
| **SEC-23** | SIEM Log Sanitization | Credential leakage in SIEM logs | `app/services/integrations/siem_exporter.py` | Scans and redacts passwords, tokens, and authorization headers in CEF and Syslog exports. | `test_integrations.py` |
| **SEC-24** | Right-to-Erasure Data Purge | Residual data retention after tenant teardown | `app/services/backup_service.py` | Cascading foreign key deletion across all child tables; vacuum database teardown. | `test_phase24_backup_recovery.py` |

---

## 3. Defense-in-Depth Verification Status

All 24 security controls documented above are backed by automated tests in the test suite. Across the full regression suite, **100% of security controls pass with exit code 0**.
