# VAPT SYSTEM — TRUST-BOUNDARY THREAT MODEL
## Comprehensive Architectural Threat Analysis, Trust Boundaries, and Prioritized Threat Register (Prompt 14)

---

## 1. Executive Summary & Methodology

The **VAPT Defensive Security Platform** operates under a Zero-Trust Architecture (ZTA) wherein no subsystem, worker, user, or target is inherently trusted. Every cross-subsystem interaction crosses an explicit trust boundary where identity, authorization, data sanity, and cryptographic integrity are re-verified at execution time.

This threat model applies STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) across all 13 major platform boundaries, documents assets and trust assumptions, details preventive and detective controls, and maintains an evidence-backed Threat Register distinguishing confirmed vulnerabilities from theoretical risks.

---

## 2. Comprehensive Trust Boundary Analysis

```
                                  UNTRUSTED NETWORK / TARGETS
                                               |
                                               v (Boundary 6: Passive Adapters)
+-----------------------------------------------------------------------------------------------------+
| WORKER EXECUTION ENCLAVE (Boundary 5: Win32 Job Object, Subprocess IPC)                             |
|  - Process Worker (PID isolation, Memory Clamped, No Child Procs)                                  |
+-----------------------------------------------------------------------------------------------------+
                                               |
                                               v (Boundary 7: Clamped JSON IPC, Authoritative Hashing)
+-----------------------------------------------------------------------------------------------------+
| CONTROL PLANE APPLICATION ENGINE                                                                    |
|  - Boundary 1: Frontend <-> FastAPI Gateway                                                        |
|  - Boundary 2: RBAC & Dual-Key Authorization                                                        |
|  - Boundary 3: Tenant & Project Boundary (Fail-Closed)                                              |
|  - Boundary 4: Scope & Exclusions Engine (Preflight & Execution Revalidation)                       |
|  - Boundary 8: Finding Normalization & Knowledge Graph                                              |
|  - Boundary 9: Contextual Risk & Attack-Path Synthesizer                                            |
|  - Boundary 10: AI Analyst & Governed Learning Gates                                                |
|  - Boundary 11: Remediation Approval & Retest Verification                                          |
|  - Boundary 12: Self-Diagnostics & Controlled Bounded Recovery                                      |
+-----------------------------------------------------------------------------------------------------+
                                               |
                                               v (Boundary 13: Cryptographic Integrity)
+-----------------------------------------------------------------------------------------------------+
| PERSISTENCE & AUDIT LEDGER                                                                          |
|  - Merkle Evidence Trees, Monotonic Audit Hash Chain, Encrypted Backups                             |
+-----------------------------------------------------------------------------------------------------+
```

---

### Boundary 1: Frontend $\leftrightarrow$ Control Plane API
- **Assets Requiring Protection:** Sensitive findings, executive reports, scope definitions, authentication credentials, project metadata.
- **Trust Assumptions:** The browser environment is untrusted. Client-side state, local storage, and request headers can be modified or spoofed by operators or browser extensions.
- **Entry Points & Untrusted Inputs:** REST API request payloads, query parameters, multipart form data, OAuth Bearer tokens, HTTP headers (`X-Forwarded-For`).
- **Potential Attack Paths:**
  - Direct API submission bypassing disabled UI controls.
  - Cross-Site Scripting (XSS) via reflected finding titles/descriptions.
  - Client-side token leakage or session hijacking.
- **Preventive & Detective Controls:**
  - Authoritative server-side validation for all state transitions and inputs.
  - Content-Security-Policy headers, strict JSON API serialization, HTML-escaping on render.
  - JWT token validation with cryptographic signatures and expiration bounds.
- **Failure Consequences:** Unauthorized actions executed if backend relies on frontend validation.
- **Automated Verification:** `test_ui_and_contract_regressions.py`, `operations_and_workflows.test.ts`.

---

### Boundary 2: Authentication & Role-Based Authorization (RBAC)
- **Assets Requiring Protection:** User credentials, password hashes, JWT signing keys, system role permissions (`ADMIN`, `SECURITY_LEAD`, `SECURITY_TESTER`, `AUDITOR`, `VIEWER`).
- **Trust Assumptions:** Any client request can claim arbitrary roles; claims must be cryptographically validated against server-side session/user records.
- **Entry Points & Untrusted Inputs:** `/api/v1/auth/login`, OAuth2 Password flow, Authorization Bearer headers.
- **Potential Attack Paths:**
  - Token forging or replay attacks.
  - Privilege escalation from `VIEWER` to `LEAD` via state mutation endpoints.
  - Brute-force credential guessing.
- **Preventive & Detective Controls:**
  - PBKDF2/bcrypt-hashed credentials with salts.
  - Cryptographic JWT signature verification (`HS256`, minimum 16-byte `SECRET_KEY`).
  - Method-level and service-level RBAC enforcement (`require_system_roles`, `_validate_transition_rules`).
  - Read-only `VIEWER` lockout from all state mutation operations.
- **Failure Consequences:** Unauthorized configuration changes, unauthorized finding risk acceptance.
- **Automated Verification:** `test_auth.py`, `test_prompt14_adversarial_validation_and_zero_trust.py::test_adv_03`.

---

### Boundary 3: Tenant & Project Boundaries (Multi-Tenancy)
- **Assets Requiring Protection:** Isolated project findings, scope rules, graph vertices, audit records, reports across competing tenants.
- **Trust Assumptions:** Organizations and projects must be strictly isolated. Project members cannot view or modify resources outside their enrolled projects.
- **Entry Points & Untrusted Inputs:** URL path parameters (`{project_id}`), body references (`project_id`), entity UUIDs.
- **Potential Attack Paths:**
  - Insecure Direct Object Reference (IDOR) to access another project's findings.
  - Cross-tenant citation injection in AI Analyst workflows.
  - Probing non-member project IDs to enumerate organizational structures.
- **Preventive & Detective Controls:**
  - `verify_project_access` dependency checks project membership; non-members receive **HTTP 404** (failing closed to avoid leaking project existence).
  - SQL queries explicitly filter by `project_id == project_id`.
  - Citation engine enforces foreign key joins to verify evidence belongs to the caller's project.
- **Failure Consequences:** Cross-tenant confidentiality breach, regulatory non-compliance.
- **Automated Verification:** `test_projects_isolation.py`, `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_10`, `test_adv_06`.

---

### Boundary 4: Scope Authorization & Exclusions Engine
- **Assets Requiring Protection:** Out-of-scope targets, third-party infrastructure, production databases excluded by policy.
- **Trust Assumptions:** Target definitions submitted by operators cannot be scanned until independently authorized by a Lead or Admin. Scope rules can change while jobs are queued.
- **Entry Points & Untrusted Inputs:** Target registration (`POST /targets`), exclusion registration (`POST /exclusions`).
- **Potential Attack Paths:**
  - Scanning unauthorized IP ranges via race conditions between job creation and execution.
  - Adding emergency exclusion that fails to stop queued or retrying jobs.
  - IP obfuscation (hex, dword, octal, IPv4-mapped IPv6) to evade CIDR exclusion matching.
- **Preventive & Detective Controls:**
  - Dual-key authorization requirement: targets in `PENDING` fail closed.
  - Scope exclusion precedence: exclusions evaluated *before* inclusions.
  - Execution-time preflight re-validation in `preflight_and_claim_job` and `retry_job`.
  - Canonical IP normalization (`normalize_and_detect_ip`) before scope evaluation.
- **Failure Consequences:** Unlawful scanning of unapproved networks or disruption of critical excluded systems.
- **Automated Verification:** `test_scope_engine.py`, `test_adv_01`, `test_adv_02`, `test_adv_07`.

---

### Boundary 5: Assessment Scheduler & Background Workers
- **Assets Requiring Protection:** Host OS resources, host filesystem, background execution slots, IPC channels.
- **Trust Assumptions:** Scanner adapter code could contain bugs, hang, crash, or attempt to spawn malicious child processes.
- **Entry Points & Untrusted Inputs:** Worker stdin/stdout IPC streams, adapter configuration dictionaries.
- **Potential Attack Paths:**
  - Worker process consuming all host RAM (OOM DoS).
  - Worker hanging indefinitely, starving the job queue.
  - Worker spoofing response messages (`job_id`, `project_id`, `attempt_count`).
- **Preventive & Detective Controls:**
  - Windows Win32 Job Object confinement (512MB RAM limit, sub-process creation forbidden).
  - Hard timeouts with forced process tree termination (`terminate_process_tree`).
  - Strict IPC payload size clamp (`WORKER_MAX_IPC_PAYLOAD_BYTES = 10MB`).
  - Worker message identity and provenance validation (rejecting mismatched IDs with `IPC_IDENTITY_MISMATCH`).
- **Failure Consequences:** Host crash, deadlocked assessment pipelines, state corruption.
- **Automated Verification:** `test_phase7a_worker_isolation.py`, `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_2`, `test_scenario_3`.

---

### Boundary 6: Scanner Adapters & External Target Connections
- **Assets Requiring Protection:** Internal cloud metadata (`169.254.169.254`), loopback services (`127.0.0.1`), internal corporate LAN (RFC 1918).
- **Trust Assumptions:** External target servers are completely untrusted and potentially adversarial. They may return malicious redirects, slow responses, or DNS rebinding responses.
- **Entry Points & Untrusted Inputs:** HTTP response headers, TLS certificates, robots.txt, RFC 9116 security.txt, redirect Location headers.
- **Potential Attack Paths:**
  - Server-Side Request Forgery (SSRF) targeting cloud metadata.
  - DNS Rebinding (TOCTOU between preflight check and socket connection).
  - Open redirect pivoting to unauthorized external domains or internal loopbacks.
  - Protocol smuggling via alternative schemes (`file://`, `gopher://`, `ftp://`).
- **Preventive & Detective Controls:**
  - Pre-connection SSRF filter unwrapping IPv4-mapped IPv6, CGNAT, and link-local.
  - Socket Pinning: TCP socket connected directly to pre-verified IP (`self.verified_ip`).
  - Strict TLS SNI preservation and certificate hostname verification.
  - `BoundedRedirectHandler`: Per-hop re-validation, scheme restriction (HTTP/HTTPS only), credential rejection, and dynamic per-hop socket pinning.
  - Prohibition of port sweeps, brute forcing, DoS, and exploit delivery.
- **Failure Consequences:** Cloud infrastructure credential theft, pivot to internal networks.
- **Automated Verification:** `test_live_network_adapter.py`, `test_adv_07`, `test_adv_08`, `test_adv_09`.

---

### Boundary 7: Evidence Collection, Clamping & Persistence
- **Assets Requiring Protection:** Raw evidence payload store, cryptographic audit trail.
- **Trust Assumptions:** Untrusted workers or target responses might return oversized payloads, invalid hashes, or corrupted JSON.
- **Entry Points & Untrusted Inputs:** `WorkerIPCResponse.findings.evidence_items`.
- **Potential Attack Paths:**
  - Worker submitting forged SHA-256 digests that do not match the payload.
  - Oversized payloads exhausting database storage.
  - Missing evidence rows causing false-positive verification passes.
- **Preventive & Detective Controls:**
  - Authoritative control plane hashing: SHA-256 computed server-side on ingestion.
  - 1MB evidence payload clamp (`MAX_EVIDENCE_PAYLOAD_BYTES`) with dual-hash tracking.
  - Missing evidence detection in `verify_evidence_integrity` (flags missing rows as invalid).
- **Failure Consequences:** Unverifiable findings, corrupted evidentiary chain of custody.
- **Automated Verification:** `test_phase8_evidence_integrity.py`, `test_adv_10`, `test_adv_11`.

---

### Boundary 8: Finding Normalization & Knowledge Graph
- **Assets Requiring Protection:** Canonical vulnerability findings, Knowledge Graph topology.
- **Trust Assumptions:** Raw tool outputs may contain duplicate findings, contradictory observations, or cyclic relationships.
- **Entry Points & Untrusted Inputs:** Raw findings from scanner adapters, manual relationship assertions.
- **Potential Attack Paths:**
  - Cyclic relationship assertions causing infinite recursion during graph traversal.
  - Contradictory evidence causing silent data overwrites.
- **Preventive & Detective Controls:**
  - Composite deduplication fingerprinting: `(project_id, target, vuln_id/title)`.
  - Epistemic Knowledge Graph: Contradictions preserved with `has_contradictions = True` and confidence discounts.
  - Cycle-safe BFS traversal with bounded depth ($\le 4$) and node limits.
- **Failure Consequences:** Graph traversal crash, inaccurate exposure modeling.
- **Automated Verification:** `test_knowledge_graph.py`, `test_finding_deduplication.py`, `test_adv_12`.

---

### Boundary 9: Contextual Risk & Attack-Path Synthesis Engines
- **Assets Requiring Protection:** Contextual risk scores, chokepoint prioritizations, attack paths.
- **Trust Assumptions:** Risk formulas must be strictly deterministic and grounded in technical facts.
- **Entry Points & Untrusted Inputs:** Asset attributes, finding severities, graph edges.
- **Potential Attack Paths:**
  - Non-deterministic risk scores leading to erratic prioritization.
  - Presenting hypothetical topological paths as verified exploitability.
- **Preventive & Detective Controls:**
  - Pure deterministic risk calculation v2.0.0 (identical inputs produce identical scores).
  - Explicit empirical uncertainty margin ($\pm \Delta$) capturing data freshness and completeness.
  - Epistemic categorization of attack paths (`CONFIRMED`, `HYPOTHETICAL`, `STALE`).
- **Failure Consequences:** Misallocated security resources, false sense of security.
- **Automated Verification:** `test_phase11_contextual_risk.py`, `test_phase12_attack_path_analysis.py`, `test_adv_13`.

---

### Boundary 10: AI Analyst & Governed Learning Pipeline
- **Assets Requiring Protection:** Machine learning classifiers, advisory remediation drafts, training datasets.
- **Trust Assumptions:** LLMs and ML models are non-authoritative advisory systems. External target content may contain prompt injection attempts.
- **Entry Points & Untrusted Inputs:** Scanner output strings, target HTTP bodies, operator training requests.
- **Potential Attack Paths:**
  - Target-controlled prompt injection forcing AI to recommend closing real vulnerabilities.
  - Unverified findings poisoning ML training labels.
  - Degrading model updates deployed without human review.
- **Preventive & Detective Controls:**
  - Input sanitization and quarantine (`sanitize_untrusted_input` flags `INJECTION_TRIGGER` and HTML-escapes).
  - AI outputs restricted to advisory drafts (`AIDraftStatus.DRAFT`), requiring human lead review.
  - Quality gates: Held-out test split evaluation (Precision/Recall $\ge 0.60$) and human sign-off before deployment.
  - Unverified findings (`DETECTED`, `INCONCLUSIVE`) strictly excluded from training labels.
- **Failure Consequences:** Compromised guidance, poisoned automated triage models.
- **Automated Verification:** `test_phase18_ai_analyst.py`, `test_phase19_learning_governance.py`, `test_adv_14`.

---

### Boundary 11: Remediation Governance & Independent Verification
- **Assets Requiring Protection:** Finding closure state, remediation change authorizations.
- **Trust Assumptions:** Remediation cannot be claimed without independent verification. Advisory guidance must not execute destructive changes.
- **Entry Points & Untrusted Inputs:** Remediation review requests, automated retest triggers.
- **Potential Attack Paths:**
  - Testers or viewers approving their own remediations.
  - Prematurely closing findings with `INCONCLUSIVE` retest results.
  - Bypassing change ticket requirements.
- **Preventive & Detective Controls:**
  - Gated state machine: `REMEDIATION_PROPOSED` $\to$ `REMEDIATION_APPROVED` (Lead/Admin only) $\to$ `REMEDIATION_ATTEMPTED` $\to$ `VERIFIED_CLOSED`.
  - Independent retest outcome space (`VERIFIED_FIXED`, `STILL_VULNERABLE`, `PARTIALLY_REMEDIATED`, `INCONCLUSIVE`); `INCONCLUSIVE` strictly blocked from closing findings.
  - Mandatory external change ticket reference ($\ge 3$ chars).
- **Failure Consequences:** Unremediated vulnerabilities closed falsely in production.
- **Automated Verification:** `test_phase14_remediation_verification.py`, `test_adv_04`, `test_adv_05`.

---

### Boundary 12: Monitoring, Self-Diagnostics & Controlled Recovery
- **Assets Requiring Protection:** System health status, diagnostic records, recovery actuation.
- **Trust Assumptions:** Diagnostic checks are read-only. Recovery actions must be bounded, idempotent, and verify post-conditions.
- **Entry Points & Untrusted Inputs:** `/api/v1/diagnostics/run`, `/api/v1/diagnostics/recover`.
- **Potential Attack Paths:**
  - Recovery action reusing stale authorization to scan unauthorized targets.
  - Recovery mutating entities in terminal states (`COMPLETED`, `CANCELLED`).
  - Diagnostic responses leaking database credentials or API secrets.
- **Preventive & Detective Controls:**
  - Two-phase pre/post condition comparison: Unmet preconditions yield `INCONCLUSIVE` without record mutation.
  - Scope and policy re-validation inside `RETRY_ASSESSMENT` recovery action.
  - Zero-secret reporting: Health engine inspects secret presence/length without exporting keys.
- **Failure Consequences:** System destabilization, unauthorized job dispatching.
- **Automated Verification:** `test_prompt12_self_diagnostics_and_recovery.py`, `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_8`.

---

### Boundary 13: Audit Ledger, Backups & Release Artifacts
- **Assets Requiring Protection:** Monotonic audit trail, database backups, clean release zip.
- **Trust Assumptions:** Application users cannot alter past audit logs. Backups must be verifiable before restore.
- **Entry Points & Untrusted Inputs:** Audit log calls, backup restore archives, package build scripts.
- **Potential Attack Paths:**
  - Concurrent audit writes breaking the Merkle hash chain.
  - Restoring a corrupted or backdoored backup archive.
  - Secret leakage into clean release packages.
- **Preventive & Detective Controls:**
  - Thread-safe monotonic audit chaining (`_chain_lock` and microsecond adjustments).
  - Sandbox backup restore verification with hash validation.
  - Automated release packager audits (0 secrets, 0 banned paths).
- **Failure Consequences:** Unprovable forensic history, leaked keys in distribution bundles.
- **Automated Verification:** `test_audit_ledger.py`, `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_9`, `test_scenario_13`.

---

## 3. Prioritized Threat Register

The following register ranks all confirmed vulnerabilities and theoretical architectural risks identified during Prompt 14 analysis.

| Threat ID | Severity | Category | Affected Boundary | Description & Impact | Confirmed / Theoretical | Status & Mitigation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **THR-001** | **High** | SSRF / Evasion | Boundary 6 | Alternative numeric IP formats (hex `0x7f000001`, dword, octal) bypass standard regex IP parsing. | **Confirmed** (Fixed) | Implemented `normalize_and_detect_ip` before DNS resolution. Tested in `test_adv_07`. |
| **THR-002** | **High** | Authorization | Boundary 4 | Failed assessment jobs could be retried after target scope authorization was revoked. | **Confirmed** (Fixed) | Added execution-time scope validation in `AssessmentExecutionEngine.retry_job`. Tested in `test_adv_01`. |
| **THR-003** | **Medium** | Multi-Tenancy | Boundary 10 | AI Analyst citation validation accepted evidence IDs from foreign projects. | **Confirmed** (Fixed) | Enforced foreign key join `AssessmentFinding.project_id == project_id` in `validate_citations`. Tested in `test_adv_06`. |
| **THR-004** | **Medium** | RBAC / Governance | Boundary 11 | `REMEDIATION_APPROVED` lacked explicit Lead/Admin role check, allowing testers/viewers to approve. | **Confirmed** (Fixed) | Enforced `is_lead_or_admin` in `_validate_transition_rules` and blocked `VIEWER`. Tested in `test_adv_03`, `test_adv_04`. |
| **THR-005** | **Medium** | Cryptography | Boundary 7 | Evidence integrity check reported `is_valid: True` when all evidence rows were deleted. | **Confirmed** (Fixed) | Enforced expected evidence count cross-check against `job.summary_stats`. Tested in `test_adv_10`. |
| **THR-006** | **Medium** | SSRF / TOCTOU | Boundary 6 | Redirects across subdomains retained initial hop IP rather than pinning to redirect IP. | **Confirmed** (Fixed) | `BoundedRedirectHandler` dynamically attaches per-hop `_verified_ip` to requests. Tested in `test_adv_09`. |
| **THR-007** | **Medium** | Cryptography | Boundary 13 | Database superuser can recompute forward audit hash chain after modifying records. | **Theoretical** (Residual) | Documented cryptographic limit; requires external RFC 3161 TSA or WORM storage for root trust. |
| **THR-008** | **Low** | Concurrency | Boundary 1 | Concurrent UI transitions on findings could overwrite intermediate states. | **Confirmed** (Fixed in P13) | Enforced optimistic concurrency control with HTTP 409 Conflict. |
| **THR-009** | **Low** | AI Prompt Injection| Boundary 10 | Scanner or target outputs attempting to override prompt instructions. | **Confirmed** (Fixed) | Quarantined via `sanitize_untrusted_input`, HTML-escaped, and advisory output isolated. Tested in `test_adv_14`. |
