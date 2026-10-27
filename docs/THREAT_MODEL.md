# VAPT Platform — Comprehensive Threat Model & Defense Matrix

## 1. Scope & Objective

The VAPT Platform provides vulnerability assessment orchestration, knowledge graph modeling, attack path discovery, and automated remediation tracking. Given that it aggregates vulnerability findings, asset network topology, and execution credentials, it constitutes a tier-1 critical security system.

This threat model documents all identified threat vectors across the entire platform lifecycle using the **STRIDE** methodology, mapping each threat to its architectural defensive controls and test verifications.

---

## 2. Platform Attack Surface Architecture

```
                                  [ External Untrusted Inputs ]
                                                │
                                  ┌─────────────┴─────────────┐
                                  │   Target Names / CIDRs    │
                                  │   Raw Scanner Payloads    │
                                  │   Adversarial HTTP Data   │
                                  └─────────────┬─────────────┘
                                                │
[ Authenticated User / API ] ─────────► [ FastAPI Control Plane ]
                                                │
                                       ┌────────┴────────┐
                                       │  Scope Engine   │
                                       │  Audit Ledger   │
                                       │  Risk Engine    │
                                       └────────┬────────┘
                                                │
                              [ Ephemeral IPC Pipe (stdin/stdout) ]
                                                │
                                                ▼
                                    [ Isolated Windows Worker ]
                                       - Job Object Sandbox
                                       - Pure Python Adapters
                                       - No Live Network Sockets
```

---

## 3. STRIDE Threat Analysis Matrix

| Threat Category | Attack Vector / Scenario | Platform Architectural Mitigation | Verification Test |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Adversary forges JWT bearer token or impersonates a Security Lead to authorize out-of-scope targets. | 1. Constant-time token verification with HMAC-SHA256.<br>2. Short-lived tokens (30 min default).<br>3. Strict dual-key authorization: actor ID cannot match lead authorizer ID. | `test_auth.py`<br>`test_phase26_final_security_assessment.py` |
| **Tampering** | Operator injects CIDR trickery (`10.0.0.0/8` vs `10.0.1.1/32`) to bypass scope exclusions. | 1. Canonical normalization of all targets (`ScopeEngine.normalize_target`).<br>2. Exclusions strictly preempt inclusions unconditionally.<br>3. IPv4/IPv6 address boundary parsing via Python standard `ipaddress`. | `test_scope_engine.py`<br>`test_scope_api_lifecycle.py` |
| **Tampering** | Rogue DBA or compromised worker alters historical audit events or finding severity in the database. | 1. SHA-256 cryptographic hash chaining (`prev_event_hash -> event_hash`).<br>2. Binary Merkle tree evidence proofs.<br>3. External trust anchor verification (`IntegrityService.anchor_audit_ledger`). | `test_phase8_evidence_integrity.py` |
| **Repudiation** | Lead authorizes sensitive target scan and later denies issuing the authorization. | 1. Mandatory immutable `authorization_evidence` field.<br>2. Dual-key authorization records actor and authorizer UUIDs.<br>3. Non-bypassable audit logging (`AUDIT_LOG_STRICT = True`). | `test_audit_ledger.py`<br>`test_assessment_api.py` |
| **Information Disclosure** | Operator from Project Alpha enumerates or accesses findings and asset graphs belonging to Project Beta. | 1. Server-side isolation dependency `verify_project_access`.<br>2. Fails closed with `404 Not Found` (zero timing or metadata disclosure).<br>3. Cross-project graph isolation enforced in SQL queries. | `test_projects_isolation.py`<br>`test_phase10_knowledge_graph.py` |
| **Information Disclosure** | Sensitive secrets, passwords, or bearer tokens leak into system logs or exported manifests. | 1. Recursive scrubbing in `AuditService` (`SENSITIVE_KEYS` redaction).<br>2. Pydantic response models omit secret and hash fields.<br>3. Clean environment isolation when spawning worker processes. | `test_phase4_security_audit.py`<br>`test_phase24_backup_recovery.py` |
| **Denial of Service** | Malicious actor dispatches thousands of concurrent scans or submits cyclic graphs to crash the engine. | 1. Request rate limiting & resource backpressure (HTTP 429).<br>2. Bounded pagination on all list endpoints (`limit <= 100`).<br>3. Graph cycle detection and maximum hop limits ($k \le 6$) in attack path discovery. | `test_phase23_performance_resilience.py`<br>`test_phase12_attack_path_analysis.py` |
| **Denial of Service** | Rogue worker process allocates excessive memory or enters infinite execution loop. | 1. Windows Job Object memory ceiling (512 MB per worker).<br>2. Hard execution timeout (180s) enforced by worker runner.<br>3. `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` ensures child processes terminate cleanly. | `test_phase7a_worker_isolation.py`<br>`test_phase7b_scanner_framework.py` |
| **Elevation of Privilege** | Standard `SECURITY_TESTER` executes Lead-only operations (model approval, project purge, target authorization). | 1. Server-side role checks (`ProjectRole.LEAD` / `ProjectRole.OWNER`).<br>2. Preflight dispatch gates strictly reject non-lead authorizations. | `test_scope_api_lifecycle.py`<br>`test_phase13_remediation_governance.py` |
| **Injection (AI)** | Malicious target banner contains adversarial prompt injection to hijack AI Security Analyst. | 1. Input sanitization with HTML-escaping.<br>2. Prompt injection signature detector quarantining adversarial inputs.<br>3. Grounded citation validation ensuring AI outputs reference verified finding IDs. | `test_phase18_ai_analyst.py` |
| **Poisoning (ML)** | Adversary poisons training datasets with mislabeled findings to degrade model accuracy. | 1. Curation splits (train/val/test) with SHA-256 dataset fingerprinting.<br>2. Minimum empirical threshold gates (Precision >= 0.60, Recall >= 0.60).<br>3. Atomic rollback to previous approved model artifact. | `test_phase19_learning_governance.py` |

---

## 4. Bounded Scanner Invariants (Defensive Release Safeguard)

The platform strictly enforces the following non-negotiable operational safeguards:
1. **No Live Network Scanning**: Scanner adapters run purely in deterministic simulation mode (`is_simulated = True`).
2. **No Raw Sockets**: Scanner workers do not create raw TCP/UDP sockets or send malicious packets over physical networks.
3. **No Active Exploitation**: The platform never delivers offensive payloads or attempts credential stuffing against external systems.
4. **Deterministic Synthetic Fixtures**: All testing and demonstration data is generated deterministically within isolated environments.

---

## 5. Security Gate Auditing & Incident Response

In the event of an anomaly or security boundary breach:
- The system automatically triggers the **Morph-State Adaptive Defense** engine.
- Engaging the **Emergency Kill-Switch** terminates all active worker processes within 500ms.
- All administrative, operator, and automated actions are logged to the cryptographic audit ledger for post-incident forensic analysis.
