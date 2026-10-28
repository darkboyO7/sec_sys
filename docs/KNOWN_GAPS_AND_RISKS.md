# VAPT SYSTEM — KNOWN GAPS AND RESIDUAL RISKS
## Architecture Limitations, Threat Boundaries, and Prioritized Risk Register (Prompt 13)

---

## 1. Executive Summary

This document provides a transparent, evidence-based inventory of the confirmed technical limitations, threat boundaries, and architectural trade-offs inherent in the current implementation of the **VAPT Defensive Security Platform** following Prompt 13 validation.

The purpose of this register is not to diminish the documented capabilities of the system, but to establish explicit boundaries around what the platform provably guarantees, identify where environmental or cryptographic assumptions apply, and provide a prioritized roadmap for enterprise production hardening.

---

## 2. Threat Model Boundaries & Cryptographic Trust Assumptions

### 2.1 Audit Hash Chain vs. Host/Database Superuser Compromise
- **Enforced Guarantee:** The Merkle audit ledger (`AuditEvent.prev_event_hash -> event_hash`) provides strong tamper-evident guarantees against application users, unprivileged attackers, and compromised web sessions. Any unauthorized modification, deletion, or backdated insertion of audit records by an application actor is immediately detected by `IntegrityService.verify_audit_ledger_integrity`.
- **Threat Boundary & Limitation:** The audit ledger is currently stored within the relational database (`vapt.db` in SQLite or PostgreSQL). An attacker who obtains root operating system access or database superuser (`postgres` / direct filesystem write) privileges can modify historical records and mathematically recompute the forward SHA-256 hash chain from the point of modification onward.
- **Enterprise Requirement for True Non-Repudiation:** Total mitigation against database superuser tampering requires anchoring periodic block digests ($M_{\text{root}}$) to an external out-of-band trust anchor, such as:
  1. An RFC 3161 compliant cryptographic Time-Stamping Authority (TSA).
  2. Write-Once-Read-Many (WORM) cloud object storage (e.g., AWS S3 Object Lock in Compliance Mode or Google Cloud Storage Bucket Lock).
  3. A public or permissioned transparency ledger (e.g., Sigstore Rekor).

### 2.2 Evidence Merkle Trees & Cold Storage
- **Enforced Guarantee:** All raw evidence items persisted for an assessment job are SHA-256 hashed and aggregated into a balanced binary Merkle tree. Corrupted or mutated evidence is pinpointed immediately.
- **Threat Boundary & Limitation:** Large binary artifacts exceeding the 1MB inline clamping limit (`MAX_EVIDENCE_PAYLOAD_BYTES`) are truncated in the primary database with an inline notice. While the original un-truncated stream hash is stored in `raw_sha256_hash`, the full payload is not automatically mirrored to persistent external object storage (e.g., S3/GCS) in the local development profile.

---

## 3. Epistemic Model & Methodology Disambiguations

### 3.1 Empirical Uncertainty Margin vs. Stochastic Confidence Intervals
- **Enforced Guarantee:** The contextual risk engine (`ContextualRiskService` v2.0.0) calculates an uncertainty margin ($\Delta$) alongside inherent and residual risk scores ($\text{score} \pm \Delta$).
- **Methodology Clarification:** This margin is an **empirical heuristic uncertainty metric** reflecting data completeness, finding confidence scores, conflicting asset observations, and evidence staleness. It is **not** a frequentist or parametric Gaussian 95% confidence interval ($Z \cdot \sigma / \sqrt{n}$) over stochastic security breach occurrences. The platform computes risk deterministically based on observed technical factors; it does not model speculative probabilistic zero-day frequency distributions.

### 3.2 Topological Exposure vs. Confirmed Exploitability
- **Enforced Guarantee:** The attack path analysis engine (`AttackPathAnalysisService`) searches the Universal Security Knowledge Graph to uncover multi-hop exposure paths connecting external network perimeters to critical assets. Paths are tagged with epistemic states (`CONFIRMED`, `HYPOTHETICAL`, `STALE`).
- **Methodology Clarification:** An identified attack path proves **topological reachability and defensive control absence**; it does not prove automated or weaponized exploitability. The platform strictly prohibits firing live exploits. Reachable paths flagged as `HYPOTHETICAL` require human validation or targeted non-destructive retesting before being treated as actively exploitable vectors.

---

## 4. Platform & Operating Environment Constraints

### 4.1 Operating System Specific Isolation (Win32 vs. POSIX)
- **Current Implementation:** Subprocess worker confinement (`subprocess_worker_runner.py`) uses Windows-native **Win32 Job Objects** (`win32_job_object.py`) to enforce hard memory limits, process termination on exit, and sub-process creation restrictions.
- **Limitation:** In a Linux or macOS containerized deployment, the Win32 API calls are bypassed or replaced with basic process handles. For Linux production deployments, worker confinement must be mapped to Linux `cgroups v2` and systemd transient scopes (`systemd-run`).

### 4.2 Single-Node Concurrency vs. Distributed Scaling
- **Current Implementation:** Concurrency control and state transitions rely on transactional atomic SQL updates (`UPDATE ... WHERE status = 'QUEUED'`) and in-memory process locks (`_chain_lock`).
- **Limitation:** While highly performant for single-node deployments using SQLite WAL mode or local PostgreSQL, multi-node distributed worker clusters require distributed locking (e.g., Redis Redlock or PostgreSQL advisory locks) and centralized job queue brokers (e.g., Celery, RabbitMQ, or Redis Streams) to prevent horizontal worker race conditions.

### 4.3 Network Interceptors and Forward Proxies
- **Current Implementation:** SSRF defense relies on DNS pre-resolution and direct socket pinning (`SafeHTTPConnection.connect` pins to `self.verified_ip`).
- **Limitation:** In corporate enterprise environments requiring outbound HTTP traffic to pass through mandatory forward proxies (e.g., Squid, Zscaler, or BlueCoat) that perform remote DNS resolution, local socket pinning is incompatible. A specialized proxy authentication and certificate trust integration is required for proxied enterprise topologies.

---

## 5. Prioritized Residual Risk Register

The following register categorizes all confirmed residual technical risks by severity, operational impact, and mitigation roadmap.

| Risk ID | Severity | Category | Description | Operational Impact | Current Defensive Mitigation | Target Resolution Phase |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RSK-001** | **Medium** | Cryptography | Database superuser can recompute forward audit hash chain after modifying records. | Complete ledger modification possible under full database compromise. | In-app tampering detected; `IntegrityService` flags broken links. | Integrate external RFC 3161 or WORM S3 Object Lock trust anchor. |
| **RSK-002** | **Medium** | OS Portability | Win32 Job Object isolation is Windows-specific. | Worker resource clamps rely on standard process controls on Linux. | Memory and execution timeouts enforced in Python subprocess runner. | Implement Linux `cgroups v2` worker isolation driver. |
| **RSK-003** | **Low** | Scalability | Multi-worker job claiming relies on single-node DB conditional updates. | Distributed horizontal clustering across multiple hosts not natively coordinated. | Single-instance SQLite/PostgreSQL atomic `WHERE` updates prevent double-claims. | Deploy Redis/Postgres advisory lock distributed worker scheduler. |
| **RSK-004** | **Low** | Enterprise Net | DNS socket pinning incompatible with forward HTTP inspection proxies. | Cannot route scanning through corporate forward proxies handling remote DNS. | Direct outbound socket pinning prevents SSRF/DNS rebinding on direct links. | Add proxy-aware CONNECT tunnel validation profile. |
| **RSK-005** | **Low** | Storage | Evidence payloads exceeding 1MB are truncated without external S3 spillover. | High-volume raw tool outputs (e.g., huge raw logs) are clamped to 1MB. | Dual SHA-256 hashes track both clamped and raw original stream digests. | Implement pluggable S3/GCS blob storage provider for large artifacts. |
| **RSK-006** | **Low** | Scope DNS | Fast-flux or dynamic DNS records could shift IP between preflight checks. | Dynamic DNS changes require periodic re-resolution sweeps. | Single DNS resolution and direct IP socket pinning locks target IP per job. | Implement automated continuous DNS change detection monitoring worker. |

---

## 6. Conclusion & Production Readiness Assessment

The VAPT Defensive Security Platform satisfies all architectural invariants required for single-node and secure-enclave deployments. The residual risks identified above represent standard production scaling and external integration enhancements rather than architectural flaws. All defensive boundaries, scope enforcement rules, Merkle audit verifications, and safety clamps are fully operational, tested, and cryptographically sound.
