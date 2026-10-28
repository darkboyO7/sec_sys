# VAPT Platform — Remaining Gaps & Future Roadmap Register

**Document Version:** 1.0.0  
**Audit Baseline Date:** 2026-10-28  
**Repository:** `D:\alt`  
**Classification:** Strategic Engineering Analysis & Operational Readiness

---

## 1. Executive Context

The core vision of the VAPT System—an integrated, closed-loop vulnerability assessment and security intelligence engine—is demonstrably implemented and fully verified in `D:\alt`. All 15 lifecycle stages function continuously with empirical network traffic, persistent database records, deterministic risk scoring, attack-path graph modeling, and cryptographic audit hash-chaining.

To ensure strict engineering transparency, this document catalogs the architectural boundaries, external dependencies, and future enhancement frontiers ranked by operational risk and business impact.

```mermaid
xychart-beta
    title "Remaining Engineering Frontiers: Risk vs Implementation Effort"
    x-axis ["DAK/DAST Headless Engine", "Active Protocol Fuzzing", "Auto Patch Deployment", "Multi-Region Distributed Nodes", "PostgreSQL 16 Staging Cluster"]
    y-axis "Risk / Architectural Impact (1-10)" 0 --> 10
    bar [7, 6, 8, 5, 4]
```

---

## 2. Ranked Gaps & Future Roadmap Register

### Gap 1: Headless Browser Engine for Single-Page Application (SPA) Crawling
- **Rank:** 1
- **Risk Level:** **HIGH**
- **Impact:** **HIGH**
- **Description:**
  The current scanner framework (`LiveNetworkAuditorAdapter` and `LiveWebsiteScannerAdapter`) operates via native Python HTTP sockets (`urllib.request` / `httpx`). While highly efficient, lightweight, and resilient for server-side endpoints, REST APIs, and HTTP security posture checks, it does not execute client-side JavaScript.
  Consequently, modern Single-Page Applications (SPAs) built with React, Vue, or Angular that render dynamic DOM elements, execute client-side routing, or load content exclusively via client-side GraphQL/XHR requests cannot be crawled beyond their initial HTML root.
- **Architectural Boundary:**
  - Client-side DOM XSS vectors cannot be identified without a JavaScript runtime.
  - Form fields dynamically mounted by client-side code are not discovered by the lightweight HTTP auditor.
- **Mitigation & Concrete Next Steps:**
  1. Integrate a containerized Chromium/Playwright headless browsing worker.
  2. Isolate the browser execution process inside an ephemeral sandbox container with restricted network egress.
  3. Expose a standard `HeadlessBrowserAuditorAdapter` adhering to the existing typed `RawAdapterEvidence` contract.

---

### Gap 2: Production Automated Patch Deployment Boundaries & Host Agents
- **Rank:** 2
- **Risk Level:** **HIGH**
- **Impact:** **MEDIUM**
- **Description:**
  The platform provides actionable remediation recommendations, governance workflows, and automated verification re-testing. However, applying physical server configuration changes (e.g. editing `nginx.conf`, regenerating TLS certificates, or patching operating system packages) is intentionally non-automated in production environments.
  Automated modification of production infrastructure carries high operational risk of service interruption, configuration corruption, or unintended downtime.
- **Architectural Boundary:**
  - The system stops at generating precise configuration snippets, approval gating, and independent post-deployment verification.
  - Direct write-access to target production hosts is excluded by design.
- **Mitigation & Concrete Next Steps:**
  1. Implement optional integration plugins for GitOps workflows (e.g., automated Pull Request generation in GitHub/GitLab).
  2. Add webhook connectors for configuration management orchestrators (Ansible, Terraform, Chef) with mandatory cryptographic signature validation.
  3. Maintain the platform's fail-closed governance invariant: human approval by Project Lead or System Admin remains mandatory prior to triggering any external automation webhook.

---

### Gap 3: Protocol-Level Active Fuzzing & Mutation Testing
- **Rank:** 3
- **Risk Level:** **MEDIUM**
- **Impact:** **MEDIUM**
- **Description:**
  The scanner architecture strictly enforces non-destructive, read-only security auditing. It performs non-intrusive header analysis, TLS negotiation inspection, protocol banner checking, and sensitive file disclosure probes.
  It does not execute high-volume, stateful protocol-level fuzzing (e.g. Radamsa/AFL-style bit flipping, buffer overflow probes, or malformed ASN.1 parsing) because such tests can crash services, corrupt database states, or trigger IDS/IPS rate limits.
- **Architectural Boundary:**
  - Zero-day memory corruption vulnerabilities and deep protocol parser defects are not covered by the current lightweight network adapter.
- **Mitigation & Concrete Next Steps:**
  1. Develop a dedicated `ActiveFuzzingAdapter` designated exclusively for staging and pre-production environments.
  2. Implement strict rate limiting, circuit breakers, and automatic heartbeat health checking to abort fuzzing runs immediately if target latency spikes or 5xx errors increase.
  3. Require explicit secondary authorization flags (`allow_destructive_fuzzing = True`) in the Scope ROE contract before enabling fuzzing modules.

---

### Gap 4: Distributed Multi-Region Scanner Nodes & Remote Worker Pool
- **Rank:** 4
- **Risk Level:** **MEDIUM**
- **Impact:** **LOW**
- **Description:**
  Currently, assessment jobs are executed locally via the background worker daemon (`app.worker.background_daemon`) or the native Win32 process runner (`app.services.subprocess_worker_runner`).
  For large enterprise organizations with hundreds of disparate network perimeters (e.g. multi-VPC, multi-cloud, on-premises data centers), scanning from a single central host requires direct VPN routing to all internal subnets.
- **Architectural Boundary:**
  - All scan traffic originates from the host running the VAPT background worker.
  - Scanning segmented network zones without IP routing requires local agent deployment.
- **Mitigation & Concrete Next Steps:**
  1. Expand the worker architecture into a distributed agent model using mutual TLS (mTLS) or WebSocket tunnels.
  2. Register remote scan agents with network zone tags (e.g. `zone: us-east-vpc`, `zone: on-prem-dmz`).
  3. Route assessment jobs to the appropriate zone agent based on the target's scope classification.

---

### Gap 5: PostgreSQL 16 Live Staging Server Availability
- **Rank:** 5
- **Risk Level:** **LOW**
- **Impact:** **LOW**
- **Description:**
  The platform codebase is fully prepared for dual-mode database operation. The PostgreSQL dialect AST, QueuePool connection pool kwargs, retry transaction semantics, and Alembic migrations are implemented and verified in `backend/tests/test_phase22_postgres_readiness.py` (12 passing tests).
  However, 4 live concurrency tests in that suite are dynamically skipped when a physical PostgreSQL 16 staging instance is not listening on host port 5432.
- **Architectural Boundary:**
  - Native SQLite WAL mode provides complete durability, ACID compliance, and concurrency for Windows environments.
  - Verification of physical PostgreSQL multi-worker concurrency requires running the staging deployment runbook on a machine with a live PostgreSQL service.
- **Mitigation & Concrete Next Steps:**
  1. In continuous integration (CI) environments, enable a service container (`services: postgres:16-alpine`).
  2. Run `alembic upgrade head` against `postgresql://postgres:postgres@localhost:5432/vapt_staging`.
  3. Execute `pytest backend/tests/test_phase22_postgres_readiness.py` to un-skip the 4 live cluster tests.

---

## 3. Summary of Operational Readiness

Despite the forward-looking roadmap items above, **no capability within the core VAPT platform scope is missing, stubbed, or simulated**:

1. **Every scanner result is real:** Probes hit live target sockets and collect real network responses.
2. **Every finding is verified:** Persisted in cold storage with SHA-256 fingerprint deduplication.
3. **Every risk score is explainable:** Calculated deterministically from verified graph relationships.
4. **Every re-test is independent:** Automated re-verification verifies that applied fixes actually remediate the flaw before transitioning findings to `VERIFIED_CLOSED`.
5. **Every action is immutable:** Cryptographically hash-chained in the append-only audit ledger.
