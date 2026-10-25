# VAPT Platform — Architecture & Design Document (Phase 1 & 2)

## 1. Executive Summary

The VAPT (Vulnerability Assessment and Penetration Testing) Platform is an enterprise cybersecurity intelligence and operational testing control plane. The system is engineered as a **Modular Monolith** for Phase 1 & 2, prioritizing high cohesion, strong tenant/project boundaries, non-invasive scope validation, verifiable proof-of-authorization, and a deterministic assessment orchestration pipeline.

Future live scanner workers, exploitation engines, and AI-driven analysis tools are strictly segregated behind an isolated execution boundary, remaining dormant until explicit authorization, resource limits, and worker sandboxing are verified.

---

## 2. System Architecture

```mermaid
flowchart TD
    subgraph UI ["Client Layer (React 19 + TypeScript + Vite)"]
        Dashboard["Mission Overview"]
        ScopeConsole["Scope Validation & Governance Console"]
        AssessmentConsole["Assessment Orchestration Console"]
        AuditViewer["Immutable Audit Feed"]
    end

    subgraph ControlPlane ["Control Plane (FastAPI Modular Monolith)"]
        API_Gateway["API Layer (/api/v1 Router)"]
        AuthMiddleware["JWT Authentication & RBAC Filter"]
        AuditService["Audit Logger & Redaction Engine"]
        ScopeEngine["Non-Invasive Scope Evaluation Engine"]
        AssessmentEngine["Assessment Execution Boundary Engine"]
        StateMachine["Assessment State Machine (QUEUED -> RUNNING -> COMPLETED)"]
    end

    subgraph AdapterLayer ["Scanner Adapter Boundary"]
        LocalAdapter["LocalFixtureAdapter\n(Deterministic Synthetic Fixtures)"]
        RawScannerWorkers[["Live Network Scanners\n(STRICTLY DISABLED)"]]
    end

    subgraph Persistence ["Persistence Layer (SQLite WAL in Dev / PostgreSQL in Prod)"]
        DB[(Database Engine)]
        AuditLedger[(Audit Event Ledger)]
        Findings[(Assessment Findings & Cryptographic Evidence)]
    end

    UI -->|HTTPS / REST API| API_Gateway
    API_Gateway --> AuthMiddleware
    AuthMiddleware --> ScopeEngine
    ScopeEngine --> Persistence
    API_Gateway --> AssessmentEngine
    AssessmentEngine -->|Mandatory Pre-Flight Scope Re-Validation| ScopeEngine
    AssessmentEngine --> StateMachine
    AssessmentEngine --> LocalAdapter
    LocalAdapter --> Findings
    API_Gateway --> AuditService
    AuditService --> AuditLedger
```

---

## 3. Core Architectural Modules

| Module | Purpose | Phase Status |
| :--- | :--- | :--- |
| **1. Core & Lifecycle** | Configuration management (`pydantic-settings`), request context tracking, liveness (`/health`) and readiness (`/ready`) probes. | **Implemented & Verified** |
| **2. Auth & Identity** | Bcrypt password hashing (cost factor 12), short-lived JWT token issuance, RBAC (`ADMIN`, `SECURITY_LEAD`, `SECURITY_TESTER`, `AUDITOR`, `VIEWER`). | **Implemented & Verified** |
| **3. Organizations & Projects** | Multi-tenant project hierarchy, project roles (`LEAD`, `TESTER`), and project-level boundary isolation. | **Implemented & Verified** |
| **4. Scopes & Target Authorization** | Target registration (`PENDING`), explicit evidence-backed authorization (`AUTHORIZED`), scope exclusions, and fail-closed validation. | **Implemented & Verified** |
| **5. Audit Logging** | Immutable security event logging with automated credential scrubbing and strict failure-mode enforcement. | **Implemented & Verified** |
| **6. Assessment Orchestration & Evidence Pipeline** | Persistent job state machine, idempotency keys, deterministic local fixture adapter, finding persistence, and cryptographic SHA-256 evidence provenance. | **Implemented & Verified (Phase 2)** |
| **7. Finding Lifecycle & Deduplication** | 13-state finding lifecycle, deduplication, revalidation, and risk acceptance. | **Implemented & Verified (Phase 3)** |
| **8. Asset Inventory & Knowledge Graph** | Asset graph topology, multi-hop relationship modeling, and choke-point discovery. | **Implemented & Verified (Phase 4)** |
| **9. Contextual Risk Engine** | Transparent, deterministic risk scoring combining severity, exposure, and asset criticality. | *Target: Phase 5* |

---

## 4. Assessment State Machine & Execution Boundary

Assessment jobs follow a strict, deterministic finite state machine:

```mermaid
stateDiagram-v2
    [*] --> QUEUED : Job Created (Idempotent)
    QUEUED --> RUNNING : Execution Boundary Scope Check Passed
    QUEUED --> CANCELLED : Operator Request
    QUEUED --> FAILED : Pre-flight Scope Re-Validation Failed
    RUNNING --> COMPLETED : All Fixture Tests Passed
    RUNNING --> PARTIAL : Tests Passed with Auxiliary Warnings/Errors
    RUNNING --> FAILED : Unhandled Adapter Exception
    RUNNING --> TIMED_OUT : Execution Exceeded timeout_seconds
    RUNNING --> CANCELLED : Operator Request
    COMPLETED --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
    TIMED_OUT --> [*]
    PARTIAL --> [*]
```

### Pre-Flight Execution Invariant
Before any adapter runs, the `AssessmentExecutionEngine`:
1. Re-evaluates `ScopeEngine.validate_target_in_scope()` against the database.
2. If authorization expired, was revoked, or an exclusion was added while the job was queued, the job transitions immediately to `FAILED` with an explicit reason, and an `ASSESSMENT_EXECUTION_DENIED` audit event is emitted.
3. Network scanning is strictly disabled. The adapter interface dispatches solely to approved adapters (default: `LocalFixtureAdapter`).

---

## 5. Audit Logging & Tamper-Evident Distinction

### Implemented Model: Structured Transactional Append-Only Ledger
The platform currently implements an **append-only relational audit ledger**:
- Immutable rows stored in `audit_events`.
- Transactional integrity tied to database transactions (`AUDIT_LOG_STRICT=True`).
- Client IP, actor ID, action, outcome, and timestamp recorded.
- Automated recursive scrubbing of all credentials and sensitive keys.

### Architectural Boundary: Cryptographic Tamper-Evidence
An append-only ledger differs from a cryptographically tamper-evident or tamper-proof system:
- In the current Phase 1/2 model, an attacker with direct, administrative SQL database access could theoretically alter historical rows.
- Future phases (Phase 8) will introduce **Merkle trees and cryptographic hash-chaining** (`previous_record_hash`) anchored to external, independent timestamping authorities to establish verifiable mathematical tamper-evidence.

---

## 6. Finding Validation & 13-State Lifecycle Pipeline

### State Machine Architecture
Findings adhere to a strict, finite 13-state lifecycle model governing discovery, validation, triage, remediation, independent verification, and closure. Direct jumps across boundaries (e.g., `DETECTED` straight to `VERIFIED_CLOSED`) are strictly forbidden.

```mermaid
stateDiagram-v2
    [*] --> DETECTED : Ingested from Assessment Job
    [*] --> NEEDS_VALIDATION : Tentative Initial Confidence
    
    DETECTED --> CONFIRMED : Operator / Lead Verification
    DETECTED --> NEEDS_VALIDATION : Ambiguous Evidence
    DETECTED --> FALSE_POSITIVE : Reviewer Sign-off (>= 10 chars)
    DETECTED --> INCONCLUSIVE : Insufficient Evidence
    DETECTED --> ACCEPTED_RISK : Authorized by Lead with Controls

    NEEDS_VALIDATION --> CONFIRMED : Verified Valid
    NEEDS_VALIDATION --> FALSE_POSITIVE : Refuted with Evidence
    NEEDS_VALIDATION --> INCONCLUSIVE : Ambiguity Persists
    NEEDS_VALIDATION --> ACCEPTED_RISK : Accepted with Controls

    CONFIRMED --> REMEDIATION_PROPOSED : Engineering Plan Created
    CONFIRMED --> ACCEPTED_RISK : Risk Acceptance Authorized
    CONFIRMED --> FALSE_POSITIVE : Re-evaluated
    CONFIRMED --> NEEDS_VALIDATION : Conflicting Signal Observed

    REMEDIATION_PROPOSED --> REMEDIATION_APPROVED : Security Lead Sign-off
    REMEDIATION_PROPOSED --> CONFIRMED : Plan Rejected
    REMEDIATION_PROPOSED --> ACCEPTED_RISK : Risk Accepted

    REMEDIATION_APPROVED --> REMEDIATION_ATTEMPTED : Patch Deployed
    REMEDIATION_APPROVED --> REMEDIATION_PROPOSED : Plan Revised

    REMEDIATION_ATTEMPTED --> REMEDIATED_PENDING_VERIFICATION : Deployed to Target Environment
    REMEDIATION_ATTEMPTED --> CONFIRMED : Patch Failed Integration

    REMEDIATED_PENDING_VERIFICATION --> VERIFIED_CLOSED : Independent Scan Confirmed Gone
    REMEDIATED_PENDING_VERIFICATION --> REOPENED : Re-scan Found Issue Present

    VERIFIED_CLOSED --> REOPENED : Subsequent Scan Observed Target Vulnerable

    REOPENED --> CONFIRMED : Triaged
    REOPENED --> REMEDIATION_PROPOSED : New Remediation Planned
    REOPENED --> ACCEPTED_RISK : Risk Acceptance Re-authorized

    ACCEPTED_RISK --> EXPIRED : Expiration Date Elapsed
    ACCEPTED_RISK --> REOPENED : New Critical Exposure Observed
    ACCEPTED_RISK --> CONFIRMED : Risk Acceptance Revoked

    EXPIRED --> NEEDS_VALIDATION : Requires Mandatory Re-evaluation
    EXPIRED --> ACCEPTED_RISK : Re-authorized with New Expiration
    EXPIRED --> REMEDIATION_PROPOSED : Remediation Initiated

    FALSE_POSITIVE --> REOPENED : New Proof-of-Concept Emerges
    INCONCLUSIVE --> CONFIRMED : Conclusive Evidence Obtained
```

### Finding Deduplication & Correlation
The platform implements deterministic SHA-256 fingerprinting based on normalized target value, normalized vulnerability identifier (e.g., `CVE-2026-1049` or `CWE-89`), and sanitized title.
1. **Recurring Observations**: When subsequent assessment executions encounter an existing finding, `occurrence_count` increments and `last_observed_at` updates without creating duplicate canonical records.
2. **Automated Reopening**: If a vulnerability is re-observed on a target that was previously marked `VERIFIED_CLOSED` or `REMEDIATED_PENDING_VERIFICATION`, the state machine automatically transitions the finding to `REOPENED` and generates an audit record.
3. **Contradictory Evidence Preservation**: If scanner observations diverge in severity or confidence across jobs (e.g., Scanner A reports `CRITICAL` / `CERTAIN` while Scanner B reports `LOW` / `TENTATIVE`), the engine flags `has_contradictions = True` and appends detailed contradiction provenance without overwriting historical evidence.

### Risk Acceptance & False Positive Governance
- **`ACCEPTED_RISK`**: Requires `ProjectRole.LEAD` or `SystemRole.ADMIN`, a mandatory future expiration date (<= 365 days), documented compensating controls, and comprehensive business rationale. Overdue accepted risks are automatically transitioned to `EXPIRED` during scheduled or automated sweeps.
- **`FALSE_POSITIVE`**: Requires `ProjectRole.LEAD` or `SystemRole.ADMIN` with mandatory justification notes (>= 10 characters) explaining why the vulnerability does not exist or constitutes expected behavior.

---

## 7. Persistent Asset Inventory & Conservative Reconciliation

### Separation of Authoritative State and Supporting Observations
The platform strictly decouples current authoritative asset state (`assets`) from raw, time-stamped scanner outputs (`asset_observations`):
- **`Asset`**: Represents the current reconciled identity of an infrastructure component, including its normalized `canonical_identifier`, `asset_type`, `criticality`, `status`, merged `attributes`, and ambiguity flags.
- **`AssetObservation`**: Immutable append-only log capturing each scanner's raw attributes, observation timestamp, adapter version, cryptographic evidence hash, confidence rating, and assessment job reference. Conflicting observations never silently overwrite previous records; attribute changes are tracked chronologically in `_attribute_history`.

### Type-Specific Canonical Normalization Rules
1. **Web Apps & API Endpoints**: Normalizes URL scheme (`http`/`https`), strips default ports (80/443), strips trailing slashes, downcases hostname, strictly validates hostname against CWE-1288 leading-zero ambiguity, and distinguishes URLs with API paths (`API_ENDPOINT`) from root web hosts (`WEB_APP`).
2. **Services**: Formats scheme and port consistently (e.g., `tcp://host:port`), stripping protocol-specific trailing syntax, and verifies host does not contain ambiguous leading zeros.
3. **IP Addresses**: Strictly rejects ambiguous IPv4 octets containing leading zeros (e.g. `0177.0.0.1` or `192.168.001.050`) per CWE-1288 standards-safe normalization to eliminate decimal vs. octal socket discrepancy vulnerabilities (CVE-2021-29921). Formats IPv6 addresses using standard compressed notation (`ipaddress.ip_address.compressed`).
4. **CIDR Blocks**: Rejects ambiguous octets with leading zeros (e.g. `192.168.001.0/24`) and normalizes network prefix and base address via `ipaddress.ip_network`.
5. **Domains & Hostnames**: Normalizes to lowercase, strips trailing FQDN root dots, validates characters against `^[a-zA-Z0-9*_\-.]+$` to reject control characters, shell metacharacters, or HTML injection, and distinguishes dotted domains from single-label hostnames.
6. **Deterministic Evidence Hashing**: When `evidence_hash` is not supplied, `record_observation` computes a canonical SHA-256 digest over key-sorted JSON serialization (`sort_keys=True, separators=(',', ':')`) for deterministic cryptographic provenance. Note that this hash verifies integrity and chronological provenance across executions, but does not substitute for external digital signatures for third-party identity proof.

### Ambiguity Tracking & Resolution Governance
If a target exhibits conflicting identity signals (e.g. dynamic IP reallocations, shared virtual hostnames, or unverified aliases), the entity is flagged with `is_ambiguous = True` and an explicit `ambiguity_reason`. Resolving ambiguity requires operator review with mandatory audit-logged `resolution_notes`, moving previous reasons into immutable `_resolution_history`.

---

## 8. Universal Security Knowledge Graph

### Relational Graph Architecture
Rather than introducing external, non-portable graph database engines, the Universal Security Knowledge Graph is engineered on relational database primitives (`graph_nodes`, `graph_relationships`) optimized for SQLite in local development and PostgreSQL in production:
- **`GraphNode`**: Represents any security entity within a project context (`ASSET`, `SERVICE`, `APPLICATION`, `IDENTITY`, `ROLE`, `PERMISSION`, `VULNERABILITY`, `FINDING`, `EVIDENCE`, `SECURITY_CONTROL`, `DEPENDENCY`, `REMEDIATION`, `ASSESSMENT`). Unique constraint on `(project_id, category, entity_id)` guarantees idempotent creation. For synthetic or logical entities where `entity_id` is None, `get_or_create_node` queries by `(project_id, category, label, entity_id is None)` to prevent duplicate orphan nodes.
- **`GraphRelationship`**: Directed typed edges (`RUNS`, `DEPENDS_ON`, `AUTHENTICATES_TO`, `CAN_ACCESS`, `EXPOSES`, `AFFECTED_BY`, `MITIGATES`, `OBSERVED_AT`, `VERIFIED_BY`, `BELONGS_TO`, `ASSOCIATED_WITH`). Self-referential edges (`source_node_id == target_node_id`) are strictly prohibited and rejected.

### Verification States & Epistemic Confidence
Each graph relationship maintains an explicit verification state and confidence score ($0.0 \le c \le 1.0$):
- **`VERIFIED`**: Confirmed via direct assessment observation or signed proof.
- **`INFERRED`**: Deduced via heuristic correlation, partial assessment outcomes, or dependency analysis.
- **`HYPOTHETICAL`**: Modeled what-if attack vector or simulated condition.
- **`STALE`**: Historical observation whose validity window has elapsed.
- **`SUPERSEDED`**: Replaced by subsequent higher-fidelity observations.

### Cycle-Safe Bounded Traversal Algorithm
Neighborhood graph queries (`GET /graph/nodes/{node_id}/neighborhood`) execute a bounded Breadth-First Search (BFS):
1. Traversal maintains a `visited_nodes` registry preventing infinite loops on cyclic topologies ($A \to B \to C \to A$).
2. Traversal strictly enforces `max_depth` (default 2, cap 4), `max_nodes` (cap 200), and `max_edges` (cap 300).
3. If query limits are reached, traversal halts gracefully and returns `truncated = True`, preventing denial-of-service on densely connected graphs.
4. Traversal response returns both `relationships` (rich metadata containing relationship_type, status, confidence, provenance, evidence_reference, observed_at, properties) and `edges` (graph layout connectors) to ensure seamless API and frontend visualization schema parity.

### Strict Project Isolation
Every graph query and relationship creation validates that both `source_node` and `target_node` reside within the authorized `project_id`. Cross-project relationship injection is rejected with fail-closed errors.

### Assessment Integration
When an assessment job finishes execution, the pipeline runs graph integration **after** the state machine finalizes the execution status:
1. Reconciles the target asset in inventory.
2. If `job.status == FAILED`: records the assessment job node with `status: "FAILED"`, but does **not** record a successful observation on the asset and does **not** establish false verified edges.
3. If `job.status == PARTIAL`: records an observation with `validation_status: "PARTIAL"`, and marks generated relationships with `status: RelationshipStatus.INFERRED`.
4. If `job.status == COMPLETED`: appends an immutable `AssetObservation` (`validation_status: "VERIFIED"`), links canonical findings to the asset (`finding.asset_id = asset.id`), and generates corresponding graph nodes and verified edges (`OBSERVED_AT`, `AFFECTED_BY`, `VERIFIED_BY`, `ASSOCIATED_WITH`).

---

## 9. Contextual Risk Intelligence & Remediation Prioritization (Phase 5)

### 9.1 Explainable Contextual Risk Engine (Version: `v1.0.0`)
The platform calculates a deterministic, explainable Contextual Risk Score $S \in [0, 100]$ as an operational prioritization index (rather than an unvalidated probability of compromise):

$$S = \text{round}\left(\min\left(100.0, \max\left(0.0, \text{BaseScore} \times \text{ConfidenceWeight} \times M_{\text{crit}} \times M_{\text{exp}} \times M_{\text{fresh}} \times M_{\text{mit}}\right)\right), 1\right)$$

#### Factor Decomposition
1. **Base Severity Score ($\text{BaseScore}$)**:
   - Anchored to categorical vendor/scanner severity: `CRITICAL` (90.0), `HIGH` (70.0), `MEDIUM` (45.0), `LOW` (20.0), `INFO` (5.0).
   - If a valid CVSS score ($0.0 \le \text{CVSS} \le 10.0$) is present, scales within the severity band ($\text{CVSS} \times 10.0$). The original finding severity is never overwritten.
2. **Finding Confidence Weight ($\text{ConfidenceWeight}$)**:
   - `CERTAIN`: 1.00 | `FIRM`: 0.85 | `TENTATIVE`: 0.65.
3. **Asset Criticality Multiplier ($M_{\text{crit}}$)**:
   - `CRITICAL`: 1.35 | `HIGH`: 1.15 | `MEDIUM`: 1.00 | `LOW`: 0.85 | `INFO`: 0.70. Default 1.00 if unlinked (explicitly flagged in `missing_factors`).
4. **Network Exposure & Reachability Multiplier ($M_{\text{exp}}$)**:
   - Internet-Facing / Exposed (`WEB_APP`, `API_ENDPOINT`, or graph `EXPOSES` edge): 1.25.
   - Standard Internal Network Service (`SERVICE`, `HOST`, IP): 1.00.
   - Isolated Backend / Datastore (`DATA_STORE`, `SOFTWARE_COMPONENT`, `SECURITY_CONTROL`): 0.85. Default 1.00 if exposure is unknown.
5. **Evidence Freshness Decay ($M_{\text{fresh}}$)**:
   - $\le 7$ days: 1.00 | $8–30$ days: 0.90 | $31–90$ days: 0.80 | $> 90$ days (stale): 0.70.
6. **Lifecycle & Compensating Controls Multiplier ($M_{\text{mit}}$)**:
   - `VERIFIED_CLOSED` / `FALSE_POSITIVE`: 0.00 (risk neutralized).
   - `ACCEPTED_RISK` (with active compensating controls): 0.40.
   - `REMEDIATED_PENDING_VERIFICATION`: 0.50 | `REMEDIATION_ATTEMPTED`: 0.75 | `REMEDIATION_APPROVED`: 0.90.
   - `REOPENED`: 1.10 (elevated urgency due to recurring vulnerability).
   - `CONFIRMED`: 1.05 | `DETECTED` / `NEEDS_VALIDATION`: 1.00.

#### Priority Mapping
- **CRITICAL**: $S \ge 80.0$
- **HIGH**: $60.0 \le S < 80.0$
- **MEDIUM**: $40.0 \le S < 60.0$
- **LOW**: $15.0 \le S < 40.0$
- **INFORMATIONAL**: $S < 15.0$

### 9.2 Reproducibility & Frozen Input Snapshots
Each persisted `RiskAssessment` records:
- A frozen JSON `input_snapshot` of every variable used in the calculation.
- An explicit list of `contributing_factors` explaining the principal drivers of the score.
- An explicit list of `missing_factors` highlighting epistemic uncertainty (e.g. unlinked asset criticality, missing CVSS).
- Recalculation is idempotent when inputs are unchanged; recalculations with new evidence supersede previous assessments (`is_superseded = True`, `superseded_at`), preserving an immutable historical audit trail.

### 9.3 Evidence-Aware Attack Path Analysis
The Knowledge Graph engine includes a bounded, read-only path analysis service (`AttackPathAnalysisService`) that connects security entities exclusively through persisted graph relationships:
- **`VERIFIED` Path**: Every relationship along the path has status `VERIFIED` AND confidence $\ge 0.7$.
- **`MIXED_EVIDENCE` Path**: Path contains both `VERIFIED` and `INFERRED` relationships without stale/superseded edges.
- **`STALE` Path**: Path contains one or more `STALE` or `SUPERSEDED` relationships; explicitly flagged with detailed missing evidence explaining expired edges.
- **`HYPOTHETICAL` Path**: Path contains `HYPOTHETICAL` relationships or uncorroborated edges requiring empirical confirmation.
- **Cycle Safety & Bounded Depth**: DFS search enforces depth bounds ($\le 4$) and candidate path caps ($\le 10$), maintaining path visited sets to cut cycles.
- **Epistemic Disclaimer**: Graph adjacency represents potential exposure and relational topology, NOT confirmed breach or automated exploitability.

### 9.4 Non-Executing Remediation Decision Support
The remediation service (`RemediationPrioritizationService`) maps confirmed findings to defensive corrective actions, operational impact assessments, rollback procedures, and independent verification criteria:
- **Strict Non-Execution Guarantee**: Phase 5 operates exclusively in an advisory capacity. It never executes shell commands, alters firewall rules, modifies code repositories, or restarts services.
- **Decoupled Verification**: A finding is never marked remediated simply because a recommendation was approved. The existing finding lifecycle requires independent scan verification (`REMEDIATED_PENDING_VERIFICATION` $\to$ `VERIFIED_CLOSED`).
- **Governance & RBAC**: Reviewing and approving remediation playbooks (`APPROVED`, `DEFERRED`, `REJECTED`) is restricted to Project LEAD and System ADMIN roles, with mandatory justification logged to the immutable audit ledger.

---

## 10. Phase 5.1 Security Audit, Model Hardening & API Scoping

### 10.1 Input Sanitization & Precedence Guarantees
- **Non-Finite Value Rejection**: Scanner outputs containing `NaN`, `+inf`, `-inf`, or scores outside $[0.0, 10.0]$ are intercepted before score calculation. The engine falls back to the categorical severity base score and logs an explicit uncertainty entry in `missing_factors`.
- **CVSS vs. Categorical Severity Precedence**: When CVSS quantitatively conflicts with triage severity (e.g. CVSS 9.8 marked `LOW`, or CVSS 1.2 marked `CRITICAL`), categorical bounds govern the floor/ceiling of the base score (`CRITICAL`: [80, 100], `HIGH`: [60, 89], `MEDIUM`: [35, 65], `LOW`: [10, 39], `INFO`: [0, 15]), and a discrepancy notice is logged in `contributing_factors`.
- **Temporal & Timezone Safety**: All calculations enforce UTC-aware comparison. Future-dated timestamps beyond clock skew are clamped to fresh observations (0 days) with explicit notices rather than causing negative duration errors.

### 10.2 Lifecycle & Historical Traceability
- **Preservation on Neutralization**: When a finding transitions to `FALSE_POSITIVE` or `VERIFIED_CLOSED`, current operational risk score drops to 0.0, but the previous active assessment is preserved in `risk_assessments` as superseded (`is_superseded = True`, `superseded_at`), maintaining complete historical scoring telemetry and verification provenance (`verified_by_id`, `verification_notes`, `false_positive_reason`).
- **Residual Risk Tracking for Risk Acceptance**: `ACCEPTED_RISK` findings do not zero out; they receive a 0.40 residual multiplier, and the approver ID, expiration date, and compensating controls are embedded into `input_snapshot` and `contributing_factors`.
- **Formula Version Upgrades**: If `active_assessment.scoring_version != SCORING_VERSION`, the engine bypasses cache reuse and forces a recalculation, ensuring formula changes take effect immediately across all findings.

### 10.3 API Dual Scoping & Boundary Clamping
- **Dual Parent-Child Constraints**: Every endpoint accepting both a `{project_id}` and a child resource ID (`{assessment_id}`, `{recommendation_id}`, `{finding_id}`, `{start_node_id}`) enforces database-level dual validation (`resource.project_id == project_id`). Mismatched cross-project queries fail-closed with 404 Not Found.
- **Pagination Protection**: All list endpoints enforce strict bounds (`limit: int = Query(50, ge=1, le=100)`, `offset: int = Query(0, ge=0)`). Requests exceeding limit bounds are rejected with 422 Unprocessable Entity.



