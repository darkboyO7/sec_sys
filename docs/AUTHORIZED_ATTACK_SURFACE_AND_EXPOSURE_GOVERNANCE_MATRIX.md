# Authorized Attack-Surface Inventory and Exposure Governance Matrix

**Document Revision:** 1.0.0  
**Prompt Target:** Prompt 46  
**Classification:** Core Governance & Discovery Safety Specification  
**Applicability:** VAPT Security Platform (Control Plane, External Adapters, Discovery Workers)

---

## 1. Architectural Overview & Security Guarantees

The VAPT Security Platform strictly enforces authorized exposure tracking without self-expansion of testing authority. All external observations are governed by cryptographic provenance, strict preflight scope boundaries, and explicit human-in-the-loop review.

```
+-------------------------------------------------------------------------------------------------+
|                                     External Observation Sources                                |
|   +--------------------------+   +----------------------------+   +-------------------------+   |
|   | Passive CT Transparency  |   | Passive DNS / Whois Lookup |   | External Telemetry      |   |
|   | (Certificates, SANs)     |   | (A, AAAA, CNAME records)   |   | (Approved Cloud Feeds)  |   |
|   +------------+-------------+   +-------------+--------------+   +------------+------------+   |
+----------------|-------------------------------|-------------------------------|----------------+
                 |                               |                               |
+----------------v-------------------------------v-------------------------------v----------------+
                 |       Strict Preflight Scope Revalidation (ScopeEngine)                       |
                 +-------------------------------+-------------------------------+
                                                 |
                        [ Target in Authorized Scope? ]
                               /                   \
                            YES                     NO / EXCLUDED
                            /                         \
+--------------------------v---+     +-----------------v------------------------------------------+
|  Authorized Exposure Ingest  |     |  Anti-Expansion Guard Triggered                            |
|  - Asset lookup & validation |     |  - ZERO automated probing or scanning permitted            |
|  - SHA-256 Deduplication     |     |  - Route to `asset_inclusion_proposals` table              |
|  - Historical digest tracking|     |  - Operator Review Required: Lead/Admin ROE Approval       |
|  - Change & Freshness checks |     +-----------------+------------------------------------------+
+--------------+---------------+                       |
               |                                       v
               |                        [ Operator Decision via UI/API ]
               |                               /                \
               |                         APPROVE                 REJECT / EXCLUDE
               |                           /                       \
               |      +-------------------v----+      +-------------v-----------------------------+
               |      | 1. Create ScopeTarget  |      | Status: REJECTED / EXCLUDED               |
               |      | 2. Create Asset Record |      | Optional: Add to `scope_exclusions`       |
               |      | 3. Proposal: APPROVED  |      | Audit event logged                        |
               |      +-------------------+----+      +-------------------------------------------+
               |                          |
               +------------------------->+
                                          |
+-----------------------------------------v-------------------------------------------------------+
|                                    Exposure Data Store                                          |
|  - Table: `attack_surface_exposures` (Unique: `project_id` + canonical ID + port + protocol)   |
|  - Provenance Tracking: VERIFIED_OBSERVATION, PASSIVE_CT, DNS_RECORDS, EXTERNAL_TELEMETRY       |
|  - Freshness Lifecycle: FRESH -> STALE -> UNVERIFIED_ABSENT -> CONFIRMED_DECOMMISSIONED         |
|  - Change History: Service discoveries, certificate renewals, new hostname associations        |
+-------------------------------------------------------------------------------------------------+
```

---

## 2. Core Governance Invariants

### 1. Anti-Expansion Invariant
* **Rule:** An observed external exposure, subdomain, or host that is not explicitly covered by an active, unexpired `ScopeTarget` record **MUST NEVER** be automatically subjected to active probing or scanning.
* **Enforcement:** The system immediately diverts unauthorized discoveries into an `AssetInclusionProposal` inbox with status `PENDING`.
* **Disallowed Actions:** No port scanning, banner grabbing, fuzzing, or vulnerability testing is dispatched against proposed assets.

### 2. Provenance Integrity
* **Rule:** Every exposure and proposal record must capture its precise observation source and cryptographic evidence digest (`evidence_hashes`).
* **Distinction:** Verified observations are strictly segregated from passive certificate transparency logs, DNS heuristics, and third-party feeds.
* **Simulation Transparency:** Any synthetic, mock, or lab-generated observation must carry `is_simulated=True` and cannot be conflated with production external exposures.

### 3. Non-Destructive Deduplication
* **Rule:** Re-observing an existing endpoint (same project, host, port, and protocol) updates telemetry without overwriting historical discovery evidence.
* **Mechanism:** Increments `observation_count`, resets `consecutive_absences` to 0, sets freshness to `FRESH`, and appends unique evidence SHA-256 digests to `evidence_hashes`.

### 4. Absence Distinct from Removal
* **Rule:** Missing an asset during a single scan cycle does not prove decommissioning.
* **State Transition:**
  * Consecutive absences increment `consecutive_absences`.
  * If absences reach the threshold (default: 3) without confirmed administrative decommission, freshness transitions to `UNVERIFIED_ABSENT`.
  * Only explicit administrative verification or decommission workflow transitions an asset to `CONFIRMED_DECOMMISSIONED`.

### 5. Operator-Approved Discovery Workflow
* **Rule:** Adding a proposed asset to active assessment requires deliberate approval by a `SECURITY_LEAD` or `ADMIN`.
* **Execution:**
  * Validates reviewer permissions.
  * Records mandatory authorization evidence (e.g. Rules of Engagement document reference `ROE-EXP-2026-009`).
  * Creates a formal `ScopeTarget` record.
  * Creates an `Asset` entity in the project.
  * Generates an immutable, hash-chained audit event.

---

## 3. Data Model & Lifecycle Schema

### `attack_surface_exposures`

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | `VARCHAR(36)` | Primary key (UUID v4) |
| `project_id` | `VARCHAR(36)` | Foreign key to `projects.id` |
| `asset_id` | `VARCHAR(36)` | Foreign key to `assets.id` |
| `canonical_identifier` | `VARCHAR(255)` | Normalized FQDN or IP address |
| `service_name` | `VARCHAR(64)` | Service identification (e.g. `https`, `ssh`, `dns`) |
| `port` | `INTEGER` | Destination port (1-65535, 0 for virtual/icmp) |
| `protocol` | `VARCHAR(16)` | Network protocol (`tcp`, `udp`) |
| `transport_security` | `VARCHAR(32)` | Security posture (`PLAINTEXT`, `TLS_1_2`, `TLS_1_3`, etc.) |
| `exposure_classification` | `ENUM` | `INTERNET_FACING`, `INTERNAL_FACING`, `DMZ`, `UNKNOWN` |
| `provenance_type` | `ENUM` | `VERIFIED_OBSERVATION`, `PASSIVE_CERTIFICATE_TRANSPARENCY`, etc. |
| `freshness` | `ENUM` | `FRESH`, `STALE`, `UNVERIFIED_ABSENT`, `CONFIRMED_DECOMMISSIONED` |
| `certificate_details` | `JSON` | TLS certificate subject, issuer, fingerprints, expiry |
| `relevant_hostnames` | `JSON` | Associated hostnames and SANs |
| `evidence_hashes` | `JSON` | Cryptographic digests of observation proofs |
| `observation_count` | `INTEGER` | Cumulative number of confirmed observations |
| `consecutive_absences` | `INTEGER` | Uninterrupted scan cycles where target was absent |
| `dedup_hash` | `VARCHAR(64)` | SHA-256 index (`project_id:host:port:protocol`) |

---

## 4. API Endpoints

| Method | Path | Role Required | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/projects/{project_id}/attack-surface/inventory` | `VIEWER+` | Filterable inventory of authorized exposure points |
| `GET` | `/projects/{project_id}/attack-surface/timeline` | `VIEWER+` | Chronological audit timeline of exposure changes |
| `GET` | `/projects/{project_id}/attack-surface/assets/{asset_id}/evidence` | `VIEWER+` | Detailed exposure evidence breakdown for an asset |
| `GET` | `/projects/{project_id}/attack-surface/proposals` | `VIEWER+` | List pending/reviewed asset inclusion proposals |
| `POST` | `/projects/{project_id}/attack-surface/proposals/{proposal_id}/approve` | `SECURITY_LEAD` | Formally approve proposal and authorize scope target |
| `POST` | `/projects/{project_id}/attack-surface/proposals/{proposal_id}/reject` | `SECURITY_LEAD` | Reject proposal with out-of-scope justification |
