# Event Processing, Deduplication, and Pipeline Governance (Prompt 15)

## 1. Executive Summary
Operational events—such as configuration changes, scan completions, new asset discoveries, monitoring runs, and diagnostic failures—must be ingested reliably without overwhelming workers, generating duplicate scans, or losing critical audit history.

The `EventProcessingService` provides:
1. Deterministic event identity calculation.
2. Sliding-window event deduplication and coalescing.
3. Queue saturation defenses against event storms.
4. Fail-closed rejection tracking with persistent reasons.

---

## 2. Deterministic Deduplication Signature

Every incoming event is hashed into a stable 64-character SHA-256 deduplication key:

$$\text{PayloadDigest} = \text{SHA256}(\text{sort\_keys}(\text{JSON}(\text{payload})))[0:16]$$
$$\text{DedupKey} = \text{SHA256}(\text{project\_id} \mathbin{\Vert} \text{event\_type} \mathbin{\Vert} \text{target\_resource} \mathbin{\Vert} \text{PayloadDigest})$$

### Properties:
- **Normalization:** Target resources are trimmed and lowercased (`API.INTERNAL` $\rightarrow$ `api.internal`).
- **Determinism:** JSON payload keys are sorted, ensuring identical payloads yield identical digests regardless of client serialization order.
- **Tenant Isolation:** Deduplication keys incorporate `project_id`, preventing cross-tenant collisions.

---

## 3. Sliding-Window Coalescing

When an event arrives:
1. The service checks for an existing record with the same `(project_id, dedup_key)` within `dedup_window_seconds` (default: 300 seconds / 5 minutes) in status `RECEIVED` or `PROCESSED`.
2. **If Found:**
   - Increments `existing_event.coalesced_count += 1`.
   - Updates `existing_event.updated_at = utc_now()`.
   - Returns `(existing_event, was_deduplicated=True)`.
   - No duplicate background job or workflow is scheduled.
3. **If Distinct:**
   - A new `OrchestrationEventRecord` is inserted in status `RECEIVED`.
   - Dispatches a new workflow execution cycle.

---

## 4. Event Storm Protection & Queue Bounds

To protect backend workers from denial-of-service via webhook flood or rapid monitoring poll storms:
- Each project has a maximum active queue limit:
  $$\text{MAX\_PROJECT\_QUEUED\_EVENTS} = 50$$
- If `active_queued_count >= 50`:
  - Excess incoming events are persisted with status `REJECTED`.
  - An explicit rejection reason is logged: `"Event queue saturated (50/50). Event rejected to prevent storm."`
  - The event history is preserved for forensic inspection, but no workflow is scheduled.

---

## 5. Verification Evidence

Verified in `backend/tests/test_prompt15_autonomous_security_orchestration.py`:
- `test_scenario_02`: Verifies second delivery within 300s window increments `coalesced_count` without launching duplicate work.
- `test_scenario_13`: Verifies that exceeding 50 queued events rejects overflow events with `REJECTED` status while preserving audit history.
