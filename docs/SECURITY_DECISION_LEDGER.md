# Security Decision Ledger Architecture & Provenance

## 1. Overview & Architectural Principles

The **Security Decision Ledger** (`DecisionLedgerService`, backed by `SecurityDecisionLedgerRecord`) provides an append-only, tamper-evident record of all security decisions made across the VAPT Platform.

In enterprise and autonomous security systems, explainability and accountability are paramount. Whenever an action is permitted, denied, scheduled, prioritized, remediated, verified, or suspended, a structured decision record is written to the ledger.

### Core Invariants:
1. **Append-Only Immutability:** Ledger records are never updated or deleted during standard operations.
2. **Provenance & Attribution:** Every entry records the `actor_id` (or `SYSTEM`), the active `policy_version`, the triggering event, and the rationale.
3. **Zero Secret Leakage:** All payloads, reasoning strings, and parameter dictionaries are scrubbed by an automated secret sanitizer before persisting to storage.
4. **Tenant Isolation:** Every record is bound to a specific `project_id`, enforcing strict query boundaries.

---

## 2. Decision Types & Schemas

The ledger tracks operational events using the `DecisionLedgerType` enum:

| Decision Type | Code | Typical Trigger | Recorded Evidence / Fields |
|---|---|---|---|
| **Target Scope Evaluation** | `TARGET_SCOPE_EVALUATION` | Target entry or scan request | Scope authorization status, RoE identifier, match status. |
| **Assessment Scheduled** | `ASSESSMENT_SCHEDULED` | Background worker queueing | Adapter name, concurrency slot, estimated budget cost. |
| **Finding Prioritized** | `FINDING_PRIORITIZED` | Risk calculation / recalculation | CVSS score, asset criticality, exposure multiplier, final score. |
| **Remediation Triggered** | `REMEDIATION_TRIGGERED` | Recommendation generation | Action type, estimated effort, affected components. |
| **Remediation Approved** | `REMEDIATION_APPROVED` | Lead/Admin review approval | Approver user ID, approval notes, target host. |
| **Retest Executed** | `RETEST_EXECUTED` | Independent probe execution | Retest method, adapter used, verification outcome. |
| **Finding Resolved** | `FINDING_RESOLVED` | Lifecycle closure | Verification ID, closing actor, resolution confirmation. |
| **Finding Reopened** | `FINDING_REOPENED` | Regression / Recurrence | New scan ID, recurrence counter, regression evidence. |
| **Policy Evaluation** | `POLICY_EVALUATION` | Permission preflight gate | Action evaluated, permitted flag, restriction reason. |
| **Emergency Suspend** | `EMERGENCY_SUSPEND` | Kill switch or threshold breach | Operator reason, consecutive failure count, timestamp. |
| **Policy Resume** | `POLICY_RESUME` | Operator reactivation | Reactivating actor ID, justification notes. |

---

## 3. Automated Secret Redaction Standards

To prevent credentials, authorization tokens, and private keys from leaking into audit tables, `DecisionLedgerService` executes strict regex and key-based sanitization on all recorded strings, JSON payloads, and parameter dictionaries:

### Masked Patterns & Redaction Rules:
1. **Bearer / JWT Tokens:** Matches `Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*` -> Replaced with `Bearer [REDACTED_TOKEN]`.
2. **API Keys & Secrets:** Matches `(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['"]?([^\s'"]+)['"]?` -> Value replaced with `[REDACTED]`.
3. **Private Cryptographic Keys:** Matches `-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----` -> Replaced with `[REDACTED_PRIVATE_KEY]`.
4. **AWS / Cloud Credentials:** Matches `AKIA[0-9A-Z]{16}` -> Replaced with `[REDACTED_AWS_KEY]`.
5. **Basic Auth Passwords:** Matches `https?://[^:]+:([^@]+)@` -> Password portion replaced with `[REDACTED]`.

---

## 4. Querying the Decision Ledger

The ledger provides fast, indexed querying for compliance audits, incident investigations, and dashboard visualizations.

### Via REST API:
```http
GET /api/v1/operations/{project_id}/ledger?decision_type=FINDING_RESOLVED&limit=50
Authorization: Bearer <member_token>
```

**Response Format:**
```json
{
  "total": 1,
  "records": [
    {
      "id": "c1f8a892-...",
      "project_id": "proj-123",
      "timestamp": "2026-10-28T14:30:00Z",
      "decision_type": "FINDING_RESOLVED",
      "decision_outcome": "SUCCESS",
      "initiating_event": "LIFECYCLE_ACTION:CLOSE_FINDING",
      "target_type": "FINDING",
      "target_id": "find-456",
      "target_resource": "https://portal.acme.local",
      "policy_version": "v1.0.0",
      "reason": "Finding marked closed by lead@acme.com. Verified fixed via independent probe.",
      "details": {
        "previous_status": "CONFIRMED",
        "new_status": "VERIFIED_CLOSED",
        "notes": "Retest confirmed CSP enforced"
      },
      "actor_id": "usr-lead-01"
    }
  ]
}
```

### Entity Provenance Trace:
To audit the entire lifecycle history of a specific asset or finding:
```python
trail = DecisionLedgerService.get_audit_trail_for_entity(
    db=db,
    project_id=project_id,
    target_id=finding_id,
)
for entry in trail:
    print(f"[{entry.timestamp}] {entry.decision_type}: {entry.reason}")
```
