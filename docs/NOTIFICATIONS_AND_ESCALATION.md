# Notification Pipeline & Escalation Architecture

## 1. Overview & Operational Principles

The **Notification & Escalation Pipeline** (`NotificationService`, supported by `NotificationRecord` and `NotificationDeliveryRecord`) provides automated, reliable alerts for critical security events, threshold violations, and operational failures.

### Key Operational Guarantees:
1. **Intelligent Deduplication:** Suppresses duplicate notifications within a sliding 1-hour window using fingerprint hashing.
2. **Honest Delivery Reporting:** When external providers (SMTP, Webhooks, PagerDuty, Slack) are unconfigured, delivery is honestly recorded as `UNCONFIGURED` rather than falsifying a successful dispatch.
3. **Bounded Retries:** Failed deliveries support manual or automated retries up to a hard ceiling of 3 attempts, recording timestamped delivery logs.
4. **Zero Secret Leakage:** Notification payloads and alert messages undergo automated credential redaction before dispatch and persistence.

---

## 2. Notification Event Types & Severities

The pipeline categorizes alerts using `NotificationEventType` and `NotificationSeverity`:

| Event Type | Enum Name | Default Severity | Escalation Criteria |
|---|---|---|---|
| **Critical Finding** | `CRITICAL_FINDING_DETECTED` | `CRITICAL` | CVSS >= 9.0 or exploit verified on internet-facing asset. |
| **New Exposure** | `NEW_EXPOSURE_OBSERVED` | `HIGH` | New open listening port or unauthenticated web route discovered. |
| **Job Failure** | `ASSESSMENT_JOB_FAILED` | `WARNING` / `HIGH` | Scanner crash, timeout, or consecutive failure limit reached. |
| **Remediation SLA** | `REMEDIATION_DEADLINE_APPROACHING`| `HIGH` | Open critical finding exceeding 14-day remediation SLA. |
| **Retest Failure** | `RETEST_FAILED` | `HIGH` | Independent retest indicates target is `STILL_VULNERABLE`. |
| **Policy Violation**| `POLICY_VIOLATION` | `CRITICAL` | Emergency kill switch triggered or out-of-scope scan attempted. |
| **Backup Failure** | `BACKUP_FAILED` | `CRITICAL` | Daily database backup or sandbox integrity restore check failed. |

---

## 3. Deduplication Architecture (1-Hour Sliding Window)

To prevent alert fatigue and notification storms during active scanning, `NotificationService` generates a deterministic deduplication key:
$$\text{dedup\_hash} = \text{SHA-256}(\text{project\_id} + \text{event\_type} + \text{target\_id} + \text{title})$$

### Deduplication Logic:
1. When `dispatch_notification` is invoked, it queries `NotificationRecord` for any existing record matching the `dedup_hash` created within the last 60 minutes.
2. **If Found:** The service increments `suppression_count` on the existing record, logs a duplicate suppression event, and suppresses dispatch.
3. **If Not Found (or expired):** A new `NotificationRecord` is persisted, and the delivery sequence begins.

---

## 4. Delivery Pipeline & Provider Status

### Delivery Execution:
- Each delivery attempt creates a child `NotificationDeliveryRecord` capturing:
  - `channel`: `EMAIL`, `WEBHOOK`, `SLACK`, `CONSOLE`.
  - `recipient`: Redacted destination address/URL.
  - `status`: `PENDING`, `SENT`, `FAILED`, `UNCONFIGURED`.
  - `attempt_number`: Integer counter (1 to 3).
  - `error_message`: Sanitized error response or diagnostic details.

### Honest "Unconfigured" Status:
If the system environment lacks SMTP configuration (`SMTP_HOST`) or webhook webhooks:
- The service flags `status = NotificationStatus.UNCONFIGURED`.
- The UI surfaces an orange banner indicating the notification channel is not configured.
- The audit ledger registers the notification as unconfigured rather than silent drop or fake success.

### Retry Mechanics:
Operators can trigger retries via REST API:
```http
POST /api/v1/operations/{project_id}/notifications/{notification_id}/retry
Authorization: Bearer <lead_token>
```
- If `delivery_attempts >= 3`, the request is rejected with `Maximum retry limit reached (3 attempts)`.
- Otherwise, a new attempt is executed, updating `delivery_attempts` and appending a delivery record.
