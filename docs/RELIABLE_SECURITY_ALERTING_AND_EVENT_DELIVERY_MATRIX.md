# Reliable Security Alerting, Event Delivery & Escalation Matrix (Prompt 31)

## 1. Overview
This matrix documents the design, verification, and enforcement mappings for Prompt 31 — Reliable Security Alerting, Event Delivery, Escalation & Notification Intelligence.

## 2. Requirement to Test & Enforcement Mapping

| Req ID | Requirement Description | Implementation / Enforcement Point | Automated Test Verification | Status |
|---|---|---|---|---|
| **ALT-01** | Canonical Security Event Model & Versioning | `SecurityEventContract`, `v1.0.0` enforcement in `AlertingService` | `test_prompt31_reliable_security_alerting.py::test_01_canonical_event_ingestion_and_outbox_atomicity` | **VERIFIED** |
| **ALT-02** | Unsupported Schema Version Rejection | `AlertingService.publish_security_event()` | `test_prompt31_reliable_security_alerting.py::test_02_schema_version_validation` | **VERIFIED** |
| **ALT-03** | Sliding-Window Alert Deduplication (1h) | `NotificationRecord.deduplication_key`, hash verification | `test_prompt31_reliable_security_alerting.py::test_03_sliding_window_deduplication` | **VERIFIED** |
| **ALT-04** | Distinct State Transition Event Generation | Entity and event type isolation in deduplication seed | `test_prompt31_reliable_security_alerting.py::test_04_material_state_change_creates_new_event` | **VERIFIED** |
| **ALT-05** | Maintenance Window Quiet Period Suppression | `MaintenanceWindowRecord`, explainable reason logging | `test_prompt31_reliable_security_alerting.py::test_05_maintenance_window_suppresses_non_critical` | **VERIFIED** |
| **ALT-06** | Critical Alert Breakthrough Invariant | Standard maintenance windows never suppress `CRITICAL` events | `test_prompt31_reliable_security_alerting.py::test_06_critical_events_bypass_standard_maintenance_window` | **VERIFIED** |
| **ALT-07** | Controlled Blackout Suppression | `suppress_critical=True` configuration override | `test_prompt31_reliable_security_alerting.py::test_07_critical_events_suppressed_when_explicitly_configured` | **VERIFIED** |
| **ALT-08** | In-App Outbox Processing & Delivery | `AlertingService.process_outbox()` | `test_prompt31_reliable_security_alerting.py::test_08_outbox_processing_in_app_dispatch` | **VERIFIED** |
| **ALT-09** | Outbound Webhook SSRF Rejection | `OutboundNetworkSecurityService.validate_destination_url` | `test_prompt31_reliable_security_alerting.py::test_09_outbox_ssrf_destination_rejected_to_dead_letter` | **VERIFIED** |
| **ALT-10** | Outbox Exponential Backoff & Retry Exhaustion | `AlertingService.process_outbox()` (max 5 retries) | `test_prompt31_reliable_security_alerting.py::test_10_outbox_retry_exhaustion_triggers_dead_letter` | **VERIFIED** |
| **ALT-11** | Dead-Letter Queue Manual Replay | `AlertingService.replay_dead_letter_event()`, `POST /alerts/outbox/{id}/replay` | `test_prompt31_reliable_security_alerting.py::test_11_dead_letter_manual_replay` | **VERIFIED** |
| **ALT-12** | Alert Acknowledgement Lifecycle | `AlertingService.acknowledge_alert()`, `POST /alerts/{id}/acknowledge` | `test_prompt31_reliable_security_alerting.py::test_12_alert_acknowledgement_lifecycle` | **VERIFIED** |
| **ALT-13** | Alert Resolution & Reopen Lifecycle | `AlertingService.resolve_alert()`, `AlertingService.reopen_alert()` | `test_prompt31_reliable_security_alerting.py::test_13_alert_resolution_and_reopen_lifecycle` | **VERIFIED** |
| **ALT-14** | Project Scoping & Isolation | `project_id` foreign key and query filtering | `test_prompt31_reliable_security_alerting.py::test_14_api_list_alerts_authenticated_and_scoped` | **VERIFIED** |
| **ALT-15** | Server-Side RBAC Enforcement | `require_system_roles` on mutations | `test_prompt31_reliable_security_alerting.py::test_15_api_alert_action_rbac_enforcement` | **VERIFIED** |
| **ALT-16** | Outbox Backlog & Operational Health Reporting | `GET /alerts/outbox/status`, `OutboxStatusResponse` | `test_prompt31_reliable_security_alerting.py::test_16_api_outbox_status_reporting` | **VERIFIED** |
| **ALT-17** | Zero Secret & Credential Leakage | Sanitization filter in `AlertingService._sanitize_dict` | `test_prompt31_reliable_security_alerting.py::test_17_zero_sensitive_data_in_event_payload` | **VERIFIED** |
| **ALT-18** | Frontend Alert Center Experience | `AlertCenterView.tsx`, `Sidebar.tsx`, `App.tsx` | `frontend/src/tests/alerts.test.ts` (6 tests passed) | **VERIFIED** |

## 3. Delivery Guarantees & Technical Semantics

1. **At-Least-Once Outbox Delivery:** Events are atomically committed with state mutations into `security_events_outbox`. Dispatch workers poll and process pending records with exponential backoff (`2^attempt + jitter`).
2. **Idempotent Webhook Dispatch:** Every webhook delivery includes deterministic headers:
   - `X-VAPT-Event-ID`: Unique event identifier
   - `X-VAPT-Correlation-ID`: Correlation tracing ID
   - `X-VAPT-Signature`: HMAC-SHA256 signature calculated with `settings.SECRET_KEY`
3. **SSRF Guard:** Webhook destinations resolving to loopback (127.0.0.1, ::1), cloud metadata (169.254.169.254, metadata.google.internal), or non-HTTP schemes are rejected pre-connection and moved to `DEAD_LETTER`.
