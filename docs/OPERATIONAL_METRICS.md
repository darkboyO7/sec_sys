# Operational Metrics & Service Level Objectives (SLOs)

## 1. Overview & Measurement Principles

The **Operational Metrics Engine** (`OperationalMetricsService`, configured via `OperationalSLOConfig`) computes empirical Service Level Objectives (SLOs) reflecting the operational health, reliability, and security efficacy of the VAPT Platform.

### Core Mathematical & Reporting Principles:
1. **Explicit `MISSING_DATA` Handling:** If no events or trials exist within the measurement window (e.g., 0 retests performed, 0 jobs dispatched), the metric status is classified as `MISSING_DATA` with `observed_value: null`. It is never represented as 0.0, which would falsely indicate a complete failure or breach.
2. **Deterministic Status Classification:**
   - `MET`: Observed value satisfies the target threshold.
   - `BREACHED`: Observed value violates the target threshold.
   - `MISSING_DATA`: Sample count is zero; metric cannot be evaluated.
3. **Aggregate Operational Health Index:** The platform calculates `overall_health_pct` as the ratio of `MET` SLOs to total evaluatable SLOs (excluding `MISSING_DATA`).

---

## 2. Standard Operational SLO Matrix

| SLO Metric | Formula | Target Threshold | Direction |
|---|---|---|---|
| **Assessment Completion Rate** | $\frac{\text{Completed Jobs}}{\text{Completed Jobs} + \text{Failed Jobs}} \times 100$ | $\ge 95.0\%$ | Higher is better |
| **Queue Scheduling Delay** | $\frac{1}{N}\sum (\text{Job Started At} - \text{Job Created At})$ (seconds) | $\le 120\text{ s}$ | Lower is better |
| **Evidence Freshness** | $\text{Current Time} - \max(\text{Finding Observed At})$ (hours) | $\le 168.0\text{ h}$ (7 days) | Lower is better |
| **Inconclusive Retest Rate** | $\frac{\text{Inconclusive Retests}}{\text{Total Retests}} \times 100$ | $\le 5.0\%$ | Lower is better |
| **Remediation Pass Rate** | $\frac{\text{Verified Fixed Retests}}{\text{Total Retests}} \times 100$ | $\ge 80.0\%$ | Higher is better |
| **Asset Assessment Coverage**| $\frac{\text{Assets with Assessed Jobs}}{\text{Total Authorized Assets}} \times 100$ | $\ge 90.0\%$ | Higher is better |
| **Notification Delivery Rate**| $\frac{\text{Sent Deliveries}}{\text{Sent} + \text{Failed Deliveries}} \times 100$ | $\ge 98.0\%$ | Higher is better |
| **Disaster Recovery Backup** | $\text{Current Time} - \text{Latest Verified Backup Time}$ (hours) | $\le 24.0\text{ h}$ | Lower is better |

---

## 3. Mathematical Definitions & Boundary Conditions

### 3.1. Assessment Completion Rate
$$\text{Rate} = \begin{cases} \text{MISSING\_DATA}, & \text{if } N_{\text{completed}} + N_{\text{failed}} = 0 \\ \frac{N_{\text{completed}}}{N_{\text{completed}} + N_{\text{failed}}} \times 100, & \text{otherwise} \end{cases}$$

### 3.2. Remediation Verification Pass Rate
$$\text{Pass Rate} = \begin{cases} \text{MISSING\_DATA}, & \text{if } N_{\text{retests}} = 0 \\ \frac{N_{\text{VERIFIED\_FIXED}}}{N_{\text{retests}}} \times 100, & \text{otherwise} \end{cases}$$
If an organization has conducted no retests yet, returning 0% would trigger false-positive compliance alarms. The system accurately reports `MISSING_DATA` until empirical retests occur.

### 3.3. Evidence Freshness
$$\text{Freshness} = \begin{cases} \text{MISSING\_DATA}, & \text{if } \text{count}(\text{findings}) = 0 \\ \frac{\text{now} - \max(\text{last\_observed\_at})}{3600}, & \text{otherwise} \end{cases}$$

---

## 4. API & Operator Dashboard Representation

### REST API:
```http
GET /api/v1/operations/{project_id}/slos
Authorization: Bearer <member_token>
```

**Response Format:**
```json
{
  "project_id": "proj-123",
  "overall_health_pct": 100.0,
  "slos": {
    "assessment_completion": {
      "name": "Assessment Completion Rate",
      "target_value": 95.0,
      "observed_value": 100.0,
      "unit": "%",
      "status": "MET",
      "sample_count": 8
    },
    "remediation_verification_pass_rate": {
      "name": "Remediation Verification Pass Rate",
      "target_value": 80.0,
      "observed_value": null,
      "unit": "%",
      "status": "MISSING_DATA",
      "sample_count": 0
    }
  }
}
```

### Frontend Presentation:
The Operator UI (`AutonomousOperationsConsole.tsx`) renders the Operational SLOs tab:
- **Green Badge:** `MET` (Target achieved).
- **Red Badge:** `BREACHED` (Target missed; incident triggered).
- **Gray Badge:** `MISSING DATA` (No samples recorded).
