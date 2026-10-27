# VAPT Platform — Operations & Maintenance Runbook

**Environment:** Windows 11 Enterprise / Windows Server 2022  
**Role:** Defensive Platform Operations & Security Engineering  
**Classification:** Internal Security Operations Procedure  

---

## 1. Routine Service Management

### 1.1 Service Startup
```powershell
# Navigate to backend
Set-Location "D:\alt\backend"

# Ensure SQLite data directory exists
if (-not (Test-Path "data")) { New-Item -ItemType Directory -Path "data" }

# Launch FastAPI control plane with Uvicorn
..\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 1.2 Graceful Shutdown
1. Send `CTRL+C` or `SIGINT` to the Uvicorn process.
2. The server will complete in-flight HTTP requests and close database connections cleanly.
3. Subprocess workers tracked by Win32 Job Objects (`KILL_ON_JOB_CLOSE`) terminate immediately on process handle closure.

---

## 2. Health Monitoring & Triage

### 2.1 Automated Readiness Probes
Run periodic health checks via PowerShell:
```powershell
$ready = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/ready"
if ($ready.status -ne "ready") {
    Write-Error "VAPT Control Plane Not Ready: $($ready | ConvertTo-Json)"
}
```

### 2.2 Worker Process Inspection
Inspect active worker subprocesses:
```powershell
# List running python workers
Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*process_worker*" } | Select-Object Id, ProcessName, WorkingSet64, StartTime
```

### 2.3 Stale Worker Triage & Clean Up
If an unhandled host disruption causes worker termination without updating the database:
1. The built-in stale worker recovery engine (`AssessmentExecutionEngine.recover_stale_workers`) polls periodically:
   - Jobs whose heartbeat exceeds 120s with `attempt_count < max_retries` are automatically reset to `QUEUED`.
   - Jobs exceeding `max_retries` transition to `FAILED` with failure category `WORKER_HEARTBEAT_TIMEOUT`.
2. Manual worker cleanup:
```powershell
# Terminate orphaned workers by PID if needed
taskkill /F /PID <WorkerPID> /T
```

---

## 3. Emergency Operations: Kill-Switch & Defensive Lock

In the event of an active host incident, unauthorized probe, or critical anomaly:

### 3.1 Engage Emergency Kill Switch
Send an authenticated POST request with an operator token:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/adaptive-defense/kill-switch" \
     -H "Authorization: Bearer <AdminToken>" \
     -H "Content-Type: application/json" \
     -d '{"reason": "Host security anomaly detected - immediate operational freeze"}'
```
**Effect:**
- Transitions platform state to `EMERGENCY_LOCKDOWN`.
- Immediately cancels and terminates all active `RUNNING` assessment jobs.
- Sets scan cadence multiplier to `0.0` (zero new assessments permitted).
- Records immutable cryptographic audit event with operator identity.

### 3.2 Resetting from Lockdown
To restore normal operations after incident resolution:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/adaptive-defense/state" \
     -H "Authorization: Bearer <AdminToken>" \
     -H "Content-Type: application/json" \
     -d '{"target_state": "NORMAL", "reason": "Incident triaged and cleared by Lead Operator"}'
```

---

## 4. Cryptographic Ledger & Evidence Verification

### 4.1 Audit Ledger Verification
Verify that project audit records have not been tampered with or modified by a database administrator:
```powershell
$res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/projects/<ProjectID>/audit/verify" -Headers @{ Authorization = "Bearer <Token>" }
if (-not $res.is_valid) {
    Write-Warning "CRITICAL: Audit chain broken! Tampered events: $($res.tampered_event_ids -join ', ')"
}
```

### 4.2 Evidence Hash Verification
Verify byte-level SHA-256 integrity and Merkle proofs for assessment findings:
```powershell
$ev = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/projects/<ProjectID>/assessments/<JobID>/evidence/verify" -Headers @{ Authorization = "Bearer <Token>" }
if (-not $ev.is_valid) {
    Write-Warning "CRITICAL: Evidence tampering detected in job $($ev.job_id)!"
}
```

---

## 5. Right-to-Erasure & Project Purge Procedure

When an authorized project reaches end-of-life or customer offboarding:
1. Obtain explicit dual-key approval.
2. Execute purge via API:
```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/projects/<ProjectID>/purge" \
     -H "Authorization: Bearer <AdminToken>" \
     -H "Content-Type: application/json" \
     -d '{"confirmation_phrase": "PURGE PROJECT <ExactProjectName>"}'
```
3. This cascades through all project findings, targets, and evidence files, leaving an immutable tombstone audit record.
