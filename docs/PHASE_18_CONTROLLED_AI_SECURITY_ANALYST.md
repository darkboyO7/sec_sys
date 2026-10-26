# Phase 18 — Controlled AI Security Analyst Report

**Milestone:** Phase 18 — Controlled AI Security Analyst  
**Completion Date:** 2026-10-26  
**Platform:** Windows 11 Native Architecture, Python 3.14.7, FastAPI, SQLite WAL, React 19  
**Status:** COMPLETE & VERIFIED  

---

## 1. Executive Summary

Phase 18 introduces the Controlled AI Security Analyst layer into the VAPT Platform as a bounded, advisory decision-support assistant:
1. **Advisory Decision Support:** AI operates strictly as an analyst assistant, never as an unrestricted autonomous actor. It drafts finding explanations, remediation blueprints, attack path summaries, and assessment overviews without modifying authoritative security states.
2. **Untrusted Data Quarantine & Prompt Injection Defenses:**
   - Detects adversarial instruction override patterns (`ignore instructions`, `system prompt:`, `unrestricted assistant`, `delete findings`).
   - Flags injection vectors in `prompt_injection_flags` and sanitizes/escapes payloads.
   - Enforces strict delimiter boundaries separating instructions from untrusted target responses.
3. **Evidence-Grounded Citation Validation:**
   - Every generated advisory draft validates its citations against persisted project findings, observation evidence SHA-256 hashes, and registered asset IDs.
   - Hallucinated references outside the project boundary are rejected.
4. **Explicit Uncertainty Assessment:**
   - Analyses explicitly evaluate observational confidence (`CERTAIN`, `FIRM`, `TENTATIVE`).
   - High uncertainty is highlighted when observational proof is incomplete.
5. **Human Review Governance Gate:**
   - AI drafts enter in `DRAFT` status and cannot be operationalized without human analyst review (`REVIEWED_APPROVED` / `REVIEWED_REJECTED`) requiring written justification.
6. **Graceful Offline Degradation:**
   - Fully deterministic local synthesis engine operates independently of external LLM availability.

---

## 2. Technical Architecture

### 2.1. Controlled AI Analyst Architecture
```
+-------------------------------------------------------------------------+
|                         Untrusted Input Layer                           |
|       (Scanner evidence, target payloads, user-supplied text)           |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  Prompt Injection Defense & Quarantine                  |
|    • Regex Pattern Detection      • Delimiter Quarantine Boundaries     |
|    • HTML Neutralization          • Audit Flagging                      |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  Evidence Grounding & Citation Engine                   |
|    • Validates Project-Scoped IDs • Links Evidence SHA-256 Hashes       |
|    • MITRE ATT&CK & CIS Mapping   • Uncertainty Qualification           |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                    Advisory Draft Persistence Table                     |
|                 (ai_analyst_drafts, status = 'DRAFT')                   |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                     Human Analyst Review Gate (RBAC)                    |
|           Lead / Tester Review -> 'REVIEWED_APPROVED' / 'REJECTED'      |
|           (Authoritative Finding Lifecycle NEVER Auto-Closed)           |
+-------------------------------------------------------------------------+
```

### 2.2. Schema & Migration Highlights
- **Alembic Migration:** `e1f2a3b4c5d6_phase18_controlled_ai_security_analyst.py`
  - Created `ai_analyst_drafts` table with `project_id`, `draft_type`, `status`, `prompt_version`, `model_identifier`, `target_resource`, `title`, `summary`, `content`, `citations`, `uncertainty_notes`, `prompt_injection_flags`, `is_reviewed`, `reviewed_by_id`, `reviewed_at`, `review_notes`.
  - Scoped indexes for project isolation and audit tracking.

### 2.3. API Endpoints
- `POST /api/v1/projects/{project_id}/ai-analyst/explain-finding/{finding_id}`: Grounded technical explanation with MITRE and CIS mapping.
- `POST /api/v1/projects/{project_id}/ai-analyst/draft-remediation/{finding_id}`: Step-by-step remediation plan draft.
- `POST /api/v1/projects/{project_id}/ai-analyst/summarize-assessment/{job_id}`: Executive and technical job summary.
- `POST /api/v1/projects/{project_id}/ai-analyst/summarize-attack-path`: Graph-backed attack path and chokepoints overview.
- `POST /api/v1/projects/{project_id}/ai-analyst/drafts/{draft_id}/review`: Analyst review gate (requires LEAD or TESTER role).
- `GET /api/v1/projects/{project_id}/ai-analyst/drafts`: List project AI drafts.
- `GET /api/v1/projects/{project_id}/ai-analyst/drafts/{draft_id}`: Detailed view of single draft.

---

## 3. Verification & Compliance

- **Backend Pytest:** 197 passed across all phases (5 dedicated Phase 18 tests).
- **Frontend Vitest:** 6 passed.
- **Frontend Production Build:** Successful TypeScript compilation and Vite bundling.
- **Safety Invariants:** AI is non-authoritative; no live network probing or unverified status changes.
