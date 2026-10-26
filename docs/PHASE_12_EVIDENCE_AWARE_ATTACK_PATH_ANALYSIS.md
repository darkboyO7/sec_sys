# Phase 12 — Evidence-Aware Attack-Path Analysis Report

**Milestone:** Phase 12 — Evidence-Aware Attack-Path Analysis  
**Completion Date:** 2026-10-26  
**Platform:** Windows 11 Native Architecture, Python 3.14.7, FastAPI, SQLite WAL, React 19  
**Status:** COMPLETE & VERIFIED  

---

## 1. Executive Summary

Phase 12 delivers an evidence-aware attack-path discovery and evaluation engine operating strictly on persisted Security Knowledge Graph relationships:
1. **Bounded, Cycle-Safe Path Traversal:** Strict depth limits (\(\le 4\)), path count caps (\(\le 10\)), and cycle avoidance ensure rapid, bounded query execution.
2. **Epistemic Path Categorization:** Evaluates every edge's epistemic status to categorize candidate paths as:
   - `VERIFIED`: All hops confirmed by verified evidence records with confidence \(\ge 0.70\).
   - `MIXED_EVIDENCE`: Combines verified scanner evidence and algorithmic inferences.
   - `HYPOTHETICAL`: Speculative chains lacking direct scanner observation.
   - `STALE`: At least one hop has expired or been superseded.
3. **Stable Path Identification & Scoring:** Computes deterministic 16-hex `path_id` digests, composite `risk_impact_score` anchored in target entity criticality, and explicit `ranking_rationale`.
4. **Defensive Chokepoint Analysis:** Automatically identifies intermediate graph nodes and relationships that intersect multiple candidate paths, quantifying their `remediation_leverage` to prioritize decisive defensive interventions.
5. **No Exploit Engine:** Analyzes potential structural exposure without launching live attacks, probing raw sockets, or fabricating breach assumptions.

---

## 2. Technical Architecture

### 2.1. Traversal Boundaries & Epistemic Rules
```
                 [ Start Node (e.g. App / Asset) ]
                                |
               Edge 1: CAN_ACCESS (VERIFIED)
                                v
               [ Intermediate Node (API Gateway) ]  <-- Identified Defensive Chokepoint
                                |
               Edge 2: CAN_ACCESS (INFERRED)
                                v
                 [ Target Node (Customer DB) ]
                                |
             Classification: MIXED_EVIDENCE
             Risk Impact Score: TargetCriticality * CumulativeConfidence
```

### 2.2. Defensive Chokepoint Formula
```
Remediation Leverage = (Paths Intersected by Element) / (Total Discovered Paths)
```
Elements with high remediation leverage represent optimal positions for firewall filtering, authentication gateways, or security controls.

---

## 3. Verification & Test Coverage

### 3.1. Test Suite Results
- `backend/tests/test_phase12_attack_path_analysis.py`:
  - `test_phase12_attack_path_ranking_and_stable_id`: PASSED
  - `test_phase12_chokepoints_and_remediation_leverage`: PASSED
  - `test_phase12_api_attack_paths_endpoint`: PASSED
- Total backend test suite: **171 passed** in 85s (0 failures).
- Total frontend test suite: **6 passed** in 0.47s.
- Production build: `tsc -b && vite build` clean in 1.11s.

---

## 4. Phase Acceptance Gate

- [x] Every path is explainable, bounded, evidence-backed, and accurately labeled.
- [x] Cycle avoidance prevents infinite loops.
- [x] Epistemic classification explicitly separates verified facts from inferences and stale data.
- [x] Defensive chokepoints and remediation leverage guide actionable defensive fixes.
