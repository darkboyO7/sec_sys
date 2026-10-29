# Asset Identity Resolution, Data Quality, and Canonical Security Records Matrix

## 1. Architectural Limitations of Previous Asset Model
Prior to Prompt 37, the asset inventory suffered from:
1. **Direct Identifier Coupling:** Raw incoming targets were immediately treated as canonical identifiers without formal confidence-scored entity resolution against known hardware, cloud ARNs, or TLS certificates.
2. **Address Reuse Vulnerability:** Ephemeral IP addresses and dynamic DNS records could match historical aliases regardless of observation age, erroneously merging unrelated systems after IP reallocation.
3. **Unreviewed Deduplication:** Merges were performed immediately without dry-run impact simulation or human review proposals, making unintended merges difficult to detect prior to execution.
4. **Lack of Automated Data Quality Audits:** No automated scanning existed for orphaned findings, unmapped scope targets, clock skews, or stale active assets.

---

## 2. Canonical Identifier Normalization & Matching Rules

| Asset Type | Raw Format Example | Canonical Form | Normalization Rule |
| :--- | :--- | :--- | :--- |
| `WEB_APP` | `https://portal.example.com:443/app/` | `https://portal.example.com/app` | Scheme + lowercased hostname, omit default ports (80/443), strip trailing slash |
| `API_ENDPOINT` | `HTTP://API.CORP.NET:8080/v1/` | `http://api.corp.net:8080/v1` | Retain non-default port, normalize path |
| `SERVICE` | `ssh://HOST.CORP:22` | `ssh://host.corp:22` | Protocol + lowercased host + explicit port |
| `IP_ADDRESS` | `198.51.100.042` | `198.51.100.42` | Octet zero-padding rejected (CWE-1288); compressed IP |
| `DOMAIN` / `HOSTNAME` | `API.CORP.INTERNAL.` | `api.corp.internal` | Lowercased, strip trailing dot, regex validate |
| `CLOUD_RESOURCE` | `arn:aws:ec2:us-east-1:...` | Canonical ARN | Authoritative cloud provider resource URI |

---

## 3. Entity Resolution Confidence Tiers & Decision Rules

```
Candidate Observation (Target, Observed At, Attributes)
                     |
                     v
   [Step 1: Check Exact Primary Canonical Key Match]
    +-- Found --> [EXACT_MATCH (100% Confidence)]
    |
    +-- Not Found
         |
         v
   [Step 2: Check Unique Cloud ARN / Hardware Fingerprint]
    +-- Found --> [STRONG_CORRELATION (95% Confidence)]
    |
    +-- Not Found
         |
         v
   [Step 3: Check Active Aliases (IP / DNS)]
    +-- Matched IP Alias:
    |     |
    |     +-- Observation Age > 7 Days --> [AMBIGUOUS_CONFLICT (45% Confidence)]
    |     |                                (IP Address Reuse Suspected)
    |     +-- Observation Age <= 7 Days --> [AMBIGUOUS_CONFLICT (60% Confidence)]
    |                                      (Shared Gateway / Multi-Tenant Host)
    |
    +-- Matched DNS Alias:
    |     +-- Age <= 7 Days --> [STRONG_CORRELATION (88% Confidence)]
    |     +-- Age > 7 Days  --> [AMBIGUOUS_CONFLICT (55% Confidence)]
    |
    +-- Not Found
         |
         v
   [Step 4: Hostname Resemblance / Fuzzy Prefix Check]
    +-- Resemblance Detected --> [AMBIGUOUS_CONFLICT (35% Confidence)]
    |
    +-- No Resemblance
         |
         v
   [Step 5: New Asset Creation -> UNMATCHED (0% Confidence)]
```

### Mandated Decision Invariants
- **NEVER merge assets solely on shared IP or fuzzy hostname resemblance.**
- **NEVER auto-merge an AMBIGUOUS_CONFLICT match.** Every uncertain match requires operator proposal, dry-run review, and Lead authorization.

---

## 4. Reviewable Deduplication & Reversible Split Workflow

```
[Propose Deduplication]
        | (Calculates Dry-Run Impact: Findings, Aliases, Observations, Conflicts)
        v
    [PROPOSED]
     /      \
    v        v
[APPROVED] [REJECTED]
    |
    | (AssetIdentityService.merge_asset_identities)
    |  - Source asset DECOMMISSIONED
    |  - Findings repointed to target
    |  - Finding IDs & attributes saved in Snapshot
    |
    v (Operator Triggers Revert / Split)
[REVERTED]
    - Source asset restored to ACTIVE
    - Findings restored to source asset ID
    - Proposal marked REVERTED
```

---

## 5. Automated Data Quality Audit Engine

The platform executes automated scans across 6 critical inventory anomalies (`POST /projects/{id}/asset-identity/data-quality/audit`):
1. `ORPHANED_FINDING`: Findings where `asset_id` is null or references a deleted/decommissioned asset.
2. `MISSING_ASSET_REFERENCE`: Scope targets with no corresponding canonical asset.
3. `DUPLICATE_IDENTIFIER`: Multiple active assets sharing identical canonical keys.
4. `INCONSISTENT_TIMESTAMPS`: Assets where `last_seen_at < first_seen_at` or set in the future.
5. `INVALID_RELATIONSHIP`: Aliases pointing to non-existent assets.
6. `STALE_OBSERVATION`: Active assets with no successful observation for $> 30$ days.
