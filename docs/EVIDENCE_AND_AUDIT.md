# VAPT Platform — Cryptographic Evidence Integrity & Audit Ledger

## 1. Overview

In defensive vulnerability assessments and compliance reporting, the integrity and provenance of vulnerability evidence and administrative actions are paramount. The VAPT Platform implements a multi-tier cryptographic architecture guaranteeing tamper-evident audit trails, deterministic Merkle tree inclusion proofs, and verifiable evidence storage.

---

## 2. Cryptographic Evidence Model

Evidence items (`FindingEvidence`) capture raw artifacts generated during scans (HTTP response headers, TLS configuration outputs, port banners).

### 2.1. Evidence Invariants
1. **SHA-256 Digest**: Every evidence record computes a canonical SHA-256 digest over its payload string:
   $$\text{sha256\_hash} = \text{SHA256}(\text{payload})$$
2. **Deterministic Canonicalization**: Payloads are stored as UTF-8 encoded text.
3. **Payload Truncation Protection**: If raw evidence exceeds 64 KB, it is safely truncated, flagged with `is_truncated = True`, and both the truncated hash (`sha256_hash`) and original hash (`raw_sha256_hash`) are persisted.
4. **Immutability**: Once written, evidence items are strictly append-only; update mutations are forbidden at the database and API layers.

---

## 3. Binary Merkle Tree Verification Engine

To allow efficient, zero-knowledge verification of large collections of evidence records or audit events, the platform implements a standard binary Merkle tree (`app/services/integrity_service.py`):

```
                       [ Merkle Root Hash ]
                              /      \
                   [ Node H01 ]      [ Node H23 ]
                      /    \            /    \
                  Leaf 0  Leaf 1    Leaf 2  Leaf 3
```

### 3.1. Construction Rules
- Empty tree root is represented by 64 zeroes (`"0" * 64`).
- Single-leaf tree root equals the leaf hash.
- Odd number of leaves duplicates the final leaf on odd levels to guarantee balanced binary tree computation.
- Parent node hash:
  $$\text{Parent} = \text{SHA256}(\text{Left} \parallel \text{Right})$$

### 3.2. Cryptographic Inclusion Proofs (`get_proof` / `verify_proof`)
- Clients and external auditors can request an $O(\log N)$ inclusion proof for any specific evidence ID without downloading the entire dataset.
- Verification evaluates step-by-step sibling hashes against the public Merkle root.

---

## 4. Tamper-Evident Audit Ledger

Every sensitive system operation (authentication, scope authorization, scan dispatch, model approval, kill-switch engagement, project purge) records an immutable record in `audit_events`.

### 4.1. Cryptographic Hash Chaining
Audit events form a verifiable hash chain:

$$\text{EventHash}_0 = \text{SHA256}(\text{"GENESIS"} \parallel \text{Timestamp}_0 \parallel \text{Actor}_0 \parallel \text{Action}_0 \parallel \text{Details}_0)$$

$$\text{EventHash}_i = \text{SHA256}(\text{EventHash}_{i-1} \parallel \text{Timestamp}_i \parallel \text{Actor}_i \parallel \text{Action}_i \parallel \text{Details}_i)$$

### 4.2. Tamper Detection Capabilities
`IntegrityService.verify_audit_ledger_integrity()` validates:
1. **Monotonic Timestamps**: Verifies that event timestamps are monotonically non-decreasing.
2. **Chain Continuity**: Verifies that `prev_event_hash` matches the preceding record's `event_hash`.
3. **Content Integrity**: Recomputes the expected hash for each record and identifies any modified field.
4. **Merkle Ledger Summary**: Constructs a Merkle tree of all event hashes in the project and returns the ledger's root digest.

---

## 5. External Trust Anchoring (`ExternalTrustAnchor`)

To bind internal cryptographic chains to an out-of-band trust authority, the platform provides the `ExternalTrustAnchor` interface:

```python
class ExternalTrustAnchor(ABC):
    @abstractmethod
    def anchor_merkle_root(self, root_hash: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Submits a Merkle root to the external trust anchor."""
        pass

    @abstractmethod
    def verify_anchor(self, root_hash: str, anchor_payload: Dict[str, Any]) -> bool:
        """Verifies that an external anchor payload attests to root_hash."""
        pass
```

### 5.1. Implemented Anchor Types
1. **`HMACExternalTrustAnchor`**:
   - Default hardened anchor using an isolated HMAC secret key.
   - Computes $\text{HMAC-SHA256}(\text{Secret}, \text{Identifier} \parallel \text{RootHash} \parallel \text{Timestamp})$.
   - Allows verifiable attestation without requiring external network connectivity.
2. **RFC 3161 / Cloud Anchor (Pluggable)**:
   - Interface ready for RFC 3161 Time-Stamp Protocol servers or cloud WORM write-once storage.

---

## 6. Export Manifest Evidence Verification

When exporting project data for archival or legal compliance (`/api/v1/projects/{id}/lifecycle/export?verify_evidence=true`), `BackupRecoveryService.export_project_manifest()` recomputes SHA-256 digests for all evidence records across all assessment jobs in the project, embeds the verification report, and computes a SHA-256 checksum over the entire canonical manifest.
