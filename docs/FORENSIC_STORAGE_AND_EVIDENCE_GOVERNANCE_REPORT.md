# Forensic Evidence Storage, Lifecycle & Governance Report (Prompts 58–62)

## 1. Executive Summary

This report documents the architectural design, security controls, and verification testing for the **Forensic Evidence Storage, Evidence Lifecycle, and Governance Subsystem** implemented for the VAPT Platform in accordance with Prompts 58–62.

The subsystem ensures that raw security assessment evidence, custody audit trails, normalized interpretations, legal holds, and deletion tombstones are cryptographically preserved and made resilient against accidental deletion, tampering, host failure, and operational errors.

---

## 2. Remote Evidence Storage Architecture

### 2.1 Storage Adapter Abstraction (`BaseEvidenceStorageAdapter`)
The platform decouples evidence handling from local filesystem storage through an abstract adapter interface:
- **`store_evidence(key, payload, expected_sha256, metadata, is_immutable)`**: Writes evidence blobs with atomic staging, preventing corrupt half-written files.
- **`retrieve_evidence(key, expected_sha256)`**: Retrieves payload bytes and performs post-retrieval SHA-256 integrity verification. If the retrieved digest diverges, it raises `EvidenceIntegrityError` immediately.
- **`check_worm_status()`**: Probes the configured storage backend to test write-once-read-many (WORM) hardware or cloud immutability.
- **`delete_evidence(key)`**: Restricts raw deletion according to retention and legal hold governance.

### 2.2 Local Storage Adapter (`LocalStorageAdapter`)
- **Atomic Two-Phase Staging**: Evidence payloads are written to `.tmp.<uuid>.staging` files before atomic rename to their target key path.
- **Overwrite Prevention**: If an evidence key already exists, any overwrite attempt raises `EvidenceOverwriteError`. Existing forensic evidence is immutable and can never be silently replaced.
- **WORM Simulation & Truthfulness**: Local POSIX/Windows permissions apply `0o444` (read-only). In strict accordance with Prompt 58–62 rules ("Do not claim WORM compliance without testing the actual configured storage provider"), the adapter truthfully reports `worm_compliant: False` and `worm_mode: "OS_READONLY_SIMULATION"` unless hardware-enforced immutability is validated.

### 2.3 S3-Compatible Storage Adapter (`S3CompatibleStorageAdapter`)
- Compatible with AWS S3, Cloudflare R2, MinIO, and Google Cloud Storage (XML/S3 API).
- Enforces conditional writes using HTTP `If-None-Match: *` headers, guaranteeing that the remote store rejects overwrites with HTTP 412 Precondition Failed.
- Evaluates genuine AWS S3 Object Lock configuration (`COMPLIANCE` vs `GOVERNANCE` mode) before claiming WORM compliance.

---

## 3. Evidence Lifecycle Governance

### 3.1 Raw vs Normalized Evidence Separation
- Original raw scan dumps, raw HTTP requests/responses, and packet captures are stored strictly in untouched form with their origin SHA-256 digest (`raw_digest_sha256`).
- Normalized findings and structured models are preserved separately with their own digests (`normalized_digest_sha256`).
- Transformations retain an immutable historical ledger documenting transformer identity, version, timestamp, and justification.

### 3.2 Legal Holds (`LegalHoldRecord`)
- Legal counsel and security officers can place active legal holds (`LegalHoldRecord`) targeting individual evidence records or entire projects.
- Any attempt to purge, archive, or delete evidence under an active hold fails closed with **HTTP 409 Conflict**.

### 3.3 Authorized Deletion & Signed Tombstoning (`EvidenceTombstoneRecord`)
- Deletion requires high-privilege authorization (`ADMIN` or `SECURITY_LEAD` role). Unauthorized callers are rejected with **HTTP 403 Forbidden**.
- When an authorized deletion occurs (and no active legal hold exists):
  1. The raw payload is purged or zeroized.
  2. A cryptographically signed deletion tombstone (`EvidenceTombstoneRecord`) is generated.
  3. The tombstone captures the original evidence ID, raw digest, actor identity, legal justification, and timestamp.
  4. The tombstone digest is signed with the platform's asymmetric Ed25519 private key.
  5. An immutable `DELETION_AUTHORIZED` custody event is appended to the evidence custody ledger.

### 3.4 Monotonic Merkle Custody Hash Chaining (`EvidenceCustodyEvent`)
- Every lifecycle operation (`COLLECTION`, `INGESTION`, `NORMALIZATION`, `LEGAL_HOLD_APPLIED`, `DELETION_AUTHORIZED`, `EXPORT`) generates a chained custody event.
- Genesis events initialize with `prev_custody_hash = "0" * 64`.
- Every subsequent event chains cryptographically to `prev_custody_hash = prior.custody_hash`.
- Any severance, forgery, or out-of-order insertion in the custody chain is flagged during verification audits.

---

## 4. Verification & Testing Matrix

| Test Case | Scenario Tested | Security Control Enforced | Status |
|:---|:---|:---|:---:|
| `test_storage_adapter_atomic_staging_and_worm_truthfulness` | Overwrite rejection, atomic `.tmp` staging, and WORM truthfulness probe | `EvidenceOverwriteError` on duplicate write; `worm_compliant: False` on local storage | **PASSED** |
| `test_active_legal_hold_and_unauthorized_deletion` | Legal hold blocks deletion; unauthorized role rejected; signed tombstone generated | HTTP 409 Conflict on hold; HTTP 403 on role; Ed25519 tombstone signature | **PASSED** |
| `test_interrupted_upload_staging_detected` | Network interruption during evidence upload | Atomic staging `.tmp` cleanup; incomplete artifacts never promoted | **PASSED** |
| `test_broken_merkle_chain_detected` | Severed or forged `prev_custody_hash` in custody ledger | Post-recovery cryptographic custody audit returns `status: CORRUPTED` | **PASSED** |
