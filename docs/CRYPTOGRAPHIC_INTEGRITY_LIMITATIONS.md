# VAPT SYSTEM — CRYPTOGRAPHIC INTEGRITY LIMITATIONS
## Scope of Cryptographic Proofs, Threat Model Boundaries, and Trust Anchor Requirements (Prompt 14)

---

## 1. Executive Summary

The **VAPT Defensive Security Platform** utilizes cryptographic algorithms—specifically SHA-256 cryptographic digests, binary Merkle trees, and monotonically chained audit logs—to provide verifiable proof of evidence custody and tamper detection across operational workflows.

However, cryptographic proofs are only as secure as their root of trust and threat model assumptions. **A cryptographic hash chain alone does not make historical records physically impossible to alter.**

This document details exactly what the platform's cryptographic implementations guarantee, defines the boundary where software-level cryptographic guarantees terminate, and outlines the external architectural requirements for absolute non-repudiation in enterprise deployments.

---

## 2. What the Platform's Cryptographic Controls Provably Guarantee

### 2.1 SHA-256 Evidence Digests
- **Mathematical Guarantee:** Pre-image resistance ($2^{256}$ operations) and collision resistance ($2^{128}$ operations).
- **Enforced Security Property:**
  - Given a stored evidence payload $P$ and recorded digest $H = \text{SHA256}(P)$, it is computationally infeasible for an adversary to modify $P$ into $P'$ such that $\text{SHA256}(P') = H$.
  - Any byte-level alteration to an evidence record stored in `finding_evidence` is immediately detected during automated integrity audits (`IntegrityService.verify_evidence_integrity`).
  - Authoritative control plane hashing ensures that worker processes cannot forge evidence digests during ingestion.

### 2.2 Binary Merkle Trees
- **Mathematical Guarantee:** Deterministic, hierarchical aggregation of $N$ leaf hashes into a single root digest $M_{\text{root}}$.
- **Enforced Security Property:**
  - Provides compact, independent logarithmic proofs of inclusion ($O(\log N)$) for any individual evidence item within an assessment job.
  - An auditor can verify that a specific evidence item belonged to a completed assessment job without inspecting all other evidence records in that job.
  - Adding, deleting, or reordering any evidence item alters the root digest $M_{\text{root}}$.

### 2.3 Monotonic Audit Hash Chaining
- **Mathematical Guarantee:** Forward hash chaining:
  $$\text{event\_hash}_i = \text{SHA256}(\text{prev\_event\_hash}_{i-1} \mid \text{timestamp}_i \mid \text{actor\_id}_i \mid \text{action}_i \mid \dots)$$
- **Enforced Security Property:**
  - **Tamper Detection for Application Actors:** An application user, compromised tester account, or malicious API client cannot alter an existing audit log row without breaking the hash link to the subsequent event ($\text{prev\_event\_hash}_{i+1} \neq \text{event\_hash}_i$).
  - **Deletion Detection:** Deleting a row from the middle of the audit chain creates a detectable link mismatch between its predecessor and successor.
  - **Backdating Detection:** Monotonic timestamp constraints and sequence locks prevent backdating events behind existing verified timestamps.

---

## 3. Cryptographic Limitations & Threat Model Boundaries

The table below delineates the exact operational boundary between protected scenarios and unprotected compromise conditions:

```
+---------------------------------------------------------------------------------------+
| PROTECTED THREAT DOMAIN (Application Layer)                                          |
| - Malicious or compromised web application users (VIEWER, TESTER, LEAD).             |
| - Malicious API injection attempts or forged client payloads.                         |
| - Rogue worker processes returning tampered evidence hashes.                          |
| - Accidental database row corruption or partial network drops.                        |
|                                                                                       |
| GUARANTEE: In-application tampering, deletion, or modification is 100% detected.      |
+---------------------------------------------------------------------------------------+
                                           |
                                [ CRITICAL TRUST BOUNDARY ]
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| UNPROTECTED THREAT DOMAIN (Host / Infrastructure Layer)                              |
| - Attacker possessing database superuser ('postgres', 'sa', direct SQLite access).     |
| - Host operating system root/administrator filesystem compromise.                    |
| - Full database snapshot rollback (erasing recent history completely).                |
|                                                                                       |
| LIMITATION: Relational hash chain alone CANNOT prevent history rewriting by superusers|
| without an out-of-band external trust anchor.                                         |
+---------------------------------------------------------------------------------------+
```

### 3.1 The Forward-Recomputation Vulnerability
If an attacker obtains direct access to the database engine (e.g., direct write access to `vapt.db` or PostgreSQL superuser credentials) and filesystem control:
1. The attacker can modify an audit row at sequence $k$ (e.g., erasing an authorization failure).
2. Because the SHA-256 algorithm and hashing formulas are deterministic and public, the attacker can execute a script that sequentially recomputes:
   $$\text{event\_hash}_k = \text{SHA256}(\dots)$$
   $$\text{prev\_event\_hash}_{k+1} = \text{event\_hash}_k$$
   $$\text{event\_hash}_{k+1} = \text{SHA256}(\dots)$$
   forward to the head of the table.
3. When `verify_audit_ledger_integrity` is subsequently executed, the chain appears mathematically valid because all intermediate links match.

### 3.2 The Database Rollback Limitation
If an attacker restores a clean database snapshot from 24 hours prior:
- The audit chain within the restored snapshot is internally valid.
- The application database alone has no intrinsic way to determine that 24 hours of subsequent events were erased unless an external reference exists.

---

## 4. Architectural Requirements for True Non-Repudiation

To achieve true legal and compliance non-repudiation resilient against host and database superuser compromise, the VAPT platform architecture defines integration hooks for **External Out-of-Band Trust Anchors**.

```
+-------------------------------------------------------------------------+
|                       VAPT Audit & Evidence Store                       |
|           (Computes periodic Merkle Root Block Digest M_root)           |
+------------------------------------+------------------------------------+
                                     |
               +---------------------+---------------------+
               |                     |                     |
               v                     v                     v
+-----------------------------+ +-------------------+ +-------------------+
|     RFC 3161 TSA Authority  | | WORM Cloud Object | | Transparency Log  |
|  (DigiCert, Sectigo, FreeTSA)| | Storage (S3/GCS)  | | (Sigstore Rekor)  |
+-----------------------------+ +-------------------+ +-------------------+
| - Cryptographic timestamp   | | - Object Lock in  | | - Public Merkle   |
|   token (TST) signed by     | |   Compliance Mode |   tree of software  |
|   trusted third-party CA.   | | - Immutable WORM  |   digests.          |
| - Legally valid proof of    | |   retention.      | - Immutable append- |
|   existence at time T.      | | - Cannot overwrite|   only ledger.      |
|                             | |   even with root. |                     |
+-----------------------------+ +-------------------+ +-------------------+
```

### 4.1 RFC 3161 Trusted Time-Stamping Authority (TSA)
- **Mechanism:** At periodic intervals (or after each completed assessment job), the application transmits $M_{\text{root}}$ to an external RFC 3161 Time-Stamping Authority.
- **Guarantee:** The TSA signs a Time-Stamp Token (TST) containing $M_{\text{root}}$ and a cryptographic timestamp signed with the TSA's private key.
- **Tamper Resistance:** Even if a database superuser rewrites the local database, they cannot forge the TSA's signature or retroactively backdate a new hash chain.

### 4.2 Write-Once-Read-Many (WORM) Cloud Storage
- **Mechanism:** Exporting audit block digests to cloud object storage configured with Object Lock in Compliance Mode (e.g., AWS S3 Object Lock or Google Cloud Storage Bucket Lock).
- **Guarantee:** In Compliance Mode, objects cannot be overwritten, modified, or deleted by any user, including the AWS/GCP root account administrator, until the retention period expires.

### 4.3 Public Transparency Logs (Sigstore Rekor)
- **Mechanism:** Publishing $M_{\text{root}}$ to a public, verifiable append-only transparency log.
- **Guarantee:** Rekor provides cryptographic monitorability where any unauthorized history fork is publicly and immediately visible.

---

## 5. Summary & Guidance for Security Auditors

1. **Within Application Boundaries:** The VAPT platform provides robust, automated tamper-detection that prevents unprivileged users, testers, and compromised application services from forging or altering evidence and audit trails.
2. **Against Root/DBA Compromise:** Security auditors must recognise that software-level hash chains do not defend against an attacker who controls the underlying storage tier. Enterprise deployments requiring regulatory compliance (SOC 2, ISO 27001, FedRAMP) must configure external WORM storage or RFC 3161 timestamp anchoring.
