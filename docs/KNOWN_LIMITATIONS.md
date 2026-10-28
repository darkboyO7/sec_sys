# VAPT Platform — Known Operational Limitations & Release Boundaries

**Audit Checkpoint:** Release Milestone  
**Target OS:** Native Windows 11 Enterprise  
**Governance Standard:** Transparent, Truthful Operational Boundaries  

---

## 1. Technical & Operational Limitations

### 1.1 Physical PostgreSQL Multi-Worker Clustering (`NOT VERIFIED`)
- **Limitation:** The platform code includes complete PostgreSQL connection pooling (`QueuePool`, `pool_size=20`), transient deadlock retries (`with_transaction_retry`), and atomic `FOR UPDATE SKIP LOCKED` query AST compilation. However, physical multi-worker concurrent transactions have **not** been executed against a live physical PostgreSQL server because no PostgreSQL instance is installed on this local Windows host.
- **Operational Boundary:** Certified for production on single-node Windows with SQLite WAL. Multi-worker cluster deployment requires prior execution of the [Staging Runbook](file:///C:/Users/Dark_Boy_/Downloads/VAPT_System/docs/DATABASE_SUPPORT.md#L66).

### 1.2 Real Network Auditing vs Active Destructive Exploitation (VERIFIED OPERATIONAL)
- **Operational Capability:** Genuine non-intrusive live network security assessment is fully operational via LiveNetworkAuditorAdapter (live_network_auditor_adapter). It connects directly over TCP/TLS/HTTP to authorized live endpoints, validates TLS certificate chains and cipher parameters, inspects HTTP response headers, parses security resources (
obots.txt, security.txt, cookie attributes), grabs banners, and correlates findings into the Knowledge Graph and Contextual Risk engines.
- **SSRF & Scope Guardrails:** All network assessments strictly enforce preflight scope authorization (requiring project LEAD approval with verifiable ROE evidence), DNS TOCTOU resolution-to-socket pinning (SafeHTTPConnection and SafeHTTPSConnection bound to preflight-verified IP with SNI preservation), IPv4/IPv6 range restrictions, and blocking of cloud metadata and internal infrastructure unless explicitly authorized for internal staging.
- **Operational Boundary:** Active destructive exploitation, intrusive remote code execution fuzzing, and unconstrained denial-of-service stress testing remain prohibited by policy to protect system availability.

### 1.3 Out-of-Band Hardware Trust Anchoring (`PARTIALLY VERIFIED`)
- **Limitation:** Evidence and audit integrity are protected via SHA-256 Merkle trees, hash chaining, local symmetric HMAC anchoring, and append-only log archiving. The platform does not currently connect to external RFC 3161 public Time-Stamp Authorities (TSA) or hardware Write-Once-Read-Many (WORM) storage appliances.
- **Operational Boundary:** Tamper detection is guaranteed against database-level manipulation. Detection of whole-host compromise requires securing the application secret key and append-only archive file outside the database host.

### 1.4 Single-Writer Concurrency in SQLite WAL
- **Limitation:** In SQLite WAL mode, readers do not block writers and writers do not block readers. However, write operations are strictly serialized (single writer at a time).
- **Operational Boundary:** If write contention exceeds the 5,000ms busy timeout (`PRAGMA busy_timeout = 5000`), requests fail with `OperationalError: database is locked`. The platform handles this via automatic exponential backoff retries (`DB_RETRY_MAX_ATTEMPTS=3`).

### 1.5 Historical Key Rotation
- **Limitation:** When using symmetric HMAC anchoring (`HMACExternalTrustAnchor`), rotating `SECRET_KEY` without preserving historical keys in a keyring will cause legacy anchor verifications to fail.
- **Operational Boundary:** Key rotation is supported in `AppendOnlyArchiveTrustAnchor` via multi-key dictionaries (`keys={"key-v1": "...", "key-v2": "..."}`). When rotating the primary system key, legacy key material must be preserved in the trust anchor configuration.

### 1.6 Cryptographic Integrity Hashes vs Asymmetric Digital Signatures
- **Limitation:** Exported manifests and evidence records contain cryptographic SHA-256 digests (`manifest_sha256`) of canonical JSON for tamper detection and audit trail anchoring. This is an integrity check, not an asymmetric public-key digital signature (e.g. Ed25519 or RSA-PSS with X.509 certificates).
- **Operational Boundary:** While SHA-256 digests detect data modification within the operational boundary, public non-repudiation and external third-party attestation require deploying an enterprise PKI digital signing service.
