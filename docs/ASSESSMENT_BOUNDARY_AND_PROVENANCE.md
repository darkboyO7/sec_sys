# VAPT SYSTEM — ASSESSMENT BOUNDARY AND PROVENANCE
## Defensive Scanning Constraints, Passive Adapter Boundaries, and Evidence Provenance (Prompt 13)

---

## 1. Executive Summary & Purpose

The **VAPT Defensive Security Platform** is architected exclusively for authorized defensive vulnerability identification, risk prioritization, and independent verification. Under no circumstances does the platform engage in adversarial exploitation, aggressive port flooding, denial of service (DoS), fuzzing, brute-force credential stuffing, or exploit payload delivery.

This document establishes the defensive assessment boundaries enforced across all scanner adapters, documents the separation between live network observations and simulated fixtures, details outbound traffic constraints (SSRF, DNS rebinding, socket pinning), and defines the cryptographic evidence provenance pipeline.

---

## 2. Defensive Assessment Boundary Architecture

### 2.1 Core Architectural Principles
1. **Passive Observation First:** Where possible, vulnerabilities and asset exposures are identified via non-intrusive observation (HTTP response headers, TLS handshake parameters, public service banners, DNS metadata, and RFC 9116 `security.txt` files).
2. **Strictly Prohibited Techniques:**
   - **No Raw Socket Sweeps / Port Flooding:** Scanning engines are forbidden from transmitting SYN floods, ICMP sweeps, or randomized port scans.
   - **No Denial of Service (DoS):** Slowloris, buffer overflow crashing probes, stress-testing HTTP floods, and resource-exhaustion payloads are prohibited at both adapter and engine levels.
   - **No Brute-Force or Credential Guessing:** Password dictionaries, username enumerators, and automated login attempts are completely excluded.
   - **No Weaponized Payloads:** SQL injection probes, remote code execution (RCE) shellcode, memory corruption exploits, and cross-site scripting (XSS) reflection scripts are never dispatched. Assessment focuses on static analysis, configuration validation, software composition analysis (SCA), and non-destructive header audits.
3. **Execution Sandbox & Resource Clamps:**
   - Subprocess worker execution is governed by operating system constraints (Win32 Job Objects on Windows) enforcing CPU quotas, memory limits (512MB default clamp per worker), restricted token privileges, and strict sub-process creation prohibition.

---

## 3. Scanner Adapters: Live vs. Simulated Disambiguation

The platform supports multiple scanner adapters managed through a central `AdapterRegistry`. Every adapter explicitly declares its operational mode via the `is_simulated` boolean attribute.

```
+-------------------------------------------------------------------------+
|                           AdapterRegistry                               |
+------------------------------------+------------------------------------+
                                     |
           +-------------------------+-------------------------+
           |                                                   |
           v                                                   v
+-----------------------------+             +-----------------------------+
|   LiveNetworkAuditorAdapter |             |     LocalFixtureAdapter     |
|   (is_simulated = False)    |             |    (is_simulated = True)    |
+-----------------------------+             +-----------------------------+
| - Non-destructive HTTP/TLS  |             | - Deterministic test data   |
| - Pre-flight scope check    |             | - Offline verification      |
| - Single DNS resolution     |             | - Synthetic findings for    |
| - SSRF / Rebinding filter   |             |   unit & integration tests  |
| - Pinned socket connection  |             | - No outbound network I/O   |
| - RFC 9116 / robots audit   |             |                             |
+-----------------------------+             +-----------------------------+
```

### 3.1 LiveNetworkAuditorAdapter (`is_simulated = False`)
The live network auditor performs non-destructive passive inspections against explicitly authorized targets:
- **HTTP Header Inspection:** Audits security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`).
- **TLS/SSL Handshake Audit:** Inspects cipher suites, TLS protocol versions (flagging TLS 1.0/1.1 as deprecated), certificate expiration, issuer trust, and hostname matching.
- **Resource Probing:** Non-intrusive GET requests to standard informational paths:
  - `/.well-known/security.txt` (RFC 9116 security contact).
  - `/robots.txt` (disclosed sensitive directories).
- **Safe Network Layer:** All network traffic routes through custom socket factories (`SafeHTTPConnection` and `SafeHTTPSConnection`) that enforce SSRF and DNS rebinding protections.

### 3.2 LocalFixtureAdapter & Simulated Adapters (`is_simulated = True`)
Simulated adapters generate deterministic, pre-configured vulnerability findings and asset metadata for offline verification, unit testing, integration tests, and sandbox demonstrations.
- **Explicit Provenance Tagging:** All findings generated by simulated adapters carry `is_simulated: true` in their metadata and raw tool evidence.
- **No Outbound Network I/O:** These adapters do not open raw or TCP sockets and execute completely in memory.
- **Governance Isolation:** Findings marked with `is_simulated: true` are isolated or down-weighted during production risk recalculations and are prevented from triggering live external remediation notifications.

---

## 4. Outbound Network Controls: SSRF, DNS Rebinding & Socket Pinning

To prevent the platform from being weaponized or coerced into probing unauthorized internal networks, cloud metadata services, or loopback interfaces, all outbound HTTP/HTTPS requests are strictly regulated.

### 4.1 Single DNS Resolution and IP Validation
Before an outbound socket is established, the target hostname is resolved exactly once using `socket.getaddrinfo`. The resolved IP address is validated against a comprehensive blacklist:

```python
# Prohibited IP Address Categories
BLOCKED_RANGES = [
    IPv4Network("127.0.0.0/8"),       # Loopback
    IPv4Network("10.0.0.0/8"),        # RFC 1918 Private
    IPv4Network("172.16.0.0/12"),     # RFC 1918 Private
    IPv4Network("192.168.0.0/16"),    # RFC 1918 Private
    IPv4Network("169.254.0.0/16"),    # Link-Local / Cloud Metadata
    IPv4Network("100.64.0.0/10"),     # Carrier-Grade NAT
    IPv4Network("224.0.0.0/4"),       # Multicast
    IPv4Network("240.0.0.0/4"),       # Reserved
    IPv6Network("::1/128"),           # IPv6 Loopback
    IPv6Network("fc00::/7"),          # IPv6 Unique Local
    IPv6Network("fe80::/10"),         # IPv6 Link-Local
]
```

### 4.2 Cloud Metadata Endpoint Blocking
Specific cloud provider metadata endpoints are blocked by explicit IP and hostname rules:
- AWS/GCP/Azure/OpenStack metadata IP: `169.254.169.254`.
- AWS IPv6 metadata IP: `fd00:ec2::254`.
- Alibaba Cloud metadata IP: `100.100.100.200`.
- Metadata hostnames: `metadata.google.internal`, `instance-data`.

### 4.3 Socket Pinning (DNS Rebinding Defense)
Standard HTTP client libraries re-resolve DNS during connection establishment, creating a Time-of-Check to Time-of-Use (TOCTOU) vulnerability where an attacker's DNS server returns a public IP during preflight validation, but an internal IP (`127.0.0.1` or `169.254.169.254`) when the connection is opened.

The VAPT platform neutralizes DNS rebinding via **Socket Pinning**:
1. The pre-verified IP is assigned directly as `self.verified_ip`.
2. When creating the underlying TCP socket, the connection is made directly to `(self.verified_ip, port)`.
3. The original target hostname is preserved in the HTTP `Host` header and the TLS Server Name Indication (`server_hostname` for SNI) to allow legitimate virtual hosting and certificate validation while guaranteeing that packets physically traverse only to the verified IP address.

---

## 5. Evidence Provenance & Cryptographic Traceability Pipeline

Every finding reported by an assessment worker must provide cryptographic proof of its discovery. The platform enforces an unbroken chain of custody from raw network responses to persistent findings.

```
+-------------------------------------------------------------------------+
|                        Raw Adapter Execution                            |
| (HTTP Response, SSL Handshake, Tool Output, RFC 9116 Text)              |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                   Payload Clamping & Hashing Phase                      |
| - Compute raw_sha256_hash = SHA256(raw_bytes)                           |
| - If len(raw_bytes) > 1MB: Truncate to 1MB and append notice            |
| - Compute sha256_hash = SHA256(clamped_bytes)                           |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                      FindingEvidence Record Persisted                   |
| - assessment_job_id, finding_id, evidence_type, collector_module        |
| - payload_bytes / text, sha256_hash, raw_sha256_hash, captured_at      |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                      Evidence Merkle Tree Generation                    |
| - Binary Merkle Tree constructed over all Job Evidence hashes           |
| - Root digest committed to Job Completion Record & Merkle Audit Ledger  |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  Independent Integrity Verification                     |
| - IntegrityService re-hashes evidence from DB & compares digests        |
| - If any byte modified: Verification fails, alerts raised               |
+-------------------------------------------------------------------------+
```

### 5.1 Evidence Payload Clamping
- **Maximum Evidence Size:** Hard clamped to `MAX_EVIDENCE_PAYLOAD_BYTES = 1,048,576` (1MB) per evidence item.
- **Safe Truncation:** If a tool output or HTTP body exceeds 1MB, it is truncated deterministically with an appended marker:
  `\n[TRUNCATED: Exceeded 1MB evidence clamp. Total size: N bytes]`
- **Dual SHA-256 Hashes:**
  - `raw_sha256_hash`: SHA-256 digest of the complete original response before truncation.
  - `sha256_hash`: SHA-256 digest of the stored (clamped) payload.
  This allows auditors to verify both that the database record is untampered and that the original stream matched the expected upstream fingerprint.

### 5.2 Merkle Tree Evidence Verification
For every completed assessment job, all evidence hashes are assembled into a balanced binary Merkle tree:
1. Leaf nodes: $L_i = \text{SHA256}(\text{evidence}_i)$.
2. Parent nodes: $P = \text{SHA256}(L_{\text{left}} \mid L_{\text{right}})$.
3. Root digest: $M_{\text{root}}$ is recorded in the job completion summary and cross-referenced in the immutable Merkle audit ledger.
4. Tamper detection: Any modification to an evidence record invalidates the leaf hash and propagates to a root mismatch, allowing automated integrity verification (`IntegrityService.verify_evidence_integrity`) to immediately pinpoint corrupted records.

---

## 6. Verification Summary

| Constraint / Mechanism | Implementation Module | Verification Test | Status |
| :--- | :--- | :--- | :--- |
| **Passive Observation Clamp** | `LiveNetworkAuditorAdapter` | `test_live_network_adapter.py` | **VERIFIED** |
| **Simulated Adapter Isolation** | `LocalFixtureAdapter` (`is_simulated = True`) | `test_phase7b_scanner_framework.py` | **VERIFIED** |
| **SSRF & Metadata Filter** | `check_ip_ssrf` | `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_14` | **VERIFIED** |
| **DNS Rebinding Socket Pinning**| `SafeHTTPConnection.connect` | `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_14` | **VERIFIED** |
| **1MB Payload Clamping** | `FindingEvidenceService` | `test_phase8_evidence_integrity.py` | **VERIFIED** |
| **Dual SHA-256 Evidence Hashes**| `IntegrityService` | `test_prompt13_cross_system_integrity_and_validation.py::test_scenario_4` | **VERIFIED** |
| **Binary Merkle Tree Proofs** | `IntegrityService.get_evidence_merkle_proof` | `test_phase8_evidence_integrity.py` | **VERIFIED** |
