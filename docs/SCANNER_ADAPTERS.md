# VAPT Platform — Scanner Adapters & Execution Contract

## 1. Overview

The VAPT Platform uses a pluggable scanner adapter architecture. To ensure system reliability and complete defensive safety, all scanning adapters adhere to strict programmatic contracts, hard timeout boundaries, and deterministic simulation guarantees.

---

## 2. Scanner Adapter Contract (`BaseScannerAdapter`)

All adapters inherit from `BaseScannerAdapter` located in `backend/app/services/scanner_adapters/base.py`. Every adapter must implement:

```python
class BaseScannerAdapter(ABC):
    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """Unique identifier for adapter registration."""
        pass

    @property
    @abstractmethod
    def adapter_version(self) -> str:
        """Semantic version of the adapter."""
        pass

    @abstractmethod
    def execute_scan(
        self,
        targets: List[str],
        parameters: Optional[Dict[str, Any]] = None,
        job_id: Optional[str] = None,
    ) -> AdapterExecutionResult:
        """
        Executes bounded, deterministic scan and returns standardized results.
        Must never raise unhandled exceptions; errors must be captured in AdapterExecutionResult.
        """
        pass
```

---

## 3. Registered Scanner Adapters

The platform currently includes four production-grade simulated adapters:

| Adapter Name | Adapter Identifier | Capabilities & Target Scope | Output Artifacts |
| :--- | :--- | :--- | :--- |
| **Passive HTTP Header Analyzer** | `passive_header_adapter` | Inspects HTTP response headers (HSTS, CSP, X-Frame-Options, Cache-Control, Cookie flags). | Header security findings, raw HTTP header evidence records. |
| **Port & Service Discovery** | `port_discovery_adapter` | Simulates open TCP/UDP port enumeration and banner discovery for IP/domain targets. | Open port findings, service banners, protocol classification. |
| **Configuration Auditor** | `config_audit_adapter` | Analyzes server configuration parameters, TLS cipher suites, and cryptographic protocols. | TLS posture findings, cipher weakness alerts, configuration diffs. |
| **Synthetic Vulnerability Generator** | `synthetic_vuln_adapter` | Generates deterministic synthetic multi-severity findings for end-to-end integration testing. | Diverse findings across all CVSS severity tiers and confidence bands. |

---

## 4. Operational Invariants & Defensive Boundaries

### 4.1. Simulation Guarantee (`is_simulated = True`)
Every finding emitted by a scanner adapter includes the immutable metadata flag `is_simulated = True`.
- Under no circumstances does any adapter open raw network sockets, dispatch TCP SYN floods, execute brute-force attacks, or transmit weaponized exploit payloads.
- All target interactions are bounded, synthetic, and designed purely for defensive evaluation and compliance auditing.

### 4.2. Evidence Payload Truncation Ceiling
To protect database storage and memory from memory-exhaustion denial of service:
- `MAX_EVIDENCE_PAYLOAD_BYTES`: 65,536 bytes (64 KB).
- If a scanner output exceeds this ceiling, the adapter safely truncates the payload, appends `\n[... TRUNCATED AT 64KB MAXIMUM CEILING ...]`, sets `is_truncated = True`, and computes the SHA-256 digest over the truncated payload while preserving `raw_sha256_hash` for the original stream.

### 4.3. Execution Timeouts & Process Budgeting
- Default adapter timeout: **60 seconds**.
- Worker process timeout: **180 seconds**.
- Worker runner forcibly terminates subprocesses exceeding their execution budget with `SIGKILL` / `TerminateProcess`, transitions the job to `FAILED`, and records a timeout audit event.

---

## 5. Standardized Output Schema (`AdapterExecutionResult`)

Every scan execution returns a strongly-typed `AdapterExecutionResult` containing:
- `status`: `SUCCESS`, `PARTIAL_SUCCESS`, `FAILED`, or `TIMEOUT`.
- `findings`: List of `RawFinding` objects:
  - `title`: Explanatory title.
  - `description`: Technical explanation of vulnerability.
  - `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`.
  - `confidence`: `CERTAIN`, `FIRM`, or `TENTATIVE`.
  - `cvss_score`: Float between 0.0 and 10.0.
  - `cve_id`: Optional CVE identifier (e.g. `CVE-2023-38606`).
  - `remediation_guidance`: Remediation actions and best practices.
  - `evidence_records`: List of evidence items with raw payloads and hashes.
- `error_message`: Detailed error traceback if execution failed.
- `metadata`: Adapter version, execution duration, and target count.
