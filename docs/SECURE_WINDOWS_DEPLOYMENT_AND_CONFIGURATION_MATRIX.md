# Secure Windows Deployment, Configuration Governance & Safe Upgrades Traceability Matrix (Prompt 28)

## 1. Overview
This matrix documents the verification, enforcement points, and test mappings for Prompt 28 — Secure Windows Deployment, Configuration Governance, and Safe Application Upgrades.

## 2. Requirement to Test & Enforcement Mapping

| Req ID | Requirement Description | Implementation / Enforcement Point | Automated Test Verification | Status |
|---|---|---|---|---|
| **DEP-01** | Central typed configuration validation & strict parsing | `app.core.config.Settings`, `app.schemas.deployment.RedactedConfigResponse` | `test_prompt28_secure_windows_deployment.py::test_07_redacted_config_masks_database_and_secret_tokens` | **VERIFIED** |
| **DEP-02** | Secret key cryptographic hardening (min 32 chars) | `StartupPreflightService.run_preflight_checks()` | `test_prompt28_secure_windows_deployment.py::test_02_preflight_fails_on_short_secret_key` | **VERIFIED** |
| **DEP-03** | Rejection of insecure default credentials in production | `StartupPreflightService.run_preflight_checks()` | `test_prompt28_secure_windows_deployment.py::test_03_preflight_fails_on_insecure_production_secret` | **VERIFIED** |
| **DEP-04** | CORS policy security & wildcard prevention | `StartupPreflightService.run_preflight_checks()` | `test_prompt28_secure_windows_deployment.py::test_04_preflight_warns_on_wildcard_cors_in_development`, `test_05_preflight_fails_on_wildcard_cors_in_production` | **VERIFIED** |
| **DEP-05** | Production debug mode exposure block | `StartupPreflightService.run_preflight_checks()` | `test_prompt28_secure_windows_deployment.py::test_06_preflight_fails_on_debug_in_production` | **VERIFIED** |
| **DEP-06** | Redacted configuration diagnostic without leaking secrets | `StartupPreflightService.get_redacted_config()`, `GET /system/deployment/config` | `test_prompt28_secure_windows_deployment.py::test_07_redacted_config_masks_database_and_secret_tokens`, `test_15_api_config_endpoint_returns_redacted_settings` | **VERIFIED** |
| **DEP-07** | Safe storage directory hierarchy (data, evidence, backups, logs) | `StartupPreflightService.ensure_data_directories()` | `test_prompt28_secure_windows_deployment.py::test_09_safe_data_directories_creation` | **VERIFIED** |
| **DEP-08** | Storage writability verification & unhandled crash prevention | `StartupPreflightService.run_preflight_checks()` | `test_prompt28_secure_windows_deployment.py::test_10_directory_writability_check_detects_unwritable_paths` | **VERIFIED** |
| **DEP-09** | Cryptographic primitives engine verification (SHA-256, HMAC) | `StartupPreflightService.run_preflight_checks()` | `test_prompt28_secure_windows_deployment.py::test_11_crypto_primitives_health_verification` | **VERIFIED** |
| **DEP-10** | Database engine connectivity & SQLite WAL/FK pragmas | `StartupPreflightService.run_preflight_checks()` | `test_prompt28_secure_windows_deployment.py::test_01_preflight_checks_pass_under_healthy_configuration` | **VERIFIED** |
| **DEP-11** | Idempotent environment initialization (secret preservation) | `scripts/initialize_environment.py` | `test_prompt28_secure_windows_deployment.py::test_12_initialize_environment_preserves_existing_secrets_idempotently` | **VERIFIED** |
| **DEP-12** | Secure random credential generation on fresh install | `scripts/initialize_environment.py` | `test_prompt28_secure_windows_deployment.py::test_13_initialize_environment_generates_secure_key_when_missing` | **VERIFIED** |
| **DEP-13** | Schema upgrade readiness & Alembic migration head tracking | `StartupPreflightService.check_upgrade_readiness()`, `POST /system/deployment/upgrade-check` | `test_prompt28_secure_windows_deployment.py::test_08_upgrade_readiness_detects_schema_revision`, `test_16_api_upgrade_check_endpoint_evaluates_readiness` | **VERIFIED** |
| **DEP-14** | Automated pre-upgrade snapshot / point-in-time backup | `scripts/upgrade_platform.py` | Verified in live execution (`vapt_pre_upgrade_*.db` created) | **VERIFIED** |
| **DEP-15** | Role-based access control for administrative deployment APIs | `app.api.v1.endpoints.deployment` (`require_system_roles`) | `test_prompt28_secure_windows_deployment.py::test_14_api_preflight_endpoint_requires_auth_and_authorized_role` | **VERIFIED** |
| **DEP-16** | Path traversal safeguards for evidence and exports | `StartupPreflightService`, filesystem path resolution | `test_prompt28_secure_windows_deployment.py::test_17_path_traversal_protection_in_filesystem_safeguards` | **VERIFIED** |
| **DEP-17** | Frontend deployment governance dashboard | `DeploymentGovernanceView.tsx`, `api.ts`, `App.tsx` | `frontend/src/tests/deployment.test.ts` (3 tests passed) | **VERIFIED** |

## 3. Operator Procedures (PowerShell on Windows)

### 3.1 First-Time Setup & Idempotent Configuration
```powershell
.\.venv\Scripts\python.exe scripts\initialize_environment.py
```
- Creates `backend/data/{evidence,backups,logs}`.
- If `.env` exists: Preserves existing credentials without modification.
- If `.env` is absent: Generates 64-char cryptographically secure `SECRET_KEY` and safe loopback defaults.

### 3.2 Safe Schema Upgrade
```powershell
.\.venv\Scripts\python.exe scripts\upgrade_platform.py
```
- Checks current revision against migration head (`e4f5a6b7c8d9`).
- Automatically takes a timestamped SQLite snapshot into `backend/data/backups/`.
- Executes `alembic upgrade head`.
- Validates post-upgrade preflight health.
