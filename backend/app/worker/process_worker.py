"""Isolated Scanner Process Worker.

This script executes scanner adapters in an independent OS subprocess.
It communicates exclusively via stdin/stdout using typed JSON IPC protocol 1.0.0.
Diagnostic logs are written to stderr.
"""
import sys
import os
import json
import time
from typing import Dict, Any

# Ensure scanner adapters are registered
from app.services.scanner_adapters.base import AdapterRegistry
from app.services.scanner_adapters.local_fixture_adapter import LocalFixtureAdapter
from app.worker.ipc_schemas import WorkerIPCRequest, WorkerIPCResponse, SUPPORTED_PROTOCOL_VERSION


def main() -> int:
    try:
        raw_input = sys.stdin.read()
        if not raw_input or not raw_input.strip():
            sys.stderr.write("[process_worker] Empty request payload received on stdin.\n")
            return 2

        try:
            req_data = json.loads(raw_input)
            request = WorkerIPCRequest.model_validate(req_data)
        except Exception as e:
            sys.stderr.write(f"[process_worker] Invalid IPC request payload: {e}\n")
            return 3

        adapter = AdapterRegistry.get(request.adapter_name)
        if not adapter:
            sys.stderr.write(f"[process_worker] Adapter '{request.adapter_name}' not registered in worker.\n")
            err_response = WorkerIPCResponse(
                protocol_version=SUPPORTED_PROTOCOL_VERSION,
                job_id=request.job_id,
                project_id=request.project_id,
                worker_id=request.worker_id,
                attempt_count=request.attempt_count,
                success=False,
                status_summary=f"Adapter '{request.adapter_name}' is not registered.",
                failure_category="UNSUPPORTED_ADAPTER",
                errors=[f"UNSUPPORTED_ADAPTER: {request.adapter_name}"],
                findings=[],
                execution_duration_ms=0.0,
                is_simulated=True,
                process_stats={"pid": os.getpid()},
            )
            sys.stdout.write(err_response.model_dump_json())
            sys.stdout.flush()
            return 0

        # Execute adapter safely, protecting stdout from stray adapter prints
        start_time = time.perf_counter()
        real_stdout = sys.stdout
        sys.stdout = sys.stderr
        try:
            result = adapter.execute(
                target=request.target_input,
                config=request.config,
            )
            duration_ms = (time.perf_counter() - start_time) * 1000
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            sys.stderr.write(f"[process_worker] Exception during adapter execution: {e}\n")
            err_response = WorkerIPCResponse(
                protocol_version=SUPPORTED_PROTOCOL_VERSION,
                job_id=request.job_id,
                project_id=request.project_id,
                worker_id=request.worker_id,
                attempt_count=request.attempt_count,
                success=False,
                status_summary=f"Worker exception: {str(e)}"[:1000],
                failure_category="WORKER_EXCEPTION",
                errors=[str(e)[:500]],
                findings=[],
                execution_duration_ms=duration_ms,
                is_simulated=True,
                process_stats={"pid": os.getpid()},
            )
            real_stdout.write(err_response.model_dump_json())
            real_stdout.flush()
            return 0
        finally:
            sys.stdout = real_stdout

        # Build successful/normal response
        response = WorkerIPCResponse(
            protocol_version=SUPPORTED_PROTOCOL_VERSION,
            job_id=request.job_id,
            project_id=request.project_id,
            worker_id=request.worker_id,
            attempt_count=request.attempt_count,
            success=result.success,
            status_summary=result.status_summary,
            failure_category=result.failure_category,
            errors=result.errors,
            findings=result.findings,
            execution_duration_ms=result.execution_duration_ms or duration_ms,
            is_simulated=result.is_simulated,
            process_stats={
                "pid": os.getpid(),
                "duration_ms": duration_ms,
            },
        )

        sys.stdout.write(response.model_dump_json())
        sys.stdout.flush()
        return 0

    except Exception as fatal_err:
        sys.stderr.write(f"[process_worker] Fatal unhandled exception: {fatal_err}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
