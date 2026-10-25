"""Subprocess Worker Runner for isolated scanner execution.

Enforces:
1. Spawning via subprocess.Popen with shell=False strictly.
2. Stripping secrets from child process environment (sanitized environment).
3. Supervised execution with cooperative cancellation and graceful/forceful teardown.
4. Windows process tree termination via 'taskkill /F /T /PID'.
5. Payload size bounds (<= 10MB) and IPC identity validation.
6. Verification that child process has fully exited before returning.
"""
import os
import sys
import json
import time
import subprocess
import logging
from typing import Dict, Any, Optional, Callable, List
from app.core.config import settings
from app.services.scanner_adapters.base import AdapterResult, RawAdapterFinding
from app.worker.ipc_schemas import WorkerIPCRequest, WorkerIPCResponse, SUPPORTED_PROTOCOL_VERSION

logger = logging.getLogger(__name__)

# Strict allowlist of safe OS environment variables for child processes
SAFE_ENV_ALLOWLIST = {
    "SYSTEMROOT",
    "WINDIR",
    "PATH",
    "TEMP",
    "TMP",
    "SYSTEMDRIVE",
    "LOCALAPPDATA",
    "COMSPEC",
    "PATHEXT",
    "HOMEDRIVE",
    "HOMEPATH",
    "USERPROFILE",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
}


def build_sanitized_env(extra_pythonpath: Optional[str] = None) -> Dict[str, str]:
    """
    Constructs a sanitized environment dictionary.
    Explicitly strips SECRET_KEY, DATABASE_URL, access tokens, and server secrets.
    """
    clean_env: Dict[str, str] = {}
    for key, val in os.environ.items():
        if key.upper() in SAFE_ENV_ALLOWLIST:
            clean_env[key] = val

    # Ensure python knows where the backend module is
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    existing_pp = clean_env.get("PYTHONPATH", "")
    if extra_pythonpath:
        clean_env["PYTHONPATH"] = f"{extra_pythonpath};{backend_dir}" if existing_pp else f"{extra_pythonpath};{backend_dir}"
    else:
        clean_env["PYTHONPATH"] = f"{backend_dir};{existing_pp}" if existing_pp else backend_dir

    return clean_env


def is_process_alive(pid: int) -> bool:
    """
    Canonically queries whether an OS process with the given PID is currently active.
    On Windows, uses Win32 OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION and GetExitCodeProcess.
    On POSIX, uses os.kill(pid, 0).
    """
    if not pid or pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.windll.kernel32
            # 0x1000 = PROCESS_QUERY_LIMITED_INFORMATION
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return False
            try:
                exit_code = wintypes.DWORD()
                STILL_ACTIVE = 259
                if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return exit_code.value == STILL_ACTIVE
                return False
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def terminate_process_tree(pid: int, timeout_sec: float = 3.0) -> None:
    """
    Forcefully terminates a Windows process and all its descendants using taskkill.
    """
    if not pid or pid <= 0:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                timeout=timeout_sec,
                check=False,
            )
        else:
            os.kill(pid, 9)
    except Exception as e:
        logger.warning(f"Error terminating process tree for PID {pid}: {e}")


class SubprocessWorkerRunner:
    """
    Supervises the execution of an isolated worker process.
    """
    worker_cmd: Optional[List[str]] = None

    def __init__(
        self,
        execution_mode: Optional[str] = None,
        worker_cmd: Optional[List[str]] = None,
    ):
        self.execution_mode = execution_mode or settings.EXECUTION_MODE
        self.worker_cmd = worker_cmd or self.__class__.worker_cmd or [sys.executable, "-m", "app.worker.process_worker"]
        self.last_spawned_pid: Optional[int] = None

    def run_job(
        self,
        request: WorkerIPCRequest,
        cancellation_check: Optional[Callable[[], bool]] = None,
        on_spawn: Optional[Callable[[int], None]] = None,
    ) -> AdapterResult:
        """
        Executes a job inside an isolated subprocess worker.
        """
        start_time = time.perf_counter()
        timeout_seconds = request.timeout_seconds
        grace_period = settings.WORKER_TIMEOUT_GRACE_PERIOD_SECONDS
        max_bytes = settings.WORKER_MAX_IPC_PAYLOAD_BYTES

        # Check early cancellation before spawning
        if cancellation_check and cancellation_check():
            duration_ms = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=request.adapter_name,
                adapter_version=request.adapter_version,
                target=request.target_input,
                is_simulated=True,
                success=False,
                status_summary="Assessment execution halted by cancellation request prior to spawn.",
                errors=["EXECUTION_CANCELLED: Operation aborted by operator prior to worker spawn."],
                failure_category="CANCELLED_BY_OPERATOR",
                findings=[],
                execution_duration_ms=duration_ms,
            )

        sanitized_env = build_sanitized_env()
        cmd = list(self.worker_cmd)

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=sanitized_env,
                shell=False,  # STRICT: never use shell=True
            )
        except Exception as spawn_err:
            duration_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Failed to spawn worker subprocess: {spawn_err}")
            return AdapterResult(
                adapter_name=request.adapter_name,
                adapter_version=request.adapter_version,
                target=request.target_input,
                is_simulated=True,
                success=False,
                status_summary=f"Worker subprocess spawn failed: {str(spawn_err)}",
                errors=[f"WORKER_SPAWN_FAILED: {str(spawn_err)}"],
                failure_category="WORKER_SPAWN_FAILED",
                findings=[],
                execution_duration_ms=duration_ms,
            )

        self.last_spawned_pid = proc.pid
        if on_spawn:
            try:
                on_spawn(proc.pid)
            except Exception as cb_err:
                logger.warning(f"Error in on_spawn callback: {cb_err}")

        # Send request payload
        req_json_bytes = request.model_dump_json().encode("utf-8")
        first_communicate = True
        stdout_data = b""
        stderr_data = b""

        try:
            while proc.poll() is None:
                # Check elapsed execution time
                elapsed = time.perf_counter() - start_time
                if elapsed > timeout_seconds:
                    duration_ms = elapsed * 1000
                    logger.warning(f"Worker PID {proc.pid} exceeded timeout ({timeout_seconds}s). Terminating.")
                    terminate_process_tree(proc.pid, timeout_sec=float(grace_period))
                    try:
                        proc.wait(timeout=grace_period)
                    except Exception:
                        pass
                    return AdapterResult(
                        adapter_name=request.adapter_name,
                        adapter_version=request.adapter_version,
                        target=request.target_input,
                        is_simulated=True,
                        success=False,
                        status_summary=f"Worker process exceeded timeout deadline ({timeout_seconds}s).",
                        errors=[f"WORKER_PROCESS_TIMEOUT: Execution exceeded {timeout_seconds}s."],
                        failure_category="WORKER_PROCESS_TIMEOUT",
                        findings=[],
                        execution_duration_ms=duration_ms,
                    )

                # Check cooperative cancellation
                if cancellation_check and cancellation_check():
                    duration_ms = (time.perf_counter() - start_time) * 1000
                    logger.info(f"Cancellation requested for Worker PID {proc.pid}. Terminating.")
                    terminate_process_tree(proc.pid, timeout_sec=float(grace_period))
                    try:
                        proc.wait(timeout=grace_period)
                    except Exception:
                        pass
                    return AdapterResult(
                        adapter_name=request.adapter_name,
                        adapter_version=request.adapter_version,
                        target=request.target_input,
                        is_simulated=True,
                        success=False,
                        status_summary="Assessment execution halted by cancellation request.",
                        errors=["EXECUTION_CANCELLED: Operation aborted by operator."],
                        failure_category="CANCELLED_BY_OPERATOR",
                        findings=[],
                        execution_duration_ms=duration_ms,
                    )

                try:
                    inp = req_json_bytes if first_communicate else None
                    first_communicate = False
                    chunk_out, chunk_err = proc.communicate(input=inp, timeout=0.2)
                    if chunk_out:
                        stdout_data += chunk_out
                    if chunk_err:
                        stderr_data += chunk_err
                    break
                except subprocess.TimeoutExpired as expired:
                    if expired.output:
                        stdout_data += expired.output
                    if expired.stderr:
                        stderr_data += expired.stderr
                    # Check maximum byte length of stream so far
                    if len(stdout_data) > max_bytes:
                        duration_ms = (time.perf_counter() - start_time) * 1000
                        terminate_process_tree(proc.pid, timeout_sec=float(grace_period))
                        return AdapterResult(
                            adapter_name=request.adapter_name,
                            adapter_version=request.adapter_version,
                            target=request.target_input,
                            is_simulated=True,
                            success=False,
                            status_summary=f"Worker exceeded maximum IPC payload size limit of {max_bytes} bytes.",
                            errors=[f"WORKER_PAYLOAD_EXCEEDED: Exceeded {max_bytes} bytes."],
                            failure_category="WORKER_PAYLOAD_EXCEEDED",
                            findings=[],
                            execution_duration_ms=duration_ms,
                        )

            # Confirm process has fully exited
            try:
                proc.wait(timeout=grace_period)
            except Exception:
                terminate_process_tree(proc.pid)

        finally:
            # Ensure process file descriptors are closed safely
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream and not stream.closed:
                    try:
                        stream.close()
                    except Exception:
                        pass

        duration_ms = (time.perf_counter() - start_time) * 1000

        # Check payload size
        if len(stdout_data) > max_bytes:
            return AdapterResult(
                adapter_name=request.adapter_name,
                adapter_version=request.adapter_version,
                target=request.target_input,
                is_simulated=True,
                success=False,
                status_summary=f"Worker exceeded maximum IPC payload size limit of {max_bytes} bytes.",
                errors=[f"WORKER_PAYLOAD_EXCEEDED: Exceeded {max_bytes} bytes."],
                failure_category="WORKER_PAYLOAD_EXCEEDED",
                findings=[],
                execution_duration_ms=duration_ms,
            )

        # Check exit code
        if proc.returncode != 0:
            stderr_snippet = stderr_data.decode("utf-8", errors="replace")[:1000]
            logger.error(f"Worker PID {proc.pid} crashed with returncode {proc.returncode}: {stderr_snippet}")
            return AdapterResult(
                adapter_name=request.adapter_name,
                adapter_version=request.adapter_version,
                target=request.target_input,
                is_simulated=True,
                success=False,
                status_summary=f"Worker process crashed with exit code {proc.returncode}.",
                errors=[f"WORKER_PROCESS_CRASHED: Exit code {proc.returncode}. Stderr: {stderr_snippet}"],
                failure_category="WORKER_PROCESS_CRASHED",
                findings=[],
                execution_duration_ms=duration_ms,
            )

        # Parse IPC JSON Response
        try:
            resp_str = stdout_data.decode("utf-8")
            resp_dict = json.loads(resp_str)
            ipc_resp = WorkerIPCResponse.model_validate(resp_dict)
        except Exception as parse_err:
            logger.error(f"Failed to parse worker IPC response: {parse_err}")
            return AdapterResult(
                adapter_name=request.adapter_name,
                adapter_version=request.adapter_version,
                target=request.target_input,
                is_simulated=True,
                success=False,
                status_summary="Worker returned unparseable or corrupted response.",
                errors=[f"CORRUPT_IPC_RESPONSE: {str(parse_err)}"],
                failure_category="CORRUPT_IPC_RESPONSE",
                findings=[],
                execution_duration_ms=duration_ms,
            )

        # Validate Identity & Provenance
        if (
            ipc_resp.protocol_version != SUPPORTED_PROTOCOL_VERSION
            or ipc_resp.job_id != request.job_id
            or ipc_resp.project_id != request.project_id
            or ipc_resp.worker_id != request.worker_id
            or ipc_resp.attempt_count != request.attempt_count
        ):
            logger.error(
                f"Worker IPC response identity mismatch. Expected job={request.job_id}, attempt={request.attempt_count}; "
                f"Got job={ipc_resp.job_id}, attempt={ipc_resp.attempt_count}"
            )
            return AdapterResult(
                adapter_name=request.adapter_name,
                adapter_version=request.adapter_version,
                target=request.target_input,
                is_simulated=True,
                success=False,
                status_summary="Worker response rejected: identity mismatch across job, project, or attempt.",
                errors=["IPC_IDENTITY_MISMATCH: Worker returned inconsistent job_id, project_id, or attempt_count."],
                failure_category="IPC_IDENTITY_MISMATCH",
                findings=[],
                execution_duration_ms=duration_ms,
            )

        # Convert to AdapterResult
        return AdapterResult(
            adapter_name=request.adapter_name,
            adapter_version=request.adapter_version,
            target=request.target_input,
            is_simulated=ipc_resp.is_simulated,
            success=ipc_resp.success,
            status_summary=ipc_resp.status_summary,
            findings=ipc_resp.findings,
            errors=ipc_resp.errors,
            failure_category=ipc_resp.failure_category,
            execution_duration_ms=ipc_resp.execution_duration_ms or duration_ms,
        )
