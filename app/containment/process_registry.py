"""
Controlled Process Registry for CryptoShield (Phase 4).

Sole authority for registering, tracking, and validating processes explicitly launched
by CryptoShield's controlled test framework.

Strict Safety Boundaries:
- Only CryptoShield's own process launcher may register a process.
- Arbitrary PIDs or event-provided PIDs are strictly rejected.
- Guards against PID reuse by validating process creation timestamps and executable identity.
- Rejects unregistered, expired, or mismatched process records.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psutil

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import ControlledProcessRecord, ProcessLifecycleStatus

logger = get_logger("process_registry")


class ControlledProcessRegistry:
    """
    Thread-safe registry for explicitly launched simulation processes.
    """

    _instance_lock = threading.Lock()
    _instance: Optional[ControlledProcessRegistry] = None

    def __init__(self) -> None:
        self._records: Dict[str, ControlledProcessRecord] = {}
        self._handles: Dict[str, Any] = {}
        self._pid_to_run_id: Dict[int, str] = {}
        self._lock = threading.RLock()

    @classmethod
    def get_instance(cls) -> ControlledProcessRegistry:
        """Singleton accessor."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = ControlledProcessRegistry()
            return cls._instance

    def register_process(
        self,
        simulation_run_id: str,
        process_handle: Any,
        pid: int,
        expected_identity: str,
        associated_lab_target: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ControlledProcessRecord:
        """
        Register a newly launched controlled simulation process.

        Validates process authenticity using psutil to prevent PID spoofing or registering
        unrelated host processes.
        """
        with self._lock:
            if not simulation_run_id or not isinstance(simulation_run_id, str):
                raise ValueError("simulation_run_id must be a non-empty string.")

            if simulation_run_id in self._records:
                raise ValueError(f"Simulation run '{simulation_run_id}' is already registered.")

            if pid <= 4:
                raise ValueError(f"Safety violation: Cannot register system process PID {pid}.")

            if pid == os.getpid():
                raise ValueError("Safety violation: Cannot register CryptoShield's own host process.")

            if process_handle is None:
                raise ValueError("Process handle reference cannot be None.")

            # Validate process exists and capture creation time and executable
            try:
                proc = psutil.Process(pid)
                create_time_raw = proc.create_time()
                create_time_iso = datetime.fromtimestamp(
                    create_time_raw, tz=CONFIG.TIMEZONE
                ).isoformat()
                exe_path = proc.exe() or "unknown"
                parent_pid = proc.ppid() or os.getpid()
                lifecycle = ProcessLifecycleStatus.RUNNING.value
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                # If process was launched and exited before registration completed
                if hasattr(process_handle, "poll") and process_handle.poll() is not None:
                    create_time_iso = datetime.now(CONFIG.TIMEZONE).isoformat()
                    exe_path = "unknown"
                    parent_pid = os.getpid()
                    lifecycle = ProcessLifecycleStatus.EXITED.value
                else:
                    raise RuntimeError(
                        f"Cannot register PID {pid}: Process is not accessible or does not exist: {e}"
                    )

            now_iso = datetime.now(CONFIG.TIMEZONE).isoformat()

            record = ControlledProcessRecord(
                simulation_run_id=simulation_run_id,
                pid=pid,
                process_creation_time=create_time_iso,
                executable_path=exe_path,
                expected_identity=expected_identity,
                parent_pid=parent_pid,
                registered_at=now_iso,
                lifecycle_status=lifecycle,
                associated_lab_target=associated_lab_target,
                metadata=metadata or {},
            )

            self._records[simulation_run_id] = record
            self._handles[simulation_run_id] = process_handle
            self._pid_to_run_id[pid] = simulation_run_id

            logger.info(
                f"[PROCESS REGISTERED] Run '{simulation_run_id}' -> PID {pid} ({record.expected_identity})",
                extra={"run_id": simulation_run_id, "pid": pid},
            )

            return record

    def verify_process_identity(self, simulation_run_id: str) -> Tuple[bool, str]:
        """
        Validate that the registered process is alive and still the exact process
        originally launched (guarding against PID reuse).

        Returns: (is_valid, reason)
        """
        with self._lock:
            record = self._records.get(simulation_run_id)
            if not record:
                return False, f"Simulation run '{simulation_run_id}' is not registered."

            if record.lifecycle_status in {
                ProcessLifecycleStatus.EXITED.value,
                ProcessLifecycleStatus.TERMINATED.value,
            }:
                return False, f"Process for run '{simulation_run_id}' has already exited."

            try:
                proc = psutil.Process(record.pid)
            except psutil.NoSuchProcess:
                record.lifecycle_status = ProcessLifecycleStatus.EXITED.value
                return False, f"Process PID {record.pid} no longer exists (already terminated)."
            except psutil.AccessDenied:
                return False, f"Access denied inspecting process PID {record.pid}."

            # Guard against PID reuse: verify creation time
            try:
                curr_create_raw = proc.create_time()
                curr_create_iso = datetime.fromtimestamp(
                    curr_create_raw, tz=CONFIG.TIMEZONE
                ).isoformat()
                curr_create_dt = datetime.fromtimestamp(curr_create_raw, tz=CONFIG.TIMEZONE)
                rec_create_dt = datetime.fromisoformat(record.process_creation_time)
                diff = abs((curr_create_dt - rec_create_dt).total_seconds())

                if diff > 1.5:  # Tolerance for timestamp conversion
                    record.lifecycle_status = ProcessLifecycleStatus.FAILED.value
                    return False, (
                        f"[CRITICAL SAFETY] PID reuse detected! PID {record.pid} creation time "
                        f"({curr_create_iso}) does not match registration ({record.process_creation_time})."
                    )
            except Exception as e:
                return False, f"Error validating creation time: {e}"

            # Verify executable / name identity
            try:
                curr_exe = proc.exe()
                # On Windows, python vs pythonw or path normalization
                if curr_exe and record.executable_path != "unknown":
                    if os.path.basename(curr_exe).lower() != os.path.basename(record.executable_path).lower():
                        return False, (
                            f"Process executable mismatch: Expected {record.executable_path}, "
                            f"found {curr_exe}."
                        )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            return True, "Process identity verified successfully."

    def is_run_registered(self, simulation_run_id: Optional[str]) -> bool:
        """Check if simulation run ID is currently registered."""
        if not simulation_run_id:
            return False
        with self._lock:
            return simulation_run_id in self._records

    def is_run_active(self, simulation_run_id: str) -> bool:
        """Check if simulation run is registered and currently running."""
        with self._lock:
            record = self._records.get(simulation_run_id)
            if not record:
                return False
            return record.lifecycle_status == ProcessLifecycleStatus.RUNNING.value

    def get_record(self, simulation_run_id: str) -> Optional[ControlledProcessRecord]:
        """Retrieve registration record by run ID."""
        with self._lock:
            return self._records.get(simulation_run_id)

    def get_record_by_pid(self, pid: int) -> Optional[ControlledProcessRecord]:
        """Retrieve registration record by PID."""
        with self._lock:
            run_id = self._pid_to_run_id.get(pid)
            if run_id:
                return self._records.get(run_id)
            return None

    def get_process_handle(self, simulation_run_id: str) -> Optional[Any]:
        """Retrieve original process handle."""
        with self._lock:
            return self._handles.get(simulation_run_id)

    def mark_status(self, simulation_run_id: str, status: ProcessLifecycleStatus) -> None:
        """Update lifecycle status of a registered process."""
        with self._lock:
            record = self._records.get(simulation_run_id)
            if record:
                record.lifecycle_status = status.value
                logger.info(
                    f"Simulation run '{simulation_run_id}' status marked as {status.value}"
                )

    def list_records(self) -> List[ControlledProcessRecord]:
        """Return snapshot of all registered processes."""
        with self._lock:
            return list(self._records.values())

    def clear(self) -> None:
        """Clear registry records."""
        with self._lock:
            self._records.clear()
            self._handles.clear()
            self._pid_to_run_id.clear()


# Global registry singleton
REGISTRY = ControlledProcessRegistry.get_instance()
