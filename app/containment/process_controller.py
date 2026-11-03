"""
Controlled Process Controller for CryptoShield (Phase 4).

Safely stops ONLY registered, directly launched simulation processes using a
cooperative shutdown mechanism with an identity-validated fallback.

Mandatory Safety Guardrails:
- Does NOT terminate processes based solely on PID or process name.
- Does NOT enumerate host processes or terminate arbitrary applications.
- Operates exclusively on process handles owned by ControlledProcessRegistry.
- Re-validates process creation timestamp and identity before any process-control action.
- Thread-safe and idempotent.
"""

from __future__ import annotations

import multiprocessing
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import psutil

from app.config import CONFIG
from app.containment.lab_write_gate import WRITE_GATE, LabWriteGate
from app.containment.process_registry import REGISTRY, ControlledProcessRegistry
from app.core.logger import get_logger
from app.core.models import ProcessLifecycleStatus

logger = get_logger("process_controller")


@dataclass
class ShutdownOutcome:
    """Detailed outcome from stopping a controlled process."""
    simulation_run_id: str
    pid: Optional[int]
    success: bool
    method: str  # "COOPERATIVE", "FORCED_FALLBACK", "ALREADY_EXITED", "REJECTED", "FAILED"
    duration_seconds: float
    exit_code: Optional[int]
    message: str


class ControlledProcessController:
    """
    Controller executing cooperative and fallback process termination on registered simulators.
    """

    def __init__(
        self,
        registry: Optional[ControlledProcessRegistry] = None,
        write_gate: Optional[LabWriteGate] = None,
        graceful_timeout: float = CONFIG.GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS,
        forced_fallback_enabled: bool = CONFIG.FORCED_TERMINATION_FALLBACK_ENABLED,
    ) -> None:
        self.registry = registry or REGISTRY
        self.write_gate = write_gate or WRITE_GATE
        self.graceful_timeout = graceful_timeout
        self.forced_fallback_enabled = forced_fallback_enabled
        self._control_channels: Dict[str, Any] = {}
        self._lock = threading.RLock()

    def register_control_channel(self, simulation_run_id: str, channel: Any) -> None:
        """
        Register a cooperative IPC channel (e.g., multiprocessing.Event, threading.Event,
        or callable stop function) for graceful termination signaling.
        """
        with self._lock:
            self._control_channels[simulation_run_id] = channel

    def stop_controlled_process(self, simulation_run_id: str) -> ShutdownOutcome:
        """
        Safely stop the registered simulation process for a given run ID.

        Enforces:
        1. Registry presence check.
        2. Process identity verification (PID reuse protection).
        3. Immediate write gate closure.
        4. Cooperative graceful stop signal.
        5. Verification of exit.
        6. Optional bounded forced fallback on owned handle only.
        """
        start_t = time.perf_counter()

        with self._lock:
            # 1. Validate registration
            record = self.registry.get_record(simulation_run_id)
            if not record:
                return ShutdownOutcome(
                    simulation_run_id=simulation_run_id,
                    pid=None,
                    success=False,
                    method="REJECTED",
                    duration_seconds=0.0,
                    exit_code=None,
                    message=f"Process control rejected: Simulation run '{simulation_run_id}' is not registered.",
                )

            # 2. Check if already marked exited
            if record.lifecycle_status in {
                ProcessLifecycleStatus.EXITED.value,
                ProcessLifecycleStatus.TERMINATED.value,
            }:
                return ShutdownOutcome(
                    simulation_run_id=simulation_run_id,
                    pid=record.pid,
                    success=True,
                    method="ALREADY_EXITED",
                    duration_seconds=round(time.perf_counter() - start_t, 3),
                    exit_code=0,
                    message="Process was already exited; no termination required.",
                )

            # 3. Close the run's LabWriteGate immediately
            self.write_gate.close_gate(simulation_run_id)

            # 4. Verify process identity and check for PID reuse
            is_valid, id_msg = self.registry.verify_process_identity(simulation_run_id)
            if not is_valid:
                # If it already exited naturally
                if "already" in id_msg.lower() or "no longer exists" in id_msg.lower():
                    self.registry.mark_status(simulation_run_id, ProcessLifecycleStatus.EXITED)
                    return ShutdownOutcome(
                        simulation_run_id=simulation_run_id,
                        pid=record.pid,
                        success=True,
                        method="ALREADY_EXITED",
                        duration_seconds=round(time.perf_counter() - start_t, 3),
                        exit_code=0,
                        message=f"Process exited prior to stop command: {id_msg}",
                    )

                logger.error(f"[SAFETY REFUSAL] Cannot stop process: {id_msg}")
                return ShutdownOutcome(
                    simulation_run_id=simulation_run_id,
                    pid=record.pid,
                    success=False,
                    method="REJECTED",
                    duration_seconds=round(time.perf_counter() - start_t, 3),
                    exit_code=None,
                    message=f"Process identity verification failed: {id_msg}",
                )

            self.registry.mark_status(simulation_run_id, ProcessLifecycleStatus.STOP_REQUESTED)
            handle = self.registry.get_process_handle(simulation_run_id)
            channel = self._control_channels.get(simulation_run_id)

            # 5. Send cooperative stop signal
            logger.info(
                f"[COOPERATIVE STOP REQUESTED] Signaling run '{simulation_run_id}' (PID {record.pid})..."
            )
            signaled = self._signal_cooperative_stop(channel, handle)

            # 6. Wait for graceful exit
            exited, exit_code = self._wait_for_process_exit(handle, record.pid, timeout=self.graceful_timeout)

            if exited:
                elapsed = round(time.perf_counter() - start_t, 3)
                self.registry.mark_status(simulation_run_id, ProcessLifecycleStatus.EXITED)
                logger.info(
                    f"[PROCESS EXITED] Run '{simulation_run_id}' exited gracefully in {elapsed}s (exit_code: {exit_code})."
                )
                return ShutdownOutcome(
                    simulation_run_id=simulation_run_id,
                    pid=record.pid,
                    success=True,
                    method="COOPERATIVE",
                    duration_seconds=elapsed,
                    exit_code=exit_code,
                    message=f"Controlled process stopped gracefully in {elapsed}s.",
                )

            # 7. Graceful timeout exceeded -> Optional forced termination fallback
            if not self.forced_fallback_enabled:
                elapsed = round(time.perf_counter() - start_t, 3)
                logger.warning(
                    f"[STOP TIMEOUT] Run '{simulation_run_id}' did not exit within {self.graceful_timeout}s; fallback disabled."
                )
                return ShutdownOutcome(
                    simulation_run_id=simulation_run_id,
                    pid=record.pid,
                    success=False,
                    method="TIMEOUT",
                    duration_seconds=elapsed,
                    exit_code=None,
                    message=f"Graceful shutdown timed out after {self.graceful_timeout}s.",
                )

            logger.warning(
                f"[FORCED FALLBACK INITIATED] Run '{simulation_run_id}' did not exit within {self.graceful_timeout}s. "
                "Executing identity-revalidated termination on owned handle..."
            )

            # Revalidate identity before fallback
            reval_ok, reval_msg = self.registry.verify_process_identity(simulation_run_id)
            if not reval_ok:
                elapsed = round(time.perf_counter() - start_t, 3)
                return ShutdownOutcome(
                    simulation_run_id=simulation_run_id,
                    pid=record.pid,
                    success=False,
                    method="FAILED",
                    duration_seconds=elapsed,
                    exit_code=None,
                    message=f"Identity revalidation failed before fallback: {reval_msg}",
                )

            # Terminate only the owned handle directly
            fallback_success = self._terminate_owned_handle(handle, record.pid)
            exited_fb, exit_code_fb = self._wait_for_process_exit(handle, record.pid, timeout=2.0)
            elapsed = round(time.perf_counter() - start_t, 3)

            if exited_fb:
                self.registry.mark_status(simulation_run_id, ProcessLifecycleStatus.TERMINATED)
                logger.info(
                    f"[FORCED FALLBACK COMPLETE] Run '{simulation_run_id}' terminated successfully in {elapsed}s."
                )
                return ShutdownOutcome(
                    simulation_run_id=simulation_run_id,
                    pid=record.pid,
                    success=True,
                    method="FORCED_FALLBACK",
                    duration_seconds=elapsed,
                    exit_code=exit_code_fb,
                    message=f"Controlled process stopped via fallback termination in {elapsed}s.",
                )
            else:
                self.registry.mark_status(simulation_run_id, ProcessLifecycleStatus.FAILED)
                return ShutdownOutcome(
                    simulation_run_id=simulation_run_id,
                    pid=record.pid,
                    success=False,
                    method="FAILED",
                    duration_seconds=elapsed,
                    exit_code=None,
                    message="Process remained running even after fallback termination attempt.",
                )

    def _signal_cooperative_stop(self, channel: Any, handle: Any) -> bool:
        """Trigger cooperative stop signal via IPC channel or object method."""
        if channel is not None:
            if hasattr(channel, "set"):
                channel.set()
                return True
            elif callable(channel):
                try:
                    channel()
                    return True
                except Exception as e:
                    logger.debug(f"Error invoking stop channel callable: {e}")

        # If handle is multiprocessing.Process or has request_stop
        if hasattr(handle, "request_stop") and callable(handle.request_stop):
            try:
                handle.request_stop()
                return True
            except Exception:
                pass

        return False

    def _wait_for_process_exit(
        self, handle: Any, pid: int, timeout: float
    ) -> Tuple[bool, Optional[int]]:
        """Wait up to timeout seconds for the process to exit."""
        start_wait = time.perf_counter()

        while (time.perf_counter() - start_wait) < timeout:
            # Check handle first
            if isinstance(handle, subprocess.Popen):
                ret = handle.poll()
                if ret is not None:
                    return True, ret
            elif isinstance(handle, multiprocessing.Process):
                if not handle.is_alive():
                    return True, handle.exitcode

            # Check psutil
            try:
                proc = psutil.Process(pid)
                if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                    return True, 0
            except psutil.NoSuchProcess:
                return True, 0
            except Exception:
                pass

            time.sleep(0.05)

        return False, None

    def _terminate_owned_handle(self, handle: Any, pid: int) -> bool:
        """Execute termination specifically on owned launcher handle."""
        try:
            if isinstance(handle, subprocess.Popen):
                handle.terminate()
                return True
            elif isinstance(handle, multiprocessing.Process):
                handle.terminate()
                return True
            else:
                # Direct psutil fallback strictly against the verified pid
                p = psutil.Process(pid)
                p.terminate()
                return True
        except Exception as e:
            logger.error(f"Error executing termination on handle: {e}")
            return False

