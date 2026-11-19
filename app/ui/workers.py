"""
CryptoShield — Asynchronous Worker Framework (Phase 10)
Provides non-blocking QThread execution for heavy cryptographic, lab, and simulation tasks.
"""

from typing import Any, Callable, Dict, Optional, Tuple
from PySide6.QtCore import QObject, QThread, Signal

from app.core.logger import get_logger

logger = get_logger("ui.workers")


class WorkerSignals(QObject):
    """Signals emitted by an AsyncWorker thread."""
    started = Signal()
    progress = Signal(int, int, str)   # (current, total, status_message)
    finished = Signal(object)          # Result object
    error = Signal(str)                # Error description / stack


class AsyncWorker(QThread):
    """
    Reusable asynchronous worker thread.
    Executes a target callable in a separate thread and reports lifecycle events via Qt signals.
    Supports injecting an optional progress callback into functions that accept `progress_callback`.
    """

    def __init__(
        self,
        target_fn: Callable[..., Any],
        *args: Any,
        parent: Optional[QObject] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(parent)
        self.target_fn = target_fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    def _progress_callback(self, current: int, total: int, message: str = "") -> None:
        """Helper callback provided to target functions supporting progress reporting."""
        self.signals.progress.emit(current, total, message)

    def run(self) -> None:
        """Executes the worker payload safely."""
        self.signals.started.emit()
        try:
            # Check if target callable accepts progress_callback
            import inspect
            sig = inspect.signature(self.target_fn)
            if "progress_callback" in sig.parameters:
                self.kwargs["progress_callback"] = self._progress_callback
            elif "progress" in sig.parameters:
                self.kwargs["progress"] = self._progress_callback

            result = self.target_fn(*self.args, **self.kwargs)
            self.signals.finished.emit(result)
        except Exception as e:
            logger.exception(f"Unhandled exception in AsyncWorker: {e}")
            self.signals.error.emit(str(e))
