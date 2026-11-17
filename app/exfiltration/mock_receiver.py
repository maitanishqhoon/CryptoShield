"""
Safe Local Mock Receiver for Simulated Exfiltration Transfers (Phase 7).

Provides a local loopback-only TCP socket listener (127.0.0.1) that safely accepts
simulated data transfers, logs telemetry, tracks throughput, and discards data
in-memory without routing packets to external networks or writing payloads to disk.
"""

from __future__ import annotations

import logging
import select
import socket
import threading
import time
from typing import Any, Dict, Optional, Tuple

from app.config import CONFIG

logger = logging.getLogger("cryptoshield.exfiltration.receiver")


class MockReceiver:
    """
    Local-only TCP listener bound strictly to 127.0.0.1 for receiving simulated
    exfiltration traffic. Discards all received payloads safely in-memory.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        buffer_size: int = 65536,
    ) -> None:
        # Enforce loopback safety constraint
        if host not in ("127.0.0.1", "localhost"):
            raise ValueError(f"Security Invariant: MockReceiver must only bind to localhost, got {host}")

        self.host = host
        self.requested_port = port
        self.actual_port: int = 0
        self.buffer_size = buffer_size

        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Telemetry metrics
        self._total_bytes_received: int = 0
        self._total_connections: int = 0
        self._active_connections: int = 0
        self._start_time: Optional[float] = None

    @property
    def endpoint(self) -> str:
        """Returns the formatted endpoint string, e.g. '127.0.0.1:8999'."""
        return f"{self.host}:{self.actual_port}"

    def is_running(self) -> bool:
        """Returns True if the receiver thread is active and listening."""
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    def start(self) -> Tuple[str, int]:
        """
        Binds to the local address and launches the listener thread.
        Returns (host, assigned_port).
        """
        with self._lock:
            if self.is_running():
                return self.host, self.actual_port

            self._stop_event.clear()
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.host, self.requested_port))
            self._server_socket.listen(16)
            self._server_socket.setblocking(False)

            self.actual_port = self._server_socket.getsockname()[1]
            self._start_time = time.time()

            self._thread = threading.Thread(
                target=self._accept_loop,
                name="CryptoShield-MockReceiver",
                daemon=True,
            )
            self._thread.start()
            logger.info("MockReceiver listening on %s", self.endpoint)
            return self.host, self.actual_port

    def stop(self, timeout_seconds: float = 2.0) -> None:
        """Stops the receiver thread and closes listening sockets."""
        with self._lock:
            if not self.is_running():
                return

            self._stop_event.set()

            if self._server_socket:
                try:
                    self._server_socket.close()
                except Exception as e:
                    logger.debug("Error closing server socket: %s", e)
                self._server_socket = None

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout_seconds)
            self._thread = None

        logger.info("MockReceiver stopped on %s (Received %d bytes)", self.endpoint, self._total_bytes_received)

    def get_metrics(self) -> Dict[str, Any]:
        """Returns thread-safe telemetry metrics for received transfers."""
        with self._lock:
            uptime = (time.time() - self._start_time) if self._start_time else 0.0
            return {
                "endpoint": self.endpoint,
                "is_running": self.is_running(),
                "total_bytes_received": self._total_bytes_received,
                "total_connections": self._total_connections,
                "active_connections": self._active_connections,
                "uptime_seconds": round(uptime, 2),
            }

    def reset_metrics(self) -> None:
        """Resets byte and connection counters."""
        with self._lock:
            self._total_bytes_received = 0
            self._total_connections = 0
            self._active_connections = 0

    def deliver_mock_payload(self, data: bytes) -> int:
        """
        In-memory loopback delivery bridge used when the host/sandbox environment
        restricts raw outgoing TCP socket connections (e.g. WinError 10013).
        Safely tallies and discards payload in-memory without disk writing.
        """
        with self._lock:
            self._total_connections += 1
            self._total_bytes_received += len(data)
            return len(data)

    def _accept_loop(self) -> None:
        """Main listening loop accepting incoming mock transfer connections."""
        while not self._stop_event.is_set():
            if not self._server_socket:
                break
            try:
                # Use select to wait up to 0.2s for incoming connections
                readable, _, _ = select.select([self._server_socket], [], [], 0.2)
                if readable and not self._stop_event.is_set():
                    client_sock, client_addr = self._server_socket.accept()
                    with self._lock:
                        self._total_connections += 1
                        self._active_connections += 1

                    # Handle connection in a dedicated worker thread
                    worker = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock,),
                        name=f"MockReceiver-Worker-{client_addr[1]}",
                        daemon=True,
                    )
                    worker.start()
            except (OSError, ValueError):
                break
            except Exception as e:
                if not self._stop_event.is_set():
                    logger.error("Unexpected error in MockReceiver accept loop: %s", e)
                break

    def _handle_client(self, client_sock: socket.socket) -> None:
        """Receives data from a client connection and discards it in-memory."""
        client_sock.settimeout(2.0)
        client_bytes = 0
        try:
            while not self._stop_event.is_set():
                data = client_sock.recv(self.buffer_size)
                if not data:
                    break
                client_bytes += len(data)
                with self._lock:
                    self._total_bytes_received += len(data)
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            with self._lock:
                self._active_connections = max(0, self._active_connections - 1)

    def __enter__(self) -> MockReceiver:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
