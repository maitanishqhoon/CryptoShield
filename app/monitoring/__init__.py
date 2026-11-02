"""
Monitoring Subsystem for CryptoShield (Phase 2).

Provides unified filesystem monitoring (Watchdog), process telemetry (psutil),
controlled file-access instrumentation, and high-priority canary decoy monitoring.
"""

from app.monitoring.access_monitor import AccessMonitor
from app.monitoring.coordinator import MonitoringCoordinator
from app.monitoring.event_normalizer import EventNormalizer
from app.monitoring.filesystem_monitor import FilesystemMonitor
from app.monitoring.process_monitor import ProcessMonitor

__all__ = [
    "AccessMonitor",
    "EventNormalizer",
    "FilesystemMonitor",
    "MonitoringCoordinator",
    "ProcessMonitor",
]
