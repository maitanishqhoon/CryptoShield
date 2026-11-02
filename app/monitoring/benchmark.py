"""
Reproducible Performance Benchmark for CryptoShield Telemetry Engine.

Safely evaluates:
- Filesystem event burst ingestion rate and throughput
- Normalization and dispatch latency (average and maximum)
- Event deduplication and coalescing rate
- Process polling iteration duration
- Memory consumption (RSS MB)
- Coordinator startup and shutdown latency

Operates strictly within temporary laboratory scratch fixtures without altering
the baseline enterprise dataset or manifest.
"""

from __future__ import annotations

import os
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import MonitoringEvent
from app.core.safety import verify_lab_marker
from app.lab.lab_manager import LabManager
from app.monitoring.coordinator import MonitoringCoordinator

logger = get_logger("benchmark")


@dataclass
class BenchmarkResults:
    """Benchmark metrics container."""
    total_files_in_lab: int
    startup_time_seconds: float
    shutdown_time_seconds: float
    total_events_generated: int
    total_events_observed: int
    total_events_coalesced: int
    total_events_dropped: int
    avg_event_latency_ms: float
    max_event_latency_ms: float
    process_polling_duration_ms: float
    initial_rss_mb: float
    peak_rss_mb: float
    benchmark_duration_seconds: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def run_monitoring_benchmark(
    base_lab_dir: Optional[Path] = None,
    burst_count: int = 500,
    include_canary_test: bool = True,
) -> BenchmarkResults:
    """
    Run an end-to-end benchmark of the CryptoShield monitoring engine.
    Ensures zero permanent changes to the existing baseline dataset.
    """
    lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
    verify_lab_marker(lab_dir)

    lab_mgr = LabManager(base_lab_dir=lab_dir)
    status = lab_mgr.get_status()
    total_lab_files = status.get("total_files", 0)

    proc = psutil.Process(os.getpid())
    initial_rss = proc.memory_info().rss / (1024 * 1024)

    # Temporary test scratch directory inside lab
    scratch_dir = lab_dir / "Benchmark_Scratch_Tmp"
    scratch_dir.mkdir(parents=True, exist_ok=True)

    latencies_ms: List[float] = []
    received_events: List[MonitoringEvent] = []

    def on_event(ev: MonitoringEvent) -> None:
        received_events.append(ev)

    coordinator = MonitoringCoordinator(base_lab_dir=lab_dir)
    coordinator.add_listener(on_event)

    bench_start = time.perf_counter()

    # 1. Measure Startup Time
    t0 = time.perf_counter()
    coordinator.start(enable_process_monitor=False)
    startup_time = time.perf_counter() - t0

    # 2. Measure Process Polling Duration
    t0 = time.perf_counter()
    coordinator.proc_monitor.poll_once()
    process_poll_duration_ms = (time.perf_counter() - t0) * 1000.0

    events_generated = 0

    try:
        # Give watchdog observer 100ms to spin up
        time.sleep(0.1)

        # 3. Controlled File Creation Burst
        for i in range(burst_count):
            file_path = scratch_dir / f"bench_file_{i:04d}.txt"
            t_event_start = time.perf_counter()
            file_path.write_text(f"Telemetry benchmark test payload {i}\n", encoding="utf-8")
            events_generated += 1

            # Controlled read instrumentation
            coordinator.access_monitor.record_access(
                file_path=file_path,
                operation="READ",
                pid=os.getpid(),
                process_name="cryptoshield_benchmark",
            )
            events_generated += 1

            lat_ms = (time.perf_counter() - t_event_start) * 1000.0
            latencies_ms.append(lat_ms)

        # 4. Controlled Modify Burst
        for i in range(min(50, burst_count)):
            file_path = scratch_dir / f"bench_file_{i:04d}.txt"
            t_event_start = time.perf_counter()
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(f"Appended test line {i}\n")
            events_generated += 1
            lat_ms = (time.perf_counter() - t_event_start) * 1000.0
            latencies_ms.append(lat_ms)

        # 5. Controlled Canary Test (if canaries exist in manifest)
        if include_canary_test and coordinator.manifest:
            canaries = [e for e in coordinator.manifest.entries.values() if e.is_canary]
            if canaries:
                sample_canary = canaries[0]
                canary_disk_path = lab_dir / sample_canary.relative_path
                if canary_disk_path.exists():
                    t_event_start = time.perf_counter()
                    # Perform controlled instrumented read on actual canary file
                    coordinator.access_monitor.read_file(canary_disk_path)
                    events_generated += 1
                    lat_ms = (time.perf_counter() - t_event_start) * 1000.0
                    latencies_ms.append(lat_ms)

        # Wait briefly for all queued watchdog events to drain
        time.sleep(0.5)

    finally:
        # 6. Measure Shutdown Time
        t0 = time.perf_counter()
        coordinator.stop()
        shutdown_time = time.perf_counter() - t0

        # Safely clean up scratch directory
        if scratch_dir.exists():
            shutil.rmtree(scratch_dir)

    bench_total_duration = time.perf_counter() - bench_start
    peak_rss = proc.memory_info().rss / (1024 * 1024)

    avg_latency = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0
    max_latency = max(latencies_ms) if latencies_ms else 0.0

    fs_status = coordinator.fs_monitor.get_status()

    return BenchmarkResults(
        total_files_in_lab=total_lab_files,
        startup_time_seconds=round(startup_time, 4),
        shutdown_time_seconds=round(shutdown_time, 4),
        total_events_generated=events_generated,
        total_events_observed=coordinator.events_observed,
        total_events_coalesced=fs_status.get("events_coalesced", 0),
        total_events_dropped=fs_status.get("events_dropped_saturation", 0),
        avg_event_latency_ms=round(avg_latency, 3),
        max_event_latency_ms=round(max_latency, 3),
        process_polling_duration_ms=round(process_poll_duration_ms, 3),
        initial_rss_mb=round(initial_rss, 2),
        peak_rss_mb=round(peak_rss, 2),
        benchmark_duration_seconds=round(bench_total_duration, 3),
    )


def print_benchmark_report(results: BenchmarkResults) -> None:
    """Print beautifully formatted benchmark results table."""
    print("\n================================================================================")
    print("           CRYPTOSHIELD PHASE 2: TELEMETRY ENGINE BENCHMARK REPORT             ")
    print("================================================================================")
    print(f"Monitored Laboratory Files   : {results.total_files_in_lab:,} enterprise files")
    print(f"Monitoring Startup Time      : {results.startup_time_seconds:.4f} seconds")
    print(f"Monitoring Shutdown Time     : {results.shutdown_time_seconds:.4f} seconds")
    print(f"Total Benchmark Duration     : {results.benchmark_duration_seconds:.2f} seconds")
    print("--------------------------------------------------------------------------------")
    print(f"Total Events Generated       : {results.total_events_generated:,}")
    print(f"Total Events Processed       : {results.total_events_observed:,}")
    print(f"Events Coalesced (Debounced) : {results.total_events_coalesced:,}")
    print(f"Events Dropped (Saturation)  : {results.total_events_dropped:,}")
    print("--------------------------------------------------------------------------------")
    print(f"Average Processing Latency   : {results.avg_event_latency_ms:.3f} ms")
    print(f"Maximum Processing Latency   : {results.max_event_latency_ms:.3f} ms")
    print(f"Process Telemetry Poll Time  : {results.process_polling_duration_ms:.3f} ms")
    print("--------------------------------------------------------------------------------")
    print(f"Process Memory Usage (Start) : {results.initial_rss_mb:.2f} MB")
    print(f"Process Memory Usage (Peak)  : {results.peak_rss_mb:.2f} MB")
    print(f"Net Memory Delta             : {results.peak_rss_mb - results.initial_rss_mb:+.2f} MB")
    print("================================================================================\n")


if __name__ == "__main__":
    res = run_monitoring_benchmark(burst_count=200)
    print_benchmark_report(res)
