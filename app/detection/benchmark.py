"""
Performance Benchmark for CryptoShield Detection and Threat Scoring Engine (Phase 3).

Measures event ingestion throughput, sliding window aggregation time,
threat scoring latency, deduplication efficiency, and memory consumption
under high event volumes (up to 20,000 events) without disk I/O bottlenecks.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil

from app.config import CONFIG
from app.core.event_bus import BUS
from app.core.models import FileAction, Manifest, ManifestEntry, MonitoringEvent, ProcessAttribution
from app.detection.detection_coordinator import DetectionCoordinator


@dataclass
class DetectionBenchmarkResult:
    """Benchmark results for Phase 3 Detection and Threat Scoring Engine."""
    total_events_generated: int
    total_events_processed: int
    duplicate_events_ignored: int
    elapsed_seconds: float
    throughput_events_per_sec: float
    average_detection_latency_ms: float
    max_detection_latency_ms: float
    correlation_window_processing_ms: float
    alerts_generated: int
    incidents_created: int
    peak_memory_mb: float
    memory_growth_mb: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_events_generated": self.total_events_generated,
            "total_events_processed": self.total_events_processed,
            "duplicate_events_ignored": self.duplicate_events_ignored,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "throughput_events_per_sec": round(self.throughput_events_per_sec, 2),
            "average_detection_latency_ms": round(self.average_detection_latency_ms, 4),
            "max_detection_latency_ms": round(self.max_detection_latency_ms, 4),
            "correlation_window_processing_ms": round(self.correlation_window_processing_ms, 4),
            "alerts_generated": self.alerts_generated,
            "incidents_created": self.incidents_created,
            "peak_memory_mb": round(self.peak_memory_mb, 2),
            "memory_growth_mb": round(self.memory_growth_mb, 2),
        }


def run_detection_benchmark(
    event_count: int = 1000,
    duplicate_ratio: float = 0.1,
    include_canary: bool = True,
) -> DetectionBenchmarkResult:
    """
    Execute high-throughput in-memory benchmark on DetectionCoordinator.
    
    Generates synthetic telemetry streams simulating diverse enterprise activity,
    including modifications, renames, canary trips, and duplicates.
    """
    process = psutil.Process(os.getpid())
    mem_start_mb = process.memory_info().rss / (1024 * 1024)

    # Initialize synthetic benchmark manifest
    bench_manifest = Manifest(
        manifest_version="1.0.0",
        lab_id="benchmark-lab-id",
        generated_at=datetime.now(timezone.utc).isoformat(),
        total_files=20000,
        total_size_bytes=50 * 1024 * 1024,
        canary_count=10,
        seed=42,
        entries={
            "Finance/canary_decoy_1.csv": ManifestEntry(
                relative_path="Finance/canary_decoy_1.csv",
                file_type="csv",
                file_size_bytes=500,
                data_classification="RESTRICTED",
                sha256="0" * 64,
                is_canary=True,
                department="Finance",
                created_at="2026-11-02T12:00:00Z",
            )
        },
    )

    coordinator = DetectionCoordinator(
        manifest=bench_manifest,
        cooldown_seconds=0.01,
    )
    coordinator.start()

    departments = CONFIG.DEPARTMENTS
    formats = CONFIG.FILE_FORMATS

    # Pre-generate synthetic events
    events: List[MonitoringEvent] = []
    duplicate_count = int(event_count * duplicate_ratio)
    unique_count = event_count - duplicate_count

    cached_duplicate_event: Optional[MonitoringEvent] = None

    for i in range(unique_count):
        dept = departments[i % len(departments)]
        fmt = formats[i % len(formats)]
        path = f"{dept}/benchmark_file_{i}.{fmt}"

        ev = MonitoringEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="FILE_MODIFIED",
            source="WATCHDOG",
            relative_path=path,
            is_canary=False,
            process_id=None,
            process_attribution=ProcessAttribution.UNKNOWN.value,
            operation=FileAction.MODIFY.value,
            metadata={"department": dept},
        )
        events.append(ev)
        if cached_duplicate_event is None:
            cached_duplicate_event = ev

    # Insert duplicates
    if cached_duplicate_event:
        for _ in range(duplicate_count):
            events.append(cached_duplicate_event)

    # Add a canary event if requested
    if include_canary:
        events.append(
            MonitoringEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="CANARY_ACCESS",
                source="CONTROLLED_INSTRUMENTATION",
                relative_path="Finance/canary_decoy_1.csv",
                is_canary=True,
                canary_id="Finance/canary_decoy_1.csv",
                operation=FileAction.ACCESS.value,
                metadata={"department": "Finance"},
            )
        )

    # Execute benchmark loop
    start_time = time.perf_counter()

    for ev in events:
        coordinator.process_event(ev)

    # Measure dedicated correlation window processing time
    corr_start = time.perf_counter()
    summary = coordinator.correlator.get_window_summary(window_seconds=5.0)
    coordinator.threat_scorer.calculate_score(
        behavior_eval=coordinator.behavior_analyzer.evaluate(summary),
        canary_eval=coordinator.canary_analyzer.evaluate_events(summary.canary_events),
    )
    corr_time_ms = (time.perf_counter() - corr_start) * 1000.0

    elapsed_time = time.perf_counter() - start_time
    mem_end_mb = process.memory_info().rss / (1024 * 1024)

    metrics = coordinator.get_metrics()
    coordinator.stop()

    total_events = len(events)
    throughput = total_events / elapsed_time if elapsed_time > 0 else 0.0

    return DetectionBenchmarkResult(
        total_events_generated=total_events,
        total_events_processed=metrics["events_processed"],
        duplicate_events_ignored=metrics["duplicate_events_ignored"],
        elapsed_seconds=elapsed_time,
        throughput_events_per_sec=throughput,
        average_detection_latency_ms=metrics["average_detection_latency_ms"],
        max_detection_latency_ms=metrics["max_detection_latency_ms"],
        correlation_window_processing_ms=corr_time_ms,
        alerts_generated=metrics["alerts_generated_count"],
        incidents_created=metrics["incidents_created_count"],
        peak_memory_mb=mem_end_mb,
        memory_growth_mb=max(0.0, mem_end_mb - mem_start_mb),
    )


def print_detection_benchmark_report(res: DetectionBenchmarkResult) -> None:
    """Print formatted terminal report of detection benchmark."""
    print("\n================ CRYPTOSHIELD DETECTION BENCHMARK REPORT ================")
    print(f"Total Events Ingested      : {res.total_events_generated:,}")
    print(f"Events Successfully Handled : {res.total_events_processed:,}")
    print(f"Duplicates Deduplicated    : {res.duplicate_events_ignored:,}")
    print(f"Total Benchmark Time       : {res.elapsed_seconds:.4f} seconds")
    print(f"Event Ingestion Throughput : {res.throughput_events_per_sec:,.2f} events/sec")
    print(f"Avg Detection Latency      : {res.average_detection_latency_ms:.4f} ms")
    print(f"Max Detection Latency      : {res.max_detection_latency_ms:.4f} ms")
    print(f"Window Processing Latency  : {res.correlation_window_processing_ms:.4f} ms")
    print(f"Security Alerts Generated  : {res.alerts_generated:,}")
    print(f"Security Incidents Created : {res.incidents_created:,}")
    print(f"Peak Memory Footprint      : {res.peak_memory_mb:.2f} MB")
    print(f"Memory Growth              : {res.memory_growth_mb:.2f} MB")
    print("=========================================================================\n")

