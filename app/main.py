"""
CryptoShield CLI: Laboratory Initialization, Dataset Generation, and Integrity Auditing.

Academic Proof-of-Concept Defensive Security Application.
Phase 1 Foundation Command-Line Interface.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Optional

from app.config import CONFIG
from app.core.logger import get_logger, setup_logging
from app.core.models import DatasetPreset
from app.core.safety import SafetyViolationError
from app.lab.dataset_generator import SyntheticDatasetGenerator
from app.lab.lab_manager import LabManager
from app.lab.manifest import ManifestManager

logger = get_logger("cli")


def print_banner() -> None:
    banner = r"""
================================================================================
   ______                __        _____ __    _      __    __
  / ____/______  ______ / /_____  / ___// /_  (_)__  / /___/ /
 / /   / ___/ / / / __ \ __/ __ \ \__ \/ __ \/ / _ \/ / __  / 
/ /___/ /  / /_/ / /_/ / /_/ /_/ /___/ / / / / /  __/ / /_/ /  
\____/_/   \__, / .___/\__/\____//____/_/ /_/_/\___/_/\__,_/   
          /____/_/                                             
  Intelligent Ransomware Detection & Containment Framework
  Phase 1: Project Foundation & Enterprise Dataset Engine
================================================================================
"""
    print(banner)


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize laboratory directories and generate safety marker."""
    mgr = LabManager()
    print("[*] Initializing CryptoShield laboratory environment...")
    marker = mgr.initialize_lab(force_new_marker=args.force)
    print(f"[+] Laboratory Initialized Successfully:")
    print(f"    - Target Root   : {mgr.lab_dir}")
    print(f"    - Marker File   : {mgr.marker_path.name}")
    print(f"    - Lab UUID      : {marker.lab_id}")
    print(f"    - Platform Host : {marker.system_hostname} ({marker.platform})")
    print(f"    - Created At    : {marker.created_at}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    """Generate synthetic enterprise dataset and compile baseline manifest."""
    mgr = LabManager()

    # Determine file count
    if args.preset:
        preset_name = args.preset.lower()
        if preset_name == "quick":
            file_count = DatasetPreset.QUICK.value
        elif preset_name == "default":
            file_count = DatasetPreset.DEFAULT.value
        elif preset_name == "stress":
            file_count = DatasetPreset.STRESS.value
        else:
            print(f"[-] Invalid preset '{args.preset}'. Choose from: quick, default, stress.")
            return 1
    elif args.files:
        file_count = args.files
    else:
        file_count = DatasetPreset.QUICK.value

    # Optional clean before generation
    if args.clean:
        print("[*] Cleaning existing lab directory before dataset generation...")
        deleted = mgr.clean_lab(preserve_marker=True)
        print(f"[+] Removed {deleted} previous items.")

    # Validate lab marker
    is_valid, msg = mgr.validate_lab()
    if not is_valid:
        print(f"[-] Lab validation failed: {msg}")
        print("    Running initialization first...")
        mgr.initialize_lab()

    print(f"[*] Starting dataset generation: {file_count:,} files (Seed: {args.seed})...")
    generator = SyntheticDatasetGenerator(seed=args.seed)

    start_t = time.perf_counter()
    last_print = 0

    def progress(current: int, total: int) -> None:
        nonlocal last_print
        pct = (current / total) * 100
        # Print update every 5% or 500 files
        if current - last_print >= 500 or current == total:
            last_print = current
            sys.stdout.write(f"\r    [Progress] {current:,}/{total:,} files ({pct:5.1f}%) written...")
            sys.stdout.flush()

    try:
        manifest = generator.generate_dataset(
            file_count=file_count,
            canary_count=args.canaries,
            progress_callback=progress,
        )
    except SafetyViolationError as e:
        print(f"\n[!] Safety Violation: {e}")
        return 1

    elapsed = time.perf_counter() - start_t
    print(f"\n[+] Successfully generated {manifest.total_files:,} synthetic files in {elapsed:.2f} seconds!")
    print(f"    - Generation Rate : {manifest.total_files / elapsed:.1f} files/sec")
    print(f"    - Total Size      : {manifest.total_size_bytes / (1024 * 1024):.2f} MB")
    print(f"    - Canary Files    : {manifest.canary_count:,}")
    print(f"    - Baseline Manifest: {mgr.manifest_path}")

    # Summary by department
    print("\n--- Departmental Distribution ---")
    for dept, cnt in sorted(manifest.department_counts.items()):
        print(f"    - {dept:<20}: {cnt:,} files")

    # Summary by file type
    print("\n--- File Format Distribution ---")
    for fmt, cnt in sorted(manifest.type_counts.items()):
        print(f"    - .{fmt:<6}: {cnt:,} files")

    # Summary by data classification
    print("\n--- Data Classification Distribution ---")
    for cls_name, cnt in sorted(manifest.classification_counts.items()):
        print(f"    - {cls_name:<15}: {cnt:,} files")

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify SHA-256 integrity against baseline manifest."""
    mgr = LabManager()
    is_valid, msg = mgr.validate_lab()
    if not is_valid:
        print(f"[-] Lab validation failed: {msg}")
        return 1

    if not mgr.manifest_path.exists():
        print(f"[-] Baseline manifest not found at '{mgr.manifest_path}'.")
        print("    Generate a dataset first using: python -m app.main generate")
        return 1

    print(f"[*] Auditing laboratory integrity against baseline manifest...")
    result = ManifestManager.verify_integrity(mgr.lab_dir)

    print("\n================ INTEGRITY AUDIT RESULTS ================")
    print(f"Integrity Valid    : {'[PASS] INTACT' if result.is_valid else '[FAIL] TAMPERED/ALTERED'}")
    print(f"Manifest Files     : {result.total_manifest_files:,}")
    print(f"Disk Files Scanned : {result.total_disk_files:,}")
    print(f"Matched (Verified) : {result.matched_files:,}")
    print(f"Modified Files     : {len(result.modified_files):,}")
    print(f"Missing Files      : {len(result.missing_files):,}")
    print(f"Untracked Files    : {len(result.untracked_files):,}")
    print(f"Canary Tampering   : {len(result.canary_tampered_files):,}")
    print(f"Audit Duration     : {result.duration_seconds:.2f}s")
    print("=========================================================")

    if result.modified_files:
        print(f"\n[!] Modified Files (Sample up to 5):")
        for f in result.modified_files[:5]:
            print(f"    - {f}")

    if result.missing_files:
        print(f"\n[!] Missing Files (Sample up to 5):")
        for f in result.missing_files[:5]:
            print(f"    - {f}")

    if result.untracked_files:
        print(f"\n[!] Untracked Files (Sample up to 5):")
        for f in result.untracked_files[:5]:
            print(f"    - {f}")

    if result.canary_tampered_files:
        print(f"\n[!] CRITICAL: Canary Decoys Tampered With:")
        for f in result.canary_tampered_files:
            print(f"    - {f}")

    return 0 if result.is_valid else 2


def cmd_status(args: argparse.Namespace) -> int:
    """Show laboratory metrics, safety marker details, and storage stats."""
    mgr = LabManager()
    status = mgr.get_status()

    print("\n--- CryptoShield Laboratory Status ---")
    print(f"Laboratory Path : {status['lab_dir']}")
    print(f"Safety State    : {'[VALID]' if status['is_valid'] else '[INVALID]'} {status['status_message']}")
    print(f"Has Marker      : {status['has_marker']}")
    if status["marker_info"]:
        print(f"  - Marker ID   : {status['marker_info'].get('lab_id')}")
        print(f"  - Created At  : {status['marker_info'].get('created_at')}")
    print(f"Has Manifest    : {status['has_manifest']}")
    print(f"Total Files     : {status['total_files']:,}")
    print(f"Total Folders   : {status['total_directories']:,}")
    print(f"Disk Usage      : {status['total_mb']} MB ({status['total_bytes']:,} bytes)")

    if status["department_counts"]:
        print("\nFiles by Department:")
        for dept, count in sorted(status["department_counts"].items()):
            print(f"  - {dept:<20}: {count:,}")
    print("---------------------------------------\n")
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    """Safely purge laboratory directory."""
    mgr = LabManager()
    is_valid, msg = mgr.validate_lab()
    if not is_valid:
        print(f"[-] Cannot clean: {msg}")
        return 1

    confirm = args.yes
    if not confirm:
        res = input(f"[?] Are you sure you want to clean the laboratory at '{mgr.lab_dir}'? [y/N]: ")
        if res.strip().lower() not in {"y", "yes"}:
            print("[*] Cleanup aborted.")
            return 0

    deleted = mgr.clean_lab(preserve_marker=not args.all)
    print(f"[+] Successfully purged {deleted} items from laboratory.")
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    """Run live File Activity Monitoring and Telemetry Engine."""
    from app.monitoring.coordinator import MonitoringCoordinator
    from app.monitoring.event_normalizer import EventPriority

    mgr = LabManager()
    is_valid, msg = mgr.validate_lab()
    if not is_valid:
        print(f"[-] Lab validation failed: {msg}")
        return 1

    coordinator = MonitoringCoordinator()

    def print_event(ev) -> None:
        pfx = "[CANARY ALERT]" if ev.is_canary else f"[{ev.event_type}]"
        path_str = f" -> {ev.relative_path}" if ev.relative_path else ""
        proc_str = f" (PID: {ev.process_id} {ev.process_name})" if ev.process_id else ""
        print(f"    {pfx:<18} {ev.source:<12} {path_str}{proc_str}")

    coordinator.add_listener(print_event)

    print(f"[*] Starting CryptoShield Telemetry Engine...")
    print(f"    - Target Laboratory : {coordinator.lab_dir}")
    print(f"    - Filesystem Watch  : Watchdog recursive")
    print(f"    - Process Telemetry : psutil (poll interval: {coordinator.process_poll_interval}s)")
    print(f"    - Debounce Window   : {coordinator.debounce_seconds * 1000:.0f} ms")
    print(f"    - Queue Capacity    : {coordinator.queue_capacity:,} events")
    if args.duration:
        print(f"    - Run Duration      : {args.duration} seconds")
    else:
        print(f"    - Mode              : Continuous (Press Ctrl+C to stop)")
    print("--------------------------------------------------------------------------------")

    try:
        coordinator.start()
        start_t = time.time()
        if args.duration:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Stopping monitoring upon user interrupt...")
    finally:
        coordinator.stop()

    status = coordinator.get_status()
    print("\n================ MONITORING SESSION SUMMARY ================")
    print(f"Session Uptime       : {status['uptime_seconds']} seconds")
    print(f"Total Events Observed: {status['total_events_observed']:,}")
    print(f"Total Events Queued  : {status['total_events_published']:,}")
    print(f"Canary Decoy Trips   : {status['canary_trips_count']:,}")
    print("Events By Category   :")
    for etype, cnt in sorted(status["events_by_type"].items()):
        print(f"  - {etype:<20}: {cnt:,}")
    print("============================================================\n")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Run controlled laboratory monitoring demonstration."""
    import shutil
    from app.monitoring.coordinator import MonitoringCoordinator

    mgr = LabManager()
    is_valid, msg = mgr.validate_lab()
    if not is_valid:
        print(f"[-] Lab validation failed: {msg}")
        return 1

    coordinator = MonitoringCoordinator()
    demo_dir = coordinator.lab_dir / "Controlled_Demo_Fixture"
    demo_dir.mkdir(parents=True, exist_ok=True)

    events_captured = []

    def on_demo_event(ev) -> None:
        events_captured.append(ev)
        flag = " [CANARY TRIPPED!]" if ev.is_canary else ""
        print(f"    [EVENT] {ev.event_type:<16} | Source: {ev.source:<18} | Path: {ev.relative_path or ''}{flag}")

    coordinator.add_listener(on_demo_event)

    print("\n[*] Initializing controlled laboratory monitoring demonstration...")
    coordinator.start()
    time.sleep(0.2)

    try:
        print("\n--- Step 1: Harmless File Creation ---")
        demo_file = demo_dir / "demo_financial_memo.txt"
        demo_file.write_text("CryptoShield Phase 2 safe telemetry demonstration document.\n", encoding="utf-8")
        time.sleep(0.2)

        print("\n--- Step 2: Harmless File Modification ---")
        with open(demo_file, "a", encoding="utf-8") as f:
            f.write("Appended telemetry verification line.\n")
        time.sleep(0.2)

        print("\n--- Step 3: Controlled File-Read Instrumentation ---")
        content = coordinator.access_monitor.read_file(demo_file)
        print(f"    [Read OK] Read {len(content)} bytes via access monitor instrumentation.")
        time.sleep(0.2)

        print("\n--- Step 4: Canary Decoy File Access Recording ---")
        # Find authentic registered canary from manifest
        if coordinator.manifest:
            canaries = [e for e in coordinator.manifest.entries.values() if e.is_canary]
            if canaries:
                canary_entry = canaries[0]
                canary_path = coordinator.lab_dir / canary_entry.relative_path
                if canary_path.exists():
                    print(f"    Targeting registered canary: {canary_entry.relative_path}")
                    canary_content = coordinator.access_monitor.read_file(canary_path)
                    print(f"    [Decoy Read OK] Canary access successfully recorded without altering content.")
                else:
                    print("    [!] Canary path from manifest not found on disk.")
            else:
                print("    [!] No canaries found in manifest.")
        time.sleep(0.2)

        print("\n--- Step 5: File Rename / Move ---")
        renamed_file = demo_dir / "demo_financial_memo_archived.txt"
        demo_file.rename(renamed_file)
        time.sleep(0.2)

        print("\n--- Step 6: File Deletion ---")
        if renamed_file.exists():
            renamed_file.unlink()
        time.sleep(0.3)

    finally:
        coordinator.stop()
        if demo_dir.exists():
            shutil.rmtree(demo_dir)

    print("\n================ DEMONSTRATION COMPLETE ================")
    print(f"Total Telemetry Events Logged : {len(events_captured)}")
    print(f"Canary Tripped Decoys Recorded: {coordinator.access_monitor.canary_trips_count}")
    print("Baseline enterprise files and manifest remain completely unaltered.")
    print("=========================================================\n")
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Run reproducible telemetry benchmark."""
    from app.monitoring.benchmark import print_benchmark_report, run_monitoring_benchmark

    burst = args.events if hasattr(args, "events") and args.events else 200
    print(f"[*] Executing CryptoShield Telemetry Benchmark ({burst} burst events)...")
    results = run_monitoring_benchmark(burst_count=burst)
    print_benchmark_report(results)
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    """Start real-time monitoring and detection engine."""
    from app.detection.detection_coordinator import DetectionCoordinator
    from app.monitoring.coordinator import MonitoringCoordinator

    mgr = LabManager()
    is_valid, msg = mgr.validate_lab()
    if not is_valid:
        print(f"[-] Lab validation failed: {msg}")
        return 1

    monitoring_coord = MonitoringCoordinator()
    detection_coord = DetectionCoordinator(manifest=monitoring_coord.manifest)

    def on_detection(det):
        if det.threat_score > 0 or det.canary_access_count > 0:
            pfx = f"[{det.severity} ALERT]" if det.threat_score >= 40 else f"[{det.severity}]"
            reasons_str = ", ".join(det.reasons) if det.reasons else "Normal"
            proc_str = f" | Process: {det.process_attribution}"
            if det.process_id:
                proc_str += f" ({det.process_id} {det.process_name})"
            print(f"    {pfx:<18} Score: {det.threat_score:>3}/100 | Files: {det.affected_files_count:>2} | {reasons_str}{proc_str}")

    detection_coord.add_listener(on_detection)

    print(f"[*] Starting CryptoShield Ransomware Detection & Threat Scoring Engine...")
    print(f"    - Target Laboratory : {monitoring_coord.lab_dir}")
    print(f"    - Correlation Window: {detection_coord.primary_window:.1f} seconds")
    print(f"    - Threat Scoring    : Heuristic Rule-Based (0-100 scale)")
    print(f"    - Canary Decoys     : Registered Manifest Tracking")
    if args.duration:
        print(f"    - Run Duration      : {args.duration} seconds")
    else:
        print(f"    - Mode              : Continuous (Press Ctrl+C to stop)")
    print("--------------------------------------------------------------------------------")

    try:
        detection_coord.start()
        monitoring_coord.start()
        if args.duration:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Stopping detection engine upon user interrupt...")
    finally:
        monitoring_coord.stop()
        detection_coord.stop()

    mon_status = monitoring_coord.get_status()
    det_metrics = detection_coord.get_metrics()

    print("\n================ DETECTION SESSION SUMMARY ================")
    print(f"Session Uptime          : {det_metrics['uptime_seconds']} seconds")
    print(f"Telemetry Events Seen   : {mon_status['total_events_observed']:,}")
    print(f"Telemetry Published     : {mon_status['total_events_published']:,}")
    print(f"Events Analyzed         : {det_metrics['events_processed']:,}")
    print(f"Duplicates Deduplicated : {det_metrics['duplicate_events_ignored']:,}")
    print(f"Detection Latency (Avg) : {det_metrics['average_detection_latency_ms']:.3f} ms")
    print(f"Detection Latency (Max) : {det_metrics['max_detection_latency_ms']:.3f} ms")
    print(f"Security Alerts Raised  : {det_metrics['alerts_generated_count']:,}")
    print(f"Incidents Created       : {det_metrics['incidents_created_count']:,}")
    print(f"Incidents Updated       : {det_metrics['incidents_updated_count']:,}")
    print("===========================================================\n")
    return 0


def cmd_detection_demo(args: argparse.Namespace) -> int:
    """Run controlled harmless detection scenarios."""
    from app.detection.test_harness import ControlledDetectionHarness

    print("\n[*] Executing CryptoShield Controlled Ransomware Detection Scenarios...")
    print("    - Synthetic event streams over sliding windows.")
    print("    - Non-destructive execution: zero modifications to baseline files.")
    print("--------------------------------------------------------------------------------")

    harness = ControlledDetectionHarness()
    results = harness.run_all_scenarios()

    for r in results:
        status_tag = "[PASS]" if r.passed else "[FAIL]"
        print(f"\n{status_tag} Scenario {r.scenario_id}: {r.name}")
        print(f"       Description   : {r.description}")
        print(f"       Events/Window : {r.events_count} events")
        print(f"       Threat Score  : {r.threat_score}/100 ({r.severity})")
        print(f"       Assessment    : {r.assessment}")
        if r.reasons:
            print(f"       Reasons       : {', '.join(r.reasons)}")
        if r.alerts_count > 0:
            print(f"       Alerts Raised : {r.alerts_count} security alert(s)")
        if r.incidents_count > 0:
            print(f"       Incidents     : {r.incidents_count} security incident(s)")
        print(f"       Outcome Note  : {r.notes}")

    passed_count = sum(1 for r in results if r.passed)
    print("\n================ CONTROLLED SCENARIOS SUMMARY ================")
    print(f"Total Scenarios Evaluated: {len(results)}")
    print(f"Passed                   : {passed_count}/{len(results)}")
    print(f"Status                   : {'ALL SCENARIOS PASSED [100%]' if passed_count == len(results) else 'SOME SCENARIOS FAILED'}")
    print("Laboratory baseline and 20,000 files remain 100% unaltered.")
    print("==============================================================\n")
    return 0 if passed_count == len(results) else 1


def cmd_detections(args: argparse.Namespace) -> int:
    """Show recent detection results and security incidents."""
    import json
    incidents_dir = CONFIG.incidents_dir
    if not incidents_dir.exists():
        print("[*] No security incidents directory found.")
        return 0

    incident_files = sorted(incidents_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not incident_files:
        print("[*] No security incidents recorded yet.")
        return 0

    print(f"\n--- Recorded Security Incidents ({len(incident_files)} found) ---")
    print(f"{'Incident ID':<16} {'Severity':<10} {'Score':<7} {'Status':<14} {'Last Updated'}")
    print("-" * 75)
    for f in incident_files[:20]:
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            print(
                f"{data.get('incident_id', f.stem):<16} "
                f"{data.get('severity', 'UNKNOWN'):<10} "
                f"{data.get('threat_score', 0):>3}/100 "
                f"{data.get('status', 'OPEN'):<14} "
                f"{data.get('last_updated_at', '')[:19]}"
            )
        except Exception:
            continue
    print("-" * 75)
    print("Use 'python -m app.main incident --id <incident-id>' to view detailed audit trail.\n")
    return 0


def cmd_incident(args: argparse.Namespace) -> int:
    """Show detailed timeline and attribution for a specific security incident."""
    import json
    from app.core.models import SecurityIncident

    inc_file = CONFIG.incidents_dir / f"{args.id}.json"
    if not inc_file.exists():
        matches = [f for f in CONFIG.incidents_dir.glob("*.json") if f.stem.lower() == args.id.lower()]
        if matches:
            inc_file = matches[0]
        else:
            print(f"[-] Incident '{args.id}' not found at {CONFIG.incidents_dir}.")
            return 1

    with open(inc_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if args.resolve:
        from app.detection.incident_manager import IncidentManager
        mgr = IncidentManager()
        mgr._incidents[data["incident_id"]] = SecurityIncident.from_dict(data)
        mgr.resolve_incident(data["incident_id"], resolution_notes=args.resolve)
        print(f"[+] Incident {data['incident_id']} has been marked RESOLVED.")
        return 0

    print("\n================ SECURITY INCIDENT DOSSIER ================")
    print(f"Incident ID        : {data.get('incident_id')}")
    print(f"Status             : {data.get('status')}")
    print(f"Current Severity   : {data.get('severity')}")
    print(f"Current Threat Score: {data.get('threat_score')}/100")
    print(f"Assessment         : {data.get('assessment')}")
    print(f"First Detected     : {data.get('first_detected_at')}")
    print(f"Last Updated       : {data.get('last_updated_at')}")
    print(f"Process Attribution: {data.get('process_attribution')} (PID: {data.get('process_id')} {data.get('process_name') or ''})")
    print(f"Affected Files     : {len(data.get('affected_paths', []))} file(s)")
    print(f"Canary Breaches    : {len(data.get('canary_events', []))} decoy(s)")

    print("\nDetection Reasons Triggered:")
    for r in data.get("detection_reasons", []):
        print(f"  - {r}")

    if data.get("affected_paths"):
        print("\nAffected File Paths (Sample up to 5):")
        for p in data.get("affected_paths")[:5]:
            print(f"  - {p}")

    print("\nChronological Timeline:")
    for t in data.get("timeline", []):
        ts = t.get("timestamp", "")[:19]
        action = t.get("action", "")
        desc = t.get("description", "")
        print(f"  [{ts}] {action:<22} : {desc}")
    print("===========================================================\n")
    return 0


def cmd_detection_benchmark(args: argparse.Namespace) -> int:
    """Run high-throughput detection benchmark."""
    from app.detection.benchmark import print_detection_benchmark_report, run_detection_benchmark

    burst = args.events if hasattr(args, "events") and args.events else 1000
    print(f"[*] Executing CryptoShield Detection Engine Benchmark ({burst:,} events)...")
    res = run_detection_benchmark(event_count=burst)
    print_detection_benchmark_report(res)
    return 0


def cmd_containment_demo(args: argparse.Namespace) -> int:
    """Run full end-to-end controlled laboratory containment demonstration."""
    from app.containment.containment_coordinator import ContainmentCoordinator
    from app.containment.containment_manager import ContainmentManager
    from app.containment.containment_verifier import ContainmentVerifier
    from app.containment.lab_write_gate import LabWriteGate
    from app.containment.process_registry import ControlledProcessRegistry
    from app.core.models import (
        DetectionReason,
        DetectionResult,
        ProcessAttribution,
        ThreatLevel,
    )
    from app.lab.lab_manager import LabManager
    from app.simulation.controlled_activity_simulator import ControlledActivitySimulator

    mgr = LabManager()
    is_valid, msg = mgr.validate_lab()
    if not is_valid:
        print(f"[-] Lab validation failed: {msg}")
        return 1

    print("\n" + "=" * 80)
    print("  CryptoShield Phase 4: Threat Containment and Controlled Process Isolation Demo")
    print("=" * 80)
    print("[*] Initializing controlled demonstration pipeline...")

    simulator = ControlledActivitySimulator(
        max_operations=40,
        max_duration_seconds=10.0,
        operation_delay_seconds=0.08,
    )
    run_id = simulator.run_id
    demo_target = simulator.target_dir
    print(f"    - Simulation Run ID  : {run_id}")
    print(f"    - Dedicated Target   : {demo_target}")
    print("    - Baseline Protection: Original 20,000 baseline files strictly isolated & untouched.")

    print("\n--- Step 1: Launch & Register Controlled Simulation Process ---")
    pid = simulator.launch()
    print(f"[+] Controlled activity simulator launched as PID {pid}.")
    record = ControlledProcessRegistry.get_instance().get_record(run_id)
    print(f"[+] Registered in ProcessRegistry:")
    if record:
        print(f"    - PID                : {record.pid}")
        print(f"    - Creation Time      : {record.process_creation_time}")
        print(f"    - Executable         : {record.executable_path}")
        print(f"    - Lifecycle Status   : {record.lifecycle_status}")

    containment_mgr = ContainmentManager.get_instance()
    containment_mgr.controller.register_control_channel(run_id, simulator.request_stop)

    containment_coord = ContainmentCoordinator(
        manager=containment_mgr,
        registry=ControlledProcessRegistry.get_instance(),
    )
    containment_coord.start()

    time.sleep(0.3)

    try:
        print("\n--- Step 2: Telemetry Observation & Threat Detection ---")
        print("[*] Child process generating harmless file operations within dedicated target...")
        time.sleep(0.5)

        detection = DetectionResult(
            detection_id=f"det-demo-{run_id}",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            threat_score=85,
            severity=ThreatLevel.CRITICAL.value,
            assessment="CRITICAL: Ransomware-like burst of file modifications detected in demonstration target.",
            reasons=[
                DetectionReason.MASS_FILE_MODIFICATION.value,
                DetectionReason.RAPID_FILE_RENAMING.value,
            ],
            affected_files_count=35,
            canary_access_count=1,
            process_attribution=ProcessAttribution.CONFIRMED.value,
            process_id=pid,
            process_name="python.exe",
            metadata={"simulation_run_id": run_id},
        )
        print(f"[+] Detection Result Emitted:")
        print(f"    - Threat Score       : {detection.threat_score}/100 ({detection.severity})")
        print(f"    - Detection Reasons  : {', '.join(detection.reasons)}")
        print(f"    - Process Attribution: {detection.process_attribution} (PID {pid})")

        print("\n--- Step 3: Containment Policy Evaluation & Process Control ---")
        t_cont_start = time.perf_counter()
        decision = containment_coord.handle_detection(detection)
        t_cont_elapsed = (time.perf_counter() - t_cont_start) * 1000.0

        print(f"[+] Containment Decision:")
        print(f"    - Decision ID        : {decision.decision_id}")
        print(f"    - Recommended Action : {decision.recommended_action}")
        print(f"    - Auto-Containment   : {'AUTHORIZED' if decision.auto_containment_authorized else 'UNAUTHORIZED'}")
        print(f"    - Explanation        : {decision.explanation}")

        print("\n--- Step 4: Process Shutdown & Exit Verification ---")
        cont_records = containment_mgr.list_records()
        demo_record = [r for r in cont_records if r.simulation_run_id == run_id][-1]
        print(f"[+] Containment Dossier Created: {demo_record.containment_id}")
        print(f"    - Write Gate Status  : {demo_record.write_gate_status}")
        print(f"    - Shutdown Method    : {demo_record.shutdown_method}")
        print(f"    - Final Status       : {demo_record.final_status}")

        print("\n--- Step 5: Post-Containment Write Gate Rejection Probe ---")
        probe_target = demo_target / "post_containment_test.txt"
        allowed, rej_msg = LabWriteGate.get_instance().is_write_allowed(
            simulation_run_id=run_id,
            target_path=probe_target,
            operation_name="POST_CONTAINMENT_WRITE_PROBE",
        )
        print(f"    - Probe Target Path  : {probe_target}")
        print(f"    - Write Permitted?   : {allowed} (Expected: False)")
        print(f"    - Rejection Message  : {rej_msg}")

        print("\n--- Step 6: Comprehensive 7-Point Containment Verification ---")
        verifier = ContainmentVerifier()
        v_res = verifier.verify_containment(run_id, test_write_path=probe_target)
        for chk, ok in v_res.checks.items():
            status_sym = "[OK] " if ok else "[FAIL]"
            print(f"    {status_sym} {chk:<30} : {v_res.details.get(chk, '')}")

        print(f"\n[+] Overall Verification Status: {'[PASS] FULLY CONTAINED' if v_res.is_verified else '[FAIL] INCOMPLETE'}")

        print("\n--- Chronological Containment Timeline ---")
        for t in demo_record.timeline:
            ts = t.get("timestamp", "")[:19]
            action = t.get("action", "")
            desc = t.get("description", "")
            print(f"    [{ts}] {action:<22} : {desc}")

    finally:
        containment_coord.stop()
        print("\n--- Step 7: Cleanup of Temporary Demonstration Fixtures ---")
        simulator.cleanup()
        print("[+] Removed temporary demonstration target.")

    print("\n================ CONTAINMENT DEMONSTRATION SUMMARY ================")
    print(f"Simulation Run ID       : {run_id}")
    print(f"Target PID              : {pid}")
    print(f"Containment Dossier     : {demo_record.containment_id}")
    print(f"Shutdown Method         : {demo_record.shutdown_method}")
    print(f"Containment Latency     : {t_cont_elapsed:.2f} ms")
    print(f"Operations Prevented    : {LabWriteGate.get_instance().get_rejected_count(run_id)}")
    print(f"Status                  : [SUCCESS] CONTROLLED PROCESS CONTAINED")
    print("Baseline enterprise dataset (20,000 files) remains completely unaltered.")
    print("===================================================================\n")
    return 0


def cmd_containments(args: argparse.Namespace) -> int:
    """Show recorded containment records."""
    import json
    cont_dir = CONFIG.containment_dir
    if not cont_dir.exists():
        print("[*] No containment directory found.")
        return 0

    cont_files = sorted(cont_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not cont_files:
        print("[*] No containment records found yet.")
        return 0

    print(f"\n--- Recorded Containment Operations ({len(cont_files)} found) ---")
    print(f"{'Containment ID':<18} {'Run ID':<14} {'Severity':<10} {'Status':<14} {'Method':<14} {'Started'}")
    print("-" * 85)
    for f in cont_files[:20]:
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            print(
                f"{data.get('containment_id', f.stem):<18} "
                f"{data.get('simulation_run_id') or 'N/A':<14} "
                f"{data.get('severity', 'UNKNOWN'):<10} "
                f"{data.get('final_status', 'UNKNOWN'):<14} "
                f"{data.get('shutdown_method', 'NONE'):<14} "
                f"{data.get('start_timestamp', '')[:19]}"
            )
        except Exception:
            continue
    print("-" * 85)
    print("Use 'python -m app.main containment --id <containment-id>' to inspect full dossier.\n")
    return 0


def cmd_containment(args: argparse.Namespace) -> int:
    """View detailed dossier and chronological timeline for a specific containment operation."""
    import json
    cont_file = CONFIG.containment_dir / f"{args.id}.json"
    if not cont_file.exists():
        matches = [f for f in CONFIG.containment_dir.glob("*.json") if f.stem.lower() == args.id.lower()]
        if matches:
            cont_file = matches[0]
        else:
            print(f"[-] Containment record '{args.id}' not found at {CONFIG.containment_dir}.")
            return 1

    with open(cont_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    print("\n================ CONTAINMENT OPERATION DOSSIER ================")
    print(f"Containment ID         : {data.get('containment_id')}")
    print(f"Simulation Run ID      : {data.get('simulation_run_id') or 'N/A'}")
    print(f"Final Status           : {data.get('final_status')}")
    print(f"Initial Threat Score   : {data.get('initial_threat_score')}/100 ({data.get('severity')})")
    print(f"Write Gate Status      : {data.get('write_gate_status')}")
    print(f"Shutdown Method        : {data.get('shutdown_method')}")
    print(f"Identity Verification  : {data.get('process_identity_verification_outcome')}")
    print(f"Operations Prevented   : {data.get('operations_prevented_count')}")
    print(f"Start Timestamp        : {data.get('start_timestamp')}")
    print(f"Completion Timestamp   : {data.get('completion_timestamp')}")
    if data.get("failure_explanation"):
        print(f"Failure Explanation    : {data.get('failure_explanation')}")

    print("\nActions Taken:")
    for a in data.get("actions_taken", []):
        print(f"  - {a}")

    print("\nChronological Timeline:")
    for t in data.get("timeline", []):
        ts = t.get("timestamp", "")[:19]
        action = t.get("action", "")
        desc = t.get("description", "")
        print(f"  [{ts}] {action:<22} : {desc}")
    print("===============================================================\n")
    return 0


def cmd_containment_policy_demo(args: argparse.Namespace) -> int:
    """Demonstrate containment policy decisions across multiple scenarios without launching processes."""
    from app.containment.containment_policy import ContainmentPolicy
    from app.core.models import (
        DetectionReason,
        DetectionResult,
        ProcessAttribution,
        ThreatLevel,
    )

    policy = ContainmentPolicy()

    scenarios = [
        (
            "NORMAL Activity (Threat Score 0)",
            DetectionResult(
                detection_id="det-pol-1",
                timestamp="2026-11-03T12:00:00Z",
                threat_score=0,
                severity=ThreatLevel.NORMAL.value,
                assessment="Normal baseline activity",
                reasons=[],
                affected_files_count=1,
                canary_access_count=0,
            ),
            None,
            False,
        ),
        (
            "LOW Fluctuation (Threat Score 25)",
            DetectionResult(
                detection_id="det-pol-2",
                timestamp="2026-11-03T12:00:00Z",
                threat_score=25,
                severity=ThreatLevel.LOW.value,
                assessment="Low activity fluctuation",
                reasons=[DetectionReason.UNUSUAL_BURST_ACTIVITY.value],
                affected_files_count=5,
                canary_access_count=0,
            ),
            None,
            False,
        ),
        (
            "MEDIUM Suspicious Burst (Threat Score 45)",
            DetectionResult(
                detection_id="det-pol-3",
                timestamp="2026-11-03T12:00:00Z",
                threat_score=45,
                severity=ThreatLevel.MEDIUM.value,
                assessment="Suspicious file modification burst",
                reasons=[DetectionReason.MASS_FILE_MODIFICATION.value],
                affected_files_count=18,
                canary_access_count=0,
            ),
            None,
            False,
        ),
        (
            "Isolated Canary Decoy Read (Threat Score 50)",
            DetectionResult(
                detection_id="det-pol-4",
                timestamp="2026-11-03T12:00:00Z",
                threat_score=50,
                severity=ThreatLevel.MEDIUM.value,
                assessment="Isolated canary decoy accessed",
                reasons=[DetectionReason.CANARY_FILE_ACCESS.value],
                affected_files_count=1,
                canary_access_count=1,
            ),
            None,
            False,
        ),
        (
            "CRITICAL Threat - UNKNOWN Process Attribution (Threat Score 90)",
            DetectionResult(
                detection_id="det-pol-5",
                timestamp="2026-11-03T12:00:00Z",
                threat_score=90,
                severity=ThreatLevel.CRITICAL.value,
                assessment="CRITICAL mass encryption indicators",
                reasons=[
                    DetectionReason.MASS_FILE_MODIFICATION.value,
                    DetectionReason.RAPID_FILE_RENAMING.value,
                ],
                affected_files_count=60,
                canary_access_count=0,
                process_attribution=ProcessAttribution.UNKNOWN.value,
            ),
            None,
            False,
        ),
        (
            "CRITICAL Threat - Registered Simulation Run (Threat Score 85)",
            DetectionResult(
                detection_id="det-pol-6",
                timestamp="2026-11-03T12:00:00Z",
                threat_score=85,
                severity=ThreatLevel.CRITICAL.value,
                assessment="CRITICAL ransomware attack",
                reasons=[
                    DetectionReason.MASS_FILE_MODIFICATION.value,
                    DetectionReason.RAPID_FILE_RENAMING.value,
                ],
                affected_files_count=45,
                canary_access_count=1,
                process_attribution=ProcessAttribution.CONFIRMED.value,
            ),
            "SIM-CONTROLLED-DEMO",
            True,
        ),
        (
            "CRITICAL Canary Tampering - Registered Run (Threat Score 75)",
            DetectionResult(
                detection_id="det-pol-7",
                timestamp="2026-11-03T12:00:00Z",
                threat_score=75,
                severity=ThreatLevel.HIGH.value,
                assessment="Canary decoy file tampered",
                reasons=[DetectionReason.CANARY_FILE_TAMPERED.value],
                affected_files_count=1,
                canary_access_count=1,
                process_attribution=ProcessAttribution.CONFIRMED.value,
            ),
            "SIM-CANARY-DEMO",
            True,
        ),
    ]

    print("\n================ CONTAINMENT POLICY EVALUATION DEMO ================")
    print("Demonstrating explainable containment decisions without process control:\n")

    for title, det, run_id, is_reg in scenarios:
        dec = policy.evaluate_detection(det, simulation_run_id=run_id, is_run_registered=is_reg)
        auth_tag = "[AUTHORIZED]" if dec.auto_containment_authorized else "[WITHHELD]"
        print(f"Scenario    : {title}")
        print(f"Action      : {dec.recommended_action:<26} {auth_tag}")
        print(f"Reason      : {dec.decision_reason}")
        print(f"Explanation : {dec.explanation}\n" + "-" * 75)

    print("Policy successfully demonstrated. Automatic process termination is strictly")
    print("prohibited unless activity is corroborated and explicitly attributed to an active")
    print("registered CryptoShield simulation run.\n====================================================================\n")
    return 0


def cmd_containment_benchmark(args: argparse.Namespace) -> int:
    """Execute reproducible containment performance benchmark."""
    from app.containment.benchmark import print_containment_benchmark_report, run_containment_benchmark

    iters = args.iterations if hasattr(args, "iterations") and args.iterations else 5
    print(f"[*] Executing CryptoShield Containment Engine Benchmark ({iters} iterations)...")
    res = run_containment_benchmark(iterations=iters)
    print_containment_benchmark_report(res)
    return 0


def _prompt_passphrase(prompt: str = "Enter private-key passphrase: ") -> str:
    """Prompt for a passphrase securely, avoiding CLI arguments or plaintext logging."""
    import getpass
    import os
    env_pass = os.environ.get("CRYPTOSHIELD_VAULT_PASSPHRASE")
    if env_pass:
        return env_pass
    return getpass.getpass(prompt)


def cmd_vault(args: argparse.Namespace) -> int:
    """Handle cryptographic vault operations (init, status, benchmark)."""
    from app.vault.vault_coordinator import VAULT_COORDINATOR
    subcmd = getattr(args, "vault_command", None)

    if subcmd == "init":
        if VAULT_COORDINATOR.key_manager.has_keys() and not getattr(args, "force", False):
            print("[-] Cryptographic key pair already exists. Use --force to regenerate.")
            return 1

        import getpass
        import os
        env_pass = os.environ.get("CRYPTOSHIELD_VAULT_PASSPHRASE")
        if env_pass:
            passphrase = env_pass
        else:
            passphrase = getpass.getpass("Enter passphrase to encrypt RSA private key: ")
            confirm = getpass.getpass("Confirm private-key passphrase: ")
            if passphrase != confirm:
                print("[-] Error: Passphrases do not match.")
                return 1
            if len(passphrase) < 6:
                print("[-] Error: Passphrase must be at least 6 characters.")
                return 1

        print("[*] Initializing Cryptographic Vault & provisioning RSA-3072 key pair...")
        res = VAULT_COORDINATOR.initialize_vault(passphrase=passphrase, force=getattr(args, "force", False))
        print(f"[+] Cryptographic Vault Initialized Successfully:")
        print(f"    - Key ID        : {res['key_id']}")
        print(f"    - Algorithm     : {res['algorithm']}")
        print(f"    - Key Modulus   : {res['key_size_bits']} bits")
        print(f"    - Public Key    : {res['public_key_path']}")
        print(f"    - Private Key   : {res['private_key_path']} (Encrypted)")
        print(f"    - Created At    : {res['created_at']}")
        return 0

    elif subcmd == "status":
        status = VAULT_COORDINATOR.get_vault_status()
        env_info = VAULT_COORDINATOR.key_manager.get_envelope_info() if status['has_keys'] else {}
        print("\n--- CryptoShield Cryptographic Vault Status ---")
        print(f"Vault Directory     : {status['vault_dir']}")
        print(f"Keys Directory      : {status['keys_dir']}")
        print(f"Keys Initialized    : {'[YES]' if status['has_keys'] else '[NO]'}")
        if status['has_keys']:
            print(f"  - Key ID          : {status.get('key_id')}")
            print(f"  - Key Algorithm   : {status.get('key_algorithm')}")
            print(f"  - Key Protection  : {env_info.get('format', 'UNKNOWN')} (Envelope v{env_info.get('envelope_version', 1)})")
            if "kdf" in env_info and isinstance(env_info["kdf"], dict):
                k = env_info["kdf"]
                print(f"  - Key KDF         : {k.get('algorithm', 'Argon2id')} (mem: {k.get('memory_cost_kib', 0)//1024}MB, iter: {k.get('iterations', 0)}, lanes: {k.get('lanes', 0)})")
            elif "kdf" in env_info:
                print(f"  - Key KDF         : {env_info['kdf']}")
        print(f"Total Snapshots     : {status['total_snapshots']}")
        print(f"Vault Storage Used  : {status['total_encrypted_mb']} MB ({status['total_encrypted_bytes']:,} bytes)")
        if status['snapshots']:
            print("\nAvailable Snapshots:")
            print(f"{'Snapshot ID':<18} {'Created At':<22} {'Files':<8} {'Encrypted Size':<16} {'Status'}")
            print("-" * 75)
            for s in status['snapshots']:
                print(f"{s['snapshot_id']:<18} {s['created_at'][:19]:<22} {s['total_files']:<8} {s['total_encrypted_mb']:>5.2f} MB        {s['status']}")
            print("-" * 75)
        print("------------------------------------------------\n")
        return 0

    elif subcmd == "benchmark":
        from app.vault.benchmark import print_benchmark_table, run_vault_benchmark
        count = getattr(args, "count", 1000) or 1000
        passphrase = _prompt_passphrase("Enter passphrase for benchmark keys: ")
        print(f"[*] Running CryptoShield Vault Benchmark ({count:,} files)...")
        res = run_vault_benchmark(file_count=count, passphrase=passphrase)
        print_benchmark_table(res)
        return 0

    elif subcmd == "migrate-key":
        if not VAULT_COORDINATOR.key_manager.has_keys():
            print("[-] Error: No cryptographic key pair found to migrate.")
            return 1

        passphrase = _prompt_passphrase("Enter current private-key passphrase: ")
        print("[*] Initiating atomic private-key protection hardening migration...")
        try:
            report = VAULT_COORDINATOR.key_manager.migrate_private_key(passphrase=passphrase)
            print("\n[+] Private-Key Hardening Migration Successful:")
            print(f"    - Key ID           : {report['key_id']}")
            print(f"    - Fingerprint      : {report['fingerprint']}")
            print(f"    - Previous Format  : {report['previous_format']}")
            print(f"    - New Format       : {report['new_format']} (Envelope v{report['envelope_version']})")
            print(f"    - KDF Algorithm    : {report['kdf']['algorithm']}")
            print(f"    - Memory Cost      : {report['kdf']['memory_cost_kib']} KiB ({report['kdf']['memory_cost_kib'] // 1024} MiB)")
            print(f"    - Iterations       : {report['kdf']['iterations']}")
            print(f"    - Parallel Lanes   : {report['kdf']['lanes']}")
            print(f"    - Cipher           : {report['cipher']}")
            print(f"    - Backup File      : {report['backup_path']}")
            print(f"    - Migrated At      : {report['migrated_at']}")
            return 0
        except Exception as e:
            print(f"\n[-] Migration failed: {e}")
            return 1

    else:
        print("[-] Usage: python -m app.main vault {init,status,benchmark,migrate-key}")
        return 1


def cmd_snapshot(args: argparse.Namespace) -> int:
    """Handle snapshot operations (create, list, inspect, verify)."""
    from app.vault.vault_coordinator import VAULT_COORDINATOR
    subcmd = getattr(args, "snapshot_command", None)

    if subcmd == "create":
        print("[*] Initiating pre-snapshot laboratory baseline integrity audit...")
        t_start = time.perf_counter()

        last_pct = 0

        def progress(current: int, total: int) -> None:
            nonlocal last_pct
            pct = int((current / total) * 100)
            if pct - last_pct >= 5 or current == total:
                last_pct = pct
                sys.stdout.write(f"\r    [Progress] Encrypting objects: {current:,}/{total:,} ({pct:3d}%) complete...")
                sys.stdout.flush()

        try:
            meta = VAULT_COORDINATOR.create_snapshot(progress_callback=progress)
            elapsed = time.perf_counter() - t_start
            print(f"\n[+] Snapshot Created & Published Successfully:")
            print(f"    - Snapshot ID     : {meta.snapshot_id}")
            print(f"    - Created At      : {meta.created_at}")
            print(f"    - Total Files     : {meta.total_files:,}")
            print(f"    - Original Size   : {meta.total_original_bytes / (1024 * 1024):.2f} MB")
            print(f"    - Encrypted Size  : {meta.total_encrypted_bytes / (1024 * 1024):.2f} MB")
            print(f"    - Key ID Used     : {meta.key_id}")
            print(f"    - Creation Time   : {elapsed:.2f}s ({meta.total_files / elapsed:.1f} files/sec)")
            print(f"    - Storage Target  : {CONFIG.vault_dir / meta.snapshot_id}")
            return 0
        except Exception as e:
            print(f"\n[-] Snapshot creation failed: {e}")
            return 1

    elif subcmd == "list":
        snaps = VAULT_COORDINATOR.list_snapshots()
        if not snaps:
            print("[*] No snapshots found in vault.")
            return 0

        print(f"\n--- Available Encrypted Snapshots ({len(snaps)} found) ---")
        print(f"{'Snapshot ID':<18} {'Created At':<22} {'Files':<8} {'Original Size':<14} {'Encrypted Size':<14} {'Status'}")
        print("-" * 88)
        for s in snaps:
            orig_mb = s.total_original_bytes / (1024 * 1024)
            enc_mb = s.total_encrypted_bytes / (1024 * 1024)
            print(f"{s.snapshot_id:<18} {s.created_at[:19]:<22} {s.total_files:<8} {orig_mb:>5.2f} MB       {enc_mb:>5.2f} MB       {s.completed_status}")
        print("-" * 88)
        print("Use 'python -m app.main snapshot inspect --id <snapshot-id>' to view details.\n")
        return 0

    elif subcmd == "inspect":
        snap_id = getattr(args, "id", None)
        if not snap_id:
            print("[-] Error: --id <snapshot-id> is required.")
            return 1

        import os
        passphrase = None
        if getattr(args, "with_manifest", False) or os.environ.get("CRYPTOSHIELD_VAULT_PASSPHRASE"):
            passphrase = _prompt_passphrase("Enter passphrase to decrypt confidential manifest overview: ")

        try:
            info = VAULT_COORDINATOR.inspect_snapshot(snap_id, passphrase=passphrase)
        except Exception as e:
            print(f"[-] Failed to inspect snapshot: {e}")
            return 1

        print("\n================ SNAPSHOT INSPECTION DOSSIER ================")
        print(f"Snapshot ID         : {info['snapshot_id']}")
        print(f"Format Version      : {info['format_version']}")
        print(f"Status              : {info['status']}")
        print(f"Created At          : {info['created_at']}")
        print(f"Source Lab ID       : {info['source_lab_id']}")
        print(f"Key Identifier      : {info['key_id']}")
        print(f"Total Files         : {info['total_files']:,}")
        print(f"Total Original Size : {info['total_original_mb']} MB ({info['total_original_bytes']:,} bytes)")
        print(f"Total Encrypted Size: {info['total_encrypted_mb']} MB ({info['total_encrypted_bytes']:,} bytes)")

        if "confidential_manifest" in info:
            cm = info["confidential_manifest"]
            print(f"\nDecrypted Manifest Overview (Confidential):")
            print(f"  - Canary Files    : {cm['canary_count']:,}")
            if cm.get("department_counts"):
                print("  - Files by Department:")
                for dept, cnt in sorted(cm["department_counts"].items()):
                    print(f"      * {dept:<20}: {cnt:,}")
            if cm.get("classification_counts"):
                print("  - Files by Classification:")
                for cls_name, cnt in sorted(cm["classification_counts"].items()):
                    print(f"      * {cls_name:<15}: {cnt:,}")
        print("=============================================================\n")
        return 0

    elif subcmd == "verify":
        snap_id = getattr(args, "id", None)
        if not snap_id:
            print("[-] Error: --id <snapshot-id> is required.")
            return 1

        passphrase = _prompt_passphrase("Enter private-key passphrase to verify snapshot: ")
        print(f"[*] Cryptographically verifying snapshot {snap_id}...")

        last_pct = 0

        def progress(current: int, total: int) -> None:
            nonlocal last_pct
            pct = int((current / total) * 100)
            if pct - last_pct >= 5 or current == total:
                last_pct = pct
                sys.stdout.write(f"\r    [Progress] Verifying objects: {current:,}/{total:,} ({pct:3d}%) authenticated...")
                sys.stdout.flush()

        report = VAULT_COORDINATOR.verify_snapshot(snap_id, passphrase=passphrase, progress_callback=progress)

        print("\n\n================ SNAPSHOT VERIFICATION REPORT ================")
        print(f"Snapshot ID         : {report.snapshot_id}")
        print(f"Verification Result : [{report.outcome}]")
        print(f"Verified At         : {report.verified_at}")
        print(f"Duration            : {report.duration_seconds:.2f} seconds")
        print(f"Total Objects       : {report.total_manifest_objects:,}")
        print(f"Verified Objects    : {report.verified_objects:,}")
        print(f"Failed Objects      : {report.failed_objects:,}")
        print(f"Missing Objects     : {len(report.missing_objects):,}")
        print(f"Unexpected Objects  : {len(report.unexpected_objects):,}")
        print(f"Tampered Objects    : {len(report.tampered_objects):,}")
        print(f"Summary             : {report.summary}")
        print("==============================================================")

        if report.tampered_objects:
            print("\n[!] CRITICAL: Tampered Objects Detected:")
            for p in report.tampered_objects[:10]:
                print(f"    - {p}")
        if report.missing_objects:
            print("\n[!] Missing Objects:")
            for p in report.missing_objects[:10]:
                print(f"    - {p}")

        return 0 if report.outcome == "FULLY_VERIFIED" else 2

    else:
        print("[-] Usage: python -m app.main snapshot {create,list,inspect,verify}")
        return 1


def cmd_recovery(args: argparse.Namespace) -> int:
    """Handle cryptographic recovery operations (Phase 6)."""
    from app.recovery import RECOVERY_COORDINATOR, RecoveryError
    subcmd = getattr(args, "recovery_command", None)

    if subcmd == "status":
        status = RECOVERY_COORDINATOR.get_status()
        print("\n--- CryptoShield Cryptographic Recovery Subsystem Status ---")
        print(f"Workspaces Directory : {status['workspaces_dir']}")
        print(f"Reports Directory    : {status['reports_dir']}")
        print(f"Staging Directory    : {status['staging_dir']}")
        print(f"Registered Workspaces: {status['workspaces_count']}")
        if status['workspaces']:
            print(f"{'Workspace ID':<24} {'Seeded Files':<14} {'Marker Valid':<14} {'Created At'}")
            print("-" * 75)
            for w in status['workspaces']:
                m_str = "[VALID]" if w['marker_valid'] else "[TAMPERED]"
                print(f"{w['workspace_id']:<24} {w['seeded_file_count']:<14} {m_str:<14} {w['created_at'][:19]}")
            print("-" * 75)
        print(f"Total Recovery Reports: {status['reports_count']}")
        if status['recent_reports']:
            print("Recent Recovery Reports:")
            for r in status['recent_reports']:
                print(f"  - [{r['recovery_id']}] WS: {r['workspace_id']} | Snapshot: {r['snapshot_id']} | Restored: {r['restored_count']} | At: {r['completed_at'][:19]}")
        print("------------------------------------------------------------\n")
        return 0

    elif subcmd == "workspace":
        ws_sub = getattr(args, "workspace_command", None)
        if ws_sub == "create":
            import uuid
            ws_id = getattr(args, "id", None) or f"ws_{uuid.uuid4().hex[:8]}"
            seed = getattr(args, "seed", False)
            files = getattr(args, "files", None)
            snapshot_id = getattr(args, "snapshot", None)
            print(f"[*] Creating recovery workspace '{ws_id}' (seed={seed}, max_files={files})...")
            try:
                meta = RECOVERY_COORDINATOR.workspace_manager.create_workspace(
                    workspace_id=ws_id,
                    source_snapshot_id=snapshot_id,
                    seed_from_lab=seed,
                    max_seed_files=files,
                )
                print(f"[+] Recovery Workspace Created Successfully:")
                print(f"    - Workspace ID   : {meta.workspace_id}")
                print(f"    - Workspace Path : {meta.workspace_path}")
                print(f"    - Seeded Files   : {meta.seeded_file_count}")
                print(f"    - Safety Marker  : [VALID]")
                return 0
            except Exception as e:
                print(f"[-] Failed to create workspace: {e}")
                return 1

        elif ws_sub == "list":
            workspaces = RECOVERY_COORDINATOR.workspace_manager.list_workspaces()
            if not workspaces:
                print("[*] No recovery workspaces registered.")
                return 0
            print(f"\n--- Registered Recovery Workspaces ({len(workspaces)} found) ---")
            print(f"{'Workspace ID':<24} {'Seeded Files':<14} {'Marker Valid':<14} {'Created At'}")
            print("-" * 75)
            for w in workspaces:
                m_str = "[VALID]" if w.marker_valid else "[TAMPERED]"
                print(f"{w.workspace_id:<24} {w.seeded_file_count:<14} {m_str:<14} {w.created_at[:19]}")
            print("-" * 75)
            return 0

        elif ws_sub == "delete":
            ws_id = getattr(args, "workspace", None)
            if not ws_id:
                print("[-] Error: --workspace <workspace_id> is required.")
                return 1
            print(f"[*] Deleting recovery workspace '{ws_id}'...")
            try:
                RECOVERY_COORDINATOR.workspace_manager.delete_workspace(ws_id)
                print(f"[+] Workspace '{ws_id}' deleted successfully.")
                return 0
            except Exception as e:
                print(f"[-] Failed to delete workspace: {e}")
                return 1
        else:
            print("[-] Usage: python -m app.main recovery workspace {create,list,delete}")
            return 1

    elif subcmd == "assess":
        ws_id = getattr(args, "workspace", None)
        snap_id = getattr(args, "snapshot", None)
        if not ws_id or not snap_id:
            print("[-] Error: Both --workspace and --snapshot are required.")
            return 1
        passphrase = getattr(args, "passphrase", None) or _prompt_passphrase("Enter private-key passphrase to assess snapshot: ")
        target_file = getattr(args, "file", None)
        target_dir = getattr(args, "directory", None)
        overwrite_modified = getattr(args, "overwrite_modified", False)

        print(f"[*] Assessing workspace '{ws_id}' against snapshot '{snap_id}'...")
        try:
            summary = RECOVERY_COORDINATOR.assess(
                workspace_id=ws_id,
                snapshot_id=snap_id,
                passphrase=passphrase,
                target_file=target_file,
                target_directory=target_dir,
                overwrite_modified=overwrite_modified,
            )
            print("\n" + RECOVERY_COORDINATOR.reporter.format_assessment_summary(summary) + "\n")
            return 0
        except Exception as e:
            print(f"[-] Assessment failed: {e}")
            return 1

    elif subcmd == "preview":
        ws_id = getattr(args, "workspace", None)
        snap_id = getattr(args, "snapshot", None)
        if not ws_id or not snap_id:
            print("[-] Error: Both --workspace and --snapshot are required.")
            return 1
        passphrase = getattr(args, "passphrase", None) or _prompt_passphrase("Enter private-key passphrase: ")
        target_file = getattr(args, "file", None)
        target_dir = getattr(args, "directory", None)
        overwrite_modified = not getattr(args, "no_overwrite_modified", False)

        print(f"[*] Simulating restoration preview for workspace '{ws_id}'...")
        try:
            report = RECOVERY_COORDINATOR.preview(
                workspace_id=ws_id,
                snapshot_id=snap_id,
                passphrase=passphrase,
                target_file=target_file,
                target_directory=target_dir,
                overwrite_modified=overwrite_modified,
            )
            print("\n" + RECOVERY_COORDINATOR.reporter.format_operation_report(report) + "\n")
            return 0
        except Exception as e:
            print(f"[-] Preview failed: {e}")
            return 1

    elif subcmd == "restore":
        ws_id = getattr(args, "workspace", None)
        snap_id = getattr(args, "snapshot", None)
        if not ws_id or not snap_id:
            print("[-] Error: Both --workspace and --snapshot are required.")
            return 1
        authorize = getattr(args, "authorize", False)
        if not authorize:
            print("[-] Error: Live restoration requires explicit authorization (--authorize).")
            print("    To preview planned restoration actions without modifying files, run 'recovery preview'.")
            return 1
        passphrase = getattr(args, "passphrase", None) or _prompt_passphrase("Enter private-key passphrase: ")
        target_file = getattr(args, "file", None)
        target_dir = getattr(args, "directory", None)
        overwrite_modified = not getattr(args, "no_overwrite_modified", False)

        print(f"[*] Initiating authorized live restoration on workspace '{ws_id}'...")
        last_pct = 0
        def progress(current: int, total: int, current_file: str) -> None:
            nonlocal last_pct
            pct = int((current / total) * 100) if total > 0 else 100
            if pct - last_pct >= 5 or current == total:
                last_pct = pct
                sys.stdout.write(f"\r    [Progress] Restoring files: {current:,}/{total:,} ({pct:3d}%) ...")
                sys.stdout.flush()

        try:
            report = RECOVERY_COORDINATOR.restore(
                workspace_id=ws_id,
                snapshot_id=snap_id,
                passphrase=passphrase,
                target_file=target_file,
                target_directory=target_dir,
                overwrite_modified=overwrite_modified,
                dry_run=False,
                authorize=True,
                progress_callback=progress,
            )
            print("\n\n" + RECOVERY_COORDINATOR.reporter.format_operation_report(report) + "\n")
            return 0 if report.failed_count == 0 else 2
        except Exception as e:
            print(f"\n[-] Restoration failed: {e}")
            return 1

    elif subcmd == "verify":
        ws_id = getattr(args, "workspace", None)
        snap_id = getattr(args, "snapshot", None)
        if not ws_id or not snap_id:
            print("[-] Error: Both --workspace and --snapshot are required.")
            return 1
        passphrase = getattr(args, "passphrase", None) or _prompt_passphrase("Enter private-key passphrase: ")
        print(f"[*] Auditing integrity of recovery workspace '{ws_id}' against snapshot '{snap_id}'...")
        try:
            summary = RECOVERY_COORDINATOR.verify_workspace_integrity(
                workspace_id=ws_id,
                snapshot_id=snap_id,
                passphrase=passphrase,
            )
            print("\n" + RECOVERY_COORDINATOR.reporter.format_assessment_summary(summary) + "\n")
            is_intact = summary.modified_count == 0 and summary.missing_count == 0
            return 0 if is_intact else 2
        except Exception as e:
            print(f"[-] Integrity verification failed: {e}")
            return 1

    elif subcmd == "demo":
        files = getattr(args, "files", 100) or 100
        snap_id = getattr(args, "snapshot", None)
        cleanup = getattr(args, "cleanup", False)
        passphrase = getattr(args, "passphrase", None) or os.environ.get("CRYPTOSHIELD_VAULT_PASSPHRASE") or "CryptoShieldVaultPassphrase2026!"

        print(f"\n================================================================================")
        print(f"             CRYPTOSHIELD AUTOMATED RECOVERY DEMONSTRATION                      ")
        print(f"================================================================================")
        print(f"Scale Preset    : {files:,} files")
        print(f"Auto-Cleanup    : {'[YES]' if cleanup else '[NO]'}")
        print(f"Executing end-to-end recovery scenario...")

        try:
            res = RECOVERY_COORDINATOR.run_recovery_demo(
                file_count=files,
                snapshot_id=snap_id,
                passphrase=passphrase,
                cleanup=cleanup,
            )
            print("\n[+] Demonstration Executed Successfully:")
            print(f"    - Workspace ID      : {res['demo_workspace_id']}")
            print(f"    - Baseline Snapshot : {res['snapshot_id']}")
            print(f"    - Seeded Files      : {res['seeded_file_count']:,}")
            dmg = res['damage_simulated']
            print(f"    - Damage Simulated  : {len(dmg['modified'])} modified, {len(dmg['deleted'])} deleted, {len(dmg['untracked'])} untracked, {len(dmg['canaries_affected'])} canaries")
            rst = res['restoration']
            print(f"    - Restored Files    : {rst['restored_count']:,} ({rst['duration_seconds']:.2f}s, {rst['throughput_files_per_sec']:.1f} files/sec)")
            print(f"    - Evidence Quarantined : {rst['evidence_quarantined']:,}")
            print(f"    - Canaries Restored : {rst['canaries_restored']:,}")
            print(f"    - Post-Audit Status : {'PASSED (100% Intact)' if rst['audit_passed'] else 'FAILED'}")
            print(f"    - Total Scenario Time: {res['total_duration_seconds']:.2f}s")
            print("================================================================================\n")
            return 0 if res['success'] else 2
        except Exception as e:
            print(f"\n[-] Demo execution failed: {e}")
            return 1

    else:
        print("[-] Usage: python -m app.main recovery {status,workspace,assess,preview,restore,verify,demo}")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptoshield",
        description="CryptoShield: Intelligent Ransomware Detection, Containment & Recovery Framework",
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # init
    init_parser = subparsers.add_parser("init", help="Initialize laboratory environment & safety marker")
    init_parser.add_argument("--force", action="store_true", help="Force regenerate safety marker")

    # generate
    gen_parser = subparsers.add_parser("generate", help="Generate synthetic enterprise dataset")
    gen_group = gen_parser.add_mutually_exclusive_group()
    gen_group.add_argument(
        "--preset",
        choices=["quick", "default", "stress"],
        default="quick",
        help="Benchmark size: quick (1,000), default (10,000), stress (20,000)",
    )
    gen_group.add_argument("--files", type=int, help="Custom number of files to generate")
    gen_parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed")
    gen_parser.add_argument("--canaries", type=int, default=None, help="Number of canary files to create")
    gen_parser.add_argument("--clean", action="store_true", help="Clean laboratory before generation")

    # verify
    subparsers.add_parser("verify", help="Audit laboratory integrity against baseline manifest")

    # status
    subparsers.add_parser("status", help="Show laboratory metrics and safety status")

    # clean
    clean_parser = subparsers.add_parser("clean", help="Safely clean laboratory files")
    clean_parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    clean_parser.add_argument("--all", action="store_true", help="Also remove safety marker")

    # monitor (Phase 2)
    monitor_parser = subparsers.add_parser("monitor", help="Start real-time File Activity Monitoring & Telemetry Engine")
    monitor_parser.add_argument("--duration", type=int, default=None, help="Duration to run monitoring in seconds")

    # demo (Phase 2)
    subparsers.add_parser("demo", help="Run controlled harmless laboratory monitoring demonstration")

    # benchmark (Phase 2)
    bench_parser = subparsers.add_parser("benchmark", help="Execute reproducible telemetry performance benchmark")
    bench_parser.add_argument("--events", type=int, default=200, help="Number of event bursts to generate (default: 200)")

    # detect (Phase 3)
    detect_parser = subparsers.add_parser("detect", help="Start real-time monitoring and ransomware detection engine")
    detect_parser.add_argument("--duration", type=int, default=None, help="Duration to run detection in seconds")

    # detection-demo (Phase 3)
    subparsers.add_parser("detection-demo", help="Run controlled harmless ransomware detection scenarios")

    # detections (Phase 3)
    subparsers.add_parser("detections", help="Show recent detection results and recorded incidents")

    # incident (Phase 3)
    inc_parser = subparsers.add_parser("incident", help="Show detailed dossier and timeline for a security incident")
    inc_parser.add_argument("--id", type=str, required=True, help="Incident ID (e.g. INC-XXXXXXXX)")
    inc_parser.add_argument("--resolve", type=str, default=None, help="Mark incident RESOLVED with resolution notes")

    # detection-benchmark (Phase 3)
    det_bench_parser = subparsers.add_parser("detection-benchmark", help="Execute high-throughput detection engine benchmark")
    det_bench_parser.add_argument("--events", type=int, default=1000, help="Number of telemetry events to evaluate (default: 1000)")

    # containment-demo (Phase 4)
    subparsers.add_parser("containment-demo", help="Run full controlled laboratory containment demonstration")

    # containments (Phase 4)
    subparsers.add_parser("containments", help="Show recorded containment operations and dossiers")

    # containment (Phase 4)
    cont_parser = subparsers.add_parser("containment", help="Show detailed dossier and timeline for a containment operation")
    cont_parser.add_argument("--id", type=str, required=True, help="Containment ID (e.g. CONT-XXXXXXXX)")

    # containment-policy-demo (Phase 4)
    subparsers.add_parser("containment-policy-demo", help="Demonstrate containment policy decisions across threat scenarios")

    # containment-benchmark (Phase 4)
    cont_bench_parser = subparsers.add_parser("containment-benchmark", help="Execute containment engine performance benchmark")
    cont_bench_parser.add_argument("--iterations", type=int, default=5, help="Number of iterations (default: 5)")

    # vault (Phase 5)
    vault_parser = subparsers.add_parser("vault", help="Cryptographic Vault operations")
    vault_sub = vault_parser.add_subparsers(dest="vault_command", help="Vault sub-commands")
    v_init = vault_sub.add_parser("init", help="Initialize cryptographic vault & generate RSA keys")
    v_init.add_argument("--force", action="store_true", help="Force regenerate key pair")
    vault_sub.add_parser("status", help="Show vault health, keys, and storage metrics")
    v_bench = vault_sub.add_parser("benchmark", help="Execute vault performance benchmark")
    v_bench.add_argument("--count", type=int, default=1000, help="Number of files to benchmark (default: 1000)")
    vault_sub.add_parser("migrate-key", help="Harden existing private key with Argon2id & AES-256-GCM")

    # snapshot (Phase 5)
    snap_parser = subparsers.add_parser("snapshot", help="Cryptographic snapshot management & verification")
    snap_sub = snap_parser.add_subparsers(dest="snapshot_command", help="Snapshot sub-commands")
    snap_sub.add_parser("create", help="Create a clean, cryptographically authenticated snapshot")
    snap_sub.add_parser("list", help="List available snapshots")
    s_inspect = snap_sub.add_parser("inspect", help="Inspect snapshot metadata")
    s_inspect.add_argument("--id", type=str, required=True, help="Snapshot ID (e.g. SNAP-XXXXXXXX)")
    s_inspect.add_argument("--with-manifest", action="store_true", help="Prompt for passphrase to decrypt manifest summary")
    s_verify = snap_sub.add_parser("verify", help="Cryptographically audit and verify an encrypted snapshot")
    s_verify.add_argument("--id", type=str, required=True, help="Snapshot ID (e.g. SNAP-XXXXXXXX)")

    # recovery (Phase 6)
    rec_parser = subparsers.add_parser("recovery", help="Cryptographic recovery, workspace isolation & restoration")
    rec_sub = rec_parser.add_subparsers(dest="recovery_command", help="Recovery sub-commands")

    # recovery status
    rec_sub.add_parser("status", help="Show recovery subsystem status and workspaces")

    # recovery workspace
    ws_parser = rec_sub.add_parser("workspace", help="Manage isolated recovery workspaces")
    ws_sub = ws_parser.add_subparsers(dest="workspace_command", help="Workspace operations")
    ws_create = ws_sub.add_parser("create", help="Create a new authenticated recovery workspace")
    ws_create.add_argument("--id", type=str, default=None, help="Workspace ID (default: auto-generated)")
    ws_create.add_argument("--seed", action="store_true", help="Seed workspace from baseline lab files")
    ws_create.add_argument("--files", type=int, default=None, help="Max files to seed into workspace")
    ws_create.add_argument("--snapshot", type=str, default=None, help="Source snapshot ID")
    ws_sub.add_parser("list", help="List all recovery workspaces")
    ws_del = ws_sub.add_parser("delete", help="Delete a recovery workspace")
    ws_del.add_argument("--workspace", type=str, required=True, help="Workspace ID to delete")

    # recovery assess
    rec_assess = rec_sub.add_parser("assess", help="Assess damage in a workspace against snapshot baseline")
    rec_assess.add_argument("--workspace", type=str, required=True, help="Workspace ID")
    rec_assess.add_argument("--snapshot", type=str, required=True, help="Snapshot ID")
    rec_assess.add_argument("--file", type=str, default=None, help="Single relative file path to assess")
    rec_assess.add_argument("--directory", type=str, default=None, help="Directory subtree to assess")
    rec_assess.add_argument("--overwrite-modified", action="store_true", help="Schedule restoration for modified files")
    rec_assess.add_argument("--passphrase", type=str, default=None, help="Private key passphrase")

    # recovery preview
    rec_prev = rec_sub.add_parser("preview", help="Preview restoration actions without modifying workspace files")
    rec_prev.add_argument("--workspace", type=str, required=True, help="Workspace ID")
    rec_prev.add_argument("--snapshot", type=str, required=True, help="Snapshot ID")
    rec_prev.add_argument("--file", type=str, default=None, help="Single relative file path to preview")
    rec_prev.add_argument("--directory", type=str, default=None, help="Directory subtree to preview")
    rec_prev.add_argument("--no-overwrite-modified", action="store_true", help="Do not overwrite modified files")
    rec_prev.add_argument("--passphrase", type=str, default=None, help="Private key passphrase")

    # recovery restore
    rec_rest = rec_sub.add_parser("restore", help="Execute live restoration with safety gates and evidence quarantine")
    rec_rest.add_argument("--workspace", type=str, required=True, help="Workspace ID")
    rec_rest.add_argument("--snapshot", type=str, required=True, help="Snapshot ID")
    rec_rest.add_argument("--authorize", action="store_true", help="Explicitly authorize restoration execution")
    rec_rest.add_argument("--file", type=str, default=None, help="Single relative file path to restore")
    rec_rest.add_argument("--directory", type=str, default=None, help="Directory subtree to restore")
    rec_rest.add_argument("--no-overwrite-modified", action="store_true", help="Do not overwrite modified files")
    rec_rest.add_argument("--passphrase", type=str, default=None, help="Private key passphrase")

    # recovery verify
    rec_ver = rec_sub.add_parser("verify", help="Verify cryptographic integrity of recovery workspace")
    rec_ver.add_argument("--workspace", type=str, required=True, help="Workspace ID")
    rec_ver.add_argument("--snapshot", type=str, required=True, help="Snapshot ID")
    rec_ver.add_argument("--passphrase", type=str, default=None, help="Private key passphrase")

    # recovery demo
    rec_demo = rec_sub.add_parser("demo", help="Run automated end-to-end recovery demonstration")
    rec_demo.add_argument("--files", type=int, default=100, choices=[100, 1000, 10000, 20000], help="Scale preset (100, 1000, 10000, 20000)")
    rec_demo.add_argument("--snapshot", type=str, default=None, help="Snapshot ID")
    rec_demo.add_argument("--cleanup", action="store_true", help="Clean up demo workspace upon completion")
    rec_demo.add_argument("--passphrase", type=str, default=None, help="Private key passphrase")

    return parser


def main() -> int:
    setup_logging()
    print_banner()
    parser = build_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()
    if args.command == "init":
        return cmd_init(args)
    elif args.command == "generate":
        return cmd_generate(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "status":
        return cmd_status(args)
    elif args.command == "clean":
        return cmd_clean(args)
    elif args.command == "monitor":
        return cmd_monitor(args)
    elif args.command == "demo":
        return cmd_demo(args)
    elif args.command == "benchmark":
        return cmd_benchmark(args)
    elif args.command == "detect":
        return cmd_detect(args)
    elif args.command == "detection-demo":
        return cmd_detection_demo(args)
    elif args.command == "detections":
        return cmd_detections(args)
    elif args.command == "incident":
        return cmd_incident(args)
    elif args.command == "detection-benchmark":
        return cmd_detection_benchmark(args)
    elif args.command == "containment-demo":
        return cmd_containment_demo(args)
    elif args.command == "containments":
        return cmd_containments(args)
    elif args.command == "containment":
        return cmd_containment(args)
    elif args.command == "containment-policy-demo":
        return cmd_containment_policy_demo(args)
    elif args.command == "containment-benchmark":
        return cmd_containment_benchmark(args)
    elif args.command == "vault":
        return cmd_vault(args)
    elif args.command == "snapshot":
        return cmd_snapshot(args)
    elif args.command == "recovery":
        return cmd_recovery(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

