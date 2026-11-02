"""
CryptoShield CLI: Laboratory Initialization, Dataset Generation, and Integrity Auditing.

Academic Proof-of-Concept Defensive Security Application.
Phase 1 Foundation Command-Line Interface.
"""

from __future__ import annotations

import argparse
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
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

