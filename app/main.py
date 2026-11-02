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
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
