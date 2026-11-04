"""
Vault Benchmark Suite for CryptoShield (Phase 5).

Measures cryptographic throughput, phase-by-phase timings, storage accounting,
encryption overhead, verification latency, and peak memory for dataset sizes
(1,000, 10,000, 20,000 files).
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import psutil

from app.config import CONFIG
from app.core.logger import get_logger
from app.lab.dataset_generator import SyntheticDatasetGenerator
from app.lab.lab_manager import LabManager
from app.vault.key_manager import KeyManager
from app.vault.snapshot_manager import SnapshotManager
from app.vault.vault_verifier import SnapshotVerifier

logger = get_logger("vault.benchmark")


@dataclass
class VaultBenchmarkResult:
    """Benchmark performance metrics and storage accounting for a file count."""
    file_count: int
    # Storage accounting
    original_logical_bytes: int
    original_logical_mb: float
    encrypted_objects_bytes: int
    encrypted_objects_mb: float
    manifest_bytes: int
    manifest_mb: float
    metadata_bytes: int
    total_vault_logical_bytes: int
    total_vault_logical_mb: float
    object_overhead_bytes: int
    object_overhead_percentage: float
    total_vault_overhead_bytes: int
    total_vault_overhead_percentage: float
    avg_extra_bytes_per_object: float

    # Phase durations
    audit_duration_seconds: float
    encryption_duration_seconds: float
    manifest_duration_seconds: float
    key_wrapping_duration_seconds: float
    publication_duration_seconds: float
    total_creation_duration_seconds: float
    verification_duration_seconds: float
    total_e2e_duration_seconds: float

    # Throughput
    encryption_throughput_fps: float
    verification_throughput_fps: float

    # Resource usage
    peak_memory_mb: float
    failed_files: int
    outcome: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_count": self.file_count,
            "original_logical_mb": round(self.original_logical_mb, 2),
            "encrypted_objects_mb": round(self.encrypted_objects_mb, 2),
            "manifest_mb": round(self.manifest_mb, 2),
            "total_vault_logical_mb": round(self.total_vault_logical_mb, 2),
            "object_overhead_percentage": round(self.object_overhead_percentage, 2),
            "total_vault_overhead_percentage": round(self.total_vault_overhead_percentage, 2),
            "avg_extra_bytes_per_object": round(self.avg_extra_bytes_per_object, 2),
            "audit_duration_seconds": round(self.audit_duration_seconds, 3),
            "encryption_duration_seconds": round(self.encryption_duration_seconds, 3),
            "manifest_duration_seconds": round(self.manifest_duration_seconds, 3),
            "key_wrapping_duration_seconds": round(self.key_wrapping_duration_seconds, 3),
            "publication_duration_seconds": round(self.publication_duration_seconds, 3),
            "total_creation_duration_seconds": round(self.total_creation_duration_seconds, 3),
            "verification_duration_seconds": round(self.verification_duration_seconds, 3),
            "total_e2e_duration_seconds": round(self.total_e2e_duration_seconds, 3),
            "encryption_throughput_fps": round(self.encryption_throughput_fps, 1),
            "verification_throughput_fps": round(self.verification_throughput_fps, 1),
            "peak_memory_mb": round(self.peak_memory_mb, 2),
            "failed_files": self.failed_files,
            "outcome": self.outcome,
        }


def run_vault_benchmark(
    file_count: int = 1000,
    passphrase: str = "TestVaultBenchmarkPassphrase2026!",
    base_lab_dir: Optional[Path] = None,
    vault_dir: Optional[Path] = None,
    keys_dir: Optional[Path] = None,
    clean_after: bool = True,
) -> VaultBenchmarkResult:
    """
    Execute an isolated vault performance benchmark for a given file count.
    Measures and separates all 7 lifecycle phases and complete storage accounting.
    """
    proc = psutil.Process()
    mem_before = proc.memory_info().rss / (1024 * 1024)
    peak_mem = mem_before

    temp_root = None
    if base_lab_dir is None:
        temp_root = Path(tempfile.mkdtemp(prefix="cryptoshield_bench_"))
        bench_lab = temp_root / "lab"
        bench_vault = temp_root / "vault"
        bench_keys = temp_root / "keys"

        # Initialize temporary lab
        lab_mgr = LabManager(base_lab_dir=bench_lab)
        lab_mgr.initialize_lab()

        # Generate dataset
        gen = SyntheticDatasetGenerator(base_lab_dir=bench_lab)
        manifest = gen.generate_dataset(file_count=file_count)
    else:
        bench_lab = base_lab_dir
        bench_vault = vault_dir or CONFIG.vault_dir
        bench_keys = keys_dir or CONFIG.keys_dir
        from app.lab.manifest import ManifestManager
        manifest = ManifestManager.load_manifest(bench_lab / CONFIG.MANIFEST_FILENAME, base_lab_dir=bench_lab)

    try:
        # Initialize key manager and generate keypair (one-time setup)
        key_mgr = KeyManager(keys_dir=bench_keys)
        if not key_mgr.has_keys():
            key_mgr.generate_key_pair(passphrase=passphrase, key_size=2048)

        # Initialize SnapshotManager
        snap_mgr = SnapshotManager(
            vault_dir=bench_vault,
            base_lab_dir=bench_lab,
            key_manager=key_mgr,
        )

        # 1. Benchmark Snapshot Creation (records granular phase timings)
        meta = snap_mgr.create_snapshot()

        curr_mem = proc.memory_info().rss / (1024 * 1024)
        peak_mem = max(peak_mem, curr_mem)

        phase_timings = meta.metadata.get("phase_durations", {})
        audit_duration = phase_timings.get("audit_duration_seconds", 0.0)
        encryption_duration = phase_timings.get("encryption_duration_seconds", 0.0)
        manifest_duration = phase_timings.get("manifest_duration_seconds", 0.0)
        key_wrapping_duration = phase_timings.get("key_wrapping_duration_seconds", 0.0)
        publication_duration = phase_timings.get("publication_duration_seconds", 0.0)
        total_creation_duration = phase_timings.get("total_creation_duration_seconds", 0.0)

        # Pure encryption throughput (files / encryption time)
        enc_throughput = file_count / encryption_duration if encryption_duration > 0 else 0.0

        # 2. Benchmark Snapshot Verification
        verifier = SnapshotVerifier(
            vault_dir=bench_vault,
            key_manager=key_mgr,
        )

        t_verify_start = time.perf_counter()
        report = verifier.verify_snapshot(
            snapshot_id=meta.snapshot_id,
            passphrase=passphrase,
        )
        verify_duration = time.perf_counter() - t_verify_start

        curr_mem = proc.memory_info().rss / (1024 * 1024)
        peak_mem = max(peak_mem, curr_mem)

        verify_throughput = file_count / verify_duration if verify_duration > 0 else 0.0
        total_e2e_duration = total_creation_duration + verify_duration

        # 3. Precise Storage Accounting
        snapshot_dir = bench_vault / meta.snapshot_id
        objects_dir = snapshot_dir / "objects"
        object_files = list(objects_dir.glob(f"*{CONFIG.VAULT_OBJECT_EXT}"))

        original_bytes = manifest.total_size_bytes
        encrypted_objects_bytes = sum(f.stat().st_size for f in object_files)
        manifest_file = snapshot_dir / "manifest.enc"
        manifest_bytes = manifest_file.stat().st_size if manifest_file.exists() else 0
        meta_file = snapshot_dir / "snapshot.json"
        meta_bytes = meta_file.stat().st_size if meta_file.exists() else 0
        total_vault_bytes = encrypted_objects_bytes + manifest_bytes + meta_bytes

        object_diff = encrypted_objects_bytes - original_bytes
        avg_extra = object_diff / file_count if file_count > 0 else 0.0
        object_overhead_pct = (object_diff / original_bytes) * 100.0 if original_bytes > 0 else 0.0
        total_vault_diff = total_vault_bytes - original_bytes
        total_vault_overhead_pct = (total_vault_diff / original_bytes) * 100.0 if original_bytes > 0 else 0.0

        return VaultBenchmarkResult(
            file_count=file_count,
            original_logical_bytes=original_bytes,
            original_logical_mb=original_bytes / (1024 * 1024),
            encrypted_objects_bytes=encrypted_objects_bytes,
            encrypted_objects_mb=encrypted_objects_bytes / (1024 * 1024),
            manifest_bytes=manifest_bytes,
            manifest_mb=manifest_bytes / (1024 * 1024),
            metadata_bytes=meta_bytes,
            total_vault_logical_bytes=total_vault_bytes,
            total_vault_logical_mb=total_vault_bytes / (1024 * 1024),
            object_overhead_bytes=object_diff,
            object_overhead_percentage=object_overhead_pct,
            total_vault_overhead_bytes=total_vault_diff,
            total_vault_overhead_percentage=total_vault_overhead_pct,
            avg_extra_bytes_per_object=avg_extra,
            audit_duration_seconds=audit_duration,
            encryption_duration_seconds=encryption_duration,
            manifest_duration_seconds=manifest_duration,
            key_wrapping_duration_seconds=key_wrapping_duration,
            publication_duration_seconds=publication_duration,
            total_creation_duration_seconds=total_creation_duration,
            verification_duration_seconds=verify_duration,
            total_e2e_duration_seconds=total_e2e_duration,
            encryption_throughput_fps=enc_throughput,
            verification_throughput_fps=verify_throughput,
            peak_memory_mb=peak_mem,
            failed_files=report.failed_objects,
            outcome=report.outcome,
        )

    finally:
        if temp_root and clean_after and temp_root.exists():
            shutil.rmtree(temp_root, ignore_errors=True)


def print_benchmark_table(result: VaultBenchmarkResult) -> None:
    """Print beautifully formatted CLI benchmark results table with full phase breakdown."""
    print("\n" + "=" * 76)
    print(f"  CryptoShield Vault Benchmark & Storage Audit ({result.file_count:,} Files)")
    print("=" * 76)
    print("--- 1. Storage Accounting & Overhead Analysis ---")
    print(f"Original Logical Dataset Size   : {result.original_logical_mb:>6.2f} MB ({result.original_logical_bytes:,} bytes)")
    print(f"Encrypted Objects (.cso files)  : {result.encrypted_objects_mb:>6.2f} MB ({result.encrypted_objects_bytes:,} bytes)")
    print(f"Encrypted Manifest (manifest.enc): {result.manifest_mb:>6.2f} MB ({result.manifest_bytes:,} bytes)")
    print(f"Public Metadata (snapshot.json) : {result.metadata_bytes:>6,} bytes")
    print(f"Total Encrypted Vault Size      : {result.total_vault_logical_mb:>6.2f} MB ({result.total_vault_logical_bytes:,} bytes)")
    print(f"Average Extra Bytes / Object    : {result.avg_extra_bytes_per_object:>6.2f} bytes (Expected: 34 bytes container)")
    print(f"File Object Container Overhead  : {result.object_overhead_percentage:>+6.2f}% ({result.object_overhead_bytes:,} bytes)")
    print(f"Total Vault Overhead (w/ Manifest: {result.total_vault_overhead_percentage:>+6.2f}% ({result.total_vault_overhead_bytes:,} bytes)")

    print("\n--- 2. Separated Lifecycle Phase Timings ---")
    print(f"[Phase 1] Pre-Snapshot Integrity Audit : {result.audit_duration_seconds:>7.3f} s")
    print(f"[Phase 2] File Streaming Encryption    : {result.encryption_duration_seconds:>7.3f} s ({result.encryption_throughput_fps:,.1f} files/sec)")
    print(f"[Phase 3] Manifest Build & Encryption  : {result.manifest_duration_seconds:>7.3f} s")
    print(f"[Phase 4] RSA-OAEP Key Wrapping        : {result.key_wrapping_duration_seconds:>7.3f} s")
    print(f"[Phase 5] Atomic Staging & Publication : {result.publication_duration_seconds:>7.3f} s")
    print(f"--> Total Snapshot Creation Duration   : {result.total_creation_duration_seconds:>7.3f} s")
    print(f"[Phase 6] Cryptographic Verification   : {result.verification_duration_seconds:>7.3f} s ({result.verification_throughput_fps:,.1f} files/sec)")
    print(f"--> Total End-to-End Duration          : {result.total_e2e_duration_seconds:>7.3f} s")

    print("\n--- 3. Reliability & System Metrics ---")
    print(f"Peak Process Memory (RSS)              : {result.peak_memory_mb:>6.2f} MB")
    print(f"Failed / Tampered Objects              : {result.failed_files}")
    print(f"Verification Outcome                   : [{result.outcome}]")
    print("=" * 76 + "\n")
