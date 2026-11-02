"""Unit tests for SyntheticDatasetGenerator, departmental taxonomy, and canary generation."""

from pathlib import Path
import pytest

from app.config import CONFIG
from app.lab.dataset_generator import SyntheticDatasetGenerator
from app.lab.lab_manager import LabManager
from app.lab.manifest import ManifestManager


def test_dataset_generator_basic(tmp_path: Path):
    lab_dir = tmp_path / "lab"
    mgr = LabManager(base_lab_dir=lab_dir)
    mgr.initialize_lab()

    generator = SyntheticDatasetGenerator(base_lab_dir=lab_dir, seed=123)
    manifest = generator.generate_dataset(file_count=50, canary_count=5)

    assert manifest.total_files == 50
    assert manifest.canary_count == 5
    assert len(manifest.entries) == 50

    # Ensure files exist on disk
    for rel_path, entry in manifest.entries.items():
        disk_path = lab_dir / rel_path
        assert disk_path.exists()
        assert disk_path.stat().st_size == entry.file_size_bytes

    # Ensure all 9 departments are represented
    assert len(manifest.department_counts) == 9
    for dept, count in manifest.department_counts.items():
        assert count > 0

    # Ensure format diversity
    assert len(manifest.type_counts) >= 6

    # Verify manifest integrity passes on clean generation
    result = ManifestManager.verify_integrity(base_lab_dir=lab_dir, manifest=manifest)
    assert result.is_valid is True
    assert result.matched_files == 50


def test_canary_files(tmp_path: Path):
    lab_dir = tmp_path / "lab"
    mgr = LabManager(base_lab_dir=lab_dir)
    mgr.initialize_lab()

    generator = SyntheticDatasetGenerator(base_lab_dir=lab_dir, seed=999)
    manifest = generator.generate_dataset(file_count=30, canary_count=4)

    canaries = [e for e in manifest.entries.values() if e.is_canary]
    assert len(canaries) == 4

    # Verify content of canaries contains canary indicators
    for canary in canaries:
        content = (lab_dir / canary.relative_path).read_text(encoding="utf-8", errors="ignore")
        assert "CRYPTOSHIELD_CANARY" in content or "HONEYTOKEN" in content or "__CRYPTOSHIELD_CANARY_DECOY__" in content


def test_deterministic_reproducibility(tmp_path: Path):
    """Ensure two generations with identical seeds produce identical file hashes."""
    lab_dir_1 = tmp_path / "lab1"
    lab_dir_2 = tmp_path / "lab2"

    mgr1 = LabManager(base_lab_dir=lab_dir_1)
    mgr1.initialize_lab()

    mgr2 = LabManager(base_lab_dir=lab_dir_2)
    mgr2.initialize_lab()

    gen1 = SyntheticDatasetGenerator(base_lab_dir=lab_dir_1, seed=777)
    manifest1 = gen1.generate_dataset(file_count=20, canary_count=2)

    gen2 = SyntheticDatasetGenerator(base_lab_dir=lab_dir_2, seed=777)
    manifest2 = gen2.generate_dataset(file_count=20, canary_count=2)

    assert manifest1.total_files == manifest2.total_files
    assert manifest1.canary_count == manifest2.canary_count

    # Compare hashes of all entries
    for rel_path, entry1 in manifest1.entries.items():
        assert rel_path in manifest2.entries
        entry2 = manifest2.entries[rel_path]
        assert entry1.sha256 == entry2.sha256
        assert entry1.file_size_bytes == entry2.file_size_bytes
