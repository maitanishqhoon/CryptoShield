"""
Integration and end-to-end tests for Forensic Incident Reporting Subsystem (Phase 9).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from app.simulation.forensic_demo import ControlledForensicDemo, ForensicDemoResult


def test_controlled_forensic_demo_end_to_end(isolated_runtime):
    """Verify full end-to-end simulation flow produces sealed multi-format dossier."""
    demo = ControlledForensicDemo()
    result: ForensicDemoResult = demo.run_demo()

    assert result.incident_id.startswith("INC-")
    assert result.report_id.startswith("REP-")
    assert result.threat_score == 95
    assert result.severity == "CRITICAL"
    assert result.actions_contained > 0
    assert result.transfers_blocked > 0
    assert result.zero_leakage_verified is True
    assert result.files_restored > 0
    assert result.sha256_seal_verified is True
    assert len(result.dossier_sha256) == 64

    # Verify all 4 export files exist
    for fmt, p_str in result.generated_reports.items():
        p = Path(p_str)
        assert p.exists()
        assert p.stat().st_size > 0


def test_cli_report_commands(isolated_runtime):
    """Verify CLI report list, inspect, verify, and demo commands return code 0."""
    env = {
        **os.environ,
        "CRYPTOSHIELD_RUNTIME_DIR": str(isolated_runtime["runtime_dir"]),
    }

    # 1. Run demo via CLI
    p_demo = subprocess.run(
        [sys.executable, "-m", "app.main", "report", "demo"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_demo.returncode == 0
    assert "Demonstration Completed Successfully" in p_demo.stdout

    # 2. Run list via CLI
    p_list = subprocess.run(
        [sys.executable, "-m", "app.main", "report", "list"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_list.returncode == 0
    assert "CryptoShield Forensic Reports Catalog" in p_list.stdout

    # Extract first report ID from list
    reports = isolated_runtime["forensic_coordinator"].list_reports()
    assert len(reports) > 0
    target_rep_id = reports[0].report_id

    # 3. Run inspect via CLI
    p_inspect = subprocess.run(
        [sys.executable, "-m", "app.main", "report", "inspect", target_rep_id],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_inspect.returncode == 0
    assert f"FORENSIC DOSSIER: {target_rep_id}" in p_inspect.stdout
    assert "Key Evaluation & Defense Metrics" in p_inspect.stdout

    # 4. Run verify via CLI
    p_verify = subprocess.run(
        [sys.executable, "-m", "app.main", "report", "verify", target_rep_id],
        capture_output=True,
        text=True,
        env=env,
    )
    assert p_verify.returncode == 0
    assert "[PASS]" in p_verify.stdout
    assert "verified successfully" in p_verify.stdout
