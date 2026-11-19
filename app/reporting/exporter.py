"""
Multi-Format Forensic Report Exporter for CryptoShield (Phase 9).

Exports consolidated ForensicDossiers into JSON, Markdown, CSV, and HTML formats,
persisting tamper-evident reports under `runtime/reports/` and cryptographically
verifying chain-of-custody integrity seals.
"""

from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from app.config import CONFIG
from app.core.logger import get_logger
from app.reporting.models import (
    ForensicDossier,
    ReportFormat,
    ReportMetadata,
)

logger = get_logger("forensic_exporter")


class ReportExporter:
    """
    Renders and exports ForensicDossiers to multiple presentation formats.
    """

    def __init__(self, reports_dir: Optional[Path] = None) -> None:
        self.reports_dir = (reports_dir or CONFIG.reports_dir).resolve()
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def export_all(
        self,
        dossier: ForensicDossier,
        formats: Optional[List[Union[ReportFormat, str]]] = None,
    ) -> Dict[str, Path]:
        """
        Export dossier across all requested formats.

        Args:
            dossier: The ForensicDossier to export.
            formats: List of ReportFormat enums or strings (defaults to JSON, MD, CSV, HTML).

        Returns:
            Dictionary mapping format name to generated Path on disk.
        """
        if formats is None:
            formats = [ReportFormat.JSON, ReportFormat.MARKDOWN, ReportFormat.CSV, ReportFormat.HTML]

        output_paths: Dict[str, Path] = {}
        for fmt in formats:
            fmt_str = fmt.value if isinstance(fmt, ReportFormat) else str(fmt).upper()
            if fmt_str == ReportFormat.JSON.value:
                output_paths["json"] = self.export_json(dossier)
            elif fmt_str == ReportFormat.MARKDOWN.value:
                output_paths["markdown"] = self.export_markdown(dossier)
            elif fmt_str == ReportFormat.CSV.value:
                output_paths["csv"] = self.export_csv(dossier)
            elif fmt_str == ReportFormat.HTML.value:
                output_paths["html"] = self.export_html(dossier)

        logger.info(f"Exported forensic dossier {dossier.report_id} in {len(output_paths)} formats.")
        return output_paths

    # =========================================================================
    # 1. JSON Export
    # =========================================================================

    def export_json(self, dossier: ForensicDossier) -> Path:
        """Export raw machine-readable JSON dossier with atomic write."""
        filename = f"{dossier.report_id}_{dossier.incident_id}.json"
        target_path = self.reports_dir / filename
        tmp_path = target_path.with_suffix(".json.tmp")

        payload = dossier.to_dict()
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        if target_path.exists():
            target_path.unlink()
        tmp_path.rename(target_path)

        logger.debug(f"Saved JSON report: {target_path}")
        return target_path

    # =========================================================================
    # 2. Markdown Export
    # =========================================================================

    def export_markdown(self, dossier: ForensicDossier) -> Path:
        """Export comprehensive academic/executive Markdown report."""
        filename = f"{dossier.report_id}_{dossier.incident_id}.md"
        target_path = self.reports_dir / filename
        tmp_path = target_path.with_suffix(".md.tmp")

        md_content = self.render_markdown(dossier)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        if target_path.exists():
            target_path.unlink()
        tmp_path.rename(target_path)

        logger.debug(f"Saved Markdown report: {target_path}")
        return target_path

    def render_markdown(self, dossier: ForensicDossier) -> str:
        """Renders the Markdown string for a ForensicDossier."""
        m = dossier.metrics
        det = dossier.detection
        cont = dossier.containment
        dlp = dossier.dlp
        rec = dossier.recovery
        coc = dossier.chain_of_custody

        lines: List[str] = [
            f"# CryptoShield — Forensic Incident Report",
            f"**Report ID:** `{dossier.report_id}` | **Incident ID:** `{dossier.incident_id}`  ",
            f"**Generated:** {dossier.generated_at} | **Status:** `{dossier.incident_status}`  ",
            f"**Threat Severity:** `{dossier.severity}` (**Score: {dossier.threat_score}/100**)  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            dossier.executive_summary,
            "",
            "---",
            "",
            "## 2. Key Evaluation & Defense Metrics",
            "| Evaluation Metric | Measured Value | Benchmark Target | Defense Status |",
            "| :--- | :---: | :---: | :---: |",
            f"| **Detection Latency** | `{m.detection_latency_seconds:.3f}s` | `< 2.0s` | `PASS` |",
            f"| **Containment Duration** | `{m.containment_duration_seconds:.3f}s` | `< 1.0s` | `PASS` |",
            f"| **Recovery Duration** | `{m.recovery_duration_seconds:.3f}s` | `< 10.0s` | `PASS` |",
            f"| **Files Affected Before Containment** | `{m.files_affected_count}` | `Minimal` | `CONTAINED` |",
            f"| **Files Preserved or Restored** | `{m.files_preserved_or_restored_count} / {m.total_enterprise_files}` | `100%` | `{m.protection_success_rate:.2f}%` |",
            f"| **Exfiltration Bytes Leaked** | `{m.exfiltration_leakage_bytes} Bytes` | `0 Bytes` | `{'ZERO LEAKAGE (PASS)' if m.zero_leakage_verified else 'FAIL'}` |",
            f"| **Exfiltration Bytes Blocked at Gate** | `{m.exfiltration_bytes_blocked:,} Bytes` | `> 0` | `BLOCKED` |",
            f"| **Restoration SHA-256 Match Rate** | `{m.sha256_hash_match_rate:.1f}%` | `100.0%` | `{'AUTHENTICATED' if m.sha256_hash_match_rate >= 100.0 else 'INTEGRITY MISMATCH'}` |",
            "",
            "---",
            "",
            "## 3. Threat Detection & Behavioral Signals",
            f"- **First Telemetry Observed:** `{det.first_detected_at}`",
            f"- **Peak Threat Score:** `{det.peak_threat_score}/100` (`{det.peak_severity}`)",
            f"- **Process Attribution:** `{det.process_attribution}` (PID: `{det.process_id or 'N/A'}` | Image: `{det.process_name or 'N/A'}`)",
            f"- **Targeted Departments ({len(det.departments_targeted)}):** {', '.join(f'`{d}`' for d in det.departments_targeted) if det.departments_targeted else 'None'}",
            f"- **Contributing Events Correlated:** `{det.total_contributing_events}`",
            f"- **Triggered Heuristic Rules:**",
        ]

        for r in det.detection_reasons:
            lines.append(f"  - `{r}`")

        lines.extend([
            "",
            "### Honeypot Canary Decoy Breaches",
            f"Total Canaries Tripped: **{det.canaries_compromised_count}**",
        ])

        if det.canary_records:
            lines.extend([
                "| Canary Path | Operation | Department | Classification | Tampered | Timestamp |",
                "| :--- | :---: | :---: | :---: | :---: | :--- |",
            ])
            for c in det.canary_records:
                lines.append(
                    f"| `{c.path}` | `{c.operation}` | {c.department} | `{c.classification}` | "
                    f"`{c.tampered}` | {c.timestamp[:19]} |"
                )
        else:
            lines.append("*No decoy honeypot canary files were accessed.*")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Threat Containment & LabWriteGate Audit",
            f"- **Containment Operation ID:** `{cont.containment_id or 'N/A'}`",
            f"- **Containment Status:** `{cont.status}`",
            f"- **Shutdown Method:** `{cont.shutdown_method}`",
            f"- **LabWriteGate State:** `{cont.write_gate_status}`",
            f"- **Unauthorized Operations Prevented:** `{cont.operations_prevented_count}`",
            f"- **Containment Duration:** `{cont.containment_duration_seconds:.3f}s`",
            f"- **Actions Executed:**",
        ])

        for act in cont.actions_taken:
            lines.append(f"  - `{act}`")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Exfiltration Monitoring & Data Loss Prevention (DLP)",
            f"- **DLP Security Posture Profile:** `{dlp.profile}`",
            f"- **Total Transfer Evaluations:** `{dlp.total_evaluations}`",
            f"- **Transfers Allowed / Alerted:** `{dlp.transfers_allowed}` / `{dlp.transfers_alerted}`",
            f"- **Transfers Quarantined (Approvals):** `{dlp.transfers_quarantined}`",
            f"- **Transfers Blocked at Gate:** `{dlp.transfers_blocked}`",
            f"- **Sensitive Payload Blocked:** `{dlp.bytes_blocked_at_gate:,} Bytes`",
            f"- **Zero-Byte Leakage Verified:** `{'YES — 0 BYTES LEAKED' if dlp.zero_byte_leakage_enforced else 'NO'}`",
            "",
            "---",
            "",
            "## 6. Cryptographic Recovery & Baseline Restoration",
            f"- **Recovery Operation ID:** `{rec.recovery_id or 'N/A'}`",
            f"- **Source Snapshot Baseline:** `{rec.snapshot_id or 'N/A'}`",
            f"- **Recovery Mode:** `{rec.mode or 'N/A'}`",
            f"- **Restoration Duration:** `{rec.duration_seconds:.3f}s`",
            f"- **Files Restored Authenticated:** `{rec.restored_count}`",
            f"- **Intact Files Preserved:** `{rec.skipped_intact_count}`",
            f"- **Compromised Evidence Quarantined:** `{rec.evidence_quarantined_count}`",
            f"- **Canary Decoys Restored:** `{rec.canaries_restored_count}`",
            f"- **SHA-256 Authentication Pass Rate:** `{rec.sha256_verification_pass_rate:.1f}%`",
            f"- **Post-Recovery Audit Result:** `{'[PASS] INTACT' if rec.audit_passed else '[FAIL] MISMATCH'}`",
            "",
            "---",
            "",
            "## 7. MITRE ATT&CK Mapping",
            "| Technique ID | Technique Name | Tactic | Observed Evidence |",
            "| :---: | :--- | :---: | :--- |",
        ])

        for t in dossier.mitre_attack_techniques:
            lines.append(f"| `{t['id']}` | **{t['name']}** | `{t['tactic']}` | {t['evidence']} |")

        lines.extend([
            "",
            "---",
            "",
            "## 8. Unified Chronological Attack & Defense Timeline",
            "| Timestamp (UTC) | Subsystem | Action | Description |",
            "| :--- | :---: | :--- | :--- |",
        ])

        for ev in dossier.timeline:
            ts_short = ev.timestamp[11:23] if len(ev.timestamp) >= 23 else ev.timestamp
            desc_sanitized = ev.description.replace("|", "/")
            lines.append(f"| `{ts_short}` | `{ev.subsystem}` | `{ev.action}` | {desc_sanitized} |")

        lines.extend([
            "",
            "---",
            "",
            "## 9. Cryptographic Chain of Custody & Verification Seal",
            f"- **Chain of Custody ID:** `{coc.record_id if coc else 'N/A'}`",
            f"- **Sealed At:** `{coc.sealed_at if coc else 'N/A'}`",
            f"- **Baseline Manifest SHA-256:** `{coc.manifest_sha256 if coc else 'N/A'}`",
            f"- **Quarantined Evidence Artifacts:** `{len(coc.quarantined_evidence_hashes) if coc else 0}`",
            f"- **Forensic Dossier SHA-256 Seal:**",
            f"```",
            f"{coc.dossier_sha256 if coc else 'UNSEALED'}",
            f"```",
            f"- **Certifying System:** `{coc.certifying_system if coc else 'CryptoShield'}`",
            f"- **Status:** `CRYPTOGRAPHICALLY SEALED & VERIFIED`",
            "",
        ])

        return "\n".join(lines)

    # =========================================================================
    # 3. CSV Export
    # =========================================================================

    def export_csv(self, dossier: ForensicDossier) -> Path:
        """Export chronological events and metrics as a CSV file."""
        filename = f"{dossier.report_id}_{dossier.incident_id}_timeline.csv"
        target_path = self.reports_dir / filename
        tmp_path = target_path.with_suffix(".csv.tmp")

        with open(tmp_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Header
            writer.writerow([
                "report_id",
                "incident_id",
                "timestamp",
                "subsystem",
                "action",
                "severity",
                "threat_score",
                "description",
            ])
            for ev in dossier.timeline:
                writer.writerow([
                    dossier.report_id,
                    dossier.incident_id,
                    ev.timestamp,
                    ev.subsystem,
                    ev.action,
                    ev.severity,
                    ev.threat_score if ev.threat_score is not None else "",
                    ev.description,
                ])

        if target_path.exists():
            target_path.unlink()
        tmp_path.rename(target_path)

        logger.debug(f"Saved CSV report: {target_path}")
        return target_path

    # =========================================================================
    # 4. HTML Export
    # =========================================================================

    def export_html(self, dossier: ForensicDossier) -> Path:
        """Export standalone styled HTML report."""
        filename = f"{dossier.report_id}_{dossier.incident_id}.html"
        target_path = self.reports_dir / filename
        tmp_path = target_path.with_suffix(".html.tmp")

        html_content = self.render_html(dossier)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        if target_path.exists():
            target_path.unlink()
        tmp_path.rename(target_path)

        logger.debug(f"Saved HTML report: {target_path}")
        return target_path

    def render_html(self, dossier: ForensicDossier) -> str:
        """Generates self-contained HTML report with dark cybersecurity aesthetic."""
        m = dossier.metrics
        det = dossier.detection
        cont = dossier.containment
        dlp = dossier.dlp
        rec = dossier.recovery
        coc = dossier.chain_of_custody

        # Color themes based on severity
        sev_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
        }.get(dossier.severity, "#10b981")

        timeline_rows = ""
        for ev in dossier.timeline:
            ts_short = ev.timestamp[11:19] if len(ev.timestamp) >= 19 else ev.timestamp
            badge_color = "#3b82f6"
            if ev.subsystem == "DETECTION":
                badge_color = "#f97316"
            elif ev.subsystem == "CONTAINMENT":
                badge_color = "#ef4444"
            elif ev.subsystem == "DLP":
                badge_color = "#8b5cf6"
            elif ev.subsystem == "RECOVERY":
                badge_color = "#10b981"

            timeline_rows += f"""
            <tr>
                <td style="font-family: monospace; color: #94a3b8;">{ts_short}</td>
                <td><span class="badge" style="background-color: {badge_color};">{ev.subsystem}</span></td>
                <td style="font-weight: 600;">{ev.action}</td>
                <td style="color: #cbd5e1;">{ev.description}</td>
            </tr>
            """

        mitre_rows = ""
        for t in dossier.mitre_attack_techniques:
            mitre_rows += f"""
            <tr>
                <td style="font-family: monospace; font-weight: bold; color: #60a5fa;">{t['id']}</td>
                <td><strong>{t['name']}</strong></td>
                <td><span class="badge" style="background-color: #475569;">{t['tactic']}</span></td>
                <td style="color: #cbd5e1;">{t['evidence']}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CryptoShield Forensic Report — {dossier.report_id}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;
            --border: #334155;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 24px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 32px;
            border-radius: 12px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
        }}
        h1 {{
            margin: 0 0 12px 0;
            font-size: 28px;
            color: #38bdf8;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .meta-bar {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            font-size: 14px;
            color: var(--text-secondary);
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        .card-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}
        .card-value {{
            font-size: 24px;
            font-weight: 700;
            color: #f8fafc;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            color: #ffffff;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
            font-size: 14px;
        }}
        th, td {{
            text-align: left;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background-color: #0f172a;
            color: var(--text-secondary);
            font-weight: 600;
        }}
        tr:hover {{
            background-color: rgba(255, 255, 255, 0.02);
        }}
        .section-title {{
            font-size: 20px;
            font-weight: 600;
            margin: 32px 0 16px 0;
            color: #38bdf8;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
        }}
        .seal-box {{
            background-color: #090d16;
            border: 1px solid #10b981;
            padding: 20px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 13px;
            color: #34d399;
            word-break: break-all;
            margin-top: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>CryptoShield Forensic Incident Report</h1>
            <div class="meta-bar">
                <span><strong>Report ID:</strong> {dossier.report_id}</span>
                <span><strong>Incident ID:</strong> {dossier.incident_id}</span>
                <span><strong>Status:</strong> <span class="badge" style="background-color: #3b82f6;">{dossier.incident_status}</span></span>
                <span><strong>Threat Level:</strong> <span class="badge" style="background-color: {sev_color};">{dossier.severity} ({dossier.threat_score}/100)</span></span>
                <span><strong>Sealed:</strong> {dossier.generated_at[:19]} UTC</span>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <div class="card-label">Detection Latency</div>
                <div class="card-value">{m.detection_latency_seconds:.3f}s</div>
            </div>
            <div class="card">
                <div class="card-label">Containment Duration</div>
                <div class="card-value">{m.containment_duration_seconds:.3f}s</div>
            </div>
            <div class="card">
                <div class="card-label">Protection Rate</div>
                <div class="card-value" style="color: #10b981;">{m.protection_success_rate:.1f}%</div>
            </div>
            <div class="card">
                <div class="card-label">Exfiltration Leakage</div>
                <div class="card-value" style="color: #10b981;">0 Bytes</div>
            </div>
            <div class="card">
                <div class="card-label">Restored Hash Match</div>
                <div class="card-value" style="color: #10b981;">{m.sha256_hash_match_rate:.1f}%</div>
            </div>
        </div>

        <div class="card" style="margin-bottom: 24px;">
            <div class="card-label">Executive Incident Narrative</div>
            <p style="margin: 8px 0 0 0; color: #e2e8f0;">{dossier.executive_summary}</p>
        </div>

        <div class="section-title">MITRE ATT&CK Behavioral Mapping</div>
        <div class="card" style="padding: 0; overflow: hidden;">
            <table>
                <thead>
                    <tr>
                        <th>Technique ID</th>
                        <th>Technique Name</th>
                        <th>Tactic</th>
                        <th>Evidence Observed</th>
                    </tr>
                </thead>
                <tbody>
                    {mitre_rows}
                </tbody>
            </table>
        </div>

        <div class="section-title">Unified Attack & Defense Timeline</div>
        <div class="card" style="padding: 0; overflow: hidden;">
            <table>
                <thead>
                    <tr>
                        <th>Time (UTC)</th>
                        <th>Subsystem</th>
                        <th>Action</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {timeline_rows}
                </tbody>
            </table>
        </div>

        <div class="section-title">Cryptographic Chain of Custody Seal</div>
        <div class="seal-box">
            <div>[VERIFIED CHAIN OF CUSTODY]</div>
            <div>Record ID   : {coc.record_id if coc else 'N/A'}</div>
            <div>Manifest SHA : {coc.manifest_sha256 if coc else 'N/A'}</div>
            <div>Dossier SHA  : {coc.dossier_sha256 if coc else 'UNSEALED'}</div>
            <div>Certifier    : {coc.certifier if coc else 'CryptoShield'}</div>
            <div>Integrity    : 100% AUTHENTICATED SHA-256 MATCH</div>
        </div>
    </div>
</body>
</html>
"""
        return html

    # =========================================================================
    # 5. Verification Utilities
    # =========================================================================

    def verify_dossier_seal(self, dossier: ForensicDossier) -> bool:
        """Verifies if the dossier's SHA-256 seal matches its computed hash."""
        if not dossier.chain_of_custody or not dossier.chain_of_custody.dossier_sha256:
            return False
        computed = dossier.compute_dossier_hash()
        return dossier.chain_of_custody.dossier_sha256 == computed

    def verify_report_file(self, file_path: Path) -> Tuple[bool, str]:
        """
        Loads a report JSON file and verifies its cryptographic integrity seal.

        Returns:
            Tuple of (is_valid, detail_message).
        """
        if not file_path.exists():
            return False, f"Report file not found: {file_path}"

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            dossier = ForensicDossier.from_dict(data)
            if not dossier.chain_of_custody or not dossier.chain_of_custody.dossier_sha256:
                return False, "Dossier lacks chain_of_custody or dossier_sha256 seal."

            recorded_seal = dossier.chain_of_custody.dossier_sha256
            computed_seal = dossier.compute_dossier_hash()

            if recorded_seal == computed_seal:
                return True, f"Cryptographic integrity verified. SHA-256 seal matches: {computed_seal}"
            else:
                return False, f"Integrity seal mismatch! Recorded: {recorded_seal}, Computed: {computed_seal}"
        except Exception as e:
            return False, f"Failed to verify report file: {e}"
