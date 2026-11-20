"""
Synthetic Enterprise Dataset Generator for CryptoShield.

Generates large-scale, memory-efficient, deterministic synthetic datasets
organized into realistic enterprise departmental hierarchies with diverse file
formats, data classifications, and decoy canary files.
"""

from __future__ import annotations

import csv
import io
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Generator, List, Optional, Tuple

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import (
    DataClassification,
    DatasetPreset,
    LabMarker,
    Manifest,
    ManifestEntry,
)
from app.core.safety import validate_lab_path, verify_lab_marker
from app.lab.manifest import compute_bytes_sha256, ManifestManager

logger = get_logger("dataset_generator")

# --- Realistic Fictional Seed Vocabulary ---
_FIRST_NAMES = [
    "Alex", "Jordan", "Taylor", "Morgan", "Sam", "Chris", "Pat", "Riley",
    "Casey", "Avery", "Cameron", "Dakota", "Jamie", "Logan", "Reese",
    "Quinn", "Skyler", "Rowan", "Hayden", "Finley", "Emerson", "Adrian"
]
_LAST_NAMES = [
    "Vance", "Mercer", "Sinclair", "Sterling", "Holloway", "Blackwood",
    "Kensington", "Montgomery", "Winslow", "Fairchild", "Whitmore", "Prescott",
    "Hawthorne", "Carrington", "Ellington", "Ashford", "Strathmore", "Kingsley"
]
_COMPANIES = [
    "Apex Global Logistics", "Quantum Dynamics Corp", "Horizon Analytics LLC",
    "Starlight Health Systems", "Vanguard Financial Partners", "OmniTech Solutions",
    "Borealis Energy Grid", "Pinnacle Media Group", "Nexus Cloud Systems"
]
_CITIES = [
    "New York", "London", "Tokyo", "Zurich", "Singapore",
    "Frankfurt", "Sydney", "Toronto", "San Francisco", "Dubai"
]
_PROJECT_CODENAMES = [
    "Aegis", "Chimera", "Prometheus", "Hyperion", "Valkyrie",
    "Cerberus", "Titan", "Centurion", "Helios", "Eclipse"
]

# Department sub-directories for clean hierarchical taxonomy
_DEPARTMENT_SUBDIRS: Dict[str, List[str]] = {
    "Finance": ["invoices", "quarterly_reports", "audits", "general_ledger"],
    "Human Resources": ["employees", "payroll", "policies", "benefits"],
    "Legal": ["contracts", "ndas", "compliance", "intellectual_property"],
    "Sales": ["leads", "proposals", "quotas", "accounts"],
    "Customers": ["profiles", "support_tickets", "surveys", "agreements"],
    "Operations": ["inventory", "supply_chain", "facilities", "vendors"],
    "Research": ["whitepapers", "experiments", "benchmarks", "specs"],
    "IT": ["network_configs", "audit_logs", "access_policies", "infrastructure"],
    "Public Documents": ["press_releases", "brochures", "faqs", "case_studies"],
}

# Fictional high-value Canary filename templates
_CANARY_TEMPLATES = [
    ("passwords_master_backup.json", "IT", "network_configs", DataClassification.RESTRICTED, "json"),
    ("executive_salaries_2026.csv", "Human Resources", "payroll", DataClassification.RESTRICTED, "csv"),
    ("merger_acquisition_targets.md", "Legal", "contracts", DataClassification.CONFIDENTIAL, "md"),
    ("swift_banking_credentials.xml", "Finance", "audits", DataClassification.RESTRICTED, "xml"),
    ("master_crypto_keys.txt", "IT", "infrastructure", DataClassification.RESTRICTED, "txt"),
    ("unreleased_patent_claims.txt", "Legal", "intellectual_property", DataClassification.CONFIDENTIAL, "txt"),
    ("vip_customer_credit_profiles.csv", "Customers", "profiles", DataClassification.RESTRICTED, "csv"),
    ("board_of_directors_compensation.json", "Finance", "quarterly_reports", DataClassification.CONFIDENTIAL, "json"),
    ("zero_day_vulnerability_catalog.log", "IT", "audit_logs", DataClassification.RESTRICTED, "log"),
    ("clinical_trial_unblinded_results.csv", "Research", "experiments", DataClassification.RESTRICTED, "csv"),
]


class SyntheticDatasetGenerator:
    """
    High-performance, streaming generator for synthetic enterprise datasets.
    """

    def __init__(
        self,
        base_lab_dir: Optional[Path] = None,
        seed: Optional[int] = 42,
    ) -> None:
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.seed = seed
        self.rng = random.Random(seed)

    def _fictional_person(self) -> Tuple[str, str, str]:
        first = self.rng.choice(_FIRST_NAMES)
        last = self.rng.choice(_LAST_NAMES)
        full = f"{first} {last}"
        email = f"{first.lower()}.{last.lower()}@example-corp.internal"
        return full, email, f"EMP-{self.rng.randint(10000, 99999)}"

    def _generate_txt(self, department: str, classification: DataClassification, idx: int) -> bytes:
        person, email, emp_id = self._fictional_person()
        codename = self.rng.choice(_PROJECT_CODENAMES)
        text = f"""================================================================================
CONFIDENTIAL ENTERPRISE MEMORANDUM
Department: {department}
Classification: {classification.value}
Document ID: DOC-{department[:3].upper()}-{idx:06d}
Date: 2026-03-{self.rng.randint(1, 28):02d}
Author: {person} ({email})
Project: Operation {codename}
================================================================================

EXECUTIVE SUMMARY:
This document records departmental operational procedures and synthetic business
deliberations for internal tracking only. All metrics discussed herein reflect
simulated quarterly benchmarks.

OPERATIONAL NOTES:
1. Target milestone completion is scheduled for Q{self.rng.randint(1, 4)}.
2. System risk evaluation index: {self.rng.uniform(1.2, 4.8):.2f} / 5.00.
3. Departmental resource allocation: ${self.rng.randint(20, 800) * 1000:,} USD.
4. Personnel assigned to review: {emp_id} - Lead Auditor.

SECURITY NOTICE:
Unauthorized duplication or transfer of this document violates internal
governance standards. File access events are recorded.
--------------------------------------------------------------------------------
[END OF DOCUMENT DOC-{department[:3].upper()}-{idx:06d}]
"""
        return text.encode("utf-8")

    def _generate_csv(self, department: str, classification: DataClassification, idx: int) -> bytes:
        output = io.StringIO()
        writer = csv.writer(output)

        if department in {"Finance", "Sales"}:
            writer.writerow(["Transaction_ID", "Date", "Customer_Name", "Department", "Amount_USD", "Status", "Classification"])
            for r in range(self.rng.randint(5, 20)):
                writer.writerow([
                    f"TXN-{self.rng.randint(100000, 999999)}",
                    f"2026-02-{self.rng.randint(1, 28):02d}",
                    self.rng.choice(_COMPANIES),
                    department,
                    f"{self.rng.uniform(500.0, 75000.0):.2f}",
                    self.rng.choice(["SETTLED", "PENDING", "APPROVED", "RECONCILED"]),
                    classification.value,
                ])
        elif department in {"Human Resources", "Customers"}:
            writer.writerow(["Record_ID", "Full_Name", "Corporate_Email", "City", "Role_Band", "Salary_Index", "Classification"])
            for r in range(self.rng.randint(5, 20)):
                name, email, rec_id = self._fictional_person()
                writer.writerow([
                    rec_id,
                    name,
                    email,
                    self.rng.choice(_CITIES),
                    f"BAND-{self.rng.randint(3, 9)}",
                    self.rng.randint(65000, 195000),
                    classification.value,
                ])
        else:
            writer.writerow(["Item_ID", "Component", "Quantity", "Warehouse_Location", "Condition", "Classification"])
            for r in range(self.rng.randint(5, 20)):
                writer.writerow([
                    f"SKU-{self.rng.randint(10000, 99999)}",
                    f"Subsystem-{self.rng.choice(_PROJECT_CODENAMES)}",
                    self.rng.randint(1, 500),
                    f"BAY-{self.rng.choice(['A', 'B', 'C', 'D'])}-{self.rng.randint(1, 40)}",
                    "OPERATIONAL",
                    classification.value,
                ])

        return output.getvalue().encode("utf-8")

    def _generate_json(self, department: str, classification: DataClassification, idx: int) -> bytes:
        person, email, emp_id = self._fictional_person()
        payload = {
            "schema_version": "2.1.0",
            "document_id": f"JSON-{department[:3].upper()}-{idx:06d}",
            "generated_at": f"2026-03-01T09:{(idx // 60) % 60:02d}:{idx % 60:02d}Z",
            "department": department,
            "security_classification": classification.value,
            "owner": {
                "name": person,
                "email": email,
                "employee_id": emp_id,
            },
            "parameters": {
                "project_codename": self.rng.choice(_PROJECT_CODENAMES),
                "server_cluster": f"cluster-{self.rng.randint(1, 16)}.internal.net",
                "datacenter_location": self.rng.choice(_CITIES),
                "active_sessions": self.rng.randint(10, 450),
                "failover_ready": True,
            },
            "audit_trail": [
                {"timestamp": "2026-01-15T08:30:00Z", "action": "INITIAL_CREATION", "status": "OK"},
                {"timestamp": "2026-02-10T14:22:10Z", "action": "POLICY_REVIEW", "status": "APPROVED"},
            ],
        }
        return json.dumps(payload, indent=2).encode("utf-8")

    def _generate_xml(self, department: str, classification: DataClassification, idx: int) -> bytes:
        person, email, emp_id = self._fictional_person()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<EnterpriseDataExchange xmlns="urn:cryptoshield:enterprise:v1">
  <Header>
    <MessageId>XML-{department[:3].upper()}-{idx:06d}</MessageId>
    <Timestamp>2026-03-01T09:{(idx // 60) % 60:02d}:{idx % 60:02d}Z</Timestamp>
    <Department>{department}</Department>
    <Classification>{classification.value}</Classification>
  </Header>
  <Signatory>
    <EmployeeId>{emp_id}</EmployeeId>
    <Name>{person}</Name>
    <Contact>{email}</Contact>
  </Signatory>
  <Payload>
    <Project>{self.rng.choice(_PROJECT_CODENAMES)}</Project>
    <Region>{self.rng.choice(_CITIES)}</Region>
    <TransactionLimit currency="USD">{self.rng.randint(10000, 500000)}</TransactionLimit>
    <IntegrityStatus verified="true" code="VALID_SCHEMA" />
  </Payload>
</EnterpriseDataExchange>
"""
        return xml.encode("utf-8")

    def _generate_md(self, department: str, classification: DataClassification, idx: int) -> bytes:
        person, email, emp_id = self._fictional_person()
        codename = self.rng.choice(_PROJECT_CODENAMES)
        md = f"""# Technical Specification: Project {codename}

- **Department:** {department}
- **Document Index:** MD-{department[:3].upper()}-{idx:06d}
- **Author:** {person} (`{email}`)
- **Security Classification:** `{classification.value}`
- **Effective Date:** March 2026

---

## 1. Objectives & Scope
This specification details the architecture for the enterprise synthetic workload module within **{department}**.

### Key Deliverables:
- Implement automated verification routines.
- Ensure cryptographic boundary isolation.
- Enforce strict role-based access control policies.

## 2. Architecture Diagram
```
[Client Applications]
         │
         ▼
[API Gateway: {_CITIES[idx % len(_CITIES)]}]
         │
         ▼
[Core Microservices] ───► [Isolated Storage Vault]
```

## 3. Compliance and Handling
> **Notice:** Files marked as `{classification.value}` are strictly subject to internal Data Loss Prevention (DLP) controls.
"""
        return md.encode("utf-8")

    def _generate_html(self, department: str, classification: DataClassification, idx: int) -> bytes:
        person, email, emp_id = self._fictional_person()
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{department} Enterprise Portal - Doc #{idx}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 30px; background: #f8fafc; color: #1e293b; }}
    .card {{ background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; max-width: 750px; margin: 0 auto; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; background: #fee2e2; color: #991b1b; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }}
    th {{ background: #f1f5f9; }}
  </style>
</head>
<body>
  <div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <h2>{department} Corporate Bulletin</h2>
      <span class="badge">{classification.value}</span>
    </div>
    <p><strong>Document ID:</strong> HTML-{department[:3].upper()}-{idx:06d} | <strong>Custodian:</strong> {person} ({email})</p>
    <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 16px 0;">
    <h3>Quarterly Operational Metrics</h3>
    <table>
      <thead>
        <tr><th>Metric</th><th>Target</th><th>Actual</th><th>Status</th></tr>
      </thead>
      <tbody>
        <tr><td>System Throughput</td><td>10,000 req/s</td><td>11,420 req/s</td><td>Exceeded</td></tr>
        <tr><td>Uptime Guarantee</td><td>99.95%</td><td>99.99%</td><td>Met</td></tr>
        <tr><td>Security Audits</td><td>100% Passed</td><td>100% Passed</td><td>Met</td></tr>
      </tbody>
    </table>
    <p style="font-size: 11px; color: #64748b; margin-top: 20px;">CryptoShield Synthetic Lab Dataset &copy; 2026. Fictional content for defensive security testing.</p>
  </div>
</body>
</html>
"""
        return html.encode("utf-8")

    def _generate_log(self, department: str, classification: DataClassification, idx: int) -> bytes:
        lines: List[str] = []
        base_time = 1772534400 + (idx * 30)  # Epoch timestamp in 2026
        hostname = f"srv-{department.lower().replace(' ', '')}-{self.rng.randint(1, 9):02d}"

        for i in range(self.rng.randint(12, 35)):
            t = datetime.fromtimestamp(base_time + (i * 12), tz=CONFIG.TIMEZONE).strftime("%Y-%m-%dT%H:%M:%S.%f%z")
            level = self.rng.choice(["INFO", "INFO", "INFO", "WARN", "DEBUG"])
            action = self.rng.choice([
                "AUTH_SUCCESS user=admin ip=10.0.4.12",
                "TLS_HANDSHAKE_COMPLETE cipher=AES256-GCM session_id=" + hex(self.rng.randint(0x100000, 0xFFFFFF)),
                "HEARTBEAT_ACK latency_ms=" + str(self.rng.randint(2, 45)),
                "DATABASE_QUERY duration_ms=" + str(self.rng.randint(1, 15)) + " rows=" + str(self.rng.randint(1, 100)),
                "FILE_ACCESS_AUDIT path=/lab/storage/record_" + str(self.rng.randint(1, 500)),
            ])
            lines.append(f"{t} [{level}] [{hostname}] [pid:{self.rng.randint(1000, 9999)}] {action}")

        return "\n".join(lines).encode("utf-8") + b"\n"

    def _generate_canary_content(
        self,
        filename: str,
        department: str,
        classification: DataClassification,
        fmt: str,
        token_id: str,
    ) -> bytes:
        """Create highly enticing synthetic decoy documents containing canary indicators."""
        header_comment = f"CRYPTOSHIELD_CANARY_TOKEN_{token_id}"

        if fmt == "json":
            payload = {
                "__CRYPTOSHIELD_CANARY_DECOY__": True,
                "canary_token": header_comment,
                "warning": "HIGH PRIORITY HONEYTOKEN DECOY. DO NOT ACCESS OR EXFILTRATE.",
                "classification": classification.value,
                "target_name": filename,
                "credentials": [
                    {"service": "Production_Postgres", "username": "db_master", "password": f"SimulatedSecretPass_{self.rng.randint(1000, 9999)}!"},
                    {"service": "AWS_Root_Access_Key", "access_key_id": f"AKIA{self.rng.randint(10000000, 99999999)}", "secret": f"MockSimulatedKey{token_id}"},
                ],
            }
            return json.dumps(payload, indent=2).encode("utf-8")

        elif fmt == "csv":
            buf = io.StringIO()
            buf.write(f"# CANARY_DECOY_FILE: {header_comment}\n")
            buf.write("Employee_ID,Full_Name,SSN_Simulated,Base_Salary_USD,Bonus_USD,Bank_Account_Mock\n")
            for _ in range(8):
                name, _, emp_id = self._fictional_person()
                buf.write(f"{emp_id},{name},999-{self.rng.randint(10,99)}-{self.rng.randint(1000,9999)},{self.rng.randint(220000, 480000)},{self.rng.randint(50000, 150000)},9876543210\n")
            return buf.getvalue().encode("utf-8")

        elif fmt == "xml":
            xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- {header_comment} -->
<CanaryDecoyVault classification="{classification.value}">
  <SecurityNotice>HONEYTOKEN CANARY OBJECT - ANY MODIFICATION TRIGGERS HIGH THREAT ALERT</SecurityNotice>
  <DecoySecretVault id="{token_id}">
    <MasterSwiftCode>SWIFT-NYC-TEST-{self.rng.randint(1000, 9999)}</MasterSwiftCode>
    <AuthorizationPasscode>SIMULATED_AUTH_TOKEN_{self.rng.randint(100000, 999999)}</AuthorizationPasscode>
  </DecoySecretVault>
</CanaryDecoyVault>
"""
            return xml.encode("utf-8")

        elif fmt == "md":
            md = f"""# [CONFIDENTIAL CANARY DECOY] {filename}

<!-- {header_comment} -->
> **CRITICAL SECURITY ALERT:** This file is an active honeypot canary document.
> Access, staging, renaming, or modification triggers CRITICAL containment.

## Target Acquisition Dossier: Project {self.rng.choice(_PROJECT_CODENAMES)}
- Target Entity Valuation: ${self.rng.randint(50, 250)}M USD
- Proposed Tender Price: ${self.rng.randint(30, 90)} / share
- Non-Disclosure Signature: Active
"""
            return md.encode("utf-8")

        elif fmt == "log":
            lines = [
                f"# CRYPTOSHIELD_CANARY_LOG: {header_comment}",
                f"2026-03-01T00:00:00.000000Z [CRITICAL] [canary-vault] ROOT KEY ACCESS GRANTED TO SIMULATED_DECOY",
                f"2026-03-01T00:00:01.000000Z [ALERT] [canary-vault] HONEYPOT MONITORED AT TOKEN={token_id}",
            ]
            return "\n".join(lines).encode("utf-8") + b"\n"

        else:  # txt
            txt = f"""================================================================================
CRYPTOSHIELD DECOY CANARY DOCUMENT
Token: {header_comment}
Filename: {filename}
Classification: {classification.value}
================================================================================
CRITICAL HONEYTOKEN DECOY:
This document contains fictional high-value secrets intended to detect
unauthorized file enumeration, rapid mass encryption, or exfiltration staging.

Fictional Master Recovery Passphrase:
  "alpha-bravo-tango-{self.rng.randint(1000, 9999)}-secure-canary"
================================================================================
"""
            return txt.encode("utf-8")

    def generate_file_content(
        self,
        department: str,
        classification: DataClassification,
        file_format: str,
        idx: int,
    ) -> bytes:
        """Route to appropriate content generator by extension."""
        fmt = file_format.lower()
        if fmt == "txt":
            return self._generate_txt(department, classification, idx)
        elif fmt == "csv":
            return self._generate_csv(department, classification, idx)
        elif fmt == "json":
            return self._generate_json(department, classification, idx)
        elif fmt == "xml":
            return self._generate_xml(department, classification, idx)
        elif fmt == "md":
            return self._generate_md(department, classification, idx)
        elif fmt == "html":
            return self._generate_html(department, classification, idx)
        elif fmt == "log":
            return self._generate_log(department, classification, idx)
        else:
            return f"CryptoShield synthetic content for {department} (file #{idx})".encode("utf-8")

    def generate_dataset(
        self,
        file_count: int,
        canary_count: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Manifest:
        """
        Streamingly create synthetic files and compile the baseline manifest.

        Args:
            file_count: Total target files (e.g., 1000, 10000, 20000).
            canary_count: Optional override for number of decoy canary files.
            progress_callback: Callback(completed_files, total_files) for progress display.

        Returns:
            Fully populated Manifest instance.
        """
        # Strict safety check before any write
        marker = verify_lab_marker(self.lab_dir)
        logger.info(
            f"Initiating synthetic dataset generation: {file_count} files (Seed: {self.seed}) "
            f"in lab '{self.lab_dir}' (Marker ID: {marker.lab_id})"
        )

        start_time = time.perf_counter()

        # Calculate canary target count
        if canary_count is None:
            computed_canaries = int(file_count * CONFIG.CANARY_RATIO)
            actual_canaries = max(CONFIG.MIN_CANARY_COUNT, min(CONFIG.MAX_CANARY_COUNT, computed_canaries))
            # Bound canaries if total file count is small
            actual_canaries = min(actual_canaries, max(1, file_count // 10))
        else:
            actual_canaries = max(0, min(file_count, canary_count))

        regular_files_target = file_count - actual_canaries

        # Create department directories
        for dept in CONFIG.DEPARTMENTS:
            subdirs = _DEPARTMENT_SUBDIRS.get(dept, ["general"])
            for sub in subdirs:
                sub_path = self.lab_dir / dept / sub
                validate_lab_path(sub_path, self.lab_dir)
                sub_path.mkdir(parents=True, exist_ok=True)

        manifest_entries: Dict[str, ManifestEntry] = {}
        department_counts: Dict[str, int] = {dept: 0 for dept in CONFIG.DEPARTMENTS}
        type_counts: Dict[str, int] = {fmt: 0 for fmt in CONFIG.FILE_FORMATS}
        classification_counts: Dict[str, int] = {c.value: 0 for c in DataClassification}
        total_size_bytes = 0

        created_files = 0

        # 1. Generate regular files
        for i in range(regular_files_target):
            dept = CONFIG.DEPARTMENTS[i % len(CONFIG.DEPARTMENTS)]
            subdirs = _DEPARTMENT_SUBDIRS.get(dept, ["general"])
            sub = subdirs[(i // len(CONFIG.DEPARTMENTS)) % len(subdirs)]
            fmt = CONFIG.FILE_FORMATS[(i + (i // 7)) % len(CONFIG.FILE_FORMATS)]

            allowed_classes = CONFIG.DEPARTMENT_CLASSIFICATIONS.get(
                dept, [DataClassification.INTERNAL]
            )
            classification = allowed_classes[self.rng.randint(0, len(allowed_classes) - 1)]

            filename = f"{dept.lower().replace(' ', '_')}_{sub}_{i:06d}.{fmt}"
            file_path = self.lab_dir / dept / sub / filename

            # Safety validate
            validate_lab_path(file_path, self.lab_dir)

            content = self.generate_file_content(dept, classification, fmt, i)
            file_size = len(content)
            file_hash = compute_bytes_sha256(content)

            # Write directly to disk
            with open(file_path, "wb") as f:
                f.write(content)

            rel_posix = file_path.relative_to(self.lab_dir).as_posix()
            entry = ManifestEntry(
                relative_path=rel_posix,
                file_type=fmt,
                file_size_bytes=file_size,
                data_classification=classification.value,
                sha256=file_hash,
                is_canary=False,
                department=dept,
                created_at=f"2026-03-01T09:{(i // 60) % 60:02d}:{i % 60:02d}Z",
            )
            manifest_entries[rel_posix] = entry

            # Update counters
            department_counts[dept] += 1
            type_counts[fmt] += 1
            classification_counts[classification.value] += 1
            total_size_bytes += file_size
            created_files += 1

            if progress_callback and (created_files % 500 == 0 or created_files == file_count):
                progress_callback(created_files, file_count)

        # 2. Generate Canary Decoy Files
        for c_idx in range(actual_canaries):
            template_choice = _CANARY_TEMPLATES[c_idx % len(_CANARY_TEMPLATES)]
            tpl_name, dept, sub, classification, fmt = template_choice

            # Make filename unique if we generate more canaries than template pool
            if c_idx >= len(_CANARY_TEMPLATES):
                stem = Path(tpl_name).stem
                ext = Path(tpl_name).suffix
                canary_filename = f"{stem}_{c_idx:03d}{ext}"
            else:
                canary_filename = tpl_name

            canary_path = self.lab_dir / dept / sub / canary_filename
            validate_lab_path(canary_path, self.lab_dir)

            token_id = f"CANARY-{c_idx:04d}-{self.rng.randint(1000, 9999)}"
            canary_bytes = self._generate_canary_content(
                canary_filename, dept, classification, fmt, token_id
            )
            canary_size = len(canary_bytes)
            canary_hash = compute_bytes_sha256(canary_bytes)

            with open(canary_path, "wb") as f:
                f.write(canary_bytes)

            rel_posix = canary_path.relative_to(self.lab_dir).as_posix()
            entry = ManifestEntry(
                relative_path=rel_posix,
                file_type=fmt,
                file_size_bytes=canary_size,
                data_classification=classification.value,
                sha256=canary_hash,
                is_canary=True,
                department=dept,
                created_at=f"2026-03-01T12:{(c_idx // 60) % 60:02d}:{c_idx % 60:02d}Z",
            )
            manifest_entries[rel_posix] = entry

            department_counts[dept] += 1
            type_counts[fmt] = type_counts.get(fmt, 0) + 1
            classification_counts[classification.value] += 1
            total_size_bytes += canary_size
            created_files += 1

            if progress_callback and (created_files % 500 == 0 or created_files == file_count):
                progress_callback(created_files, file_count)

        duration = time.perf_counter() - start_time
        logger.info(
            f"Dataset generation complete: {created_files} files ({total_size_bytes / (1024*1024):.2f} MB, "
            f"{actual_canaries} canaries) in {duration:.2f}s"
        )

        manifest = Manifest(
            manifest_version="1.0.0",
            lab_id=marker.lab_id,
            generated_at=datetime.now(CONFIG.TIMEZONE).isoformat(),
            total_files=created_files,
            total_size_bytes=total_size_bytes,
            canary_count=actual_canaries,
            seed=self.seed,
            department_counts=department_counts,
            type_counts=type_counts,
            classification_counts=classification_counts,
            entries=manifest_entries,
        )

        # Save manifest to laboratory root
        ManifestManager.save_manifest(
            manifest,
            self.lab_dir / CONFIG.MANIFEST_FILENAME,
            base_lab_dir=self.lab_dir,
        )

        return manifest
