# CryptoShield: An Intelligent Ransomware Detection, Containment, Data Exfiltration Prevention and Cryptographic Recovery Framework

> **Academic Proof-of-Concept Defensive Security Application**  
> Developed for university-level cybersecurity research on double-extortion ransomware defense.

---

## 1. Project Overview

CryptoShield is an educational, prototype defensive security application designed to analyze, contain, and remediate double-extortion ransomware attacks in a strictly controlled laboratory environment.

Double-extortion attacks violate:
1. **Data Integrity & Availability:** via unauthorized file modifications, mass renaming, and encryption.
2. **Data Confidentiality:** via unauthorized file access, staging, and data exfiltration.

CryptoShield introduces a multi-tier defense comprising filesystem event monitoring, behavioral detection heuristics, automated process containment, an isolated cryptographic backup vault, verified restoration, and rule-based Data Loss Prevention (DLP).

---

## 2. Architectural Blueprint & Directory Layout

```
CryptoShield/
│
├── app/
│   ├── main.py                  # CLI entrypoint for laboratory lifecycle & dataset operations
│   ├── config.py                # Central configuration (paths, limits, taxonomy, presets)
│   │
│   ├── core/                    # Core infrastructure & safety enforcement
│   │   ├── models.py            # Strongly-typed schemas (Manifest, LabMarker, Enums)
│   │   ├── safety.py            # Strict boundary validation & laboratory marker verification
│   │   ├── logger.py            # Structured logging (Console, text file, JSON lines)
│   │   └── event_bus.py         # Thread-safe pub/sub event bus
│   │
│   ├── lab/                     # Laboratory management & synthesis
│   │   ├── dataset_generator.py # Streaming synthetic enterprise dataset & canary generator
│   │   ├── manifest.py          # SHA-256 manifest compilation & multi-threaded auditor
│   │   └── lab_manager.py       # Lab initialization, directory lifecycle & safe purging
│   │
│   ├── monitoring/              # [Phase 2] Filesystem (Watchdog) & process telemetry (psutil)
│   ├── detection/               # [Phase 3] Rule-based threat scoring & sliding window analysis
│   ├── containment/             # [Phase 4] Controlled simulator process isolation
│   ├── vault/                   # [Phase 5] Isolated cryptographic snapshot vault (AES-256-GCM / RSA)
│   ├── recovery/                # [Phase 6] Verified file restoration & hash audit
│   ├── exfiltration/            # [Phase 7] Outbound staging & mock transfer monitoring
│   ├── dlp/                     # [Phase 8] Data loss prevention rules & policy enforcement
│   ├── reporting/               # [Phase 9] Forensic incident report generation
│   └── ui/                      # [Phase 10] PySide6 desktop dashboard
│
├── runtime/                     # Isolated runtime sandbox (git-ignored)
│   ├── lab/                     # Active laboratory targets (.cryptoshield_lab_marker, manifest)
│   ├── vault/                   # Encrypted snapshots
│   ├── snapshots/               # Metadata records
│   ├── logs/                    # Rotating plain text and JSONL logs
│   └── reports/                 # Incident forensics
│
├── tests/                       # Automated pytest suite
│   ├── test_safety.py           # Safety boundary & path validation tests
│   ├── test_config.py           # Configuration integrity tests
│   ├── test_lab_manager.py      # Lab lifecycle & cleanup tests
│   ├── test_manifest.py         # Hash computation & tampering detection tests
│   └── test_dataset_generator.py# Dataset synthesis, taxonomy & canary tests
│
├── requirements.txt             # Project dependencies
├── .gitignore                   # Git configuration
└── README.md                    # Project documentation
```

---

## 3. Strict Safety Boundaries & Controls

CryptoShield operates under defensive containment rules:

1. **Explicit Laboratory Marker:** Every laboratory root directory contains a cryptographically signed `.cryptoshield_lab_marker`. If this marker is missing, corrupted, or altered, all write operations and cleanups are immediately aborted.
2. **Path Containment:** The safety engine validates all target paths with strict canonicalization (`Path.resolve().relative_to(...)`). Any attempt to touch paths outside `runtime/lab/` raises a `SafetyViolationError`.
3. **Targeted Process Isolation:** Containment rules only ever terminate explicitly registered test simulator PIDs. System PIDs (e.g., 0, 4) and CryptoShield's own PID are strictly protected.
4. **Isolated Cryptographic Storage:** Snapshots and cryptographic keys are stored in `runtime/vault/`, segregated from the laboratory target directory.
5. **No External Network Transfer:** Simulated exfiltration is exclusively tested against local mock loopback endpoints; no laboratory data is ever routed outside the machine.

---

## 4. Phase 1 Implementation Highlights

### Synthetic Enterprise Dataset Engine
- **Hierarchical Taxonomy:** Files are organized into 9 realistic enterprise departments:
  - `Finance`, `Human Resources`, `Legal`, `Sales`, `Customers`, `Operations`, `Research`, `IT`, `Public Documents`
  - Each department includes dedicated subdirectories (e.g., `Finance/invoices`, `Legal/contracts`, `IT/network_configs`).
- **Diverse File Formats:** Realistically structured fictional content across 7 formats:
  - `.txt` (executive memos, policy directives)
  - `.csv` (financial transactions, employee registries, warehouse stock)
  - `.json` (system configurations, customer account schemas)
  - `.xml` (interchange purchase orders, enterprise data exchanges)
  - `.md` (technical specifications, architectural blueprints)
  - `.html` (departmental portal bulletins, executive dashboards)
  - `.log` (service audit trails, authentication logs)
- **Data Classification:** Every generated file is labeled with a sensitivity level (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`).
- **High-Value Canary Files:** Automated generation of honeypot decoy files (e.g., `passwords_master_backup.json`, `executive_salaries_2026.csv`, `swift_banking_credentials.xml`) containing canary tokens to trip detection engines upon access or modification.
- **High Performance & Streaming:** Streamingly computes SHA-256 hashes in-flight without secondary disk passes, achieving generation rates exceeding **1,200+ files per second**.
- **Deterministic Experiments:** Supports reproducible dataset generation using the `--seed` flag.

### Baseline Manifest & Integrity Auditing
- Captures POSIX relative paths, file types, byte sizes, classifications, canary flags, and SHA-256 hashes.
- Fast multi-threaded integrity verification (`verify`) comparing disk state with baseline hashes in fractions of a second.
- Detects modified files, deleted files, untracked rogue files, and tampered canary documents.

---

## 5. Setup & Installation

### Requirements
- **Python 3.12+**
- Windows, Linux, or macOS

### Dependencies Installation
Install dependencies in your environment:
```bash
pip install -r requirements.txt
```

Core dependencies:
- `cryptography>=42.0.0`
- `watchdog>=4.0.0`
- `psutil>=5.9.0`
- `PySide6>=6.6.0`
- `pytest>=8.0.0`
- `matplotlib>=3.8.0`

---

## 6. CLI Usage & Commands

CryptoShield provides a CLI for managing the laboratory environment and datasets.

### 1. Initialize Laboratory
Creates necessary directory trees and generates the signed `.cryptoshield_lab_marker`:
```bash
python -m app.main init
```

### 2. Inspect Laboratory Status
Displays current lab health, marker details, file counts, and disk usage:
```bash
python -m app.main status
```

### 3. Generate Synthetic Datasets
Generate datasets using standard presets or custom file counts:

- **Quick preset (1,000 files):**
  ```bash
  python -m app.main generate --preset quick --clean
  ```

- **Default preset (10,000 files):**
  ```bash
  python -m app.main generate --preset default --clean
  ```

- **Stress preset (20,000 files):**
  ```bash
  python -m app.main generate --preset stress --clean
  ```

- **Custom file count with custom seed:**
  ```bash
  python -m app.main generate --files 5000 --seed 42 --canaries 50
  ```

### 4. Verify Laboratory Integrity
Computes SHA-256 hashes of all disk files in parallel and verifies against `baseline_manifest.json`:
```bash
python -m app.main verify
```

### 5. Safely Clean Laboratory
Purges generated files while strictly preserving the laboratory safety marker:
```bash
python -m app.main clean -y
```

---

## 7. Automated Test Suite

Run all automated unit tests:
```bash
python -m pytest -v
```

Test coverage includes:
- Path boundary containment and directory traversal rejection (`test_safety.py`)
- Lab marker generation, signature validation, and tamper detection (`test_safety.py`)
- Configuration constants, paths, and departmental taxonomy (`test_config.py`)
- Lab manager lifecycle, status reporting, and guarded purge (`test_lab_manager.py`)
- SHA-256 hash calculation, manifest serialization, and tamper detection (`test_manifest.py`)
- Dataset generator departmental distribution, file format diversity, canary flags, and deterministic seed reproducibility (`test_dataset_generator.py`)
