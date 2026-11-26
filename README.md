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
│   ├── main.py                  # Unified CLI & GUI entrypoint (python -m app.main ...)
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
├── runtime/                     # Local runtime workspace (auto-created; data git-ignored, .gitkeep tracked)
│   ├── lab/                     # Active laboratory targets (.cryptoshield_lab_marker, manifest)
│   ├── vault/                   # Encrypted snapshots
│   ├── keys/                    # Encrypted RSA-3072 private key, public key, metadata
│   ├── snapshots/               # Snapshot index/records
│   ├── logs/                    # Rotating plain text and JSONL logs
│   ├── reports/                 # Multi-format forensic incident dossiers
│   ├── incidents/               # Correlated SecurityIncident records
│   ├── containment/             # Containment action audit dossiers
│   ├── recovery/                # Isolated recovery workspaces, staging, and reports
│   ├── exfiltration/            # Outbound mock transfer telemetry artifacts
│   └── dlp/                     # Active DLP rules & audit logs
│
├── tests/                       # Automated pytest suite
│   ├── conftest.py              # Ephemeral tmp_path isolation fixture (isolated_runtime)
│   ├── test_safety.py           # Safety boundary & path validation tests
│   ├── test_config.py           # Configuration, runtime override & passphrase tests
│   ├── test_lab_manager.py      # Lab lifecycle & cleanup tests
│   ├── test_manifest.py         # Hash computation & tampering detection tests
│   ├── test_dataset_generator.py# Dataset synthesis, taxonomy & canary tests
│   └── ...                      # Phase 2–10 monitoring, vault, recovery, DLP, forensic & UI tests
│
├── requirements.txt             # Aligned cross-platform project dependencies
├── .gitignore                   # Git ignore rules (keeps runtime/* data untracked)
└── README.md                    # Project documentation & onboarding guide
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

### Supported Python & Operating Systems
| Platform / Runtime | Status | Notes |
| :--- | :--- | :--- |
| **Python 3.12+** | **Required / Verified** | Tested on **Python 3.12.4**. Uses modern type syntax and `Argon2id` bindings from `cryptography>=44.0.0`. |
| **Windows 10 / 11 (x64)** | **Verified Primary Platform** | Full CLI, PySide6 GUI, `watchdog`, `psutil`, and automated test suite verified. |
| **Linux / macOS** | **Cross-Platform Compatible** | Application code uses cross-platform `pathlib`, `cryptography`, `watchdog`, `psutil`, and `PySide6` without Windows-only syscalls (not yet CI-verified on Linux/macOS hardware). On headless Linux servers, pass `--offscreen` to GUI commands. |

### Dependencies (`requirements.txt`)
- `cryptography>=44.0.0` (AES-256-GCM, RSA-3072, Argon2id key protection)
- `watchdog>=4.0.0` (filesystem telemetry)
- `psutil>=5.9.0` (process telemetry & controlled isolation)
- `PySide6>=6.5.0` (Phase 10 Desktop SOC Console)
- `pytest>=8.0.0` (automated verification suite)

### Fresh Clone & First-Run Setup Procedure

Run all commands below from the root of the cloned `CryptoShield` repository (or add the repository root to `PYTHONPATH` if invoking `python -m app.main` from another directory). All `runtime/` subdirectories are created automatically on first run.

#### 1. Clone and create a virtual environment

**Windows (PowerShell):**
```powershell
git clone <repository-url>
cd CryptoShield
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Linux / macOS (bash/zsh):**
```bash
git clone <repository-url>
cd CryptoShield
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### 2. Initialize your independent laboratory & cryptographic vault

Each installation generates its own signed `.cryptoshield_lab_marker` and its own Argon2id-encrypted RSA-3072 key pair (no keys or lab data are shared in Git):

```bash
# 1. Initialize runtime directories and the signed laboratory safety marker
python -m app.main init

# 2. Generate your installation's RSA-3072 vault keys (prompts securely for a passphrase)
python -m app.main vault init

# 3. Generate a synthetic enterprise dataset + baseline SHA-256 manifest
#    (--preset quick = 1,000 files; --preset stress = 20,000 files)
python -m app.main generate --preset quick --clean

# 4. Audit baseline integrity against baseline_manifest.json
python -m app.main verify

# 5. Create your first encrypted baseline snapshot in runtime/vault/
python -m app.main snapshot create
```

#### 3. Launch the Desktop GUI or CLI Demos
```bash
# Launch the PySide6 Desktop SOC Console
python -m app.main gui

# Or run the automated cryptographic recovery demonstration (prompts for passphrase)
python -m app.main recovery demo --cleanup
```

### Environment Variables
- `CRYPTOSHIELD_RUNTIME_DIR`: Optional directory path overriding the default `<repo>/runtime/` storage location (useful for running separate experiments or isolated environments).
- `CRYPTOSHIELD_VAULT_PASSPHRASE`: Optional passphrase for non-interactive CLI demos, scripts, and CI runs. When unset, CLI commands prompt securely via `getpass` and the GUI Simulation tab prompts with a masked password dialog.

---

## 6. CLI Usage & Commands

CryptoShield uses `python -m app.main <command>` as its unified entrypoint from the repository root (run `python -m app.main --help` for full subcommand help).

### 1. Initialize Laboratory
Creates runtime directory trees and generates the signed `.cryptoshield_lab_marker`:
```bash
python -m app.main init
```

### 2. Inspect Laboratory Status
Displays current lab health, marker details, file counts, and disk usage:
```bash
python -m app.main status
```

### 3. Generate Synthetic Datasets
Generate datasets using standard presets (`quick` = 1,000, `default` = 10,000, `stress` = 20,000) or custom file counts:

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

### 6. Cryptographic Vault, Recovery, Exfiltration, DLP, Forensics & GUI
```bash
python -m app.main vault status         # Inspect RSA key pair & vault snapshots
python -m app.main snapshot create      # Encrypt verified baseline into runtime/vault/
python -m app.main recovery demo        # Run automated workspace damage & restoration demo
python -m app.main exfiltration demo    # Run loopback staging & read-burst demo
python -m app.main dlp demo             # Run multi-tier DLP interception demo
python -m app.main report demo          # Run end-to-end attack/defense forensic dossier demo
python -m app.main gui                  # Open PySide6 SOC Console (--offscreen for headless)
```

---

## 7. Automated Test Suite

Run the full automated regression suite from the repository root:
```bash
python -m pytest -v
```

Integration, UI, and forensic CLI tests use the shared `isolated_runtime` fixture in [tests/conftest.py](tests/conftest.py) so they pass on a clean clone with an empty `runtime/` folder without modifying your personal keys or baseline. On a fresh installation without pre-existing developer vault snapshots, `test_real_vault_snapshot_unlock_and_canary_staging_readonly` skips cleanly while the remaining suite passes.

Test coverage includes:
- Path boundary containment and directory traversal rejection (`test_safety.py`)
- Configuration, `CRYPTOSHIELD_RUNTIME_DIR` override, and passphrase requirements (`test_config.py`)
- Lab manager lifecycle, status reporting, and guarded purge (`test_lab_manager.py`)
- SHA-256 hash calculation, manifest serialization, and tamper detection (`test_manifest.py`)
- Dataset generator departmental distribution, file format diversity, canary flags, and deterministic seed reproducibility (`test_dataset_generator.py`)
- Monitoring, behavioral detection, containment, vault encryption, recovery, exfiltration, DLP, forensic dossiers, and PySide6 UI suites (`test_monitoring_*`, `test_detection_*`, `test_containment_*`, `test_vault_*`, `test_recovery_*`, `test_exfiltration_*`, `test_dlp_*`, `test_forensic_*`, `test_ui_*`)
