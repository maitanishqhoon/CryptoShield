# CryptoShield — Full Architecture & Operational Guide (Phases 1–10)

**Welcome to the Full CryptoShield Architecture Guide!**  
Now that all **10 project phases are complete** (with **280 out of 280 automated tests passing across 59 test modules**), this document serves as the complete reference for explaining the architecture, technological concepts, testing methodology, PySide6 SOC Console, and end-to-end double-extortion defense workflow to your team.

---

## 1. CryptoShield in Layman's Language: The Big Picture

### The Real-World Problem
Modern ransomware has evolved into **"Double Extortion"**:
1. **The Theft (Exfiltration):** First, the attackers quietly read and copy your private documents, pack them into an archive, and sneak them out over the network. They threaten to publish them publicly if you don't pay.
2. **The Lockup (Encryption):** Next, they run through your hard drive at lightning speed, scrambling every file into gibberish (encrypting them) and deleting your backups so you can't restore them.

### The CryptoShield Analogy: A High-Tech Bank & Embassy
Imagine an embassy or a high-security bank. CryptoShield is not just a single lock on the front door; it is an **integrated immune system**:
* **The Tripwires (Canary Files):** Fake stacks of money left on tables. If anyone so much as touches them, silent alarms blare.
* **The Security Guards & Cameras (Monitoring):** Guards watching who touches what file, how fast they are opening drawers, and what programs are running.
* **The Suspicion Brain (Threat Scorer):** Distinguishes a busy accountant from a masked burglar shoving files into bags.
* **The Blast Doors (Containment):** The instant a thief is spotted, steel shutters drop over the vault door, and the suspect is disarmed and frozen.
* **The Border Customs Checkpoint (DLP & Exfiltration Gate):** Even if a thief grabs documents, they cannot walk out the gate without customs inspecting every single box. Confidential files are stopped cold before a single byte leaves the building.
* **The Indestructible Underground Vault (Crypto Vault & Recovery):** A hidden, sealed backup taken earlier. Even if a fire burns down the front desk, the original documents are decrypted in staging, verified bit-for-bit, and put right back where they belong.
* **The Black Box & Notary Seal (Phase 9 — Forensic Reporting):** After an incident, an automated investigator fuses every camera clip, alarm, customs log, and recovery receipt into one tamper-evident dossier sealed with a cryptographic SHA-256 fingerprint.
* **The Command Center Wall (Phase 10 — PySide6 Desktop SOC Console):** A unified dark-mode Security Operations Center where operators watch live threat gauges, throw emergency blast-door switches, inspect forensic seals, and run safe attack simulations—all synced to one IST clock.

---

## 2. Technological Concepts Used (What They Mean & Why We Used Them)

Here is every major computer science, cryptographic, forensic, and UI concept built into CryptoShield, explained in plain terms:

### A. Cryptography & Forensic Integrity Concepts

| Concept | What It Is in Plain English | Where & Why We Use It |
| :--- | :--- | :--- |
| **AES-256-GCM** *(Symmetric Authenticated Encryption)* | Think of this as an armored military lockbox. It scrambles data using a 256-bit key. **GCM (Galois/Counter Mode)** generates a cryptographic "tamper-evident seal" (the 128-bit Auth Tag). If an attacker changes even one single bit of the encrypted file on disk, GCM detects it immediately and refuses to open. | Used by `CryptoEngine` to encrypt files into `.cso` (CryptoShield Object) containers for backup snapshots, and by `RestorationManager` to verify data before committing plaintext. |
| **RSA-3072 & RSA-OAEP** *(Asymmetric Public/Private Encryption)* | A two-key system: a **Public Key** that can only lock the safe, and a **Private Key** needed to open it. **OAEP** with SHA-256 prevents mathematical pattern attacks. | Used by `KeyManager` and `SnapshotManager`. Each backup snapshot gets its own random AES session key, wrapped with RSA-OAEP so snapshots cannot be opened without the master private key. |
| **Argon2id** *(Memory-Hard Key Derivation)* | A password hasher that deliberately consumes 64 MiB of RAM, 3 iterations, and 4 parallel lanes. It makes brute-force password guessing impractical, even on GPUs. | Used in Envelope V2 (`Argon2id-AES256GCM`) to protect the master RSA private key on disk against offline brute-force cracking. |
| **SHA-256** *(Cryptographic Hash Function)* | A one-way mathematical fingerprint. Change a single byte in a file, and its 64-character hex fingerprint changes completely. | Used in `baseline_manifest.json`, `RecoveryAssessor`, and `RestorationManager` to verify every restored file matches the original 100%. |
| **HMAC-SHA256** *(Keyed-Hash Message Authentication)* | A digital signature created with a secret key proving a marker file was created by CryptoShield and has not been forged or moved. | Used in `.cryptoshield_lab_marker` and `.cryptoshield_recovery_marker`. Prevents CryptoShield from touching files outside authorized lab or recovery folders. |
| **Cryptographic Chain of Custody & Dossier Seal** *(Phase 9)* | Freezing an entire incident report by computing a deterministic SHA-256 digest over canonical sorted JSON (`sort_keys=True`), binding the baseline manifest hash and quarantined evidence hashes. | Used by `ForensicDossier.compute_dossier_hash()` and `ReportExporter.verify_dossier_seal()`. Changing a single metric or timestamp invalidates the seal immediately. |

### B. Operating System, Forensic & Desktop UI Concepts

| Concept | What It Is in Plain English | Where & Why We Use It |
| :--- | :--- | :--- |
| **Canary Files / Honeypots** | Deceptive "bait" files (e.g., `passwords_master_backup.json`, `executive_salaries_2026.csv`) placed quietly in directories. Normal users never touch them; ransomware inevitably hits them first. | Used in `CanaryAnalyzer` and `ReadBurstDetector`. Touching a canary awards +50 to +60 threat points and raises immediate high-priority alerts. |
| **File System Telemetry (`watchdog`)** | Hooking into the OS filesystem notification layer to capture file creations, edits, renames, and deletions in real time. | Used in `FilesystemMonitor` to track rapid file activity across the 20,000-file laboratory baseline. |
| **Process Inspection (`psutil`)** | Inspecting the OS process table for running programs, parent processes, PIDs, start times, and executable paths. | Used in `ProcessMonitor` and `ControlledProcessRegistry` to attribute simulator activity accurately without guessing. |
| **Sliding Time Windows** | Evaluating activity over rolling intervals (1s, 5s, 10s, 30s) rather than isolated snapshots. | Used in `BehaviorAnalyzer` and `ReadBurstDetector` to distinguish normal edits from rapid ransomware bursts. |
| **Pub/Sub Event Bus** | A central thread-safe broadcasting hub (`app/core/event_bus.py`). Subsystems emit typed events (`FILE_MODIFIED`, `CANARY_ACCESS`, `SECURITY_INCIDENT_RESOLVED`) without tight coupling. | Connects monitoring, detection, containment, exfiltration, DLP, recovery, Phase 9 auto-reporting, and Phase 10 live GUI updates. |
| **PID Reuse Protection** | Operating systems recycle PIDs after a process exits. Verifying PID alone risks terminating an innocent app started later. | `ControlledProcessRegistry` checks PID + process creation timestamp + executable path + owned handle before `ProcessController` stops any simulator. |
| **Pre-Transmission Gate (DLP)** | Intercepting outbound transfers in memory *before* bytes reach the network socket, enforcing `ALLOW`, `ALERT`, `REQUIRE_APPROVAL`, or `BLOCK`. | Used in `DLPTransferGate` and `DLPApprovalManager` (`APR-*` tokens) to guarantee zero-byte leakage of restricted or canary data. |
| **Multi-Subsystem Aggregation & MITRE ATT&CK Mapping** *(Phase 9)* | Fusing scattered logs from detection, containment, recovery, DLP, and exfiltration into one chronological dossier with academic KPIs and MITRE technique tags (`T1486`, `T1083`, `T1005`, `T1074`, `T1048`). | Implemented in `ForensicAggregator` and `ReportExporter`, exporting `JSON`, `Markdown`, `CSV`, and dark-theme `HTML` reports under `runtime/reports/`. |
| **Thread-Safe Qt Signal Bridge & Async Workers** *(Phase 10)* | Background threads cannot safely touch GUI widgets directly. A bridge converts EventBus events into Qt queued signals while `QThread` workers run heavy crypto/simulations off the UI thread. | Implemented in `EventBusBridge` (`app/ui/bridge.py`) and `AsyncWorker` (`app/ui/workers.py`), keeping the 8-tab PySide6 console smooth and responsive. |
| **Centralized Temporal Sync (IST / UTC+05:30)** | Normalizing every clock, event timestamp, log line, and dossier entry to one authoritative timezone (`Indian Standard Time`). | Implemented in `app/core/time.py` (`now_ist()`, `format_ist()`, `parse_iso_to_ist()`) so cross-subsystem forensic timelines sort cleanly to the microsecond. |

---

## 3. What Are the Multiple Tests For? (280 Tests Explained)

CryptoShield now includes **59 test files with 280 total automated tests** (`280 / 280 passing` via `.venv\Scripts\pytest.exe`). In high-stakes security and cryptography software, you never assume code works—you prove it against edge cases, tampering, concurrency bugs, and simulated attacks.

### Test Categories Breakdown:

1. **Safety, Config & Lab Foundation Tests (`test_safety.py`, `test_config.py`, `test_lab_manager.py`, `test_manifest.py`, `test_dataset_generator.py` — 25 tests)**
   * **What they test:** Directory traversal attacks (`../../Windows/System32`), symlink escapes, tampered `.cryptoshield_lab_marker` files, `CRYPTOSHIELD_RUNTIME_DIR` isolation, deterministic dataset generation, and SHA-256 baseline auditing.
   * **Why it matters:** Guarantees CryptoShield can never touch files outside its authenticated lab boundary.

2. **Monitoring, Detection & Containment Tests (`test_*monitor*.py`, `test_canary_*.py`, `test_behavior_analyzer.py`, `test_threat_scorer.py`, `test_containment_*.py` — 85 tests)**
   * **What they test:** High-throughput event telemetry, distinguishing normal typing from `.locked` burst encryption, canary honeypot scoring (+50 / +60), `LabWriteGate` closure, PID-reuse-safe `ControlledProcessRegistry`, and post-containment write rejection.
   * **Why it matters:** Eliminates false alarms while ensuring simulator threats are neutralized cleanly without touching host OS apps.

3. **Cryptographic Vault & Anti-Tampering Tests (`test_vault_*.py` — 43 tests)**
   * **What they test:** Single-bit ciphertext tampering in `.cso` files (rejected by AES-GCM tag), substituted manifest entries (rejected by SHA-256/AAD), wrong passphrases against Argon2id V2 envelopes, and RSA-OAEP session key wrapping.
   * **Why it matters:** Guarantees the backup vault is mathematically tamper-evident.

4. **Bit-for-Bit Recovery Tests (`test_recovery_*.py` — 28 tests)**
   * **What they test:** Multi-threaded damage assessment, isolated recovery workspace markers, staging decryption without leaking unauthenticated plaintext, evidence quarantine, and 100% SHA-256 hash match after restore.
   * **Why it matters:** Proves recovery never commits corrupt or unverified files.

5. **Exfiltration & DLP Policy Tests (`test_exfiltration_*.py`, `test_mock_receiver.py`, `test_read_burst_detector.py`, `test_staging_detector.py`, `test_transfer_monitor.py`, `test_dlp_*.py` — 52 tests)**
   * **What they test:** Multi-department read bursts, staging archive (`.zip`) detection, loopback-only mock receiver boundaries (`127.0.0.1`), zero-byte `BLOCK` enforcement for `RESTRICTED`/canary data, and `APR-*` quarantine approval workflows.
   * **Why it matters:** Proves complete defense against the data-theft half of double extortion.

6. **Forensic Reporting & Temporal Sync Tests (`test_forensic_*.py`, `test_timezone_sync.py` — 26 tests)**
   * **What they test:** `ForensicAggregator` cross-subsystem timeline fusion, MITRE ATT&CK mapping, academic KPI math, 4-format export (`JSON`, `Markdown`, `CSV`, `HTML`), `verify_dossier_seal()` catching single-field tampering, end-to-end `ControlledForensicDemo`, and IST (`UTC+05:30`) synchronization across all logs and reports.
   * **Why it matters:** Ensures post-incident evidence is chronologically exact and cryptographically tamper-proof.

7. **PySide6 Desktop GUI & E2E Console Tests (`test_ui_*.py` — 21 tests)**
   * **What they test:** Headless (`--offscreen`) rendering of the dark SOC theme, `KPICard` / `ThreatGauge` / `EventTable` widgets, thread-safe `EventBusBridge` signals, `AsyncWorker` progress/error handling, all 8 operational tabs, all 5 simulation scenarios, and full live multi-tab event propagation (`test_ui_stage5_e2e_integration.py`).
   * **Why it matters:** Verifies that the entire 10-phase platform works cohesively from a single interactive operator console.

---

## 4. The Complete End-to-End Workflow (Step-by-Step)

Here is how CryptoShield operates end-to-end—both under the hood and visually inside the **PySide6 SOC Console** (`python -m app.main gui`):

1. **Step 1: Peacetime Preparation (The Immune Blueprint)**  
   CryptoShield initializes `runtime/lab/` with an HMAC-SHA256 `.cryptoshield_lab_marker`, generates up to 20,000 synthetic corporate files across 9 departments, computes `baseline_manifest.json` (SHA-256), plants deceptive Canary files, and creates an encrypted Vault Snapshot (`SNAP-XXXX`) with AES-256-GCM, RSA-3072, and Argon2id. On the GUI, the top ribbon shows `LAB: VALID`, `GATE: UNLOCKED`, `THREAT: 0 NORMAL`, `DLP: DEFAULT`, and `Canaries: ARMED`.
2. **Step 2: Attack Phase 1 — Data Harvesting (The Theft)**  
   An attacker reads sensitive files across Engineering/Research, HR, and Finance. `ReadBurstDetector` flags the abnormal multi-department read spike and broadcasts telemetry over the `EventBus` to `ExfiltrationCorrelator`.
3. **Step 3: Attack Phase 2 — Staging**  
   Stolen files are gathered and compressed into `confidential_export.zip`. `StagingDetector` catches the staging archive creation in real time.
4. **Step 4: Attack Phase 3 — Exfiltration Blocked by DLP**  
   The simulator attempts to stream the staged payload to the loopback `MockReceiver` (`127.0.0.1`). `DLPTransferGate` intercepts the transfer *before* socket egress, inspects its classification/canary flags, slams the gate shut (**0 bytes leaked**), logs to `runtime/dlp/audit.log`, and updates Tab 6 (**Exfiltration & DLP**) via `EventBusBridge`.
5. **Step 5: Attack Phase 4 — Ransomware Burst & Canary Tripwire**  
   Ransomware rapidly scrambles files and touches a canary (`passwords_master_backup.json`). `CanaryAnalyzer` triggers a breach (+50/+60), `BehaviorAnalyzer` detects the write burst, and `ThreatScorer` hits **CRITICAL (95–100/100)**. On the GUI Dashboard, the canary KPI flips to **BREACHED**, the `ThreatGauge` turns red, and the top ribbon flashes `THREAT: CRITICAL`.
6. **Step 6: Instant Containment**  
   `IncidentManager` triggers `ContainmentManager`: `LabWriteGate` locks (`.write_gate_state` -> `LOCKED`, ribbon badge turns red `GATE: LOCKED`), `ProcessController` verifies PID + start-time + path in `ControlledProcessRegistry` and stops the simulator cleanly, and `ContainmentVerifier` confirms zero post-containment writes.
7. **Step 7: Cryptographic Restoration (The Cure)**  
   `RecoveryAssessor` compares disk files against the snapshot manifest in parallel. Modified files are quarantined as forensic evidence. `RestorationManager` decrypts clean `.cso` objects into temporary staging, validates both the AES-GCM auth tag and SHA-256 digest, and atomically commits the restored files back into place (monitored live via Tab 5's progress bar).
8. **Step 8: Automated Forensic Dossier & Chain-of-Custody Seal (Phase 9)**  
   When the incident transitions to `RESOLVED` (`SECURITY_INCIDENT_RESOLVED`), `ForensicCoordinator` triggers `ForensicAggregator` and `ReportExporter` to compile a unified `ForensicDossier` (`REP-XXXXXXXX`) under `runtime/reports/` in **JSON, Markdown, CSV, and HTML** formats. Every timeline entry is aligned in IST, behaviors are tagged with MITRE ATT&CK techniques, academic KPIs are computed, and `ChainOfCustodyRecord` seals the dossier with `dossier_sha256`.
9. **Step 9: Operator Verification in the PySide6 SOC Console (Phase 10)**  
   In Tab 7 (**Forensic Reports**), the operator selects the new `REP-*` report and clicks **Cryptographically Verify Seal** (`[PASS] VALID`), inspects the Academic KPIs (`0 Bytes Leaked`, `100.0%` SHA-256 match) and IST timeline, and runs Tab 2's **Integrity Audit** across all 20,000 files (`100% matched, 0 modified, 0 missing`).

---

## 5. PySide6 SOC Console (8 Operational Tabs) & Key CLI Commands

* **Top Status Ribbon & Bottom Bar:** Live `LAB`, `GATE`, `THREAT`, and `DLP` status pills, synchronized IST clock, active lab path, and `EventBus Bridge: ONLINE` indicator.
* **8 Subsystem Tabs:**
  1. **Dashboard & Telemetry:** KPI cards, 0–100 `ThreatGauge`, active incident panel (`Emergency Lock Gate` / `Resolve Incident`), and searchable live `EventTable`.
  2. **Lab & Dataset Engine:** Lab marker validation, 1k / 10k / 20k dataset synthesizer, and parallel SHA-256 integrity auditor.
  3. **Threat Containment:** Manual `LabWriteGate` lock/unlock, `ControlledProcessRegistry` table, and `CONT-*` JSON audit dossiers.
  4. **Cryptographic Vault:** RSA-3072 key info (`Argon2id-AES256GCM` V2), encrypted snapshot creation, and `.cso` container verifier.
  5. **Recovery & Restoration:** Isolated `WKSP-*` workspace manager, multithreaded damage assessor, and two-stage authenticated restoration wizard.
  6. **Exfiltration & DLP:** Loopback mock receiver (`127.0.0.1`), DLP posture selector (`DEFAULT`/`STRICT`/`AUDIT_ONLY`/`PERMISSIVE`), rule matrix, `APR-*` approval queue, and live audit stream.
  7. **Forensic Reports:** `runtime/reports/` catalog, SHA-256 seal verifier, Academic KPI scorecard, IST chronological timeline, Markdown summary, and raw JSON inspector.
  8. **Simulation Testbed:** One-click launcher (with Demonstration / Extended / Rapid pacing) for all 5 controlled defensive scenarios and live terminal output.
* **Key Phase 9 & 10 CLI Entrypoints:**
  * `python -m app.main report {list, inspect, generate, verify, demo}`
  * `python -m app.main gui [--offscreen]`

---

## 6. Summary Checklist of All Completed Phases (1 through 10)

| Phase | Subsystem | Core Purpose in Simple Words | Tests Passing |
| :---: | :--- | :--- | :---: |
| **1** | **Lab & Dataset Engine** | Builds a realistic 20,000-file corporate playground with SHA-256 fingerprints & safety boundaries. | **25 / 25** |
| **2** | **File Telemetry & Sentry** | Cameras and microphones recording every file read, edit, delete, and process start. | **25 / 25** |
| **3** | **Threat Brain & Scoring** | Weighs suspicious activity and canary breaches to calculate a 0–100 threat score. | **28 / 28** |
| **4** | **Blast Doors & Containment** | Drops `LabWriteGate` and safely stops registered simulators without hurting host apps. | **32 / 32** |
| **5** | **Cryptographic Vault** | Indestructible backups encrypted with AES-256-GCM, RSA-3072, and Argon2id. | **43 / 43** |
| **6** | **Two-Stage Restoration** | Medical recovery verifying GCM tags and SHA-256 hashes before atomic file restore. | **28 / 28** |
| **7** | **Exfiltration Radar** | Detects mass reading, folder harvesting, archive staging (`.zip`), and loopback transfers. | **25 / 25** |
| **8** | **Data Loss Prevention (DLP)** | Customs gate that inspects and halts confidential transfers before socket egress. | **27 / 27** |
| **9** | **Forensic Incident Reporting** | Fuses multi-subsystem timelines, MITRE ATT&CK tags, 4-format exports, and SHA-256 custody seals. | **21 / 21** |
| **10** | **PySide6 Desktop GUI & Integration** | 8-tab dark SOC console with thread-safe `EventBusBridge`, `AsyncWorker`, and 5 simulation demos. | **21 / 21** |
| **Sync** | **Temporal Sync (IST)** | Synchronizes all event buses, logs, dossiers, and GUI clocks to Indian Standard Time (`UTC+05:30`). | **5 / 5** |
| **Total** | **Phases 1–10 (59 Test Files)** | **Complete End-to-End Double-Extortion Defense Platform** | **280 / 280** |
