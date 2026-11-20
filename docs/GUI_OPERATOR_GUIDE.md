# CryptoShield — PySide6 Desktop GUI Operator & User Guide
**Comprehensive Operational Manual & Demonstration Walkthrough**

---

## 1. Quick Start: Launching the Console

Open a terminal (PowerShell or Command Prompt) in the repository root:
```powershell
# Navigate to the CryptoShield root directory
cd C:\NFSU\AC\CryptoShield

# Launch the interactive desktop interface
.venv\Scripts\python.exe -m app.main gui
```
The application will open in a high-resolution dark-themed window (recommended display resolution: 1280x800 or higher).

---

## 2. Visual Layout Overview

The user interface is split into three main regions:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ [1] TOP OPERATIONAL STATUS RIBBON                                                       │
│     Brand Logo | IST Clock | Lab Marker | Write Gate | Threat Score | DLP Posture       │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [2] CENTRAL TABBED OPERATOR CONSOLE (8 Dedicated Tabs)                                  │
│     1. Dashboard & Telemetry          5. Recovery & Restoration                         │
│     2. Lab Baseline & Dataset Engine  6. Exfiltration & DLP                             │
│     3. Threat Containment             7. Forensic Reports                               │
│     4. Cryptographic Vault            8. Simulation Testbed                             │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [3] BOTTOM AUDIT STATUS BAR                                                             │
│     Active Laboratory Directory Path  |  EventBus Bridge Health Status                  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Top Operational Ribbon: Key Indicators

At the very top of the window, four persistent status badges give you instant situational awareness:

| Badge | Meaning | Normal State | Attack / Alert State |
| :--- | :--- | :--- | :--- |
| **`LAB: VALID`** | Verifies HMAC-SHA256 authenticated `.cryptoshield_lab_marker` | **Green**: Lab is isolated & protected | **Amber / Red**: Marker missing |
| **`GATE: UNLOCKED`** | Status of the application-level `LabWriteGate` | **Green**: Normal writes permitted | **Red (`GATE: LOCKED`)**: All write attempts blocked |
| **`THREAT: 0 NORMAL`** | Real-time aggregate threat score (0–100) | **Green**: No active threat | **Orange / Red (`THREAT: 95 CRITICAL`)**: Attack detected |
| **`DLP: DEFAULT`** | Active Data Loss Prevention posture profile | **Blue**: Enforcing policy rules | Displays `STRICT`, `AUDIT_ONLY`, or `PERMISSIVE` |

---

## 4. Subsystem Tabs: Step-by-Step Navigation

### Tab 1: Dashboard & Live Telemetry Feed (SOC Command Center)
*The central nerve center for real-time threat monitoring.*
- **Top KPI Cards:** Displays Threat Level, Gate State, Canary Status, and DLP Profile at a glance.
- **Threat Gauge (Left):** Real-time gauge showing the 0–100 threat score with color progression (Green $\rightarrow$ Cyan $\rightarrow$ Amber $\rightarrow$ Orange $\rightarrow$ Red) and attack description.
- **Active Incident Panel (Right):**
  - Shows active Incident ID (`INC-XXXXXXXX`), severity badge, and summary description.
  - **`Emergency Lock Gate` Button:** Manually lock the `LabWriteGate` to halt rogue writing immediately.
  - **`Resolve Incident` Button:** Marks an active incident as resolved after containment/recovery.
- **Live Defensive Telemetry Stream (Bottom):** High-speed table capturing all events.
  - **Search Bar:** Type file paths, departments, or event names to filter in real-time.
  - **Category Filter Dropdown:** Select `Canary Breaches`, `Filesystem Events`, `Access & Reads`, `Containment`, `DLP Gate`, or `Incidents`.
  - **Auto-scroll Checkbox:** Automatically keeps the table scrolled to the newest event.

---

### Tab 2: Lab Baseline & Synthetic Dataset Engine
*Manage enterprise synthetic datasets and audit cryptographic integrity.*
- **Safety Boundary Panel:** Displays lab directory path and validates `.cryptoshield_lab_marker`.
- **Dataset Synthesizer Controls:**
  - **Presets:** Quick (`1,000` files), Default (`10,000` files), Stress (`20,000` files).
  - **Customization:** Spinbox for target file count, deterministic random seed (default: `42`), and clean checkbox.
  - **`Generate Dataset` Button:** Dispatches streaming background dataset generation without freezing the UI.
- **Baseline Manifest SHA-256 Auditor:**
  - Click **`Execute Integrity Audit`** to compare all files on disk against `baseline_manifest.json`.
  - The results table displays: Matched files (100%), Modified files, Missing files, Untracked files, and Canary Tampering count.

---

### Tab 3: Threat Containment Console
*Control write interception and audit controlled process lifecycles.*
- **LabWriteGate Panel:**
  - Toggle between **`Emergency Lock Gate`** and **`Unlock Gate`**.
  - Displays the active state file (`runtime/containment/.write_gate_state`).
- **Controlled Test Process Registry:**
  - Displays registered test simulator processes (PID, Run ID, Lifecycle Status, Executable).
  - Enforces the safety invariant that host OS processes are strictly protected.
- **Recorded Containment Operations & Dossiers:**
  - Lists historical containment actions (`CONT-*`). Click any row to view its full JSON audit trail.

---

### Tab 4: Cryptographic Vault & Snapshot Engine
*Asymmetric key protection, Argon2id parameters, and AES-256-GCM backups.*
- **RSA-3072 Key Manager:**
  - Active Key ID (`KEY-0FC7E4DF74B0D16E`).
  - Envelope Version: **Argon2id-AES256GCM (Version 2)**.
  - Parameters: 64 MiB Memory Cost, 3 Iterations, 4 Parallel Lanes.
  - SHA-256 Fingerprint.
- **Snapshot Catalog Table:**
  - Lists snapshots (`SNAP-*`) with timestamps, file count, raw size, and ciphertext size.
  - **`Create New Encrypted Snapshot` Button:** Encrypts baseline files using streaming AES-256-GCM chunks.
  - **`Inspect Selected Snapshot` Button:** Displays JSON metadata in the lower console.
  - **`Cryptographically Verify Snapshot` Button:** Audits `.cso` authenticated containers and GCM tags.

---

### Tab 5: Cryptographic Recovery & Restoration Console
*Safely assess encryption damage and execute two-stage authenticated recovery.*
- **Isolated Recovery Workspaces (`runtime/recovery/`):**
  - Click **`Create Workspace`** to initialize a new authenticated workspace (`WKSP-*`).
  - Click **`Seed Selected`** to populate the workspace with test files and deceptive canaries.
  - Click **`Delete Selected`** to safely dispose of a recovery workspace after testing.
- **Multithreaded Damage Assessment:**
  - Select your workspace and baseline snapshot.
  - Click **`Execute Damage Assessment`** to identify intact, modified, missing, and unreadable files.
- **Two-Stage Authenticated Restoration Wizard:**
  - Enter the private key passphrase in the masked password field.
  - Select **`Overwrite Modified`** (remediates attack damage) and **`Authorize Live Restoration`**.
  - Click **`Preview Restoration Actions`** to dry-run the recovery plan without altering files.
  - Click **`Commit Authenticated Restoration`** to decrypt objects to temporary staging, verify AES-GCM tags and SHA-256 hashes, quarantine modified evidence, and atomically commit restored files.

---

### Tab 6: Data Exfiltration Monitoring & DLP Center
*Prevent confidential data theft using active pre-transmission policy gates.*
- **Mock Loopback Receiver (127.0.0.1):**
  - Click **`Start Mock Receiver`** to bind a safe local loopback socket.
  - Displays bound port and live received bytes/payload metrics.
- **DLP Security Posture Selector:**
  - Switch postures: `DEFAULT`, `STRICT`, `AUDIT_ONLY`, or `PERMISSIVE`.
  - Click **`Apply Profile`** to dynamically update policy enforcement.
- **Priority Rule Matrix:**
  - Lists rules ordered by priority: Canary honeypot blocks, restricted data gates, confidential approval thresholds.
- **Quarantined Approval Queue:**
  - Displays pending `APR-*` authorization requests.
  - Select any transfer and click **`Approve Selected Transfer`** or **`Reject Selected Transfer`**.
- **Audit Stream:** Tail of real-time policy decisions from `runtime/dlp/audit.log`.

---

### Tab 7: Forensic Incident Reports & Chain of Custody
*Post-incident audit dossiers, attack timelines, and cryptographic verification seals.*
- **Forensic Reports Catalog:**
  - Lists all generated reports (`REP-*`) with incident IDs, timestamps, and SHA-256 seals.
  - Enter an Incident ID (`INC-*`) and click **`Compile Report`** to aggregate and export across 4 formats (`JSON`, `Markdown`, `CSV`, `HTML`).
  - Click **`Cryptographically Verify Seal`** to audit the dossier’s SHA-256 tamper seal.
- **Tabbed Dossier Inspector:**
  - **Academic KPIs:** Detection Latency, Containment Duration, Recovery Duration, Protection Rate, Zero-Byte Exfiltration Leakage (PASS/FAIL), and Hash Match Rate.
  - **Chronological Attack Timeline:** Multi-subsystem event sequence across monitoring, detection, containment, DLP, and recovery.
  - **Executive Summary:** Formatted technical Markdown summary.
  - **Raw JSON Dossier:** Full machine-readable audit record.

---

### Tab 8: Defensive Simulation Testbed (Interactive Scenarios)
*One-click execution of controlled attack and defense demonstrations.*
1. **Ransomware Containment Demo:** Controlled simulator process launch, rapid file writes, canary honeypot breach, `LabWriteGate` emergency lock, and cooperative process termination.
2. **Data Exfiltration Demo:** Multi-department read burst, staging folder compression (`.zip`), and mock loopback transmission.
3. **DLP Multi-Tier Enforcement Demo:** Evaluates all four policy outcomes (`PUBLIC` allow, `INTERNAL` alert, `CONFIDENTIAL` approval, `RESTRICTED` zero-byte block).
4. **Full Double-Extortion Forensic Demo:** Complete 7-stage attack and defense flow: discovery $\rightarrow$ canary breach $\rightarrow$ write containment $\rightarrow$ zero-byte DLP gate $\rightarrow$ cryptographic recovery $\rightarrow$ sealed forensic report.
5. **Cryptographic Recovery Demo:** Damage simulation, two-stage recovery, and SHA-256 baseline verification.

---

## 5. Recommended Demonstration Script for Faculty / Presentations

Follow this 3-minute sequence for an end-to-end demonstration:

1. **Start on Tab 1 (Dashboard):** Show the normal operational baseline. All badges are Green (`GATE: UNLOCKED`, `THREAT: 0 NORMAL`, `LAB: VALID`).
2. **Switch to Tab 8 (Simulation Testbed):** Click **`4. Full Double-Extortion Forensic Demo`**.
   - Watch the live execution terminal log each phase in real-time.
   - Watch the 4 KPI cards populate: `1 CONTAINED`, `0 BYTES [PASS]`, `Files RESTORED`, and execution time.
3. **Switch to Tab 1 (Dashboard):** Show that the incident was detected, the threat gauge spiked to CRITICAL, and `LabWriteGate` was locked.
4. **Switch to Tab 6 (Exfiltration & DLP):** Point out the zero-byte leakage verification and DLP rule interception.
5. **Switch to Tab 7 (Forensic Reports):**
   - Click **`Refresh Catalog`** and select the newest `REP-*` report.
   - Click **`Cryptographically Verify Seal`** to demonstrate that the SHA-256 seal is `[PASS] VALID`.
   - Show the **Academic KPIs** and the **Chronological Attack Timeline**.
6. **Switch to Tab 2 (Lab):** Click **`Execute Integrity Audit`** to prove that the laboratory baseline files are **100% intact** (0 modified, 0 missing).
