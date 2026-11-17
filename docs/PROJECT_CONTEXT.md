# CryptoShield — Project Context & Foundational Charter

## 1. Official Project Identity
- **Full Title:** CryptoShield: An Intelligent Ransomware Detection, Containment, Data Exfiltration Prevention and Cryptographic Recovery Framework
- **Category:** Academic Proof-of-Concept Defensive Cybersecurity Framework
- **Institution / Context:** University-level defensive cybersecurity research
- **Primary Repository:** `C:\NFSU\AC\CryptoShield`
- **Environment:** Windows AMD64 | Python 3.12.4 | pytest 9.2.0 | OpenSSL 4.0.3 Backend

---

## 2. Executive Purpose & Defensive Paradigm
Modern ransomware operations operate under a **double-extortion** model:
1. **Integrity & Availability Violation:** Mass encryption, tampering, or deletion of enterprise files to deny operational access.
2. **Confidentiality Violation:** Mass file discovery, staging of sensitive corporate intellectual property, and unauthorized exfiltration to external infrastructure.

CryptoShield is an educational, defensive security proof-of-concept designed to model, detect, contain, and remediate double-extortion ransomware attacks in a strictly controlled laboratory environment. 

### Historical Evolution & Out-of-Scope Boundaries
- The project originally started as an attacker-focused ransomware simulation involving AES/RSA encryption, attacker/victim interfaces, and a virtual ransom payment mechanism.
- Following academic faculty guidance, the project underwent a complete **defensive pivot**.
- **Permanently Out of Scope:** Attacker payment portals, virtual ransom negotiations, persistence mechanisms, evasion techniques, lateral movement, real malware binaries, and actual external data theft.
- **Educational Boundary:** CryptoShield is a bounded university prototype demonstrating measurable defensive controls and cryptographic verification. It is not an enterprise EDR (Endpoint Detection and Response) product or OS-level kernel driver.

---

## 3. Synthetic Enterprise Dataset Engine (Phase 1 Baseline)
To eliminate reliance on ad-hoc test files and enable reproducible benchmarking, CryptoShield incorporates an in-memory streaming dataset synthesizer.

### Departmental Taxonomy (9 Departments)
- `Finance` (invoices, accounts ledger, payroll reports)
- `Human Resources` (employee registries, benefits, performance reviews)
- `Legal` (contracts, nondisclosure agreements, regulatory filings)
- `Sales` (pipeline trackers, customer quotes, regional forecasts)
- `Customers` (account metadata, service records, SLA agreements)
- `Operations` (inventory manifests, supply chain logs, facility metrics)
- `Research` (patent filings, experimental blueprints, research whitepapers)
- `IT` (network topologies, master configuration files, access policies)
- `Public Documents` (press releases, public statements, published whitepapers)

### Supported File Formats (7 Formats)
- `.txt` (executive directives, operational notes)
- `.csv` (financial tables, payroll matrices)
- `.json` (structured configurations, account records)
- `.xml` (enterprise data exchange, purchase orders)
- `.md` (architectural specifications, technical docs)
- `.html` (departmental bulletins, internal newsletters)
- `.log` (service audit logs, system event trails)

### Data Classification Tiers
1. `PUBLIC`: Low-risk, publicly disclosable information.
2. `INTERNAL`: General internal business communication.
3. `CONFIDENTIAL`: Sensitive business operations, contracts, and internal financials.
4. `RESTRICTED`: High-value intellectual property, executive compensation, and master credentials.

### High-Value Deception Canaries (Honeypots)
- Deceptive enterprise files intentionally placed across departments (e.g., `IT/network_configs/passwords_master_backup.json`, `Human Resources/payroll/executive_salaries_2026.csv`).
- They contain fictional high-value tokens but do not disclose their honeypot nature in their pathnames.
- Registered in `baseline_manifest.json` with `is_canary=True` and a unique `canary_id`.
- Any access (read, modify, delete, rename) generates an immediate high-priority alert and drives threat scoring.

---

## 4. The 10-Phase Lifecycle Roadmap

- [x] **Phase 1: Foundation & Enterprise Dataset Engine**
  - Modular structure, safety engine, lab lifecycle, deterministic dataset generation (1k, 10k, 20k), SHA-256 baseline manifest.
- [x] **Phase 2: File Activity Monitoring & Telemetry**
  - Filesystem monitoring (Watchdog), process monitoring (psutil), controlled active access monitoring (`AccessMonitor`), event normalization, thread-safe `EventBus`.
- [x] **Phase 3: Behavioral Detection & Threat Scoring**
  - Heuristic behavior analyzer, sliding window correlation, canary trip analyzer, multi-department burst detection, threat scorer (0–100), incident manager (`INC-*.json`).
- [x] **Phase 4: Threat Containment**
  - Containment policy engine, controlled process registry (start-time validated), application-level `LabWriteGate`, non-destructive process controller, verification harness.
- [x] **Phase 5: Cryptographic Backup Vault**
  - AES-256-GCM object encryption, RSA-3072 key encapsulation (OAEP with SHA-256), Argon2id-AES256GCM private key envelope (V2), `.cso` authenticated container format, tamper-evident encrypted snapshot manifests.
- [x] **Phase 6: Cryptographic Recovery & File Restoration Engine**
  - Marker-authenticated isolated recovery workspaces (`runtime/recovery/workspaces/`), multi-threaded damage assessment, two-stage authenticated restoration (AES-GCM tag + SHA-256 verification before atomic commit), evidence quarantine for modified files.
- [x] **Phase 7: Data Exfiltration Monitoring**
  - Suspicious read-burst detection, staging directory aggregation detection, mock loopback socket transfer monitoring, incident dossier correlation.
- [x] **Phase 8: Data Loss Prevention (DLP) Engine**
  - Classification-aware transfer policy evaluation (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`), rule-based decisions (`ALLOW`, `BLOCK`, `ALERT`, `REQUIRE_APPROVAL`), controlled transfer interception.
- [ ] **Phase 9: Forensic Incident Reporting**
  - Forensic dossier aggregation, chain-of-custody verification logs, chronological attack timelines, multi-format export (JSON, Markdown, CSV).
- [ ] **Phase 10: PySide6 Desktop GUI & Final System Integration**
  - Interactive desktop operator console, real-time telemetry visualizer, interactive containment and recovery controls, live exfiltration/DLP graphs, and end-to-end multi-tier demonstration scenarios.
