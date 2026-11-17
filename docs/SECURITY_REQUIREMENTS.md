# CryptoShield — Security Requirements & Invariants

## 1. Permanent Defensive Invariants

Every subsystem, simulator, test, and CLI workflow in CryptoShield must strictly adhere to the following ten security invariants:

1. **Strictly Authenticated Laboratory Boundaries:**  
   All file operations, modifications, simulations, and tests must remain confined within authenticated CryptoShield laboratory workspaces (`runtime/lab/`) or registered recovery workspaces (`runtime/recovery/workspaces/`). Never scan, modify, encrypt, delete, or restore arbitrary host or personal directories.
2. **Defensive Research Only — No Real Ransomware:**  
   Never implement real ransomware capabilities, persistence mechanisms, evasion tactics, anti-analysis loops, lateral movement, disabling of security tools, or unauthorized external data theft. Simulated malicious activity must remain harmless, synthetically bounded, and contained.
3. **Controlled Process Containment Only:**  
   Containment actions (process termination, write gating) may only ever be applied to explicitly registered, CryptoShield-controlled test simulator processes. Killing arbitrary system or host processes by PID or process name is strictly prohibited.
4. **Uninferred Process Attribution:**  
   Unknown process attribution must remain `UNKNOWN`. Process attribution may only be marked `CONFIRMED` or `INFERRED` when verified by controlled instrumentation or trusted subprocess handles. Causation must never be inferred purely from concurrent filesystem events.
5. **Canary File Integration:**  
   Canary files (deceptive honeypots) are permanent core detection capabilities. Canary generation, cataloging, monitoring, alerting, and restoration must remain integrated across all applicable subsystems. Canary support must never be bypassed or removed.
6. **Immutable Reference Baseline & Snapshot Preservation:**  
   The reference 20,000-file baseline in `runtime/lab/` must never be altered, damaged, or deleted during demonstration runs. Existing valid snapshots in `runtime/vault/` must never be overwritten, casually deleted, or migrated without explicit authorization.
7. **No Unauthenticated Plaintext Commits:**  
   AES-GCM streaming decryption produces plaintext incrementally before the final authentication tag is verified. Plaintext must remain strictly segregated in temporary staging directories and must never be committed to the target workspace until authentication succeeds.
8. **Dual-Gate Verification on File Restoration:**  
   Before any restored file is committed to a workspace, it must pass dual validation:
   - Successful verification of the 128-bit AES-GCM authentication tag.
   - Successful match of the SHA-256 hash against the authenticated snapshot manifest.
9. **Zero Secret Logging:**  
   Private keys, passphrases, AES session keys, and sensitive plaintext contents must never be logged to console, plain text log files, JSONL audit trails, or incident dossiers. Structured logs must record only safe metadata (key IDs, fingerprints, algorithms, and hashes).
10. **Irreversible Operations Require Authorization:**  
    Destructive operations on keys, snapshots, baselines, or active security boundaries require explicit user authorization and a rollback/backup plan.

---

## 2. Cryptographic Specifications

### 2.1 Private Key Protection (Envelope Version 2)
- **Algorithm:** RSA-3072, public exponent 65537 (`cryptography.hazmat.primitives.asymmetric.rsa`).
- **Key Wrapping KDF:** Argon2id (`cryptography.hazmat.primitives.kdf.argon2.Argon2id`).
  - Memory Cost: 65,536 KiB (64 MiB)
  - Iterations: 3
  - Parallelism (Lanes): 4
  - Salt: 32 cryptographically secure random bytes (`os.urandom(32)`)
  - Output Key Material: 64 bytes (split into 32-byte AES key and 32-byte HMAC integrity key).
- **Envelope Cipher:** AES-256-GCM with a 96-bit random nonce and 128-bit tag.

### 2.2 Object Storage Container (`.cso`)
- **Format:** Binary container consisting of a 34-byte fixed header:
  - Offset `0..3`: 4-byte Magic (`CSO1`)
  - Offset `4..5`: 2-byte Version (`0x0001`)
  - Offset `6..17`: 12-byte GCM Nonce
  - Offset `18..33`: 16-byte GCM Authentication Tag
  - Offset `34..EOF`: Ciphertext (AES-256-GCM)
- **Streaming Chunks:** 1 MiB chunk size for memory-bounded processing.
- **Canonical AAD Binding:** Binds `snapshot_id`, `format_version`, `object_id`, `original_relative_path`, `sha256_hash`, `file_size_bytes`, `data_classification`, `department`, and `is_canary`.

### 2.3 Key Encapsulation (Session Key)
- **Session Cipher:** AES-256 (32 random bytes).
- **Key Wrap:** RSA-OAEP with SHA-256 digest, MGF1 padding with SHA-256, and a snapshot-specific OAEP label.
