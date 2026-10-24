# SecureDB: Complete Project Architecture & Engineering Guide
**CSE Final Year / Capstone Cybersecurity Project Reference Manual**

---

## 1. Project Purpose: What Problem Does SecureDB Solve?

Traditional database backup systems (like running automated `cron` jobs with raw `pg_dump` or `mysqldump`) suffer from critical security vulnerabilities:
1. **Plaintext Exposure at Rest**: Backups are stored unencrypted on disks, NFS shares, or cloud buckets. If an attacker gains access to the storage volume, all student, customer, or financial data is exposed.
2. **Undetected Tampering (Ransomware / Bit Flips / Insider Threats)**: A malicious actor can silently modify backups (e.g., altering bank balances, tampering with university grades, or inserting backdoors) without anyone noticing until disaster strikes. Plain checksums (like MD5 or SHA1) fail because an attacker who can modify the file can also modify the plaintext hash.
3. **Disaster Recovery Blindness**: Organizations frequently believe they are protected because backup files exist, only to find during an outage that the backups were corrupted, truncated, or unrecoverable.
4. **Accidental Production Overwrite**: Restore scripts often fail to prevent accidental restoration over the live production database, resulting in catastrophic data loss.

### The Four Fundamental Questions SecureDB Answers:
| # | Question | Engineering & Cryptographic Answer |
|---|---|---|
| 1 | **Is my database backed up?** | Automated APScheduler cron engine + database-stored schedules + automated retention policies that prune older backups while keeping the latest $N$ archives. |
| **2** | **Is the backup secure?** | **Envelope Encryption** (random 256-bit DEK per backup) + **AES-256-GCM streaming** in 4 MB chunks. The plaintext dump resides exclusively in a private temporary directory and is zeroized before deletion. Target DB passwords are encrypted at rest with AES-GCM. |
| **3** | **Has anyone modified it?** | **HMAC-SHA256** checksum calculated over the ciphertext stream with constant-time verification. Nonces use an 8-byte random prefix + 4-byte counter. Chunk counters, final-chunk flags, and header hashes are bound into **AAD**, so bit flips, chunk reordering, and file truncation are immediately caught. |
| **4** | **Can I recover if something goes wrong?** | **Verified Disaster Recovery**: The system refuses to restore if integrity verification fails. Enforces user password re-authentication and restores strictly into a **new, isolated database name** (never overwriting production). |

---

## 2. Project Directory Map: Where Everything Is Located

The complete project is located at:
`C:\Users\DELL\OneDrive\Desktop\SecureDB`

```text
SecureDB/
├── START_SECUREDB.bat             # ⚡ One-click double-click launcher for Windows
├── RUN_TESTS_AND_VIVA_DEMO.bat    # 🧪 One-click testing & cryptographic viva demo
├── app/                           # Backend Application Package
│   ├── api/                       # REST API Endpoints
│   │   ├── deps.py                # JWT verification & role lookup fresh from DB
│   │   ├── routes_auth.py         # Register, Login (Argon2id, Lockout), Logout
│   │   ├── routes_databases.py    # Target DB registration & TCP socket test
│   │   ├── routes_backups.py      # Backup creation, 4-level verify, restore, delete
│   │   ├── routes_schedules.py    # APScheduler cron configuration & retention
│   │   ├── routes_logs.py         # Audit logs & GET /logs/verify-chain
│   │   ├── routes_alerts.py       # Anomaly alerts (Open/Resolved)
│   │   └── routes_dashboard.py    # KPI statistics & Recharts feeds
│   ├── core/                      # Cryptographic & Security Core
│   │   ├── crypto.py              # Envelope DEK wrap, HKDF subkeys, 4MB AES-GCM, HMAC
│   │   ├── password.py            # Argon2id password hashing & PBKDF2 fallback
│   │   ├── security.py            # JWT token creation & validation
│   │   ├── rbac.py                # Deny-by-default role permission matrix
│   │   ├── audit.py               # Forward blockchain-style hash chaining
│   │   └── alerts.py              # Anomaly detection rules & alert dispatcher
│   ├── models/                    # SQLAlchemy 2.0 ORM Models
│   │   ├── user.py                # User credentials & lockout timestamps
│   │   ├── target_db.py           # Target DB connection strings & encrypted passwords
│   │   ├── backup.py              # Backup records, HMAC digests, integrity statuses
│   │   ├── schedule.py            # Cron expressions & retention limits
│   │   ├── audit_log.py           # Chained logs (prev_hash, entry_hash)
│   │   └── alert.py               # Security alerts & severity levels
│   ├── schemas/                   # Pydantic Schemas with strict regex validation
│   ├── services/                  # Business Logic & Workflows
│   │   ├── backup_service.py      # pg_dump runner & retention pruning
│   │   ├── verify_service.py      # 4-level integrity verification engine
│   │   ├── restore_service.py     # Verified disaster recovery into isolated DB
│   │   └── scheduler_service.py   # APScheduler cron background jobs
│   ├── config.py                  # Environment settings, keys, and directories
│   ├── database.py                # SQLAlchemy engine & SQLite/Postgres connection
│   └── main.py                    # FastAPI app, CORS, lifespan, SPA static mount
├── frontend/                      # React (Vite) + Recharts Dark Theme Dashboard
│   ├── src/
│   │   ├── components/            # UI Components (Charts, Tables, Modals, Banners)
│   │   ├── context/               # AuthContext (JWT management & current user)
│   │   ├── api.js                 # Centralized API fetch layer
│   │   ├── App.jsx                # Main dashboard layout with 15s auto-refresh
│   │   └── index.css              # Dark theme CSS stylesheet
│   └── dist/                      # Pre-compiled production React distribution
├── tests/                         # Pytest Suite (24/24 passing unit & integration tests)
├── scripts/
│   ├── demo_tamper.py             # Standalone 1-bit flip viva demo (no Postgres needed)
│   ├── live_demo.py               # Live HTTP pipeline demonstration script
│   └── seed_collegedb.sql         # Sample CollegeDB schema & student records
├── storage/                       # Storage for encrypted .secdb backup files
├── docker-compose.yml             # Docker stack (App + System Postgres + CollegeDB)
├── Dockerfile                     # Multi-stage production container build
├── requirements.txt               # Backend Python dependencies
└── .env.example                   # Environment configuration example
```

---

## 3. How It Works: The 7-Stage End-to-End Pipeline

### Stage 1: Triggering the Backup (Manual or Scheduled)
- Triggered manually via `POST /api/backups/create` or automatically by **APScheduler** according to the cron schedule stored in the database.
- Target database credentials are retrieved from the database, and the password is decrypted in-memory using the HKDF-derived `db_credentials_key`.

### Stage 2: Database Dump Execution
- A subprocess runs `pg_dump` with custom binary format (`-Fc`) using argument lists only (`shell=True` is prohibited).
- The password is passed exclusively through the `PGPASSWORD` environment variable (never exposed on the CLI).
- Output is written to a private temporary directory (`storage/temp/dump_<uuid>.tmp`).

### Stage 3: Envelope Encryption (DEK Generation & Key Wrap)
- SecureDB generates a cryptographically secure random 256-bit (32-byte) **Data Encryption Key (DEK)** using `os.urandom(32)`.
- The DEK is wrapped using the **Key Encryption Key (KEK)** derived from `SECUREDB_MASTER_KEY` via RFC 3394 AES Key Wrap.
- An 8-byte random nonce prefix is generated.
- The 62-byte file header is assembled:
  `MAGIC (8B: b"SECDB01\x00") + Wrapped_DEK_Len (2B) + Wrapped_DEK (40B) + Nonce_Prefix (8B) + Chunk_Size (4B)`

### Stage 4: AES-256-GCM Streaming with AAD Binding
- The plaintext dump is read in 4 MB chunks.
- For each chunk $i$ ($i = 0, 1, 2, \dots$):
  - **Nonce** = `8-byte nonce prefix + 4-byte big-endian counter` (12 bytes total).
  - Lookahead determines if this is the final chunk (`is_final = 1` or `0`).
  - **AAD (Authenticated Additional Data)** binds:
    `b"SECDB_CHUNK:" + counter (4B) + is_final (1B) + SHA256(header)`
  - AES-256-GCM encrypts the chunk, producing ciphertext and a 16-byte authentication tag.
  - Disk framing: `counter (4B) + is_final (1B) + ciphertext_len (4B) + ciphertext + tag (16B)`.

### Stage 5: HMAC-SHA256 Integrity Sealing
- As the ciphertext stream is written to disk, an **HMAC-SHA256** checksum is updated over every byte written.
- The HMAC key is derived from the master key via HKDF (`info=b"backup-hmac"`).
- The final HMAC digest is saved in the database record.
- The temporary plaintext dump file is zeroized with zeros and deleted.

### Stage 6: Retention Policy Enforcement
- SecureDB checks how many completed backups exist for this target database.
- If the count exceeds the configured retention limit $N$ (e.g., keep last 5), older backups are deleted from disk, and their database records are marked as `PRUNED`.

### Stage 7: Verified Disaster Recovery (Restore)
- When a restore is requested via `POST /api/backups/{id}/restore`:
  1. The target database name must **not** match the original database name (overwriting production is blocked).
  2. The user must re-enter their login password to authorize the recovery.
  3. The system executes integrity checks (Levels 1, 2, 3). If any check fails, **restore is refused**.
  4. The encrypted backup is decrypted into a temporary file.
  5. `createdb` creates the new database, and `pg_restore` populates it.
  6. The temporary decrypted file is purged.

---

## 4. Cryptographic Deep-Dive

### A. Envelope Encryption: Why DEK + KEK?
If a single master key directly encrypted every backup file:
- **Key Wear-out**: Encrypting terabytes of data under one AES key increases cryptographic exhaustion risks.
- **Key Rotation**: Changing the master key would require decrypting and re-encrypting gigabytes or terabytes of existing backups.
- **SecureDB's Approach**: Each backup gets its own fresh 256-bit DEK. The master key only encrypts the 32-byte DEK. Rotating the master key only requires re-wrapping the 40-byte wrapped DEK headers!

### B. HKDF Subkey Separation (RFC 5869)
SecureDB uses HMAC-based Key Derivation Function (HKDF) with SHA-256 to derive isolated keys from the single `SECUREDB_MASTER_KEY`:
$$K_{\text{wrap}} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{salt}, K_{\text{master}}), \text{"key-wrap"}, 32)$$
$$K_{\text{hmac}} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{salt}, K_{\text{master}}), \text{"backup-hmac"}, 32)$$
$$K_{\text{creds}} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{salt}, K_{\text{master}}), \text{"db-credentials"}, 32)$$
**Cryptographic Guarantee**: Even if an adversary compromises a target database password or finds an HMAC collision, they gain zero mathematical advantage toward decrypting backup archives or unwrapping DEKs.

### C. AAD Sequence Binding: Defeating Reordering and Truncation
In naive chunked encryption, an attacker could swap Chunk 2 and Chunk 1, or drop the last chunk. Because each chunk is valid AES, standard decryption might succeed on individual blocks while corrupting the database.
SecureDB solves this by binding the sequence counter into the **Authenticated Additional Data (AAD)**:
$$\text{AAD}_i = \text{"SECDB\_CHUNK:"} \mathbin{\Vert} i \mathbin{\Vert} \text{is\_final} \mathbin{\Vert} H(\text{header})$$
- If an attacker swaps Chunk 0 and Chunk 1: Chunk 1's AAD expects $i=1$, but the parser checks counter 0. The AES-GCM Poly1305/GHASH tag check **fails immediately**.
- If an attacker truncates the last chunk: The parser hits EOF without having seen $\text{is\_final} = 1$, and throws `TruncatedBackupError`.

### D. HMAC-SHA256 vs Plain Hashing
Plain hashes (MD5, SHA-256) are **unkeyed**. If an adversary modifies a backup file, they can compute a new SHA-256 hash.
SecureDB uses **HMAC-SHA256**, which requires the secret derived key $K_{\text{hmac}}$. An attacker without the master key cannot forge a valid HMAC.
Furthermore, comparisons use `hmac.compare_digest` (constant-time comparison), eliminating side-channel timing attacks.

### E. Argon2id Password Hashing & Enumeration Defense
- **Argon2id**: Memory-hard password hashing algorithm (winner of the Password Hashing Competition), resistant to GPU/ASIC brute-force attacks.
- **Account Lockout**: 5 failed login attempts lock the account for 15 minutes.
- **User Enumeration Defense**: The server returns the exact same message (`"Invalid username or password"`) and identical HTTP 401 status for both non-existent usernames and incorrect passwords.

### F. Blockchain-Style Hash-Chained Audit Trail
Every security event (login, backup, verification, restore, denial) is recorded in an immutable hash chain:
$$\text{entry\_hash}_i = \text{SHA-256}(\text{prev\_hash}_{i} \mathbin{\Vert} \text{timestamp} \mathbin{\Vert} \text{username} \mathbin{\Vert} \text{action} \mathbin{\Vert} \text{resource} \mathbin{\Vert} \text{status} \mathbin{\Vert} \text{details})$$
- Genesis entry: $\text{prev\_hash}_0 = \text{"0"}^{64}$.
- Any subsequent entry: $\text{prev\_hash}_i = \text{entry\_hash}_{i-1}$.
- `GET /api/logs/verify-chain`: Recalculates the hash chain from row 0 to $N$. If any attacker alters a historical record in SQLite/PostgreSQL, the chain breaks and the endpoint identifies the exact record ID that was tampered with!

---

## 5. The 4 Verification Levels Explained

When an operator clicks **Verify** or **Deep** in the dashboard, the system evaluates:

```
[Level 1] Physical File Check (Exists & Size > 0)
   └── PASS ──> [Level 2] HMAC-SHA256 Constant-Time Comparison
                   └── PASS ──> [Level 3] Full AES-256-GCM Stream Decryption & Tag Check
                                   └── PASS ──> [Level 4] Deep Restore into verify_tmp_<id>
```

1. **Level 1 (Storage Presence)**: Checks that the encrypted `.secdb` file physically exists on the disk and has a non-zero byte size.
2. **Level 2 (HMAC Seal)**: Reads the entire ciphertext stream, computes HMAC-SHA256 using $K_{\text{hmac}}$, and verifies that it matches the stored seal. If this fails, the file has been modified or corrupted $\rightarrow$ status: **`TAMPERED`** (raises CRITICAL alert).
3. **Level 3 (Cryptographic Tag & AAD Sequence)**: Unwraps the DEK, streams through all chunks, and verifies every AES-256-GCM authentication tag and chunk counter. Ensures no bits were flipped and no chunks were swapped or truncated $\rightarrow$ status: **`SAFE`**.
4. **Level 4 (Deep Recovery Drill - Optional `?deep=true`)**: Creates a temporary scratch database (`verify_tmp_<id>`), executes `pg_restore` into it, queries the schema to verify table counts, and drops the temporary database. This proves that the backup is not just mathematically valid, but structurally recoverable.

---

## 6. Role-Based Access Control (RBAC)

SecureDB enforces a strict **deny-by-default** permission matrix:

| Action / Permission | Admin | Manager | Viewer |
|---|:---:|:---:|:---:|
| View Dashboard & Statistics | ✅ | ✅ | ✅ |
| View Backups & Integrity Status | ✅ | ✅ | ✅ |
| View Target Databases | ✅ | ✅ | ✅ |
| View Schedules | ✅ | ✅ | ✅ |
| View & Verify Audit Hash Chain | ✅ | ✅ | ✅ |
| View Security Alerts | ✅ | ✅ | ✅ |
| Run On-Demand Backup | ✅ | ✅ | ❌ |
| Run Integrity Verification (L1-L4) | ✅ | ✅ | ❌ |
| Execute Database Restore | ✅ | ✅ | ❌ |
| Resolve Security Alerts | ✅ | ✅ | ❌ |
| Register Target Database | ✅ | ❌ | ❌ |
| Delete Target Database | ✅ | ❌ | ❌ |
| Create / Delete Cron Schedules | ✅ | ❌ | ❌ |
| Delete Backup Archives | ✅ | ❌ | ❌ |

### Key Security Feature: Role Read Fresh from Database
In many web applications, the user's role is stored in the JWT token payload. If an admin demotes a compromised manager to a viewer, the manager can continue performing privileged actions until their token expires.
**In SecureDB**: The JWT only proves username identity (`sub`). The FastAPI dependency `get_current_user` queries the database on **every single request** to retrieve the user's real-time role. A role change takes effect immediately without waiting for token expiration.
Every denial writes an `RBAC_DENIED` entry to the audit log and raises a **HIGH severity security alert**.

---

## 7. Automated Anomaly Detection Engine

SecureDB continuously monitors operations against 5 anomaly detection rules:

1. **Excessive Failed Logins (`excessive_failed_logins`)**:
   - Rule: $>5$ failed login attempts for a user within 5 minutes.
   - Severity: **HIGH**.
   - Action: Account locked for 15 minutes, security alert raised on dashboard banner.
2. **Unauthorized Access Attempt (`rbac_denial`)**:
   - Rule: Any user attempts an API endpoint without holding the required permission.
   - Severity: **HIGH**.
   - Action: Request blocked with HTTP 403, incident recorded in hash-chained audit log, alert raised.
3. **Backup Integrity Failure (`backup_tampered`)**:
   - Rule: An HMAC checksum mismatch or AES-GCM tag verification failure occurs during verification.
   - Severity: **CRITICAL**.
   - Action: Backup marked `TAMPERED`, restore is blocked, critical alert banner appears on dashboard.
4. **Excessive Restore Attempts (`excessive_restores`)**:
   - Rule: $>3$ database restore attempts initiated within 10 minutes.
   - Severity: **HIGH**.
   - Action: Alerts administrators to potential unauthorized data extraction or recovery floods.
5. **Scheduled Backup Failure (`backup_failed`)**:
   - Rule: An automated cron job or manual dump process fails (e.g., target DB unreachable).
   - Severity: **HIGH**.
   - Action: Alert raised immediately so administrators can intervene before data loss occurs.

---

## 8. Technology Stack Rationale

| Component | Technology | Rationale |
|---|---|---|
| **Backend Framework** | **FastAPI / Starlette** | High-performance asynchronous Python web framework with clean dependency injection, OpenAPI documentation, and robust middleware support. |
| **Database ORM** | **SQLAlchemy 2.0** | Modern declarative ORM providing clean migration paths between SQLite (for zero-dependency local demos) and PostgreSQL (for production/Docker). |
| **Task Scheduling** | **APScheduler** | In-process background scheduler supporting standard crontab expressions, persistence, and startup job recovery without needing external brokers like Celery/Redis. |
| **Password Hashing** | **Argon2id (`argon2-cffi`)** | Winner of the Password Hashing Competition; state-of-the-art memory-hard algorithm resistant to GPU cracking. |
| **Cryptography** | **OpenSSL 3 EVP / Cryptography** | Industrial-grade cryptographic primitives executing hardware-accelerated AES-NI instructions for AES-256-GCM and HKDF. |
| **Frontend Framework** | **React (Vite)** | Lightning-fast reactive component model with modular component hierarchy and Vite proxy configuration. |
| **Data Visualization** | **Recharts** | Declarative SVG charting library providing responsive Area charts (backup size over time), Pie charts (integrity distribution), and Bar charts (7-day login telemetry). |
| **Theme / Styling** | **Plain CSS Dark Theme** | Zero external CSS framework dependencies (no Tailwind/Bootstrap build bloat); clean cyber-defense aesthetic using CSS custom properties. |

---

## 9. Typical Viva & Project Defense Questions & Answers

### Q1: Why use AES-256-GCM instead of AES-CBC?
**Answer**: AES-CBC only provides **confidentiality** (encryption), not authenticity. An attacker can perform bit-flipping attacks on CBC ciphertext (padding oracle attacks) without detection unless an HMAC is manually added. AES-GCM is an **Authenticated Encryption with Associated Data (AEAD)** cipher that generates a 128-bit authentication tag, guaranteeing confidentiality, integrity, and authenticity in a single cryptographic operation.

### Q2: What is the purpose of envelope encryption?
**Answer**: Envelope encryption separates data encryption from key management. Each backup file is encrypted with a unique, randomly generated 256-bit Data Encryption Key (DEK). The master key only encrypts the 32-byte DEK. This prevents master key exhaustion, limits the blast radius if a single DEK is compromised, and makes key rotation fast (only the 40-byte wrapped key header needs re-wrapping, not the whole backup file).

### Q3: Why is HMAC-SHA256 used instead of a standard SHA-256 hash?
**Answer**: Standard SHA-256 is an unkeyed hash. If an attacker modifies the backup file on disk, they can easily recalculate the standard SHA-256 hash and update the record. HMAC-SHA256 requires a secret key derived from the master key via HKDF. Without the master key, an attacker cannot forge a valid HMAC tag.

### Q4: How does SecureDB detect if an attacker swaps chunks or truncates the file?
**Answer**: In SecureDB, chunk nonces are built using an 8-byte prefix and a 4-byte counter. Crucially, the chunk counter $i$, the `is_final` flag, and the header hash are bound into the **Authenticated Additional Data (AAD)** of the AES-GCM cipher. If chunks are reordered, the counter in the AAD will not match what the decryptor expects, and the GCM authentication tag verification will fail. If the file is truncated, the decryptor reaches EOF without encountering the chunk with `is_final = 1`, raising a `TruncatedBackupError`.

### Q5: Why is restoring over the original database name blocked?
**Answer**: Accidental production overwrites are one of the leading causes of disaster recovery catastrophes. SecureDB enforces strict database isolation: restores must go into a newly named database (e.g., `collegedb_restored_2026`). Furthermore, the operator must re-enter their password to authorize the restore, preventing unauthorized recovery by someone who stepped away from their computer.

### Q6: How does the hash-chained audit log work?
**Answer**: Each audit log record contains the SHA-256 hash of the previous record concatenated with its own canonical fields. This creates a forward hash chain starting from a 64-zero genesis hash. If an insider connects to the SQLite or PostgreSQL database and modifies or deletes an old row, the cryptographic chain is broken. The `GET /api/logs/verify-chain` endpoint traverses the chain and identifies the exact row ID where the link broke.
