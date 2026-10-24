# SecureDB: Automated Database Backup & Cryptographic Security Management System

**SecureDB** is a web-based automated database backup, encryption, integrity monitoring, and verified disaster recovery system engineered as a CSE college capstone / final-year cybersecurity project.

---

## 🎯 Project Mission & Core Questions

SecureDB answers four mission-critical database security questions:

| Question | SecureDB Cryptographic & Architectural Solution |
| :--- | :--- |
| **1. Is my database backed up?** | Automated APScheduler cron engine + pg_dump streaming with configurable retention policies and real-time backup metrics. |
| **2. Is the backup secure?** | Multi-tier **Envelope Encryption** (random 256-bit DEK per backup wrapped by master key) + **AES-256-GCM** 4 MB chunk streaming. Dump files reside exclusively in secure temporary RAM/storage and are zeroized before deletion. |
| **3. Has anyone modified it?** | **HMAC-SHA256** checksum calculated over the ciphertext stream with constant-time comparison. Additional chunk sequence counter and final-chunk flag bound into **AAD** so chunk reordering, truncation, and 1-bit flips are immediately caught. |
| **4. Can I recover if something goes wrong?** | **Verified Restore Pipeline**: Refuses restore if integrity verification fails. Enforces user password re-authentication and restores strictly into a **new, isolated database name** (never overwriting production). |

---

## 🏗️ System Architecture & Cryptographic Pipeline

```
┌─────────────────┐       ┌─────────────────┐       ┌────────────────────────┐
│ Target Database │ ────> │  pg_dump (-Fc)  │ ────> │ Envelope Encryption    │
│  (e.g CollegeDB)│       │ Private Temp Dir│       │ DEK: 256-bit Random    │
└─────────────────┘       └─────────────────┘       └───────────┬────────────┘
                                                                │
                                                                ▼
┌─────────────────┐       ┌─────────────────┐       ┌────────────────────────┐
│ Secure Storage  │ <──── │ HMAC-SHA256     │ <──── │ AES-256-GCM Streaming │
│ (.secdb Archive)│       │ Derived Subkey  │       │ 4 MB Chunks + AAD Bind │
└────────┬────────┘       └─────────────────┘       └────────────────────────┘
         │
         ▼
┌─────────────────┐       ┌─────────────────┐       ┌────────────────────────┐
│ 4-Level Verify  │ ────> │ Anomaly Engine  │ ────> │ Disaster Recovery      │
│ L1 -> L2 -> L3  │       │ Chained Logs    │       │ New DB Isolation       │
│ L4 (Deep Temp)  │       │ Alerts Raised   │       │ Password Re-auth       │
└─────────────────┘       └─────────────────┘       └────────────────────────┘
```

---

## 🔐 Security Design & Cryptographic Specification

| Threat Vector / Requirement | Cryptographic / Engineering Mitigation | Implementation Detail |
| :--- | :--- | :--- |
| **Master Key Compromise** | Envelope Encryption & HKDF Subkey Isolation | Random 256-bit Data Encryption Key (DEK) generated per backup (`os.urandom(32)`). Wrapped with RFC 3394 AES Key Wrap. Master key (`SECUREDB_MASTER_KEY`) derives distinct subkeys using HKDF-SHA256 (`info=b"key-wrap"`, `b"backup-hmac"`, `b"db-credentials"`). |
| **Ciphertext Modification & Bit Flips** | HMAC-SHA256 & AES-256-GCM Authenticated Encryption | HMAC-SHA256 computed over the ciphertext stream. Re-verified using constant-time comparison (`hmac.compare_digest`). AES-256-GCM 128-bit authentication tags verify each chunk. |
| **Chunk Reordering & Splicing** | Authenticated Additional Data (AAD) Sequence Binding | Each chunk nonce is `8B prefix + 4B big-endian counter`. AAD binds `b"SECDB_CHUNK:" + counter + is_final + header_hash`. Any swap or reordering fails GCM tag verification. |
| **Backup Truncation Attacks** | Strict Lookahead & Final-Chunk AAD Flag | The last chunk is flagged with `is_final = 1`. If an attacker truncates bytes or drops the last chunk, the decryptor halts with `TruncatedBackupError`. |
| **Credential Storage at Rest** | AES-256-GCM Encryption with HKDF Derived Key | Target database passwords are encrypted at rest with AES-GCM and base64-encoded. Never stored in plaintext, never logged, and never returned in API responses. |
| **Credential Brute-Force & Enumeration** | Argon2id Hashing & Account Lockout Defense | Argon2id memory-hard password hashing. Identical error response (`"Invalid username or password"`) for both unknown usernames and invalid passwords. 5 failed logins within 15 minutes trigger an automated account lockout. |
| **Privilege Escalation** | Role-Based Access Control (RBAC) Read Fresh from DB | Roles: `admin` (super-admin), `manager` (backup/restore/verify), `viewer` (read-only). Fast API dependency `require_perm("...")` checks role fresh from the database on every request (JWT token claims are not trusted for authorization). Denied requests raise HIGH severity security alerts. |
| **Audit Log Forgery & Repudiation** | Cryptographic Hash Chaining (Blockchain-Style) | Each log entry contains `prev_hash` and `entry_hash = SHA256(prev_hash + canonical_fields)`. Genesis entry begins with 64 zeros. `GET /api/logs/verify-chain` verifies continuity and reports the exact ID of any broken or altered row. |
| **Accidental Production Overwrite** | Forced Target Database Isolation & Password Confirm | Restore refuses to execute if target database name equals the original database name. Restores require re-entering the user's password. More than 3 restore attempts in 10 minutes trigger an `excessive_restores` alert. |
| **Command Injection in Subprocess** | Secure Subprocess Execution | All subprocess invocations use explicit argument lists (`["pg_dump", "-h", ...]`). `shell=True` is strictly forbidden. DB credentials are passed exclusively via `PGPASSWORD` environment variables. |

---

## 🛠️ Tech Stack

- **Backend**: Python 3.12+, FastAPI / Starlette, SQLAlchemy 2.0, APScheduler
- **App Database**: PostgreSQL (with automated SQLite fallback for local zero-dependency demos)
- **Frontend**: React (Vite) + Recharts, plain CSS dark theme, Vite proxy `/api` -> FastAPI
- **Security Primitives**: Argon2id (`argon2-cffi`), PyJWT, OpenSSL 3 EVP / `cryptography`
- **Database Tools**: PostgreSQL `pg_dump`, `pg_restore`, `psql`, `createdb`, `dropdb`
- **Containerization**: Docker Compose with app container, Postgres app DB, and sample `CollegeDB` target

---

## 🚀 Quickstart & Setup Guide

### Option 1: Docker Compose (Full Stack with PostgreSQL & CollegeDB)

Prerequisites: Docker & Docker Compose installed.

```bash
# 1. Clone or navigate to the project directory
cd securedb

# 2. Copy the sample environment file
cp .env.example .env

# 3. Build and launch all services
docker-compose up --build -d

# 4. Access the web dashboard:
# Web UI: http://localhost:8000
# Backend API Docs: http://localhost:8000/docs
```

Services started by Docker Compose:
- `securedb_app` (port 8000): FastAPI backend + compiled React frontend
- `securedb_postgres` (port 5432): SecureDB system database
- `securedb_collegedb` (port 5433): Pre-seeded sample CollegeDB instance to back up

---

### Option 2: Local Zero-Dependency Run (Localhost Demo)

SecureDB features an automated SQLite fallback and demo data generator, allowing full evaluation on any developer workstation without needing PostgreSQL installed!

#### 1. Backend Setup:
```bash
# In project root:
python -m pip install -r requirements.txt

# Start FastAPI server on port 8000:
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### 2. Frontend Setup (in a separate terminal):
```bash
cd frontend
npm install
npm run dev
# Vite dev server starts at http://localhost:5173 with proxy to http://localhost:8000
```

---

## 🧪 Running the Test Suite

SecureDB includes a comprehensive `pytest` test suite covering 100% of the cryptographic, authentication, RBAC, verification, and scheduler requirements.

```bash
# Run all tests with verbose output:
python -m pytest -v
```

### Test Coverage Summary:
- **`tests/test_crypto.py`**:
  - Key wrap roundtrip (RFC 3394 AES Key Wrap)
  - Credential encryption/decryption roundtrip
  - Empty file (0 bytes) roundtrip
  - Multi-chunk streaming roundtrip
  - 1-bit flipped byte detection (Level 2 HMAC and Level 3 GCM tag failure)
  - Truncation detection (missing final chunk)
  - Chunk reordering detection (swapped chunk counter AAD failure)
- **`tests/test_auth_rbac.py`**:
  - First registered user automatically becomes Admin; subsequent users become Viewers
  - Enumeration defense (identical error messages)
  - 5-failure account lockout window
  - Database-read role verification on every request
  - RBAC denial audit logging & security alert generation
- **`tests/test_backup_restore.py`**:
  - Full backup creation & Level 1-3 verification as SAFE
  - Tampered backup detection & CRITICAL alert generation
  - Prohibition of overwriting original database
  - Password confirmation requirement
  - Refusal to restore unverified or tampered backups
- **`tests/test_audit_alerts.py`**:
  - Hash chain validity from genesis to head
  - Detection of tampered audit log rows (identifies exact row ID)
  - Excessive failed logins alert rule (>5 in 5 minutes)
  - Excessive restore attempts alert rule (>3 in 10 minutes)
- **`tests/test_schedules_retention.py`**:
  - Schedule creation & APScheduler cron integration
  - Retention policy enforcement (keeps last N backups, securely erases older files)

---

## 🎓 Viva & Lab Demonstration Walkthrough

SecureDB is specifically organized for step-by-step examination and lab viva demonstrations:

### Step 1: Run the Standalone Tamper Demonstration Script
Execute the standalone demonstration script:
```bash
python scripts/demo_tamper.py
```
**What the examiner sees:**
1. Plaintext student records dump is generated.
2. File is envelope-encrypted using 4 MB AES-256-GCM chunks with AAD binding.
3. Untampered backup passes Level 1 (Existence), Level 2 (HMAC), and Level 3 (GCM Tags).
4. **The Attack Simulation**: The script flips exactly **ONE bit** in the ciphertext (`byte ^= 0x01`).
5. **Level 2 HMAC Check fails immediately**, catching the tampering at storage time.
6. The script demonstrates cryptographic defense-in-depth: even if an attacker bypasses the HMAC check, Level 3 AES-256-GCM tag verification throws `AuthenticationTagError` and halts decryption.
7. Demonstrates truncation detection when trailing chunks are omitted.

---

### Step 2: Web Dashboard Walkthrough

1. **User Registration & RBAC**:
   - Navigate to `http://localhost:5173` (or `http://localhost:8000`).
   - Register the first user `admin` (automatically granted `admin` role).
   - Register a second user `student_viewer` (granted `viewer` role).
   - Observe role pills in the navigation bar.

2. **Automated Anomaly Detection (Lockout)**:
   - Log out, and enter an incorrect password 5 consecutive times for an account.
   - On the 6th attempt, observe the HTTP 403 Account Lockout response and the corresponding `excessive_failed_logins` security alert banner.

3. **Target Database Management**:
   - Navigate to the **Databases** tab.
   - Click **+ Register Database**, enter connection details, and click **Test Connection** to test socket reachability.
   - Passwords are encrypted at rest with AES-GCM and never exposed.

4. **On-Demand Encrypted Backup**:
   - In the **Backups** tab, click **+ Run Backup Now**.
   - Watch the backup execute, stream-encrypt, compute HMAC-SHA256, and appear in the repository table.

5. **Integrity Verification (Levels 1 - 4)**:
   - Click **Verify** on a backup row: verifies file existence, HMAC match, and AES-GCM tag authentication.
   - Click **Deep**: runs Level 4 deep check by restoring into temporary database `verify_tmp_<id>`, verifying schema tables, and dropping it.

6. **Verified Disaster Recovery (Restore)**:
   - Click **Restore** on any safe backup.
   - Enter a new target database name (e.g., `collegedb_restored_2026`).
   - Try entering the original database name `collegedb` - observe the system strictly block the overwrite.
   - Confirm your password and submit: the backup is decrypted and restored.

7. **Cryptographic Hash-Chained Audit Trail**:
   - Navigate to the **Audit Chain Logs** tab.
   - Observe the chained SHA-256 forward links (`prev_hash` -> `entry_hash`).
   - Click **🔍 Verify Chain Integrity**: all records are recomputed and verified against genesis.

---

## 🔮 Future Work & Enterprise Enhancements

1. **Incremental Backups via WAL Archiving & pgBackRest**:
   - Current release focuses on complete, standalone full backups (`-Fc`) with cryptographic sealing.
   - Future expansion includes continuous Write-Ahead Log (WAL) archiving paired with `pgBackRest` or `WAL-G` for Point-In-Time Recovery (PITR) with delta chunk deduplication.

2. **Hardware Security Module (HSM) & Cloud KMS Integration**:
   - Integration with PKCS#11 hardware security modules (YubiHSM2, Nitrokey HSM) and cloud key managers (AWS KMS, GCP Cloud KMS, HashiCorp Vault) for envelope master key protection.

3. **Zero-Knowledge Encrypted Search**:
   - Integration of searchable encryption (SSE) or verifiable Bloom filters allowing queries over encrypted backup metadata without revealing schema contents.

4. **Multi-Region Geo-Replication with WORM Storage**:
   - Automated replication of encrypted `.secdb` archives across multiple geographic regions with AWS S3 Object Lock (Write Once, Read Many) to provide immutability against ransomware.

5. **Automated Chaos Engineering & Disaster Recovery Drills**:
   - Scheduled autonomous recovery drills that spin up ephemeral containerized environments, restore backups, execute synthetic SQL regression tests, and log automated RTO (Recovery Time Objective) and RPO (Recovery Point Objective) compliance scorecards.

---

## 📜 Academic Project Metadata

- **Project Title**: SecureDB - Web-Based Automated Database Backup and Security Management System
- **Domain**: Cryptography, Database Security & Full-Stack Web Development
- **Course**: Final Year B.Tech / B.E. Computer Science & Engineering Capstone Project
- **License**: MIT License
