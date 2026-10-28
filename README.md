# SecureDB

Automated database backup, encryption, integrity monitoring and verified disaster recovery.**

SecureDB is a web-based system that backs up PostgreSQL databases on a schedule, encrypts every backup, detects tampering, and restores only after the backup has passed verification.


# Features

- **Automated backups**: `pg_dump` streaming with APScheduler cron schedules and retention policies.
- **Envelope encryption**: a random 256-bit key per backup, wrapped by a master key, with AES-256-GCM streaming in 4 MB chunks.
- **Tamper detection**: HMAC-SHA256 over the ciphertext, plus per-chunk GCM tags bound to chunk order and a final-chunk flag. This catches bit flips, reordering and truncation.
- **Verified restore**: restores are refused if verification fails, require password re-authentication, and only go into a new database (never over the original).
- **Hash-chained audit log**: every entry links to the previous one with SHA-256, and a chain check finds the exact altered row.
- **RBAC and alerts**: `admin`, `manager` and `viewer` roles checked against the database on every request, plus alerts for failed logins and excessive restores.



## Architecture

Target DB -> pg_dump -> Envelope Encryption -> AES-256-GCM chunks -> HMAC-SHA256 -> .secdb archive
                                                                                        |
                              Verify (L1-L4) -> Anomaly alerts + audit chain -> Verified restore (new DB)

**Verification levels**

| Level | Check |
| :--- | :--- |
| L1 | Backup file exists |
| L2 | HMAC-SHA256 matches |
| L3 | Every AES-GCM tag authenticates |
| L4 | Deep check: test restore into a temporary database, verify tables, drop it |


# Security Design

| Threat | Mitigation |

| Master key exposure | Per-backup random key, RFC 3394 key wrap, HKDF-SHA256 subkeys for separate purposes |
| Ciphertext modification | HMAC-SHA256 (constant-time compare) + AES-256-GCM tags |
| Chunk reordering / splicing | Chunk counter and final flag bound into GCM AAD |
| Truncation | Final-chunk flag; missing final chunk raises `TruncatedBackupError` |
| Stored DB credentials | AES-GCM encrypted at rest, never logged or returned by the API |
| Brute force / user enumeration | Argon2id hashing, identical login error message, lockout after 5 failures in 15 minutes |
| Privilege escalation | Role read fresh from the database on every request; denials raise security alerts |
| Audit log forgery | SHA-256 hash chain starting from a 64-zero genesis hash |
| Production overwrite | Restore blocked if target name equals the original; password re-entry required |
| Command injection | Argument lists only, no `shell=True`; credentials passed via `PGPASSWORD` |



# Tech Stack

- **Backend:** Python 3.12+, FastAPI, SQLAlchemy 2.0, APScheduler
- **Frontend:** React (Vite), Recharts
- **Database:** PostgreSQL (SQLite fallback for local demos)
- **Security:** `cryptography`, `argon2-cffi`, PyJWT
- **Tools:** `pg_dump`, `pg_restore`, `psql`, Docker Compose


# Getting Started

# Option 1: Docker Compose


cp .env.example .env
# edit .env and set SECUREDB_MASTER_KEY and JWT_SECRET_KEY (see below)
docker-compose up --build -d


- Web UI: http://localhost:8000
- API docs: http://localhost:8000/docs

Services: the SecureDB app (8000), the app's PostgreSQL database (5432), and a sample `collegedb` target to back up (5433).

> The database passwords in `docker-compose.yml` are **demo values only**. Change them for any real deployment.

# Option 2: Local run (SQLite, no PostgreSQL needed)


python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload


Frontend, in a second terminal:

cd frontend
npm install
npm run dev


Open http://localhost:5173 (proxies `/api` to the backend).

### Configuration

Copy `.env.example` to `.env` and generate your own secrets:

python -c "import secrets; print(secrets.token_hex(32))"


Use one value for `SECUREDB_MASTER_KEY` (must be 64 hex characters) and another for `JWT_SECRET_KEY`. **Never commit `.env`.**



## Running Tests
python -m pytest -v


Tests cover:

- **Crypto:** key wrap, credential encryption, empty and multi-chunk files, bit-flip, truncation and reorder detection
- **Auth and RBAC:** first user becomes admin, enumeration defense, lockout, per-request role checks
- **Backup and restore:** verification levels, tamper detection, overwrite protection, password confirmation
- **Audit and alerts:** hash chain validity, tamper location, alert rules
- **Schedules and retention:** cron scheduling, secure deletion of old backups

On Windows you can run `RUN_TESTS_AND_VIVA_DEMO.bat` to run the tests and the demo together.


# Tamper Demo

python scripts/demo_tamper.py


The script encrypts a sample dump, passes Levels 1-3, flips a single bit in the ciphertext, and shows the HMAC check failing. It then shows GCM tag verification and truncation detection also failing.

# Using the Dashboard

1. **Register:** the first user becomes `admin`, later users become `viewer`.
2. **Databases:** register a target and use *Test Connection*.
3. **Backups:** click *Run Backup Now* to create an encrypted backup.
4. **Verify:** *Verify* runs Levels 1-3, and *Deep* runs Level 4.
5. **Restore:** pick a safe backup, enter a **new** database name, and confirm your password.
6. **Audit Logs:** use *Verify Chain Integrity* to check the whole log.

# Future Work

- WAL archiving (pgBackRest / WAL-G) for point-in-time recovery
- HSM and cloud KMS integration (AWS KMS, GCP KMS, HashiCorp Vault)
- Immutable multi-region storage (S3 Object Lock)
- Automated disaster-recovery drills with RTO/RPO reports

## License

MIT License.
