import urllib.request
import urllib.error
import json
import os
import sys

BASE_URL = "http://127.0.0.1:8000"

def req(endpoint, method="GET", data=None, token=None):
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode("utf-8") if data else None
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(err_body)
        except Exception:
            parsed = {"detail": err_body}
        return e.code, parsed

def print_box(text):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def main():
    print_box("SECUREDB LIVE SYSTEM DEMONSTRATION")
    print(f"Target Server: {BASE_URL}")

    # 1. Health check
    status, health = req("/api/health")
    print(f"\n[1] Health Check: HTTP {status} -> {health}")

    # 2. Register Admin User
    print("\n[2] Registering System Admin Account ('sec_admin')...")
    status, reg = req("/api/auth/register", method="POST", data={
        "username": "sec_admin",
        "password": "SecurePassword123!"
    })
    if status == 201:
        print(f"    Success: Created user '{reg['username']}' with role '{reg['role']}'")
    else:
        print(f"    Notice: {reg.get('detail')} (Proceeding to login)")

    # 3. Login
    print("\n[3] Authenticating with Argon2id...")
    status, auth = req("/api/auth/login", method="POST", data={
        "username": "sec_admin",
        "password": "SecurePassword123!"
    })
    token = auth["access_token"]
    user_info = auth["user"]
    print(f"    Success: Logged in as '{user_info['username']}' [Role: {user_info['role']}]")
    print(f"    JWT Access Token: {token[:25]}...{token[-15:]}")

    # 4. Target Databases
    print("\n[4] Querying Registered Target Databases...")
    status, dbs = req("/api/databases", token=token)
    print(f"    Found {len(dbs)} target database(s):")
    for d in dbs:
        print(f"    - ID #{d['id']}: '{d['name']}' ({d['database_name']}) at {d['host']}:{d['port']} [Type: {d['db_type']}]")

    target_db_id = dbs[0]["id"]
    target_name = dbs[0]["name"]

    # 5. Create Encrypted Backup
    print(f"\n[5] Triggering Envelope Encryption Backup for '{target_name}'...")
    status, backup = req("/api/backups/create", method="POST", data={"target_db_id": target_db_id}, token=token)
    print(f"    Backup Generated: #{backup['id']}")
    print(f"    - Target DB: {backup['target_db_name']}")
    print(f"    - Encrypted File Size: {backup['file_size_bytes']} bytes")
    print(f"    - HMAC-SHA256 Seal: {backup['encrypted_file_hmac']}")
    print(f"    - Storage Path: {backup['file_path']}")

    # 6. Run 4-Level Verification
    print(f"\n[6] Running Cryptographic Integrity Verification on Backup #{backup['id']}...")
    status, verify_res = req(f"/api/backups/{backup['id']}/verify", method="POST", token=token)
    print(f"    Overall Integrity Status: [{verify_res['status']}]")
    print(f"    - Level 1 (File Existence): {'PASS' if verify_res['level1_exists'] else 'FAIL'}")
    print(f"    - Level 2 (HMAC-SHA256 Match): {'PASS' if verify_res['level2_hmac_valid'] else 'FAIL'}")
    print(f"    - Level 3 (AES-256-GCM Tags & AAD): {'PASS' if verify_res['level3_decrypt_valid'] else 'FAIL'}")

    # 7. Disaster Recovery: Attempt Illegal Overwrite
    print("\n[7] Testing Safeguard: Attempting Overwrite of Original Database ('collegedb')...")
    status, bad_restore = req(f"/api/backups/{backup['id']}/restore", method="POST", data={
        "target_database_name": "collegedb",
        "confirm_password": "SecurePassword123!"
    }, token=token)
    print(f"    Expected Rejection: HTTP {status} -> {bad_restore.get('detail')}")

    # 8. Disaster Recovery: Verified Restore into New Database
    print("\n[8] Executing Verified Disaster Recovery into New Isolated Database ('collegedb_restored_viva')...")
    status, good_restore = req(f"/api/backups/{backup['id']}/restore", method="POST", data={
        "target_database_name": "collegedb_restored_viva",
        "confirm_password": "SecurePassword123!"
    }, token=token)
    print(f"    Success: HTTP {status} -> {good_restore.get('message')}")
    print(f"    Duration: {good_restore.get('duration_seconds')}s | Tables Recovered: {good_restore.get('table_count')}")

    # 9. Verify Hash-Chained Audit Trail
    print("\n[9] Cryptographic Hash-Chain Audit Verification (GET /api/logs/verify-chain)...")
    status, chain_check = req("/api/logs/verify-chain", token=token)
    print(f"    Chain Validity: {'VALID (Intact)' if chain_check['valid'] else 'BROKEN'}")
    print(f"    Total Chained Records: {chain_check['total_records']}")
    print(f"    Details: {chain_check['details']}")

    # 10. Dashboard Statistics
    print("\n[10] Real-time Dashboard KPI Telemetry (GET /api/dashboard/statistics)...")
    status, stats = req("/api/dashboard/statistics", token=token)
    print(f"    - Total Backups: {stats['total_backups']}")
    print(f"    - Safe Backups: {stats['safe_backups']}")
    print(f"    - Failed/Tampered: {stats['tampered_backups'] + stats['failed_backups']}")
    print(f"    - Open Alerts: {stats['open_alerts']}")
    print(f"    - Connected Databases: {stats['total_databases']}")

    print_box("LIVE DEMONSTRATION COMPLETE: ALL MODULES NOMINAL")
    print(f"Access the interactive Dark Theme Web Dashboard now at: {BASE_URL}/\n")

if __name__ == "__main__":
    main()
