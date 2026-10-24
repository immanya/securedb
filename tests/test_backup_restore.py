import os
import pytest
from app.models.backup import Backup
from app.models.alert import SecurityAlert
from app.core.security import create_access_token

def test_backup_create_and_verify(client, db_session, sample_users, sample_target_db):
    """Create backup, verify untampered passes all levels as SAFE."""
    admin = sample_users["admin"]
    token = create_access_token({"sub": admin.username})
    headers = {"Authorization": f"Bearer {token}"}
    
    # Create backup
    create_res = client.post("/api/backups/create", headers=headers, json={"target_db_id": sample_target_db.id})
    assert create_res.status_code == 201
    backup_data = create_res.json()
    backup_id = backup_data["id"]
    
    # Run verification (Level 1 - 3)
    verify_res = client.post(f"/api/backups/{backup_id}/verify", headers=headers)
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["status"] == "SAFE"
    assert v_data["level1_exists"] is True
    assert v_data["level2_hmac_valid"] is True
    assert v_data["level3_decrypt_valid"] is True

def test_tampered_backup_verification_and_alert(client, db_session, sample_users, sample_target_db):
    """Tampering a backup file causes verification to return TAMPERED and raises CRITICAL alert."""
    admin = sample_users["admin"]
    token = create_access_token({"sub": admin.username})
    headers = {"Authorization": f"Bearer {token}"}
    
    # Create backup
    create_res = client.post("/api/backups/create", headers=headers, json={"target_db_id": sample_target_db.id})
    backup_id = create_res.json()["id"]
    
    # Locate encrypted file and tamper 1 byte
    backup_rec = db_session.query(Backup).filter(Backup.id == backup_id).first()
    file_bytes = bytearray(open(backup_rec.file_path, "rb").read())
    file_bytes[70] ^= 0x01
    with open(backup_rec.file_path, "wb") as f:
        f.write(file_bytes)
        
    # Verify tampered backup
    verify_res = client.post(f"/api/backups/{backup_id}/verify", headers=headers)
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["status"] == "TAMPERED"
    assert v_data["level2_hmac_valid"] is False
    
    # Check that CRITICAL security alert was raised
    alert = db_session.query(SecurityAlert).filter(
        SecurityAlert.alert_type == "backup_tampered",
        SecurityAlert.severity == "CRITICAL"
    ).first()
    assert alert is not None
    assert f"#{backup_id}" in alert.message

def test_restore_prohibits_original_database_overwrite(client, sample_users, sample_target_db):
    """Restore strictly rejects target name matching original database."""
    admin = sample_users["admin"]
    token = create_access_token({"sub": admin.username})
    headers = {"Authorization": f"Bearer {token}"}
    
    create_res = client.post("/api/backups/create", headers=headers, json={"target_db_id": sample_target_db.id})
    backup_id = create_res.json()["id"]
    
    # Attempt restoring into sample_target_db.database_name ('collegedb')
    res = client.post(
        f"/api/backups/{backup_id}/restore",
        headers=headers,
        json={
            "target_database_name": sample_target_db.database_name,
            "confirm_password": "AdminPass123!"
        }
    )
    assert res.status_code == 400
    assert "overwriting the original database" in res.json()["detail"].lower()

def test_restore_requires_password_confirmation(client, sample_users, sample_target_db):
    """Restore requires re-entering current user's password."""
    admin = sample_users["admin"]
    token = create_access_token({"sub": admin.username})
    headers = {"Authorization": f"Bearer {token}"}
    
    create_res = client.post("/api/backups/create", headers=headers, json={"target_db_id": sample_target_db.id})
    backup_id = create_res.json()["id"]
    
    # Wrong confirmation password
    res = client.post(
        f"/api/backups/{backup_id}/restore",
        headers=headers,
        json={
            "target_database_name": "collegedb_restored_2026",
            "confirm_password": "IncorrectPassword!"
        }
    )
    assert res.status_code == 400
    assert "invalid confirmation password" in res.json()["detail"].lower()

def test_restore_refuses_tampered_backup(client, db_session, sample_users, sample_target_db):
    """Restore refuses to execute if backup fails cryptographic integrity."""
    admin = sample_users["admin"]
    token = create_access_token({"sub": admin.username})
    headers = {"Authorization": f"Bearer {token}"}
    
    create_res = client.post("/api/backups/create", headers=headers, json={"target_db_id": sample_target_db.id})
    backup_id = create_res.json()["id"]
    
    # Tamper file
    backup_rec = db_session.query(Backup).filter(Backup.id == backup_id).first()
    data = bytearray(open(backup_rec.file_path, "rb").read())
    data[75] ^= 0x01
    with open(backup_rec.file_path, "wb") as f:
        f.write(data)
        
    res = client.post(
        f"/api/backups/{backup_id}/restore",
        headers=headers,
        json={
            "target_database_name": "collegedb_restored_test",
            "confirm_password": "AdminPass123!"
        }
    )
    assert res.status_code == 400
    assert "refusing restore" in res.json()["detail"].lower()
