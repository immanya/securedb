import os
import pytest
from app.models.backup import Backup
from app.models.schedule import BackupSchedule
from app.services.backup_service import dump_and_encrypt_database, apply_retention_policy
from app.core.security import create_access_token

def test_schedule_crud(client, sample_users, sample_target_db):
    """Admin can create and list automated cron backup schedules."""
    admin = sample_users["admin"]
    token = create_access_token({"sub": admin.username})
    headers = {"Authorization": f"Bearer {token}"}
    
    # Create schedule
    res = client.post(
        "/api/schedules",
        headers=headers,
        json={
            "target_db_id": sample_target_db.id,
            "cron_expression": "0 3 * * *",
            "retention_count": 3
        }
    )
    assert res.status_code == 201
    sched_data = res.json()
    assert sched_data["cron_expression"] == "0 3 * * *"
    assert sched_data["retention_count"] == 3
    
    # List schedules
    list_res = client.get("/api/schedules", headers=headers)
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1
    
    # Delete schedule
    del_res = client.delete(f"/api/schedules/{sched_data['id']}", headers=headers)
    assert del_res.status_code == 200

def test_retention_policy_enforcement(db_session, sample_target_db):
    """Retention policy keeps the last N backups, securely pruning older backups."""
    # Set schedule retention count = 3
    sched = BackupSchedule(
        target_db_id=sample_target_db.id,
        target_db_name=sample_target_db.name,
        cron_expression="0 2 * * *",
        retention_count=3,
        is_active=True
    )
    db_session.add(sched)
    db_session.commit()
    
    # Generate 5 backups
    created_backups = []
    for i in range(5):
        b = dump_and_encrypt_database(db=db_session, target=sample_target_db, username="test_retention")
        created_backups.append(b)
        
    # Check that exactly 3 are COMPLETED and the 2 oldest are PRUNED
    completed = db_session.query(Backup).filter(
        Backup.target_db_id == sample_target_db.id,
        Backup.status == "COMPLETED"
    ).all()
    assert len(completed) == 3
    
    pruned = db_session.query(Backup).filter(
        Backup.target_db_id == sample_target_db.id,
        Backup.status == "PRUNED"
    ).all()
    assert len(pruned) == 2
    
    # Verify that the physical files of the pruned backups were removed
    for p in pruned:
        assert not os.path.exists(p.file_path)
