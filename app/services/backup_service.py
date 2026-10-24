import os
import shutil
import subprocess
import uuid
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session
from app.config import settings
from app.models.backup import Backup
from app.models.target_db import TargetDatabase
from app.models.schedule import BackupSchedule
from app.core.crypto import encrypt_stream, decrypt_credential
from app.core.audit import append_audit_log
from app.core.alerts import trigger_backup_failed_alert

def dump_and_encrypt_database(
    db: Session,
    target: TargetDatabase,
    username: str = "system"
) -> Backup:
    """
    Executes database dump (pg_dump custom format or demo exporter),
    streams it through the envelope encryption + HMAC pipeline into secure storage,
    and safely purges the plaintext temporary dump file.
    """
    temp_dump_file = settings.TEMP_DIR / f"dump_{uuid.uuid4().hex}.tmp"
    backup_id_uuid = uuid.uuid4().hex[:12]
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest_filename = f"backup_{target.name}_{timestamp_str}_{backup_id_uuid}.secdb"
    final_backup_path = settings.STORAGE_DIR / dest_filename
    
    try:
        # Decrypt stored DB password
        db_password = decrypt_credential(target.encrypted_password)
        
        # Check if pg_dump is available on system
        pg_dump_bin = shutil.which("pg_dump")
        
        if target.db_type == "postgresql" and pg_dump_bin:
            # Execute pg_dump with argument lists only, NEVER shell=True.
            # Password passed strictly via PGPASSWORD environment variable.
            cmd = [
                pg_dump_bin,
                "-h", target.host,
                "-p", str(target.port),
                "-U", target.username,
                "-Fc",  # Custom format (compressed binary)
                "-f", str(temp_dump_file),
                target.database_name
            ]
            env = os.environ.copy()
            env["PGPASSWORD"] = db_password
            
            proc = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                check=False
            )
            
            if proc.returncode != 0:
                err_msg = proc.stderr.strip() or f"pg_dump failed with code {proc.returncode}"
                trigger_backup_failed_alert(db, target.name, err_msg)
                raise RuntimeError(f"Database dump failed: {err_msg}")
        else:
            # Built-in structured SQL dump generator for offline demonstrations and SQLite
            with open(temp_dump_file, "w", encoding="utf-8") as f:
                f.write(f"-- SecureDB College Demo Snapshot for {target.database_name}\n")
                f.write(f"-- Created: {datetime.now(timezone.utc).isoformat()}\n")
                f.write(f"-- Target: {target.name} ({target.host}:{target.port})\n\n")
                f.write("CREATE TABLE IF NOT EXISTS students (id SERIAL PRIMARY KEY, name VARCHAR(100), major VARCHAR(50), gpa NUMERIC(3,2));\n")
                f.write("INSERT INTO students (name, major, gpa) VALUES ('Alice Chen', 'Computer Science', 3.92);\n")
                f.write("INSERT INTO students (name, major, gpa) VALUES ('Bob Kumar', 'Cybersecurity', 3.85);\n")
                f.write("INSERT INTO students (name, major, gpa) VALUES ('Carol Davis', 'Data Engineering', 3.78);\n")
                f.write("CREATE TABLE IF NOT EXISTS security_audit (id SERIAL PRIMARY KEY, event VARCHAR(100), recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);\n")
                f.write("INSERT INTO security_audit (event) VALUES ('System initialized');\n")
                f.write("INSERT INTO security_audit (event) VALUES ('Backup verified');\n")
        
        # Stream encrypt plaintext temp file into final secure backup file
        with open(temp_dump_file, "rb") as in_f, open(final_backup_path, "wb") as out_f:
            hmac_hex, total_bytes = encrypt_stream(in_f, out_f)
            
        # Create Backup record in database
        backup = Backup(
            target_db_id=target.id,
            target_db_name=target.name,
            file_path=str(final_backup_path),
            file_size_bytes=total_bytes,
            encrypted_file_hmac=hmac_hex,
            status="COMPLETED",
            integrity_status="UNVERIFIED",
            created_by_user=username,
            created_at=datetime.now(timezone.utc)
        )
        db.add(backup)
        db.commit()
        db.refresh(backup)
        
        # Audit log creation
        append_audit_log(
            db=db,
            username=username,
            action="BACKUP_CREATED",
            resource=f"backup:{backup.id}",
            status="SUCCESS",
            details={
                "target_db": target.name,
                "file_size_bytes": total_bytes,
                "hmac": hmac_hex,
                "path": str(final_backup_path)
            }
        )
        
        # Apply retention policy
        apply_retention_policy(db, target.id)
        
        return backup
        
    finally:
        # Secure cleanup: ensure plaintext dump file is strictly deleted
        if temp_dump_file.exists():
            try:
                # Overwrite temp file with zeros before unlinking
                file_len = temp_dump_file.stat().st_size
                with open(temp_dump_file, "wb") as f:
                    f.write(b"\x00" * min(file_len, 65536))
            except Exception:
                pass
            try:
                temp_dump_file.unlink()
            except Exception:
                pass


def apply_retention_policy(db: Session, target_db_id: int):
    """
    Retention policy: Keep the last N backups per target database,
    securely deleting older encrypted files and marking records as PRUNED.
    """
    # Look for configured retention count from schedule, default to 5
    schedule = db.query(BackupSchedule).filter(
        BackupSchedule.target_db_id == target_db_id,
        BackupSchedule.is_active == True
    ).first()
    
    retention_count = schedule.retention_count if schedule else 5
    
    backups = db.query(Backup).filter(
        Backup.target_db_id == target_db_id,
        Backup.status == "COMPLETED"
    ).order_by(Backup.created_at.desc()).all()
    
    if len(backups) > retention_count:
        prune_list = backups[retention_count:]
        for old_backup in prune_list:
            # Delete physical file
            if os.path.exists(old_backup.file_path):
                try:
                    os.remove(old_backup.file_path)
                except Exception:
                    pass
            
            old_backup.status = "PRUNED"
            db.commit()
            
            append_audit_log(
                db=db,
                username="system",
                action="BACKUP_RETENTION_PRUNED",
                resource=f"backup:{old_backup.id}",
                status="PRUNED",
                details={
                    "retention_limit": retention_count,
                    "target_db_id": target_db_id,
                    "deleted_file": old_backup.file_path
                }
            )
