import os
from typing import List, Optional
from app.compat import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.backup import Backup
from app.models.target_db import TargetDatabase
from app.models.user import User
from app.schemas.all_schemas import (
    BackupCreate,
    BackupResponse,
    VerifyResponse,
    RestoreRequest,
    RestoreResponse
)
from app.services.backup_service import dump_and_encrypt_database
from app.services.verify_service import verify_backup
from app.services.restore_service import perform_restore
from app.core.audit import append_audit_log
from app.api.deps import require_perm

router = APIRouter(prefix="/backups", tags=["Backups"])

@router.get("", response_model=List[BackupResponse])
def list_backups(
    current_user: User = Depends(require_perm("backups:view")),
    db: Session = Depends(get_db)
):
    """List all backups sorted by newest first."""
    return db.query(Backup).order_by(Backup.created_at.desc()).all()


@router.get("/{id}", response_model=BackupResponse)
def get_backup(
    id: int,
    current_user: User = Depends(require_perm("backups:view")),
    db: Session = Depends(get_db)
):
    """Get single backup details."""
    backup = db.query(Backup).filter(Backup.id == id).first()
    if not backup:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Backup not found")
    return backup


@router.post("/create", response_model=BackupResponse, status_code=status.HTTP_201_CREATED)
def create_backup(
    req: BackupCreate,
    current_user: User = Depends(require_perm("backups:create")),
    db: Session = Depends(get_db)
):
    """
    Trigger immediate full backup and envelope stream encryption.
    Plaintext dump is isolated to a temporary directory and purged afterwards.
    """
    target = db.query(TargetDatabase).filter(TargetDatabase.id == req.target_db_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target database not found")
        
    try:
        backup = dump_and_encrypt_database(db=db, target=target, username=current_user.username)
        return backup
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Backup failed: {str(e)}")


@router.post("/{id}/verify", response_model=VerifyResponse)
def verify_backup_endpoint(
    id: int,
    deep: bool = Query(False, description="Perform optional deep restore test into verify_tmp_<id>"),
    current_user: User = Depends(require_perm("backups:verify")),
    db: Session = Depends(get_db)
):
    """
    Run 4-level integrity verification:
    1. File existence
    2. HMAC-SHA256 constant-time comparison
    3. AES-256-GCM authentication tags and AAD sequence checks
    4. Optional deep restore test into temporary database
    Returns status: SAFE / TAMPERED / FAILED.
    """
    backup = db.query(Backup).filter(Backup.id == id).first()
    if not backup:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Backup not found")
        
    res = verify_backup(db=db, backup_id=id, deep=deep, username=current_user.username)
    return {
        "backup_id": id,
        "status": res["status"],
        "level1_exists": res["level1_exists"],
        "level2_hmac_valid": res["level2_hmac_valid"],
        "level3_decrypt_valid": res["level3_decrypt_valid"],
        "level4_deep_restore_valid": res.get("level4_deep_restore_valid"),
        "details": res
    }


@router.post("/{id}/restore", response_model=RestoreResponse)
def restore_backup_endpoint(
    id: int,
    req: RestoreRequest,
    current_user: User = Depends(require_perm("backups:restore")),
    db: Session = Depends(get_db)
):
    """
    Restore an encrypted backup into a NEW database name:
    - Never overwrites the original database
    - Requires confirming the current user's password
    - Refuses restore if integrity verification fails
    - Rate limits repeated restores (>3 in 10 minutes raises alert)
    """
    try:
        res = perform_restore(
            db=db,
            backup_id=id,
            target_database_name=req.target_database_name,
            confirm_password=req.confirm_password,
            current_user=current_user
        )
        return res
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Restore operation failed: {str(e)}")


@router.delete("/{id}")
def delete_backup(
    id: int,
    current_user: User = Depends(require_perm("backups:delete")),
    db: Session = Depends(get_db)
):
    """Delete an encrypted backup file and its record (Admin only)."""
    backup = db.query(Backup).filter(Backup.id == id).first()
    if not backup:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Backup not found")
        
    # Remove file from disk
    if os.path.exists(backup.file_path):
        try:
            os.remove(backup.file_path)
        except Exception:
            pass
            
    db.delete(backup)
    db.commit()
    
    append_audit_log(
        db=db,
        username=current_user.username,
        action="BACKUP_DELETED",
        resource=f"backup:{id}",
        status="SUCCESS",
        user_id=current_user.id
    )
    
    return {"message": f"Backup #{id} deleted successfully"}
