from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from app.compat import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.backup import Backup
from app.models.alert import SecurityAlert
from app.models.target_db import TargetDatabase
from app.models.schedule import BackupSchedule
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.all_schemas import DashboardStats, DashboardCharts
from app.api.deps import require_perm

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/statistics", response_model=DashboardStats)
def get_dashboard_statistics(
    current_user: User = Depends(require_perm("dashboard:view")),
    db: Session = Depends(get_db)
):
    """Retrieve top-level system security and backup KPI statistics."""
    total_backups = db.query(Backup).count()
    safe_backups = db.query(Backup).filter(Backup.integrity_status == "SAFE").count()
    tampered_backups = db.query(Backup).filter(Backup.integrity_status == "TAMPERED").count()
    failed_backups = db.query(Backup).filter(
        (Backup.status == "FAILED") | (Backup.integrity_status == "FAILED")
    ).count()
    open_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == "OPEN").count()
    total_dbs = db.query(TargetDatabase).filter(TargetDatabase.is_active == True).count()
    active_scheds = db.query(BackupSchedule).filter(BackupSchedule.is_active == True).count()
    
    return {
        "total_backups": total_backups,
        "safe_backups": safe_backups,
        "tampered_backups": tampered_backups,
        "failed_backups": failed_backups,
        "open_alerts": open_alerts,
        "total_databases": total_dbs,
        "active_schedules": active_scheds
    }


@router.get("/charts", response_model=DashboardCharts)
def get_dashboard_charts(
    current_user: User = Depends(require_perm("dashboard:view")),
    db: Session = Depends(get_db)
):
    """Retrieve chart metrics: backup sizes over time, status breakdown, and 7-day login metrics."""
    # 1. Backup size over time (last 15 backups)
    backups = db.query(Backup).order_by(Backup.created_at.asc()).limit(15).all()
    size_history = []
    for b in backups:
        # Convert bytes to MB or KB
        size_kb = round(b.file_size_bytes / 1024.0, 2)
        created_str = b.created_at.strftime("%b %d %H:%M") if b.created_at else "Unknown"
        size_history.append({
            "id": b.id,
            "target": b.target_db_name,
            "date": created_str,
            "size_kb": size_kb,
            "status": b.integrity_status
        })
        
    # 2. Status distribution
    safe_cnt = db.query(Backup).filter(Backup.integrity_status == "SAFE").count()
    tampered_cnt = db.query(Backup).filter(Backup.integrity_status == "TAMPERED").count()
    failed_cnt = db.query(Backup).filter(
        (Backup.status == "FAILED") | (Backup.integrity_status == "FAILED")
    ).count()
    unverified_cnt = db.query(Backup).filter(Backup.integrity_status == "UNVERIFIED").count()
    
    status_distribution = [
        {"name": "Safe", "value": safe_cnt, "color": "#10b981"},
        {"name": "Tampered", "value": tampered_cnt, "color": "#ef4444"},
        {"name": "Failed", "value": failed_cnt, "color": "#f59e0b"},
        {"name": "Unverified", "value": unverified_cnt, "color": "#6366f1"}
    ]
    
    # 3. Login attempts for the last 7 days
    now = datetime.now(timezone.utc)
    login_metrics = []
    
    for i in range(6, -1, -1):
        day_date = (now - timedelta(days=i)).date()
        day_start = datetime(day_date.year, day_date.month, day_date.day, 0, 0, 0, tzinfo=timezone.utc)
        day_end = datetime(day_date.year, day_date.month, day_date.day, 23, 59, 59, tzinfo=timezone.utc)
        
        successes = db.query(AuditLog).filter(
            AuditLog.action == "LOGIN_SUCCESS",
            AuditLog.timestamp >= day_start,
            AuditLog.timestamp <= day_end
        ).count()
        
        failures = db.query(AuditLog).filter(
            AuditLog.action.in_(["LOGIN_FAILED", "LOGIN_BLOCKED_LOCKOUT"]),
            AuditLog.timestamp >= day_start,
            AuditLog.timestamp <= day_end
        ).count()
        
        login_metrics.append({
            "day": day_date.strftime("%a %d"),
            "success": successes,
            "failed": failures
        })
        
    return {
        "backup_size_history": size_history,
        "status_distribution": status_distribution,
        "login_attempts_7days": login_metrics
    }
