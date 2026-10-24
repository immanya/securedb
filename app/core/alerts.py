import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from app.models.alert import SecurityAlert
from app.models.audit_log import AuditLog
from app.config import settings

def create_security_alert(
    db: Session,
    alert_type: str,
    severity: str,
    message: str,
    details: Optional[Dict[str, Any]] = None
) -> SecurityAlert:
    """Create a security alert in the database."""
    now = datetime.now(timezone.utc)
    details_json = json.dumps(details or {}, sort_keys=True)
    
    alert = SecurityAlert(
        alert_type=alert_type,
        severity=severity.upper(),
        message=message,
        status="OPEN",
        details_json=details_json,
        created_at=now
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def check_failed_login_anomaly(db: Session, username: str) -> Optional[SecurityAlert]:
    """
    Check if failed logins exceed threshold (>5 in 5 minutes).
    If triggered, creates a HIGH severity security alert.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.FAILED_LOGIN_ALERT_WINDOW_SEC)
    count = db.query(AuditLog).filter(
        AuditLog.action == "LOGIN_FAILED",
        AuditLog.username == username,
        AuditLog.timestamp >= cutoff
    ).count()
    
    if count >= settings.FAILED_LOGIN_ALERT_THRESHOLD:
        msg = f"Security Alert: Excessive failed logins detected for user '{username}' ({count} failures within 5 minutes)."
        return create_security_alert(
            db,
            alert_type="excessive_failed_logins",
            severity="HIGH",
            message=msg,
            details={"username": username, "failed_count": count, "window_seconds": settings.FAILED_LOGIN_ALERT_WINDOW_SEC}
        )
    return None


def trigger_rbac_denial_alert(db: Session, username: str, resource: str, action: str) -> SecurityAlert:
    """Trigger HIGH severity alert on unauthorized access attempt."""
    msg = f"Security Alert: Unauthorized access attempt by '{username}' on '{resource}' for action '{action}'."
    return create_security_alert(
        db,
        alert_type="rbac_denial",
        severity="HIGH",
        message=msg,
        details={"username": username, "resource": resource, "attempted_action": action}
    )


def trigger_backup_tampered_alert(db: Session, backup_id: int, reason: str, details: Optional[Dict[str, Any]] = None) -> SecurityAlert:
    """Trigger CRITICAL severity alert on backup integrity failure / tampering detection."""
    msg = f"CRITICAL SECURITY ALERT: Tampering or integrity failure detected on backup #{backup_id}! Reason: {reason}"
    d = {"backup_id": backup_id, "reason": reason}
    if details:
        d.update(details)
    return create_security_alert(
        db,
        alert_type="backup_tampered",
        severity="CRITICAL",
        message=msg,
        details=d
    )


def check_excessive_restores_anomaly(db: Session, username: str) -> Optional[SecurityAlert]:
    """
    Check if restore attempts exceed threshold (>3 in 10 minutes).
    If triggered, creates a HIGH severity security alert.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.RESTORE_ALERT_WINDOW_SEC)
    count = db.query(AuditLog).filter(
        AuditLog.action == "RESTORE_ATTEMPT",
        AuditLog.timestamp >= cutoff
    ).count()
    
    if count >= settings.RESTORE_ALERT_THRESHOLD:
        msg = f"Security Alert: Excessive database restore attempts ({count} attempts in 10 minutes) triggered by '{username}'."
        return create_security_alert(
            db,
            alert_type="excessive_restores",
            severity="HIGH",
            message=msg,
            details={"username": username, "attempts": count, "window_seconds": settings.RESTORE_ALERT_WINDOW_SEC}
        )
    return None


def trigger_backup_failed_alert(db: Session, target_db_name: str, error_message: str) -> SecurityAlert:
    """Trigger HIGH severity alert when a scheduled or manual backup fails."""
    msg = f"Security Alert: Backup operation failed for database '{target_db_name}'. Error: {error_message}"
    return create_security_alert(
        db,
        alert_type="backup_failed",
        severity="HIGH",
        message=msg,
        details={"target_db_name": target_db_name, "error": error_message}
    )
