import pytest
from datetime import datetime, timezone, timedelta
from app.models.audit_log import AuditLog
from app.models.alert import SecurityAlert
from app.core.audit import append_audit_log, verify_audit_chain
from app.core.alerts import check_failed_login_anomaly, check_excessive_restores_anomaly

def test_audit_hash_chain_validity(db_session):
    """Appending multiple log entries produces a valid cryptographic hash chain."""
    entry1 = append_audit_log(db_session, username="alice", action="LOGIN", resource="auth", status="SUCCESS")
    entry2 = append_audit_log(db_session, username="alice", action="BACKUP", resource="backup:1", status="SUCCESS")
    entry3 = append_audit_log(db_session, username="bob", action="RESTORE", resource="backup:1", status="SUCCESS")
    
    # Verify links
    assert entry1.prev_hash == "0" * 64
    assert entry2.prev_hash == entry1.entry_hash
    assert entry3.prev_hash == entry2.entry_hash
    
    is_valid, broken_id, total, msg = verify_audit_chain(db_session)
    assert is_valid is True
    assert broken_id is None
    assert total >= 3

def test_tampered_audit_chain_detection(db_session):
    """Modifying any row in the audit log is detected by verify_audit_chain reporting the exact broken row ID."""
    entry1 = append_audit_log(db_session, username="alice", action="LOGIN", resource="auth", status="SUCCESS")
    entry2 = append_audit_log(db_session, username="alice", action="BACKUP", resource="backup:1", status="SUCCESS")
    entry3 = append_audit_log(db_session, username="bob", action="RESTORE", resource="backup:1", status="SUCCESS")
    
    # Adversary attempts to tamper entry2 (changing status from SUCCESS to FAILED)
    entry2.status = "TAMPERED_BY_ATTACKER"
    db_session.commit()
    
    is_valid, broken_id, total, msg = verify_audit_chain(db_session)
    assert is_valid is False
    assert broken_id == entry2.id
    assert "tampered entry" in msg.lower()

def test_excessive_failed_logins_alert_trigger(db_session):
    """Trigger alert when failed logins exceed 5 in 5 minutes."""
    username = "attacker_target"
    # Append 5 failed login audit logs
    for _ in range(5):
        append_audit_log(db_session, username=username, action="LOGIN_FAILED", resource="auth", status="FAILURE")
        
    alert = check_failed_login_anomaly(db_session, username)
    assert alert is not None
    assert alert.alert_type == "excessive_failed_logins"
    assert alert.severity == "HIGH"

def test_excessive_restores_alert_trigger(db_session):
    """Trigger alert when restore attempts exceed 3 in 10 minutes."""
    username = "dba_user"
    for _ in range(3):
        append_audit_log(db_session, username=username, action="RESTORE_ATTEMPT", resource="backup:1", status="ATTEMPTED")
        
    alert = check_excessive_restores_anomaly(db_session, username)
    assert alert is not None
    assert alert.alert_type == "excessive_restores"
    assert alert.severity == "HIGH"
