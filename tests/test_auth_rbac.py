import pytest
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.alert import SecurityAlert
from app.core.security import create_access_token

def test_registration_roles(client, db_session):
    """First registered user becomes admin, second user becomes viewer."""
    # Register first user
    res1 = client.post("/api/auth/register", json={"username": "alice_first", "password": "Password123!"})
    assert res1.status_code == 201
    assert res1.json()["role"] == "admin"
    
    # Register second user
    res2 = client.post("/api/auth/register", json={"username": "bob_second", "password": "Password123!"})
    assert res2.status_code == 201
    assert res2.json()["role"] == "viewer"

def test_enumeration_defense(client):
    """Same error message for unknown user and wrong password."""
    # Unknown user
    res1 = client.post("/api/auth/login", json={"username": "nonexistent_ghost", "password": "WrongPassword1!"})
    assert res1.status_code == 401
    
    # Existing user, wrong password
    res2 = client.post("/api/auth/login", json={"username": "admin_user", "password": "WrongPassword2!"})
    assert res2.status_code == 401
    
    assert res1.json()["detail"] == res2.json()["detail"] == "Invalid username or password"

def test_account_lockout(client, db_session):
    """Lockout after 5 failed login attempts."""
    username = "lockout_victim"
    client.post("/api/auth/register", json={"username": username, "password": "ValidPassword123!"})
    
    # 5 consecutive failed logins
    for _ in range(5):
        res = client.post("/api/auth/login", json={"username": username, "password": "IncorrectPassword!"})
        assert res.status_code == 401
        
    # 6th attempt should be blocked by lockout (403)
    res6 = client.post("/api/auth/login", json={"username": username, "password": "ValidPassword123!"})
    assert res6.status_code == 403
    assert "locked" in res6.json()["detail"].lower()

def test_role_read_from_db_on_every_request(client, db_session, sample_users):
    """Role is read from the DB on every request, not trusted from token."""
    viewer = sample_users["viewer"]
    token = create_access_token({"sub": viewer.username})
    headers = {"Authorization": f"Bearer {token}"}
    
    # As viewer, creating database should be forbidden (403)
    res = client.post(
        "/api/databases",
        headers=headers,
        json={
            "name": "DB_ViewerTest",
            "host": "localhost",
            "port": 5432,
            "username": "user",
            "password": "pwd",
            "database_name": "db",
            "db_type": "postgresql"
        }
    )
    assert res.status_code == 403
    
    # Now dynamically promote user to 'admin' in the database directly
    viewer.role = "admin"
    db_session.commit()
    
    # Without issuing a new token, the exact same token now succeeds because role is read from DB!
    res2 = client.post(
        "/api/databases",
        headers=headers,
        json={
            "name": "DB_ViewerTest",
            "host": "localhost",
            "port": 5432,
            "username": "user",
            "password": "pwd",
            "database_name": "db",
            "db_type": "postgresql"
        }
    )
    assert res2.status_code == 201

def test_rbac_denial_writes_audit_and_raises_alert(client, db_session, sample_users):
    """Every RBAC denial is written to the audit log and raises a security alert."""
    viewer = sample_users["viewer"]
    token = create_access_token({"sub": viewer.username})
    headers = {"Authorization": f"Bearer {token}"}
    
    # Viewer attempts admin-only operation
    res = client.post(
        "/api/schedules",
        headers=headers,
        json={
            "target_db_id": 1,
            "cron_expression": "0 2 * * *",
            "retention_count": 5
        }
    )
    assert res.status_code == 403
    
    # Check that audit log has RBAC_DENIED entry
    audit_entry = db_session.query(AuditLog).filter(
        AuditLog.username == viewer.username,
        AuditLog.action == "RBAC_DENIED"
    ).first()
    assert audit_entry is not None
    assert audit_entry.status == "DENIED"
    
    # Check that security alert was raised
    alert = db_session.query(SecurityAlert).filter(
        SecurityAlert.alert_type == "rbac_denial",
        SecurityAlert.severity == "HIGH"
    ).first()
    assert alert is not None
    assert viewer.username in alert.message
