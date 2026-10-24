import os, base64
os.environ["SECUREDB_MASTER_KEY"] = base64.b64encode(os.urandom(32)).decode()
os.environ["DATABASE_URL"] = "sqlite:///./test_api.db"
from fastapi.testclient import TestClient
from app.main import app

c = TestClient(app)


def token(u, p="StrongPass123"):
    return {"Authorization": "Bearer " + c.post("/auth/login", json={"username": u, "password": p}).json()["access_token"]}


def test_rbac_lockout_and_audit_chain():
    for u in ("admin1", "viewer1"):
        assert c.post("/auth/register", json={"username": u, "email": f"{u}@x.com", "password": "StrongPass123"}).status_code == 201
    admin, viewer = token("admin1"), token("viewer1")
    assert c.get("/backups", headers=viewer).status_code == 200            # viewer can look
    assert c.delete("/backups/1", headers=viewer).status_code == 403       # but not delete
    assert c.post("/backups/create?database_id=1", headers=viewer).status_code == 403
    assert c.get("/logs", headers=viewer).status_code == 403
    assert c.get("/security-alerts", headers=admin).json()[0]["type"] == "unauthorized_action"
    assert c.get("/backups").status_code == 401                            # no token
    for _ in range(5):
        assert c.post("/auth/login", json={"username": "viewer1", "password": "wrong"}).status_code == 401
    assert c.post("/auth/login", json={"username": "viewer1", "password": "StrongPass123"}).status_code == 423
    assert c.get("/logs/verify-chain", headers=admin).json()["valid"] is True


def test_schedule_and_retention(tmp_path):
    from app import scheduler
    from app.db import SessionLocal
    from app.models import TargetDatabase, Backup
    admin = token("admin1")
    with SessionLocal() as db:
        db.add(TargetDatabase(name="Demo", host="localhost", port=5432, username="u", encrypted_password="00"))
        for i in range(5):
            f = tmp_path / f"b{i}.enc"; f.write_bytes(b"x")
            db.add(Backup(database_id=1, file_path=str(f), hmac="0" * 64, wrapped_key="00", status="safe"))
        db.commit()
        assert scheduler.apply_retention(db, 1, 2) == 3
        assert len(list(tmp_path.iterdir())) == 2
    assert c.post("/schedules", json={"database_id": 1, "cron": "nonsense"}, headers=admin).status_code == 422
    r = c.post("/schedules", json={"database_id": 1, "cron": "0 23 * * *", "keep_last": 7}, headers=admin)
    assert r.status_code == 201 and scheduler.sched.get_job(f"schedule-{r.json()['id']}")
    c.post("/auth/register", json={"username": "viewer2", "email": "v2@x.com", "password": "StrongPass123"})
    assert c.post("/schedules", json={"database_id": 1}, headers=token("viewer2")).status_code == 403
    assert "backups" in c.get("/dashboard/charts", headers=admin).json()
