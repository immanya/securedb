from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    timestamp_iso = Column(String(32), nullable=False)
    user_id = Column(Integer, nullable=True)
    username = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)       # e.g., LOGIN_SUCCESS, RBAC_DENIED, BACKUP_CREATE
    resource = Column(String(128), nullable=False)     # e.g., backup:1, auth, db:CollegeDB
    status = Column(String(32), nullable=False)        # SUCCESS, FAILURE, DENIED, TAMPERED
    details_json = Column(Text, nullable=False, default="{}")
    prev_hash = Column(String(64), nullable=False)     # SHA-256 of preceding log entry
    entry_hash = Column(String(64), nullable=False)    # SHA-256(prev_hash + canonical_fields)
