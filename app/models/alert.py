from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.database import Base

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(64), nullable=False)   # excessive_failed_logins, rbac_denial, backup_tampered, excessive_restores, backup_failed
    severity = Column(String(20), nullable=False)     # LOW, MEDIUM, HIGH, CRITICAL
    message = Column(Text, nullable=False)
    status = Column(String(20), default="OPEN", nullable=False)  # OPEN, ACKNOWLEDGED, RESOLVED
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(64), nullable=True)
