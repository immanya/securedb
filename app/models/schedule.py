from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from app.database import Base

class BackupSchedule(Base):
    __tablename__ = "backup_schedules"

    id = Column(Integer, primary_key=True, index=True)
    target_db_id = Column(Integer, ForeignKey("target_databases.id", ondelete="CASCADE"), nullable=False)
    target_db_name = Column(String(64), nullable=False)
    cron_expression = Column(String(64), nullable=False)  # e.g., "0 2 * * *"
    retention_count = Column(Integer, nullable=False, default=5)
    is_active = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
