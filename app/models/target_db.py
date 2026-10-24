from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from app.database import Base

class TargetDatabase(Base):
    __tablename__ = "target_databases"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, index=True, nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False, default=5432)
    username = Column(String(64), nullable=False)
    encrypted_password = Column(Text, nullable=False)  # Encrypted with HKDF-derived db_credentials_key
    database_name = Column(String(64), nullable=False)
    db_type = Column(String(20), default="postgresql", nullable=False)  # postgresql or sqlite
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
