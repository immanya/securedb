from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, BigInteger, DateTime, Text, ForeignKey
from app.database import Base

class Backup(Base):
    __tablename__ = "backups"

    id = Column(Integer, primary_key=True, index=True)
    target_db_id = Column(Integer, ForeignKey("target_databases.id", ondelete="CASCADE"), nullable=False)
    target_db_name = Column(String(64), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(BigInteger, nullable=False, default=0)
    encrypted_file_hmac = Column(String(64), nullable=False)  # HMAC-SHA256 of encrypted file
    status = Column(String(20), default="COMPLETED", nullable=False)  # COMPLETED, FAILED, PRUNED
    integrity_status = Column(String(20), default="UNVERIFIED", nullable=False)  # UNVERIFIED, SAFE, TAMPERED, FAILED
    last_verified_at = Column(DateTime, nullable=True)
    verification_details = Column(Text, nullable=True)  # JSON summary of verification levels
    created_by_user = Column(String(64), default="system", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
