from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Text, ForeignKey, BigInteger
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base


def now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    status: Mapped[str] = mapped_column(String(16), default="active")
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class TargetDatabase(Base):
    __tablename__ = "databases"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    db_type: Mapped[str] = mapped_column(String(32), default="postgresql")
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    username: Mapped[str] = mapped_column(String(128))
    encrypted_password: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Backup(Base):
    __tablename__ = "backups"
    id: Mapped[int] = mapped_column(primary_key=True)
    database_id: Mapped[int] = mapped_column(ForeignKey("databases.id"))
    file_path: Mapped[str] = mapped_column(Text)
    backup_type: Mapped[str] = mapped_column(String(16), default="full")
    file_size: Mapped[int] = mapped_column(BigInteger, default=0)
    hmac: Mapped[str] = mapped_column(String(64))
    wrapped_key: Mapped[str] = mapped_column(Text)
    algorithm: Mapped[str] = mapped_column(String(32), default="AES-256-GCM")
    encryption_status: Mapped[str] = mapped_column(String(16), default="encrypted")
    status: Mapped[str] = mapped_column(String(16), default="created")  # created|safe|tampered|failed
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    prev_hash: Mapped[str] = mapped_column(String(64), default="0" * 64)
    entry_hash: Mapped[str] = mapped_column(String(64), default="")


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class BackupSchedule(Base):
    __tablename__ = "backup_schedules"
    id: Mapped[int] = mapped_column(primary_key=True)
    database_id: Mapped[int] = mapped_column(ForeignKey("databases.id"))
    cron: Mapped[str] = mapped_column(String(64))  # e.g. "0 23 * * *" = daily 11 PM (UTC)
    keep_last: Mapped[int] = mapped_column(Integer, default=7)  # retention
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
