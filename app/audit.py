"""Tamper-evident audit log (hash chain) + rule-based alerts."""
import hashlib
from datetime import timedelta
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .models import AuditLog, SecurityAlert, now

GENESIS = "0" * 64


def _entry_hash(prev: str, e: AuditLog) -> str:
    payload = "|".join([prev, e.username, e.action, e.status, e.ip_address, e.details, e.timestamp.isoformat()])
    return hashlib.sha256(payload.encode()).hexdigest()


def log(db: Session, username: str, action: str, status: str, ip: str = "", details: str = "") -> AuditLog:
    last = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).first()
    e = AuditLog(username=username, action=action, status=status, ip_address=ip,
                 details=details, timestamp=now(), prev_hash=last.entry_hash if last else GENESIS)
    e.entry_hash = _entry_hash(e.prev_hash, e)
    db.add(e)
    db.commit()
    return e


def verify_chain(db: Session) -> dict:
    prev = GENESIS
    for e in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        ts = e.timestamp if e.timestamp.tzinfo else e.timestamp.replace(tzinfo=now().tzinfo)
        e.timestamp = ts
        if e.prev_hash != prev or e.entry_hash != _entry_hash(prev, e):
            db.rollback()
            return {"valid": False, "broken_at_id": e.id}
        prev = e.entry_hash
    db.rollback()
    return {"valid": True}


def alert(db: Session, type_: str, severity: str, description: str) -> None:
    db.add(SecurityAlert(type=type_, severity=severity, description=description))
    db.commit()


def _count(db: Session, action: str, status: str, minutes: int, username: str | None = None) -> int:
    q = select(func.count()).select_from(AuditLog).where(
        AuditLog.action == action, AuditLog.status == status,
        AuditLog.timestamp >= now() - timedelta(minutes=minutes))
    if username:
        q = q.where(AuditLog.username == username)
    return db.scalar(q) or 0


def check_failed_logins(db: Session, username: str) -> None:
    # Rule 1: >5 failed logins in 5 minutes
    if _count(db, "login", "failed", 5, username) > 5:
        alert(db, "brute_force", "high", f"More than 5 failed logins for '{username}' in 5 minutes")


def check_repeated_restores(db: Session, username: str) -> None:
    # Rule 4: repeated restore attempts
    if _count(db, "restore", "attempt", 10, username) > 3:
        alert(db, "repeated_restore", "medium", f"'{username}' attempted more than 3 restores in 10 minutes")
