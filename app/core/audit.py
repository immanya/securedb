import json
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog

GENESIS_HASH = "0" * 64

def calculate_entry_hash(
    prev_hash: str,
    timestamp_iso: str,
    username: str,
    action: str,
    resource: str,
    status: str,
    details_json: str
) -> str:
    """Calculate the cryptographic hash of an audit log entry chained to prev_hash."""
    canonical_payload = f"{prev_hash}|{timestamp_iso}|{username}|{action}|{resource}|{status}|{details_json}"
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def append_audit_log(
    db: Session,
    username: str,
    action: str,
    resource: str,
    status: str,
    details: Optional[Dict[str, Any]] = None,
    user_id: Optional[int] = None
) -> AuditLog:
    """Append a cryptographically chained entry to the immutable audit log."""
    now = datetime.now(timezone.utc)
    timestamp_iso = now.isoformat()
    details_json = json.dumps(details or {}, sort_keys=True)
    
    # Fetch previous entry to obtain its hash
    last_entry = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = last_entry.entry_hash if last_entry else GENESIS_HASH
    
    entry_hash = calculate_entry_hash(
        prev_hash=prev_hash,
        timestamp_iso=timestamp_iso,
        username=username,
        action=action,
        resource=resource,
        status=status,
        details_json=details_json
    )
    
    log_entry = AuditLog(
        timestamp=now,
        timestamp_iso=timestamp_iso,
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        status=status,
        details_json=details_json,
        prev_hash=prev_hash,
        entry_hash=entry_hash
    )
    
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry


def verify_audit_chain(db: Session) -> Tuple[bool, Optional[int], int, str]:
    """
    Verify the entire cryptographic hash chain of audit logs from genesis to head.
    Returns: (is_valid, broken_at_id, total_records, message)
    """
    records = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    total = len(records)
    
    if total == 0:
        return True, None, 0, "No audit logs present (chain is empty and valid)"
    
    expected_prev = GENESIS_HASH
    
    for idx, rec in enumerate(records):
        # 1. Verify link to previous entry
        if rec.prev_hash != expected_prev:
            return (
                False,
                rec.id,
                total,
                f"Broken link at record #{rec.id}: expected prev_hash '{expected_prev}', got '{rec.prev_hash}'"
            )
        
        # 2. Recompute and verify entry_hash
        recomputed = calculate_entry_hash(
            prev_hash=rec.prev_hash,
            timestamp_iso=rec.timestamp_iso,
            username=rec.username,
            action=rec.action,
            resource=rec.resource,
            status=rec.status,
            details_json=rec.details_json
        )
        
        if rec.entry_hash != recomputed:
            return (
                False,
                rec.id,
                total,
                f"Tampered entry at record #{rec.id}: recorded hash '{rec.entry_hash}' != computed hash '{recomputed}'"
            )
        
        expected_prev = rec.entry_hash
    
    return True, None, total, f"All {total} audit records successfully verified against cryptographic hash chain"
