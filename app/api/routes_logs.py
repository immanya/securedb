from typing import List
from app.compat import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.all_schemas import AuditLogResponse, AuditVerifyResponse
from app.core.audit import verify_audit_chain
from app.api.deps import require_perm

router = APIRouter(prefix="/logs", tags=["Audit Logs"])

@router.get("", response_model=List[AuditLogResponse])
def get_audit_logs(
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(require_perm("logs:view")),
    db: Session = Depends(get_db)
):
    """Retrieve audit log records sorted newest to oldest."""
    return db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()


@router.get("/verify-chain", response_model=AuditVerifyResponse)
def verify_logs_chain_endpoint(
    current_user: User = Depends(require_perm("logs:verify")),
    db: Session = Depends(get_db)
):
    """
    Cryptographically verify the hash chain of all audit log rows from genesis to head.
    Detects if any row was tampered with, injected, modified, or deleted.
    Reports the exact ID of the first broken row if integrity is violated.
    """
    valid, broken_id, total, details = verify_audit_chain(db)
    return {
        "valid": valid,
        "broken_at_id": broken_id,
        "total_records": total,
        "details": details
    }
