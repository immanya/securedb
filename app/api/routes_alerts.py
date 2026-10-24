from datetime import datetime, timezone
from typing import List, Optional
from app.compat import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.alert import SecurityAlert
from app.models.user import User
from app.schemas.all_schemas import SecurityAlertResponse
from app.core.audit import append_audit_log
from app.api.deps import require_perm

router = APIRouter(prefix="/security-alerts", tags=["Security Alerts"])

@router.get("", response_model=List[SecurityAlertResponse])
def get_security_alerts(
    status_filter: Optional[str] = Query(None, description="Filter by OPEN, ACKNOWLEDGED, RESOLVED"),
    current_user: User = Depends(require_perm("alerts:view")),
    db: Session = Depends(get_db)
):
    """Retrieve security alerts with optional status filtering."""
    q = db.query(SecurityAlert)
    if status_filter:
        q = q.filter(SecurityAlert.status == status_filter.upper())
    return q.order_by(SecurityAlert.created_at.desc()).all()


@router.post("/{id}/resolve", response_model=SecurityAlertResponse)
def resolve_alert(
    id: int,
    current_user: User = Depends(require_perm("alerts:resolve")),
    db: Session = Depends(get_db)
):
    """Mark a security alert as RESOLVED."""
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        
    alert.status = "RESOLVED"
    alert.resolved_at = datetime.now(timezone.utc)
    alert.resolved_by = current_user.username
    db.commit()
    db.refresh(alert)
    
    append_audit_log(
        db=db,
        username=current_user.username,
        action="ALERT_RESOLVED",
        resource=f"alert:{id}",
        status="RESOLVED",
        details={"alert_type": alert.alert_type, "severity": alert.severity},
        user_id=current_user.id
    )
    
    return alert
