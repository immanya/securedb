from typing import List
from app.compat import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.schedule import BackupSchedule
from app.models.target_db import TargetDatabase
from app.models.user import User
from app.schemas.all_schemas import ScheduleCreate, ScheduleResponse
from app.services.scheduler_service import add_or_update_schedule_job, remove_schedule_job
from app.core.audit import append_audit_log
from app.api.deps import require_perm

router = APIRouter(prefix="/schedules", tags=["Schedules"])

@router.get("", response_model=List[ScheduleResponse])
def list_schedules(
    current_user: User = Depends(require_perm("schedules:view")),
    db: Session = Depends(get_db)
):
    """List all configured automated backup schedules."""
    return db.query(BackupSchedule).all()


@router.post("", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
def create_schedule(
    sched_in: ScheduleCreate,
    current_user: User = Depends(require_perm("schedules:create")),
    db: Session = Depends(get_db)
):
    """Create an automated cron-based backup schedule with retention policy (Admin only)."""
    target = db.query(TargetDatabase).filter(TargetDatabase.id == sched_in.target_db_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target database not found")
        
    schedule = BackupSchedule(
        target_db_id=target.id,
        target_db_name=target.name,
        cron_expression=sched_in.cron_expression,
        retention_count=sched_in.retention_count,
        is_active=True
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    
    # Register with background scheduler
    add_or_update_schedule_job(schedule)
    db.commit()
    db.refresh(schedule)
    
    append_audit_log(
        db=db,
        username=current_user.username,
        action="SCHEDULE_CREATED",
        resource=f"schedule:{schedule.id}",
        status="SUCCESS",
        details={
            "target_db": target.name,
            "cron": schedule.cron_expression,
            "retention": schedule.retention_count
        },
        user_id=current_user.id
    )
    
    return schedule


@router.delete("/{id}")
def delete_schedule(
    id: int,
    current_user: User = Depends(require_perm("schedules:delete")),
    db: Session = Depends(get_db)
):
    """Delete an automated backup schedule (Admin only)."""
    sched = db.query(BackupSchedule).filter(BackupSchedule.id == id).first()
    if not sched:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
        
    remove_schedule_job(id)
    db.delete(sched)
    db.commit()
    
    append_audit_log(
        db=db,
        username=current_user.username,
        action="SCHEDULE_DELETED",
        resource=f"schedule:{id}",
        status="SUCCESS",
        user_id=current_user.id
    )
    return {"message": f"Schedule #{id} deleted successfully"}
