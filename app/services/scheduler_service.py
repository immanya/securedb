import logging
from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.schedule import BackupSchedule
from app.models.target_db import TargetDatabase
from app.services.backup_service import dump_and_encrypt_database
from app.core.alerts import trigger_backup_failed_alert

logger = logging.getLogger("securedb.scheduler")
scheduler = BackgroundScheduler()

def _run_scheduled_backup_job(schedule_id: int):
    """Job executed by APScheduler when cron trigger fires."""
    db: Session = SessionLocal()
    try:
        schedule = db.query(BackupSchedule).filter(BackupSchedule.id == schedule_id).first()
        if not schedule or not schedule.is_active:
            return
            
        target = db.query(TargetDatabase).filter(TargetDatabase.id == schedule.target_db_id).first()
        if not target or not target.is_active:
            return
            
        try:
            dump_and_encrypt_database(db=db, target=target, username="scheduler")
            schedule.last_run_at = datetime.now(timezone.utc)
            # Update next run time
            job = scheduler.get_job(f"schedule_{schedule_id}")
            if job and job.next_run_time:
                schedule.next_run_at = job.next_run_time
            db.commit()
        except Exception as e:
            trigger_backup_failed_alert(db, target.name, f"Scheduled backup failed: {str(e)}")
            logger.error(f"Scheduled backup failed for {target.name}: {e}")
    finally:
        db.close()


def add_or_update_schedule_job(schedule: BackupSchedule):
    """Register or update an APScheduler cron job from a BackupSchedule record."""
    job_id = f"schedule_{schedule.id}"
    
    # Remove existing job if present
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        
    if not schedule.is_active:
        return
        
    try:
        trigger = CronTrigger.from_crontab(schedule.cron_expression)
        job = scheduler.add_job(
            _run_scheduled_backup_job,
            trigger=trigger,
            args=[schedule.id],
            id=job_id,
            replace_existing=True
        )
        if job and job.next_run_time:
            schedule.next_run_at = job.next_run_time
    except Exception as e:
        logger.error(f"Failed to register cron trigger '{schedule.cron_expression}' for schedule #{schedule.id}: {e}")


def remove_schedule_job(schedule_id: int):
    """Remove a job from APScheduler."""
    job_id = f"schedule_{schedule_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)


def init_scheduler():
    """Initialize APScheduler and load all active schedules from the database on startup."""
    if not scheduler.running:
        scheduler.start()
        
    db: Session = SessionLocal()
    try:
        active_schedules = db.query(BackupSchedule).filter(BackupSchedule.is_active == True).all()
        for sched in active_schedules:
            add_or_update_schedule_job(sched)
        db.commit()
    finally:
        db.close()


def shutdown_scheduler():
    """Gracefully shutdown scheduler."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
