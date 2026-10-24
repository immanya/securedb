"""APScheduler jobs: cron-based backups + retention. Schedules live in the DB and are reloaded at startup."""
import os
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select
from . import audit, backup_engine as engine
from .db import SessionLocal
from .models import Backup, BackupSchedule, TargetDatabase

sched = BackgroundScheduler(timezone="UTC")


def apply_retention(db, database_id: int, keep_last: int) -> int:
    rows = db.scalars(select(Backup).where(Backup.database_id == database_id).order_by(Backup.id.desc())).all()
    removed = 0
    for b in rows[keep_last:]:
        if os.path.isfile(b.file_path):
            os.remove(b.file_path)
        db.delete(b)
        removed += 1
    db.commit()
    if removed:
        audit.log(db, "scheduler", "retention", "success", details=f"removed {removed} old backup(s), keeping {keep_last}")
    return removed


def run_scheduled_backup(schedule_id: int) -> None:
    db = SessionLocal()
    try:
        s = db.get(BackupSchedule, schedule_id)
        if not s or not s.enabled:
            return
        t = db.get(TargetDatabase, s.database_id)
        try:
            b = engine.create_backup(t, None)
            db.add(b)
            db.commit()
            audit.log(db, "scheduler", "backup", "success", details=f"backup #{b.id} (schedule #{s.id})")
            apply_retention(db, t.id, s.keep_last)
        except Exception as e:
            audit.log(db, "scheduler", "backup", "failed", details=str(e)[:200])
            audit.alert(db, "backup_failed", "high", f"Scheduled backup of '{t.name}' failed: {str(e)[:200]}")
    finally:
        db.close()


def register_job(s: BackupSchedule) -> None:
    sched.add_job(run_scheduled_backup, CronTrigger.from_crontab(s.cron, timezone="UTC"),
                  args=[s.id], id=f"schedule-{s.id}", replace_existing=True)


def remove_job(schedule_id: int) -> None:
    if sched.get_job(f"schedule-{schedule_id}"):
        sched.remove_job(f"schedule-{schedule_id}")


def start() -> None:
    db = SessionLocal()
    try:
        for s in db.scalars(select(BackupSchedule).where(BackupSchedule.enabled)):
            register_job(s)
    finally:
        db.close()
    if not sched.running:
        sched.start()
