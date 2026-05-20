import uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Optional

from loguru import logger

from app.services.celery_app import celery_app
from app.modules.database.database import transaction
from app.modules.database.models.models import ScheduledScans
from app.modules.tasks.pipeline import launch_full_pipeline, is_target_responsive
from app.modules.interfaces.types.context import ScanContext


def _is_due(schedule: ScheduledScans, now: datetime) -> bool:
    config      = schedule.configuration or {}
    last_run    = schedule.last_run_at

    if schedule.job_type == 'interval':
        if last_run is None:
            return True
        delta = timedelta(
            weeks=int(config.get('weeks', 0)),
            days=int(config.get('days', 0)),
            hours=int(config.get('hours', 0)),
            minutes=int(config.get('minutes', 0)),
            seconds=int(config.get('seconds', 0)),
        )
        return (now - last_run) >= delta

    elif schedule.job_type == 'cron':
        # Don't re-fire in the same minute
        if last_run and last_run.replace(second=0, microsecond=0) == now.replace(second=0, microsecond=0):
            return False

        def matches(val, current: int) -> bool:
            return str(val) == '*' or int(val) == current

        return (
            matches(config.get('minute', '*'), now.minute) and
            matches(config.get('hour',   '*'), now.hour)   and
            matches(config.get('day',    '*'), now.day)    and
            matches(config.get('month',  '*'), now.month)
        )

    return False


@celery_app.task
def task_run_scheduled_scans():
    now = datetime.now()
    logger.info("Scheduler: checking due scans")

    with transaction() as db:
        schedules = db.query(ScheduledScans).all()
        for schedule in schedules:
            if not _is_due(schedule, now):
                continue

            logger.info(f"Scheduler: firing '{schedule.codename}' → {schedule.url}")
            try:
                session_id = str(uuid.uuid4())
                host = urlparse(schedule.url).hostname
                ctx  = ScanContext(
                    session_id=session_id,
                    primary_url=schedule.url,
                    primary_host=host,
                    config=None,
                )
                if is_target_responsive(session_id, ctx):
                    launch_full_pipeline(session_id, schedule.user_id or 0, ctx)
                schedule.last_run_at = now
                db.add(schedule)
            except Exception as e:
                logger.error(f"Scheduler: failed to launch '{schedule.codename}': {e}")