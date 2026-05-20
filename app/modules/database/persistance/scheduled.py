from typing import Optional
from app.modules.database.database import transaction
from app.modules.database.models.models import ScheduledScans


def get_all_scheduled(user_id: Optional[int] = None) -> list[ScheduledScans]:
    with transaction() as db:
        query = db.query(ScheduledScans)
        if user_id is not None:
            query = query.filter(ScheduledScans.user_id == user_id)
        return query.all()


def create_scheduled(
    id: str, url: str, user_id: Optional[int],
    codename: str, job_type: str, configuration: dict
) -> ScheduledScans:
    with transaction() as db:
        schedule = ScheduledScans(
            id=id, url=url, user_id=user_id,
            codename=codename, job_type=job_type,
            configuration=configuration,
        )
        db.add(schedule)
        return schedule


def get_scheduled(schedule_id: str) -> Optional[ScheduledScans]:
    with transaction() as db:
        return db.query(ScheduledScans).filter(ScheduledScans.id == schedule_id).first()


def update_scheduled(schedule_id: str, **kwargs) -> ScheduledScans:
    with transaction() as db:
        schedule = db.query(ScheduledScans).filter(ScheduledScans.id == schedule_id).first()
        if not schedule:
            raise ValueError(f"Schedule {schedule_id} not found")
        for key, value in kwargs.items():
            setattr(schedule, key, value)
        db.add(schedule)
        return schedule


def delete_scheduled(schedule_id: str) -> None:
    with transaction() as db:
        schedule = db.query(ScheduledScans).filter(ScheduledScans.id == schedule_id).first()
        if not schedule:
            raise ValueError(f"Schedule {schedule_id} not found")
        db.delete(schedule)