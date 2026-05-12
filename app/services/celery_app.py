from celery import Celery
from dotenv import load_dotenv

load_dotenv(".env")

celery_app = Celery(
    "scanner",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1",
)

celery_app.conf.update(
    task_track_started=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_soft_time_limit=360,
    task_time_limit=600,
)

celery_app.autodiscover_tasks([
    "app.modules.tasks",
    "app.modules.tasks.web.attack",
    "app.modules.tasks.discovery.query",
    "app.modules.tasks.normalization.normalization",
])