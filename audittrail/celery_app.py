from celery import Celery

from audittrail.config import get_settings

settings = get_settings()

celery_app = Celery(
    "audittrail",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)

celery_app.conf.include = ["audittrail.tasks.scan_tasks"]
