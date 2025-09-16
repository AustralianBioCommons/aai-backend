from apscheduler.events import (
    EVENT_JOB_ERROR,
    EVENT_JOB_EXECUTED,
    EVENT_JOB_MISSED,
    JobExecutionEvent,
)
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from loguru import logger


def job_listener(event: JobExecutionEvent):
    with logger.contextualize(job_id=event.job_id, run_time=getattr(event, "scheduled_run_time", None)):
        if event.code == EVENT_JOB_EXECUTED:
            logger.info("job executed successfully")
        elif event.code == EVENT_JOB_ERROR:
            logger.error("job failed: %s\n%s")
        elif event.code == EVENT_JOB_MISSED:
            logger.warning("job missed its run time")


def create_scheduler():
    from db.setup import get_db_config
    db_url, _ = get_db_config()
    jobstores = {
        "default": SQLAlchemyJobStore(url=db_url)
    }
    executors = {
        "default": {"type": "asyncio"},
    }
    scheduler = AsyncIOScheduler(
        jobstores=jobstores,
        executors=executors,
        job_defaults={
            "misfire_grace_time": 5 * 60,
            "coalesce": True,
        },
        timezone="UTC"
    )
    scheduler.add_listener(job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED)
    return scheduler


# Only want to create the scheduler once
SCHEDULER = create_scheduler()
