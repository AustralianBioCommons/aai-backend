import asyncio
import signal
import sys
from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from loguru import logger

from scheduled_tasks.scheduler import SCHEDULER
from scheduled_tasks.tasks import populate_db_groups, sync_auth0_roles, sync_auth0_users


def schedule_jobs(scheduler: AsyncIOScheduler):
    hourly_trigger = IntervalTrigger(minutes=60)
    logger.info("Adding one-off job: populate DB groups")
    scheduler.add_job(
        populate_db_groups,
        trigger=DateTrigger(run_date=datetime.now(UTC))
    )
    logger.info("Adding hourly job: sync_auth0_roles")
    scheduler.add_job(
        sync_auth0_roles,
        trigger=hourly_trigger,
        id="sync_auth0_roles",
        replace_existing=True,
        next_run_time=datetime.now(UTC)
    )
    logger.info("Adding hourly job: sync_auth0_users")
    scheduler.add_job(
        sync_auth0_users,
        trigger=hourly_trigger,
        id="sync_auth0_users",
        replace_existing=True,
        next_run_time=datetime.now(UTC) + timedelta(minutes=15)
    )


async def main():
    logger.info("Setting up scheduler")
    schedule_jobs(SCHEDULER)
    logger.info("Starting scheduler")
    SCHEDULER.start()
    logger.info("Scheduler started, waiting for shutdown...")
    # Wait for shutdown
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    logger.info("Stopping scheduler")
    SCHEDULER.shutdown(wait=False)


if __name__ == "__main__":
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green>\t<level>{level}</level>\t{message}\t<blue>{name}</blue>\t<cyan>{extra}</cyan>",
        level="INFO"
    )
    asyncio.run(main())
