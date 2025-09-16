import asyncio
import signal
import sys

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from loguru import logger

from scheduled_tasks.scheduler import SCHEDULER
from scheduled_tasks.tasks import sync_auth0_users


def schedule_jobs(scheduler: AsyncIOScheduler):
    hourly_trigger = IntervalTrigger(minutes=2)
    logger.info("Adding job: sync_auth0_users")
    scheduler.add_job(
        sync_auth0_users,
        trigger=hourly_trigger,
        id="sync_auth0_users",
        replace_existing=True
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
