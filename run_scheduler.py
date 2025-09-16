import asyncio
import logging
import signal

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from scheduled_tasks.scheduler import SCHEDULER
from scheduled_tasks.tasks import sync_auth0_users

log = logging.getLogger(__name__)


def schedule_jobs(scheduler: AsyncIOScheduler):
    hourly_trigger = IntervalTrigger(minutes=2)
    scheduler.add_job(
        sync_auth0_users,
        trigger=hourly_trigger,
        id="sync_auth0_users",
        replace_existing=True
    )


async def main():
    log.info("Setting up scheduler")
    schedule_jobs(SCHEDULER)
    log.info("Starting scheduler")
    SCHEDULER.start()
    log.info("Scheduler started, waiting for shutdown...")
    # Wait for shutdown
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("Stopping scheduler")
    SCHEDULER.shutdown(wait=False)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    asyncio.run(main())
