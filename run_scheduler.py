import asyncio
import signal
import sys
from datetime import UTC, datetime, timedelta

import typer
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from loguru import logger
from sqlalchemy import text

from db.setup import get_engine
from scheduled_tasks.scheduler import SCHEDULER
from scheduled_tasks.tasks import populate_db_groups, sync_auth0_roles, sync_auth0_users


def schedule_jobs(scheduler: AsyncIOScheduler):
    hourly_trigger = IntervalTrigger(minutes=60)
    logger.info("Adding one-off job: populate DB groups")
    scheduler.add_job(
        populate_db_groups,
        trigger=DateTrigger(run_date=datetime.now(UTC)),
        id="populate_db_groups",
        replace_existing=True
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


def clear_db_jobs():
    engine = get_engine()
    with engine.connect() as conn:
        conn.execute(text("DELETE FROM apscheduler_jobs"))
        conn.commit()
    engine.dispose()
    logger.info("Database jobs cleared")


async def run_immediate():
    logger.info("Clearing existing jobs")
    clear_db_jobs()
    now_trigger = DateTrigger(run_date=datetime.now(UTC))
    logger.info("Adding one-off job: populate DB groups")
    SCHEDULER.add_job(
        populate_db_groups,
        trigger=now_trigger,
        id="populate_db_groups",
        replace_existing=True
    )
    logger.info("Adding one-off job: sync_auth0_roles")
    SCHEDULER.add_job(
        sync_auth0_roles,
        trigger=now_trigger,
        id="sync_auth0_roles",
        replace_existing=True
    )
    logger.info("Adding one-off job: sync_auth0_users")
    SCHEDULER.add_job(
        sync_auth0_users,
        trigger=now_trigger,
        id="sync_auth0_users",
        replace_existing=True
    )
    SCHEDULER.start()
    logger.info("Scheduler started, waiting for jobs to complete...")
    while SCHEDULER.get_jobs():
        SCHEDULER.print_jobs()
        await asyncio.sleep(0.5)
    logger.info("Stopping scheduler")
    SCHEDULER.shutdown(wait=True)


async def run_with_scheduler():
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


def main(immediate: bool = False):
    """
    Run the job scheduler. If --immediate is given, run the jobs immediately, then exit.
    """
    if immediate:
        asyncio.run(run_immediate())
    else:
        asyncio.run(run_with_scheduler())


if __name__ == "__main__":
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green>\t<level>{level}</level>\t{message}\t<blue>{name}</blue>\t<cyan>{extra}</cyan>",
        level="INFO"
    )
    typer.run(main)
