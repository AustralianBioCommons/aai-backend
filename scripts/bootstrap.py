"""Entrypoint for ECS tasks to bootstrap the database and run the API service."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from contextlib import suppress

import uvicorn
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from db.setup import get_db_config

LOG = logging.getLogger("bootstrap")


def _configure_logging() -> None:
    logging.basicConfig(
        level=os.getenv("BOOTSTRAP_LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def wait_for_database(max_attempts: int = 60, delay_seconds: int = 5) -> str:
    """Poll the database until a simple query succeeds."""

    db_url, connect_args = get_db_config()
    LOG.info("Waiting for database to become available...")
    attempt = 0

    while True:
        attempt += 1
        engine = create_engine(db_url, connect_args=connect_args, pool_pre_ping=True)
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except OperationalError as exc:
            engine.dispose()
            LOG.warning("Database not ready (attempt %s/%s): %s", attempt, max_attempts, exc)
            if attempt >= max_attempts:
                raise
            time.sleep(delay_seconds)
            continue
        except Exception:
            engine.dispose()
            LOG.exception("Unexpected error while checking database readiness")
            raise
        else:
            engine.dispose()
            LOG.info("Database is ready")
            return db_url


def run_migrations() -> None:
    """Run Alembic migrations up to the latest revision."""

    LOG.info("Running database migrations")
    config_path = os.getenv("ALEMBIC_CONFIG", "alembic.ini")
    config = Config(config_path)
    command.upgrade(config, "head")
    LOG.info("Database migrations complete")


def start_application(db_url: str) -> None:
    """Start the FastAPI application using uvicorn."""

    # Ensure the application reuses the database settings we resolved above.
    os.environ.setdefault("DB_URL", db_url)

    host = os.getenv("UVICORN_HOST", "0.0.0.0")
    port = int(os.getenv("UVICORN_PORT", "8000"))
    workers = int(os.getenv("UVICORN_WORKERS", "2"))
    forwarded_allow_ips = os.getenv("FORWARDED_ALLOW_IPS", "*")
    app_dir = os.getenv("UVICORN_APP_DIR", "/app")

    LOG.info("Starting uvicorn on %s:%s with %s workers", host, port, workers)

    uvicorn.run(  # type: ignore[call-arg]
        "main:app",
        host=host,
        port=port,
        workers=workers,
        proxy_headers=True,
        forwarded_allow_ips=forwarded_allow_ips,
        app_dir=app_dir,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap database and run application")
    parser.add_argument(
        'mode',
        choices=('migrate', 'serve'),
        help="Select whether to run migrations only or start the API service",
    )
    parser.add_argument(
        '--run-migrations',
        action='store_true',
        help="When serving, run migrations again before starting the API",
    )
    parser.add_argument(
        '--max-attempts',
        type=int,
        default=int(os.getenv('BOOTSTRAP_MAX_ATTEMPTS', '60')),
        help="Maximum attempts while waiting for database readiness",
    )
    parser.add_argument(
        '--delay-seconds',
        type=int,
        default=int(os.getenv('BOOTSTRAP_DELAY_SECONDS', '5')),
        help="Delay between database readiness checks",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    _configure_logging()
    try:
        db_url = wait_for_database(max_attempts=args.max_attempts, delay_seconds=args.delay_seconds)

        if args.mode == 'migrate':
            run_migrations()
            LOG.info("Migration task complete")
            return

        if args.run_migrations:
            run_migrations()

        start_application(db_url)
    except Exception:
        LOG.exception("Fatal error during bootstrap (%s mode)", args.mode)
        sys.exit(1)


if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        main()
