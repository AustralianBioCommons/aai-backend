import logging
import os
from typing import Tuple

from dotenv import dotenv_values
from sqlmodel import Session, create_engine

from db.core import BaseModel

log = logging.getLogger('uvicorn.error')

POSTGRES_STATEMENT_TIMEOUT_S = 30

SQLITE_CONNECT_ARGS = {
    "check_same_thread": False,
    "timeout": 30,
}
POSTGRES_CONNECT_ARGS = {
    "connect_timeout": 10,
    "options": f"-c statement_timeout={POSTGRES_STATEMENT_TIMEOUT_S * 1000}"
}

# Set engine as None initially so it's not created on import
_engine = None


def get_engine():
    global _engine
    if _engine is None:
        db_url, db_connect_args = get_db_config()
        _engine = create_engine(
            db_url,
            connect_args=db_connect_args,
            pool_size=20,
            max_overflow=20,
            pool_timeout=60,
            pool_pre_ping=True,
            pool_recycle=60 * 10,
        )
    return _engine


def get_db_config() -> Tuple[str, dict]:
    """
    Get database configuration from environment variables
    or the .env file

    Note we don't use pydantic-settings or our Settings object for
    this - we need to do it before loading the FastAPI app
    """
    # Case 1: AWS: assemble the DB url from individual environment variables.
    host = os.getenv("DB_HOST")
    if host is not None:
        user = os.getenv("DB_USER")
        password = os.getenv("DB_PASSWORD")
        database_name = os.getenv("DB_NAME")
        port = os.getenv("DB_PORT")

        host_with_port = host
        if port and ':' not in host_with_port:
            host_with_port = f"{host_with_port}:{port}"

        database_path = f"/{database_name}" if database_name else ""

        db_url = f"postgresql+psycopg://{user}:{password}@{host_with_port}{database_path}"
        return db_url, POSTGRES_CONNECT_ARGS

    # Case 2: explicit DB_URL provided via environment or .env file
    explicit_url = os.getenv("DB_URL")
    if explicit_url:
        if explicit_url.startswith("postgresql"):
            connect_args = POSTGRES_CONNECT_ARGS
        else:
            connect_args = SQLITE_CONNECT_ARGS
        return explicit_url, connect_args

    # Case 3: DB_URL from .env file (dev/local)
    env_values = dotenv_values(".env")
    db_url = env_values.get("DB_URL") or "sqlite://"
    if db_url.startswith("postgresql"):
        connect_args = POSTGRES_CONNECT_ARGS
    else:
        connect_args = SQLITE_CONNECT_ARGS
    return db_url, connect_args


def create_db_and_tables():
    # NOTE: we only do this in dev (with sqlite).
    # For production, we manage the DB schema with alembic
    db_url, connect_args = get_db_config()
    if db_url.startswith("sqlite://"):
        engine = get_engine()
        log.info("Automatically creating DB tables for sqlite")
        BaseModel.metadata.create_all(engine)


def get_db_session():
    engine = get_engine()
    with Session(engine) as session:
        try:
            yield session
        finally:
            session.close()
