import logging
import os
from typing import Tuple

from dotenv import dotenv_values
from sqlmodel import Session, create_engine

from db.core import BaseModel

log = logging.getLogger('uvicorn.error')


def get_db_config() -> Tuple[str, dict]:
    """
    Get database configuration from environment variables
    or the .env file
    """
    # Get database URL
    # Case 1: AWS: we need to assemble the DB url from different
    #   environment variables (as these need to be populated from
    #   secrets)
    host = os.getenv("DB_HOST", None)
    if host is not None:
        user = os.getenv("DB_USER")
        password = os.getenv("DB_PASSWORD")
        db_url = f"postgresql+psycopg://{user}:{password}@{host}"
        return db_url, {}
    # Case 2: we have DB_URL set in the .env file, or we just want
    #   an in-memory DB for dev/testing
    # Doing this separately from pydantic-settings as we
    # need this before loading the FastAPI app
    env_values = dotenv_values(".env")
    # Prefer the explicitly set value in .env, then environment variable,
    #   fallback to in-memory DB
    db_url = env_values.get("DB_URL") or os.getenv("DB_URL") or "sqlite://"
    if db_url.startswith("sqlite://"):
        connect_args = {"check_same_thread": False}
    else:
        connect_args = {}
    return db_url, connect_args


DB_URL, db_connect_args = get_db_config()
engine = create_engine(DB_URL, connect_args=db_connect_args)


def create_db_and_tables():
    # NOTE: we only do this in dev (with sqlite).
    # For production, we manage the DB schema with alembic
    db_url, connect_args = get_db_config()
    if db_url.startswith("sqlite://"):
        log.info("Automatically creating DB tables for sqlite")
        BaseModel.metadata.create_all(engine)


def get_db_session():
    with Session(engine) as session:
        yield session
