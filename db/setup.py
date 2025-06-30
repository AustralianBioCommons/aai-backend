import os

from dotenv import dotenv_values
from sqlmodel import Session, SQLModel, create_engine

# Read DB_URL from .env
# Doing this separately from pydantic-settings as we
# need this before loading the FastAPI app
env_values = dotenv_values(".env")
# Prefer the explicitly set value in .env, then environment variable,
#   fallback to in-memory DB
DB_URL = env_values.get("DB_URL") or os.getenv("DB_URL") or "sqlite://"

connect_args = {"check_same_thread": False}
engine = create_engine(DB_URL, connect_args=connect_args)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_db_session():
    with Session(engine) as session:
        yield session
