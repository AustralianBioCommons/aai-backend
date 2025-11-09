import os
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version

from dotenv import dotenv_values
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

# This has to be imported even if unused
from db import models  # noqa: F401
from db.admin import DatabaseAdmin
from routers import (
    admin,
    biocommons_admin,
    biocommons_groups,
    biocommons_register,
    sbp_register,
    user,
    utils,
)

# Load .env to get CORS_ALLOWED_ORIGINS.
# Note that for most env variables, we use pydantic-settings
#   and load them via config.py. But we need the
#   allowed_origins before we load the app
env_values = dotenv_values(".env")

def read_setting(key: str, default: str | None = None) -> str | None:
    """
    Read a setting from environment variables or the .env file.
    The environment variable will take precedence if present.
    """
    value = os.getenv(key)
    if value is not None and value.strip():
        return value
    from_env_file = env_values.get(key)
    if from_env_file is not None and str(from_env_file).strip():
        return from_env_file
    return default

ALLOWED_ORIGINS = [origin.strip() for origin in read_setting("CORS_ALLOWED_ORIGINS", "").split(",") if origin.strip()]
SECRET_KEY = read_setting("JWT_SECRET_KEY")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # NOTE: we only create the database and tables automatically in development:
    # we assume that if the DB is an sqlite DB, we are in dev.
    from db.setup import create_db_and_tables

    create_db_and_tables()
    DatabaseAdmin.setup(app=app, secret_key=SECRET_KEY)
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

metrics_enabled = os.getenv("ENABLE_PROMETHEUS_METRICS", "").lower() in {"1", "true", "yes"}

if metrics_enabled:
    from prometheus_fastapi_instrumentator import Instrumentator

    Instrumentator().instrument(app).expose(app, include_in_schema=False)


@app.get("/")
def public_route():
    return {"message": "AAI Backend API", "version": SERVICE_VERSION}


app.include_router(admin.router)
app.include_router(biocommons_admin.router)
app.include_router(user.router)
app.include_router(biocommons_register.router)
app.include_router(sbp_register.router)
app.include_router(utils.router)
app.include_router(biocommons_groups.router)
try:
    SERVICE_VERSION = version("aai-backend")
except PackageNotFoundError:
    SERVICE_VERSION = "unknown"
