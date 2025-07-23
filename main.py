from contextlib import asynccontextmanager

from dotenv import dotenv_values
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

# This has to be imported even if unused
from db import models  # noqa: F401
from db.setup import create_db_and_tables
from routers import admin, biocommons_groups, bpa_register, galaxy_register, user, utils

# Load .env to get CORS_ALLOWED_ORIGINS.
# Note that for most env variables, we use pydantic-settings
#   and load them via config.py. But we need the
#   allowed_origins before we load the app
env_values = dotenv_values(".env")
ALLOWED_ORIGINS = [
    origin.strip() for origin in env_values.get("CORS_ALLOWED_ORIGINS", "").split(",")
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def public_route():
    return {"message": "AAI Backend API"}


app.include_router(admin.router)
app.include_router(user.router)
app.include_router(bpa_register.router)
app.include_router(galaxy_register.router)
app.include_router(utils.router)
app.include_router(biocommons_groups.router)
