import os

from dotenv import load_dotenv
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from routers import galaxy_register, user

# Load .env to get CORS_ALLOWED_ORIGINS.
# Note that for most env variables, we use pydantic-settings
#   and load them via auth.config. But we need the
#   allowed_origins before we load the app
load_dotenv()
ALLOWED_ORIGINS = [origin.strip()
                   for origin in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")]

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.get("/")
def public_route():
    return {"message": "AAI Backend API"}


app.include_router(user.router)
app.include_router(galaxy_register.router)
