from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from auth.config import get_settings
from routers import user
from routers import galaxy_register

app = FastAPI()
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],  # Include 'registration-token' if needed
)


@app.get("/")
def public_route():
    return {"message": "AAI Backend API"}


app.include_router(user.router)
app.include_router(galaxy_register.router)