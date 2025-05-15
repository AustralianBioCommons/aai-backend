from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from auth.config import get_settings
from routers import galaxy_register, user


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Set up CORS middleware after startup so we can override it in testing
    :param app:
    :return:
    """
    settings = app.dependency_overrides.get(get_settings, get_settings)()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )

    yield

app = FastAPI(lifespan=lifespan)


@app.get("/")
def public_route():
    return {"message": "AAI Backend API"}


app.include_router(user.router)
app.include_router(galaxy_register.router)