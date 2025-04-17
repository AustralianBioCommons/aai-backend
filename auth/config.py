from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    auth0_domain: str
    auth0_management_id: str
    auth0_management_secret: str
    auth0_audience: str
    auth0_algorithms: list[str] = ["RS256"]

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache()
def get_settings():
    return Settings()