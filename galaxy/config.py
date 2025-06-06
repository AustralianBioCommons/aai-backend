from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class GalaxySettings(BaseSettings):
    """
    Settings for the Galaxy API.

    Note: these are currently read from the same .env file
    as other settings (which pydantic-settings supports).
    """
    galaxy_url: str
    galaxy_api_key: str

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache
def get_galaxy_settings():
    return GalaxySettings()
