from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AdminSettings(BaseSettings):
    """
    Settings used by starlette-admin, which currently requires a separate
    Auth0 app to that used by the main backend service
    """
    auth0_custom_domain: Optional[str] = None
    admin_client_id: Optional[str] = None
    admin_client_secret: Optional[str] = None
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @field_validator("auth0_custom_domain", mode="before")
    def strip_trailing_slash(cls, value: str) -> str:
        if isinstance(value, str):
            return value.rstrip("/")
        return value


def get_admin_settings() -> AdminSettings:
    return AdminSettings()
