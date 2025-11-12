from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AdminSettings(BaseSettings):
    auth0_custom_domain: Optional[str]
    admin_client_id: Optional[str]
    admin_client_secret: Optional[str]
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @field_validator("auth0_custom_domain", mode="before")
    def strip_trailing_slash(cls, value: str) -> str:
        if isinstance(value, str):
            return value.rstrip("/")
        return value
