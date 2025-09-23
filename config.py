from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    auth0_domain: str
    auth0_management_id: str
    auth0_management_secret: str
    auth0_audience: str
    # Optional: issuer may be different to the auth0_domain if
    #   a custom domain is used
    auth0_issuer: Optional[str] = None
    jwt_secret_key: str
    auth0_algorithms: list[str] = ["RS256"]
    admin_roles: list[str] = []
    send_email: bool = False
    # Note we process this separately in app startup as it needs
    #   to be available before the app starts
    cors_allowed_origins: str
    # AAI Portal URL for admin links in emails
    aai_portal_url: str = "https://aaiportal.test.biocommons.org.au"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache()
def get_settings():
    return Settings()
