from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    auth0_domain: str
    auth0_custom_domain: Optional[str] = None
    auth0_management_id: str
    auth0_management_secret: str
    auth0_audience: str
    # Optional: issuer may be different to the auth0_domain if
    #   a custom domain is used
    auth0_issuer: Optional[str] = None
    auth0_db_connection: str = "Username-Password-Authentication"
    jwt_secret_key: str
    auth0_algorithms: list[str] = ["RS256"]
    admin_roles: list[str] = []
    enable_admin_dashboard: bool = False
    # Note we process this separately in app startup as it needs
    #   to be available before the app starts
    cors_allowed_origins: str
    # AAI Portal URL for admin links in emails
    aai_portal_url: str = "https://aaiportal.test.biocommons.org.au"
    # Allowed email domains for SBP registration
    sbp_allowed_email_domains: list[str] = [
        # UNSW
        "unsw.edu.au", "ad.unsw.edu.au", "student.unsw.edu.au",
        # BioCommons
        "biocommons.org.au",
        # USyd
        "sydney.edu.au", "uni.sydney.edu.au",
        # WEHI
        "wehi.edu.au",
        # Monash
        "monash.edu", "student.monash.edu",
        # Griffith
        "griffith.edu.au", "griffithuni.edu.au",
        # UoM
        "unimelb.edu.au", "student.unimelb.edu.au"
    ]

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache()
def get_settings():
    return Settings()
