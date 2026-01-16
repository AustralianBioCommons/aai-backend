from functools import lru_cache
from typing import Literal, Optional

from pydantic import EmailStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    environment: Literal["dev", "staging", "production"] = "dev"
    auth0_domain: str
    auth0_custom_domain: Optional[str] = None
    auth0_management_id: str
    auth0_management_secret: str
    auth0_audience: str
    # Optional: issuer may be different to the auth0_domain if
    #   a custom domain is used
    auth0_issuer: Optional[str] = None
    recaptcha_secret: str
    auth0_db_connection: str = "Username-Password-Authentication"
    jwt_secret_key: str
    auth0_algorithms: list[str] = ["RS256"]
    admin_roles: list[str] = []
    enable_admin_dashboard: bool = False
    # Note we process this separately in app startup as it needs
    #   to be available before the app starts
    cors_allowed_origins: str
    # AAI Portal URL for admin links in emails
    aai_portal_url: Optional[str] = None
    # Default sender for outbound emails
    default_email_sender: Optional[EmailStr] = None
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

    @field_validator("environment", mode="before")
    @classmethod
    def normalize_environment(cls, value: str | None) -> Literal["dev", "staging", "production"]:
        normalized = str(value).strip().lower()
        if normalized in {"dev", "development"}:
            return "dev"
        if normalized in {"staging", "stage"}:
            return "staging"
        if normalized in {"prod", "production"}:
            return "production"
        return normalized

    @field_validator('auth0_custom_domain', mode="after")
    @classmethod
    def strip_trailing_slash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.rstrip("/")

    @field_validator("aai_portal_url", mode="after")
    @classmethod
    def strip_aai_portal_trailing_slash(self, value: str | None) -> str | None:
        if value is None:
            return None
        return value.rstrip("/")

    @model_validator(mode="after")
    def set_default_aai_portal_url(self) -> "Settings":
        if self.aai_portal_url:
            return self
        env_to_url = {
            "dev": "https://dev.portal.aai.test.biocommons.org.au",
            "staging": "https://staging.portal.aai.test.biocommons.org.au",
            "production": "https://production.portal.aai.test.biocommons.org.au",
        }
        default_url = env_to_url.get(self.environment)
        if not default_url:
            raise ValueError(
                "Unknown ENVIRONMENT value and AAI_PORTAL_URL is not set."
            )
        self.aai_portal_url = default_url
        return self

    @model_validator(mode="after")
    def set_default_email_sender(self) -> "Settings":
        """
        Set based on environment name if not set explicitly
        """
        if self.default_email_sender:
            return self
        self.default_email_sender = f"{self.environment}@aai.test.biocommons.org.au"
        return self


@lru_cache()
def get_settings():
    return Settings()
