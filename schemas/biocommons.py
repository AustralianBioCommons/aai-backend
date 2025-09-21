"""
Schemas for how we represent users in Auth0 for BioCommons.

These are the core schemas we use for storing/representing users
and their metadata
"""

import re
from datetime import datetime
from typing import Annotated, List, Literal, Optional, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    EmailStr,
    Field,
    HttpUrl,
)
from pydantic_core import PydanticCustomError

import db
import schemas
from db.types import GroupMembershipData, PlatformMembershipData

# From Auth0 password settings
ALLOWED_SPECIAL_CHARS = "!@#$%^&*"
VALID_PASSWORD_REGEX = re.compile(
    f"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[{ALLOWED_SPECIAL_CHARS}]).{{8,}}$"
)
PASSWORD_FORMAT_MESSAGE = (
    "Password must contain at least one uppercase letter, one lowercase letter, one number, "
    f"and one special character. Allowed special characters: {ALLOWED_SPECIAL_CHARS}"
)


def ValidatedString(
    *,
    min_length: int | None = None,
    max_length: int | None = None,
    pattern: str | re.Pattern[str] | None = None,
    messages: dict[Literal["min_length", "max_length", "pattern"] , str] | None = None,
):
    """
    Define a string type where we can customize the error messages to make
     them more user-friendly – pydantic's
    StringConstraints doesn't support this easily
    """
    compiled = re.compile(pattern) if pattern else None

    def _check(v: str) -> str:
        if not isinstance(v, str):
            raise PydanticCustomError("string_type", "Value must be a string.")

        if min_length is not None and len(v) < min_length:
            raise PydanticCustomError("string_too_short", messages["min_length"] or f"Must be at least {min_length} characters.")

        if max_length is not None and len(v) > max_length:
            raise PydanticCustomError("string_too_long", messages["max_length"] or f"Must be at most {max_length} characters.")

        if compiled and not compiled.fullmatch(v):
            raise PydanticCustomError("string_pattern_mismatch", messages["pattern"] or "Invalid format.")

        return v

    # Use only AfterValidator so OUR messages are the ones users see
    return Annotated[str, AfterValidator(_check)]


AppId = Literal["biocommons", "galaxy", "bpa", "sbp"]
BiocommonsUsername = ValidatedString(min_length=3, max_length=128, pattern="^[-_a-z0-9]+$", messages={
    "min_length": "Username must be at least 3 characters.",
    "max_length": "Username must be 128 characters or less.",
    "pattern": "Username must only contain lowercase letters, numbers, hyphens and underscores."
})
BiocommonsPassword = ValidatedString(min_length=8, max_length=128, pattern=VALID_PASSWORD_REGEX, messages={
    "min_length": "Password must be at least 8 characters.",
    "max_length": "Password must be 128 characters or less.",
    "pattern": PASSWORD_FORMAT_MESSAGE
})


class BPAMetadata(BaseModel):
    registration_reason: str


class SBPMetadata(BaseModel):
    registration_reason: str


class BiocommonsUserMetadata(BaseModel):
    """
    User metadata we use for user-changeable data
    like preferred usernames
    """

    bpa: Optional[BPAMetadata] = None
    sbp: Optional[SBPMetadata] = None


class BiocommonsAppMetadata(BaseModel):
    """
    app_metadata we use to store Auth0-specific info
    Note we expect all app_metadata from Auth0 to match this format
    (if not empty).
    """
    registration_from: Optional[AppId] = None

    model_config = {
        "extra": "ignore"
    }


class BiocommonsRegisterData(BaseModel):
    """
    Data we send to the /api/v2/users endpoint to register a user
    """

    email: EmailStr
    email_verified: bool = False
    password: BiocommonsPassword
    connection: str = "Username-Password-Authentication"
    username: BiocommonsUsername
    name: Optional[str] = None
    user_metadata: Optional[BiocommonsUserMetadata] = None
    app_metadata: BiocommonsAppMetadata

    def model_dump(self, **kwargs):
        """Override model_dump to exclude user_metadata when it's None"""
        data = super().model_dump(**kwargs)
        if data.get("user_metadata") is None:
            data.pop("user_metadata", None)
        return data

    @classmethod
    def from_bpa_registration(
        cls, registration: "schemas.bpa.BPARegistrationRequest"
    ) -> Self:
        return cls(
            email=registration.email,
            password=registration.password,
            username=registration.username,
            name=registration.fullname,
            user_metadata=BiocommonsUserMetadata(
                bpa=BPAMetadata(registration_reason=registration.reason),
            ),
            app_metadata=BiocommonsAppMetadata(
                registration_from="bpa"
            ),
        )

    @classmethod
    def from_sbp_registration(
        cls, registration: "schemas.sbp.SBPRegistrationRequest"
    ) -> Self:
        return cls(
            email=registration.email,
            password=registration.password,
            username=registration.username,
            name=f"{registration.first_name} {registration.last_name}",
            user_metadata=BiocommonsUserMetadata(
                sbp=SBPMetadata(registration_reason=registration.reason),
            ),
            app_metadata=BiocommonsAppMetadata(
                registration_from="sbp"
            ),
        )

    @classmethod
    def from_galaxy_registration(
        cls,
        registration: "schemas.galaxy.GalaxyRegistrationData",
    ):
        return BiocommonsRegisterData(
            email=registration.email,
            username=registration.username,
            password=registration.password,
            email_verified=False,
            connection="Username-Password-Authentication",
            app_metadata=BiocommonsAppMetadata(
                registration_from="galaxy"
            ),
        )

    @classmethod
    def from_biocommons_registration(
        cls,
        registration: "schemas.biocommons_register.BiocommonsRegistrationRequest",
    ):
        return BiocommonsRegisterData(
            email=registration.email,
            username=registration.username,
            password=registration.password,
            name=f"{registration.first_name} {registration.last_name}",
            email_verified=False,
            connection="Username-Password-Authentication",
            app_metadata=BiocommonsAppMetadata(
                registration_from="biocommons",
            ),
        )


class Auth0Identity(BaseModel):
    connection: str
    provider: str
    user_id: str
    isSocial: bool


class Auth0UserData(BaseModel):
    """
    Represents the user data we get back from Auth0 for Biocommons users
    (with our user and app metadata, if defined).
    """

    created_at: datetime
    email: EmailStr
    username: Optional[BiocommonsUsername] = None
    email_verified: bool
    identities: List[Auth0Identity]
    name: str
    nickname: str
    picture: HttpUrl
    updated_at: datetime
    user_id: str
    # Auth0 will not include user/app metadata in the response when
    #   empty, so make it optional
    user_metadata: Optional[BiocommonsUserMetadata] = None
    app_metadata: Optional[BiocommonsAppMetadata] = None
    last_ip: Optional[str] = None
    last_login: Optional[datetime] = None
    logins_count: Optional[int] = None


class Auth0UserDataWithMemberships(Auth0UserData):
    """
    User data from Auth0, plus group and platform membership data from our
    database
    """
    platform_memberships: list[PlatformMembershipData] = Field(default_factory=list)
    group_memberships: list[GroupMembershipData] = Field(default_factory=list)

    @classmethod
    def from_auth0_data(cls, auth0_data: Auth0UserData, db_data: 'db.models.BiocommonsUser') -> Self:
        """
        Create from Auth0 user data and DB user data.
        """
        platforms = [platform.get_data() for platform in db_data.platform_memberships]
        groups = [group.get_data() for group in db_data.group_memberships]
        return cls(**auth0_data.model_dump(), platform_memberships=platforms, group_memberships=groups)
