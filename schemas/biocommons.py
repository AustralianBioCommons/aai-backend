"""
Schemas for how we represent users in Auth0 for BioCommons.

These are the core schemas we use for storing/representing users
and their metadata
"""

import re
from datetime import datetime, timezone
from typing import Annotated, List, Literal, Optional, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    EmailStr,
    Field,
    HttpUrl,
)
from pydantic_core import PydanticCustomError

import schemas
from schemas import Resource, Service
from schemas.service import Group, Identity

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


AppId = Literal["biocommons", "galaxy", "bpa"]
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


class BiocommonsUserMetadata(BaseModel):
    """
    User metadata we use for user-changeable data
    like preferred usernames
    """

    bpa: Optional[BPAMetadata] = None


class BiocommonsAppMetadata(BaseModel):
    """
    app_metadata we use to manage service/resource requests.
    Note we expect all app_metadata from Auth0 to match this format
    (if not empty).
    """

    groups: List[Group] = Field(default_factory=list)
    services: List[Service] = Field(default_factory=list)
    registration_from: Optional[AppId] = None

    def get_pending_services(self) -> List[Service]:
        """Get all pending services."""
        return [s for s in self.services if s.status == "pending"]

    def get_approved_services(self) -> List[Service]:
        """Get all approved services."""
        return [s for s in self.services if s.status == "approved"]

    def get_all_resources(self) -> List[Resource]:
        """Get all resources across services."""
        return [r for s in self.services for r in s.resources]

    def get_pending_resources(self) -> List[Resource]:
        """Get all pending resources."""
        return [r for s in self.services for r in s.resources if r.status == "pending"]

    def get_approved_resources(self) -> List[Resource]:
        """Get all approved resources."""
        return [r for s in self.services for r in s.resources if r.status == "approved"]

    def get_service_by_id(self, service_id: str) -> Optional[Service]:
        """Get a service by its ID."""
        return next((s for s in self.services if s.id == service_id), None)

    def get_resource_by_id(
        self, service_id: str, resource_id: str
    ) -> Optional[Resource]:
        """Get a resource by its ID."""
        service = self.get_service_by_id(service_id)
        if service:
            return service.get_resource_by_id(resource_id)
        else:
            return None

    def approve_service(self, service_id: str, updated_by: str):
        """Approve a service by its ID."""
        service = self.get_service_by_id(service_id)
        if service:
            service.approve(updated_by)

    def revoke_service(self, service_id: str, updated_by: str):
        """Revoke a service by its ID."""
        service = self.get_service_by_id(service_id)
        if service:
            service.revoke(updated_by=updated_by)

    def approve_resource(self, service_id: str, resource_id: str, updated_by: str):
        service = self.get_service_by_id(service_id)
        if not service:
            raise ValueError(f"Service '{service_id}' not found.")

        resource = service.get_resource_by_id(resource_id)
        if not resource:
            raise ValueError(
                f"Resource '{resource_id}' not found in service '{service_id}'."
            )

        resource.status = "approved"
        resource.last_updated = datetime.now(timezone.utc)
        resource.updated_by = updated_by


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
        cls, registration: "schemas.bpa.BPARegistrationRequest", bpa_service: Service
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
                services=[bpa_service], registration_from="bpa"
            ),
        )

    @classmethod
    def from_galaxy_registration(
        cls,
        registration: "schemas.galaxy.GalaxyRegistrationData",
    ):
        # Galaxy registration is approved automatically
        galaxy_service = Service(
            name="Galaxy Australia",
            id="galaxy",
            initial_request_time=datetime.now(),
            status="approved",
            last_updated=datetime.now(),
            updated_by="",
        )
        return BiocommonsRegisterData(
            email=registration.email,
            username=registration.username,
            password=registration.password,
            email_verified=False,
            connection="Username-Password-Authentication",
            app_metadata=BiocommonsAppMetadata(
                services=[galaxy_service], registration_from="galaxy"
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


class Auth0UserData(BaseModel):
    """
    Represents the user data we get back from Auth0 for Biocommons users
    (with our user and app metadata, if defined).
    """

    created_at: datetime
    email: EmailStr
    username: Optional[BiocommonsUsername] = None
    email_verified: bool
    identities: List[Identity]
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

    @property
    def pending_services(self) -> List[Service]:
        """Get all services with pending status."""
        return self.app_metadata.get_pending_services()

    @property
    def approved_services(self) -> List[Service]:
        """Get all services with approved status."""
        return self.app_metadata.get_approved_services()

    @property
    def pending_resources(self) -> List[Resource]:
        """Get all resources with pending status across all services."""
        return self.app_metadata.get_pending_resources()

    @property
    def approved_resources(self) -> List[Resource]:
        """Get all resources with approved status across all services."""
        return self.app_metadata.get_approved_resources()
