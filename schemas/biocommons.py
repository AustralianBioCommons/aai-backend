"""
Schemas for how we represent users in Auth0 for BioCommons.

These are the core schemas we use for storing/representing users
and their metadata
"""
import re
from datetime import datetime, timezone
from typing import Annotated, List, Literal, Optional, Self

from pydantic import BaseModel, EmailStr, Field, HttpUrl, StringConstraints

import schemas.bpa
import schemas.galaxy
from schemas import Resource, Service
from schemas.service import Group, Identity

# From Auth0 password settings
ALLOWED_SPECIAL_CHARS = "!@#$%^&*"
VALID_PASSWORD_REGEX = re.compile(f"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[{ALLOWED_SPECIAL_CHARS}]).{{8,}}$")

AppId = Literal["biocommons", "galaxy", "bpa"]
BiocommonsUsername = Annotated[str, StringConstraints(min_length=3, max_length=100, pattern='^[-_a-z0-9]+$')]
BiocommonsPassword = Annotated[str, StringConstraints(min_length=8, pattern=VALID_PASSWORD_REGEX)]


class BPAMetadata(BaseModel):
    registration_reason: str
    username: str


class BiocommonsUserMetadata(BaseModel):
    """
    User metadata we use for user-changeable data
    like preferred usernames
    """
    bpa: Optional[BPAMetadata] = None
    galaxy_username: Optional[str] = None


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

    def get_resource_by_id(self, service_id: str, resource_id: str) -> Optional[Resource]:
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
            raise ValueError(f"Resource '{resource_id}' not found in service '{service_id}'.")

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
    username: Optional[str] = None
    user_metadata: Optional[BiocommonsUserMetadata] = None
    app_metadata: BiocommonsAppMetadata

    @classmethod
    def from_bpa_registration(
            cls,
            registration: 'schemas.bpa.BPARegistrationRequest',
            bpa_service: Service) -> Self:
        return cls(
            email=registration.email,
            password=registration.password,
            username=registration.username,
            name=registration.fullname,
            user_metadata=BiocommonsUserMetadata(
                bpa=BPAMetadata(registration_reason=registration.reason,
                                username=registration.username,),
            ),
            app_metadata=BiocommonsAppMetadata(
                services=[bpa_service],
                registration_from="bpa"
            ),
        )

    @classmethod
    def from_galaxy_registration(
            cls,
            registration: 'schemas.galaxy.GalaxyRegistrationData',):
        # Galaxy registration is approved automatically
        galaxy_service = Service(
            name="Galaxy Australia",
            id="galaxy",
            initial_request_time=datetime.now(),
            status="approved",
            last_updated=datetime.now(),
            updated_by=""
        )
        return BiocommonsRegisterData(
            email=registration.email,
            user_metadata=BiocommonsUserMetadata(galaxy_username=registration.public_name),
            password=registration.password,
            email_verified=False,
            connection="Username-Password-Authentication",
            app_metadata=BiocommonsAppMetadata(
                services=[galaxy_service],
                registration_from='galaxy'
            ),
        )


class BiocommonsAuth0User(BaseModel):
    """
    Represents the user data we get back from Auth0 for Biocommons users
    (with our user and app metadata, if defined).
    """
    created_at: datetime
    email: EmailStr
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
