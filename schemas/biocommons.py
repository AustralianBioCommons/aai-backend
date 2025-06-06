"""
Schemas for how we represent users in Auth0 for BioCommons.

These are the core schemas we use for storing/representing users
and their metadata
"""
from datetime import datetime
from typing import List, Literal, Optional, Self

from pydantic import BaseModel, EmailStr, Field, HttpUrl

from schemas import Resource, Service
from schemas.bpa import BPARegistrationRequest
from schemas.galaxy import GalaxyRegistrationData
from schemas.service import Group, Identity

AppId = Literal["biocommons", "galaxy", "bpa"]


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
    signup_from: Optional[AppId] = None

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

    def approve_resource(self, service_id: str, resource_id: str):
        """Approve a resource by its ID."""
        resource = self.get_resource_by_id(service_id=service_id, resource_id=resource_id)
        if resource:
            resource.approve()
            return resource
        else:
            raise ValueError("Resource not found.")


class BiocommonsRegisterData(BaseModel):
    """
    Data we send to the /api/v2/users endpoint to register a user
    """
    email: EmailStr
    email_verified: bool = False
    password: str
    connection: str = "Username-Password-Authentication"
    username: str
    name: Optional[str] = None
    username: Optional[str] = None
    user_metadata: BiocommonsUserMetadata
    app_metadata: BiocommonsAppMetadata

    @classmethod
    def from_bpa_registration(
            cls, registration: BPARegistrationRequest,
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
                signup_from="bpa"
            ),
        )

    @classmethod
    def from_galaxy_registration(
            cls,
            registration: GalaxyRegistrationData):
        # Galaxy registration is approved automatically
        galaxy_service = Service(
            name="Galaxy Australia",
            id="galaxy",
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
                signup_from='galaxy'
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
