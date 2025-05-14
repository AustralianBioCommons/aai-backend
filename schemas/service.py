from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class Resource(BaseModel):
    name: str
    status: Literal["approved", "revoked", "pending"]
    id: str


class Service(BaseModel):
    name: str
    id: str
    status: Literal["approved", "revoked", "pending"]
    last_updated: datetime
    updated_by: str
    resources: List[Resource] = Field(default_factory=list)


class Group(BaseModel):
    name: str
    id: str


class AppMetadata(BaseModel):
    groups: List[Group] = Field(default_factory=list)
    services: List[Service] = Field(default_factory=list)

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


class Identity(BaseModel):
    connection: str
    provider: str
    user_id: str
    isSocial: bool


class Auth0User(BaseModel):
    created_at: datetime
    email: str
    email_verified: bool
    identities: List[Identity]
    name: str
    nickname: str
    picture: HttpUrl
    updated_at: datetime
    user_id: str
    user_metadata: dict = Field(default_factory=dict)
    app_metadata: AppMetadata
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
