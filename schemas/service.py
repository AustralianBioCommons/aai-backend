from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class Resource(BaseModel):
    name: str
    status: Literal["approved", "revoked", "pending"]
    id: str
    last_updated: Optional[datetime] = None
    updated_by: Optional[str] = None

    def approve(self):
        self.status = "approved"

    def revoke(self):
        self.status = "revoked"


class Service(BaseModel):
    name: str
    id: str
    status: Literal["approved", "revoked", "pending"]
    last_updated: datetime
    updated_by: str
    resources: List[Resource] = Field(default_factory=list)

    def approve(self, updated_by: str):
        self.status = "approved"
        self.updated_by = updated_by
        self.last_updated = datetime.now()

    def revoke(self, updated_by: str):
        self.status = "revoked"
        self.updated_by = updated_by
        self.last_updated = datetime.now()

    def approve_resource(self, resource_id: str):
        if not self.status == "approved":
            raise PermissionError("Service must be approved before approving a resource.")
        resource = self.get_resource_by_id(resource_id)
        if resource:
            resource.approve()
            self.last_updated = datetime.now()
            return resource
        else:
            raise ValueError("Resource not found.")

    def get_resource_by_id(self, resource_id: str) -> Optional[Resource]:
        return next((r for r in self.resources if r.id == resource_id), None)


class Group(BaseModel):
    name: str
    id: str


class Identity(BaseModel):
    connection: str
    provider: str
    user_id: str
    isSocial: bool
