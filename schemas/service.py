from pydantic import BaseModel, Field
from typing import Literal
from datetime import datetime

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
    resources: list[Resource] = Field(default_factory=list)
