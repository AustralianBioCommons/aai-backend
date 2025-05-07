from pydantic import BaseModel


class ServiceRequest(BaseModel):
    name: str
    id: str
    user_id: str


class ResourceRequest(BaseModel):
    name: str
    id: str
    service_id: str
    user_id: str
