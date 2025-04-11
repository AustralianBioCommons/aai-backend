from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class Resource(BaseModel):
    name: str
    status: str
    id: str

class Service(BaseModel):
    name: str
    id: str
    status: str
    last_updated: datetime
    updated_by: str
    resources: Optional[List[Resource]] = None