from typing import Dict

from pydantic import BaseModel, EmailStr


class BPARegistrationRequest(BaseModel):
    username: str
    fullname: str
    email: EmailStr
    reason: str
    password: str
    organizations: Dict[str, bool]
