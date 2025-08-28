from typing import Dict

from pydantic import BaseModel, EmailStr

from schemas.biocommons import BiocommonsPassword, BiocommonsUsername


class BPARegistrationRequest(BaseModel):
    username: BiocommonsUsername
    fullname: str
    email: EmailStr
    reason: str
    password: BiocommonsPassword
    organizations: Dict[str, bool]

class OrgOut(BaseModel):
    """
    Minimal org payload for the portal dropdown.
    """
    id: str
    name: str
    title: str
