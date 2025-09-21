from pydantic import BaseModel, EmailStr

from schemas.biocommons import BiocommonsPassword, BiocommonsUsername


class SBPRegistrationRequest(BaseModel):
    first_name: str
    last_name: str
    username: BiocommonsUsername
    email: EmailStr
    reason: str
    password: BiocommonsPassword
