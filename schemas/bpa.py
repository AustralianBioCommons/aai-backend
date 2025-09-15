from pydantic import BaseModel, EmailStr

from schemas.biocommons import BiocommonsPassword, BiocommonsUsername


class BPARegistrationRequest(BaseModel):
    username: BiocommonsUsername
    fullname: str
    email: EmailStr
    reason: str
    password: BiocommonsPassword
