from typing import Literal

from pydantic import BaseModel, EmailStr

from schemas.biocommons import BiocommonsPassword, BiocommonsUsername

BundleType = Literal["bpa-galaxy", "tsi"]


class BiocommonsRegistrationRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    username: BiocommonsUsername
    password: BiocommonsPassword
    bundle: BundleType
