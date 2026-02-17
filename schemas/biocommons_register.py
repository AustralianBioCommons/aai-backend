from typing import Optional

from pydantic import BaseModel, EmailStr

from biocommons.bundles import BundleType
from schemas.biocommons import BiocommonsPassword, BiocommonsUsername


class BiocommonsRegistrationRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    username: BiocommonsUsername
    password: BiocommonsPassword
    bundle: Optional[BundleType] = None
    request_reason: Optional[str] = None
    recaptcha_token: Optional[str] = None
