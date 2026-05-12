from typing import Optional

from pydantic import BaseModel, EmailStr

from biocommons.bundles import BundleType
from schemas.biocommons import BiocommonsPassword, BiocommonsUsername


class BundleRequest(BaseModel):
    bundle_id: BundleType
    reason: Optional[str] = None


class BiocommonsRegistrationRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    username: BiocommonsUsername
    password: BiocommonsPassword
    bundles: Optional[list[BundleRequest]] = None
    recaptcha_token: Optional[str] = None
