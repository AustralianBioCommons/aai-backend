from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr

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

    model_config = ConfigDict(extra="forbid")


class AafRegistrationRequest(BaseModel):
    """
    email and name come from AAF and are encoded in the session_token,
    which needs to be verified.
    """
    session_token: str
    # Auth0 redirect state; when present the endpoint returns a redirect_url that
    # resumes the post-login action at Auth0 /continue. Optional so non-redirect
    # callers (and existing tests) still work.
    state: Optional[str] = None
    username: BiocommonsUsername
    bundles: Optional[list[BundleRequest]] = None
    recaptcha_token: Optional[str] = None
