from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from schemas.biocommons import BiocommonsAppMetadata


class Auth0UserResponse(BaseModel):
    """
    Response returned by Auth0's /users endpoint.
    Note we have our own BiocommonsAuth0User model
    that includes specifying the metadata fields we use.
    """
    user_id: str
    email: EmailStr
    email_verified: bool
    username: Optional[str] = None
    phone_number: Optional[str] = None
    phone_verified: Optional[bool] = None
    created_at: datetime
    updated_at: datetime
    identities: List[dict]
    app_metadata: BiocommonsAppMetadata = Field(default_factory=BiocommonsAppMetadata)
    user_metadata: Optional[dict] = None
    picture: Optional[str] = None
    name: Optional[str] = None
    nickname: Optional[str] = None
    last_ip: Optional[str] = None
    last_login: Optional[datetime] = None
    logins_count: Optional[int] = None
    blocked: Optional[bool] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None

    model_config = ConfigDict(extra="allow")
