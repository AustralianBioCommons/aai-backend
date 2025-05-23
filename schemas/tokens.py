from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class AccessTokenPayload(BaseModel):
    """
    Schema for the access token payload.
    """

    biocommons_roles: list[str] = Field(
        alias="https://biocommons.org.au/roles",
        description="BioCommons-specific roles assigned to the user",
    )
    email: Optional[str] = Field(None, description="Email address")
    iss: str = Field(description="Issuer identifier")
    sub: str = Field(description="Subject identifier")
    aud: list[str] = Field(description="Audience(s) that this token is intended for")
    exp: int = Field(description="Expiration time (as Unix timestamp)")
    iat: int = Field(description="Issued at time (as Unix timestamp)")
    azp: Optional[str] = Field(None, description="Authorized party")
    permissions: list[str] = Field(description="Permissions granted to the user")

    # Set populate_by_name so we can specify biocommons_roles as an argument
    model_config = ConfigDict(populate_by_name=True)
