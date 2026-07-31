from typing import Annotated

import httpx
from fastapi.params import Depends
from pydantic import BaseModel, ConfigDict, Field

from auth import get_auth0_token
from config import Settings, get_settings


class UserInfo(BaseModel):
    sub: str
    name: str
    email: str
    picture: str
    email_verified: bool
    given_name: str | None = None
    family_name: str | None = None
    show_welcome_message: bool | None = Field(None, alias="https://biocommons.org.au/show_migration_welcome")

    # AAF core attributes — namespaced claims added by the Auth0 post-login Action
    # (only present for AAF logins where AAF released the attribute). Multi-valued
    # eduPerson attributes may arrive as a list.
    aaf_scoped_affiliation: str | list[str] | None = Field(
        None, alias="https://biocommons.org.au/aaf/eduperson_scoped_affiliation")
    aaf_affiliation: str | list[str] | None = Field(
        None, alias="https://biocommons.org.au/aaf/eduperson_affiliation")
    aaf_assurance: str | list[str] | None = Field(
        None, alias="https://biocommons.org.au/aaf/eduperson_assurance")
    aaf_entitlement: str | list[str] | None = Field(
        None, alias="https://biocommons.org.au/aaf/eduperson_entitlement")
    aaf_principal_name: str | None = Field(
        None, alias="https://biocommons.org.au/aaf/eduperson_principal_name")
    aaf_home_organization: str | None = Field(
        None, alias="https://biocommons.org.au/aaf/schac_home_organization")
    aaf_home_organization_type: str | list[str] | None = Field(
        None, alias="https://biocommons.org.au/aaf/schac_home_organization_type")

    model_config = ConfigDict(validate_by_name=True, validate_by_alias=True)


async def get_auth0_user_info(
        auth0_token: Annotated[str, Depends(get_auth0_token)],
        settings: Annotated[Settings, Depends(get_settings)]) -> UserInfo:
    """
    Fetch and return user info from Auth0's userinfo endpoint for the current user.
    Doesn't require management API access so may be more efficient when
    only the current user is required
    """
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://{settings.auth0_domain}/userinfo", headers={
                "Authorization": f"Bearer {auth0_token}"
            })
    resp.raise_for_status()
    return UserInfo(**resp.json())
