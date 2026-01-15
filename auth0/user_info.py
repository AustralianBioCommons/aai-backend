from typing import Annotated

import httpx
from fastapi.params import Depends
from pydantic import BaseModel

from auth.validator import oauth2_scheme
from config import Settings, get_settings


class UserInfo(BaseModel):
    sub: str
    name: str
    email: str
    picture: str
    email_verified: bool
    given_name: str | None = None
    family_name: str | None = None


async def get_auth0_user_info(
        token: Annotated[str, Depends(oauth2_scheme)],
        settings: Annotated[Settings, Depends(get_settings)]) -> UserInfo:
    """
    Fetch and return user info from Auth0's userinfo endpoint for the current user.
    Doesn't require management API access so may be more efficient when
    only the current user is required
    """
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://{settings.auth0_domain}/userinfo", headers={
                "Authorization": f"Bearer {token}"
            })
    resp.raise_for_status()
    return UserInfo(**resp.json())
