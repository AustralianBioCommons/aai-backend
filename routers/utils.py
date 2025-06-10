from typing import Annotated

from fastapi import APIRouter
from fastapi.params import Depends
from pydantic import BaseModel

from auth0.client import Auth0Client, get_auth0_client
from schemas.biocommons import AppId

router = APIRouter(prefix="/utils", tags=["utils"])


class RegistrationInfo(BaseModel):
    app: AppId = "biocommons"


@router.get("/registration_info")
async def get_registration_info(
        user_email: str,
        client: Annotated[Auth0Client, Depends(get_auth0_client)]):
    """
    Return the app a user used to register, if available in app_metadata.
    """
    results = client.search_users_by_email(email=user_email)
    for user in results:
        current_email = str(user.email).lower()
        if current_email == user_email.lower():
            if user.app_metadata.registration_from is None:
                return RegistrationInfo(app="biocommons")
            return RegistrationInfo(app=user.app_metadata.registration_from)
    return RegistrationInfo(app="biocommons")
