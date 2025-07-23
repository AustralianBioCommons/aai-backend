import logging
from typing import Annotated, Optional

import httpx
from fastapi import APIRouter, Header, HTTPException
from fastapi.params import Depends

from auth.management import get_management_token
from config import Settings, get_settings
from galaxy.client import GalaxyClient, get_galaxy_client
from register.tokens import create_registration_token, verify_registration_token
from schemas.biocommons import BiocommonsRegisterData
from schemas.galaxy import GalaxyRegistrationData

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/galaxy", tags=["galaxy", "registration"]
)


@router.get("/get-registration-token")
async def get_registration_token(settings: Settings = Depends(get_settings)):
    return {"token": create_registration_token(settings)}


@router.post("/register")
def register(
        registration_data: GalaxyRegistrationData,
        settings: Annotated[Settings, Depends(get_settings)],
        galaxy_client: Annotated[GalaxyClient, Depends(get_galaxy_client)],
        registration_token: Optional[str] = Header(None),
):
    if not registration_token:
        raise HTTPException(status_code=400, detail="Missing registration token")

    verify_registration_token(registration_token, settings=settings)
    logger.debug("Registration token verified.")

    user_data = BiocommonsRegisterData.from_galaxy_registration(registration_data)
    logger.debug("Checking if username exists in Galaxy")
    galaxy_username = user_data.user_metadata.galaxy_username
    try:
        existing = galaxy_client.username_exists(galaxy_username)
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
    except httpx.HTTPError as e:
        logger.warning(f"Failed to check username in Galaxy: {e}")

    url = f"https://{settings.auth0_domain}/api/v2/users"
    logger.debug("Getting management token.")
    management_token = get_management_token(settings=settings)
    headers = {"Authorization": f"Bearer {management_token}"}
    logger.debug("Registering with Auth0 management API")
    resp = httpx.post(
        url,
        # Use exclude_none so we don't include username/name fields
        #   when not specified, Auth0 doesn't like this
        json=user_data.model_dump(
            mode="json",
            exclude_none=True
        ),
        headers=headers
    )
    if resp.status_code != 201:
        raise HTTPException(status_code=400, detail=f'Registration failed: {resp.json()["message"]}')
    return {"message": "User registered successfully", "user": resp.json()}
