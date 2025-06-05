import logging
from typing import Optional

import httpx
from fastapi import APIRouter, Header, HTTPException
from fastapi.params import Depends

from auth.config import Settings, get_settings
from auth.management import get_management_token
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
        registration_token: Optional[str] = Header(None),
        settings: Settings = Depends(get_settings),
):
    if not registration_token:
        raise HTTPException(status_code=400, detail="Missing registration token")

    verify_registration_token(registration_token, settings=settings)
    logger.debug("Registration token verified.")

    url = f"https://{settings.auth0_domain}/api/v2/users"
    logger.debug("Getting management token.")
    management_token = get_management_token(settings=settings)
    headers = {"Authorization": f"Bearer {management_token}"}
    user_data = BiocommonsRegisterData.from_galaxy_registration(registration_data)
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
