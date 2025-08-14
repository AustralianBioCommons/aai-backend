import logging
from typing import Annotated, Optional

import httpx
from fastapi import APIRouter, Header, HTTPException
from fastapi.params import Depends
from sqlmodel import Session

from auth0.client import Auth0Client, get_auth0_client
from config import Settings, get_settings
from db.models import BiocommonsUser, PlatformEnum
from db.setup import get_db_session
from galaxy.client import GalaxyClient, get_galaxy_client
from register.tokens import create_registration_token, verify_registration_token
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData
from schemas.galaxy import GalaxyRegistrationData

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/galaxy", tags=["galaxy", "registration"]
)


@router.get("/register/get-registration-token")
async def get_registration_token(settings: Settings = Depends(get_settings)):
    return {"token": create_registration_token(settings)}


@router.post("/register")
def register(
        registration_data: GalaxyRegistrationData,
        settings: Annotated[Settings, Depends(get_settings)],
        galaxy_client: Annotated[GalaxyClient, Depends(get_galaxy_client)],
        auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
        db_session: Annotated[Session, Depends(get_db_session)],
        registration_token: Optional[str] = Header(None),
):
    if not registration_token:
        raise HTTPException(status_code=400, detail="Missing registration token")

    verify_registration_token(registration_token, settings=settings)
    logger.debug("Registration token verified.")

    user_data = BiocommonsRegisterData.from_galaxy_registration(registration_data)
    logger.debug("Checking if username exists in Galaxy")
    galaxy_username = user_data.username
    try:
        existing = galaxy_client.username_exists(galaxy_username)
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists in galaxy")
    except httpx.HTTPError as e:
        logger.warning(f"Failed to check username in Galaxy: {e}")

    try:
        logger.info("Registering user with Auth0")
        auth0_user_data = auth0_client.create_user(user_data)
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f'Registration failed: {e}')
    # Add to database and record Galaxy membership
    logger.info("Adding user to DB")
    _create_galaxy_user_record(auth0_user_data, db_session)
    return {"message": "User registered successfully", "user": auth0_user_data.model_dump(mode="json")}


def _create_galaxy_user_record(auth0_user_data: Auth0UserData, session: Session) -> BiocommonsUser:
    db_user = BiocommonsUser.from_auth0_data(data=auth0_user_data)
    galaxy_membership = db_user.add_platform_membership(
        platform=PlatformEnum.GALAXY,
        db_session=session,
        auto_approve=True
    )
    session.add(db_user)
    session.add(galaxy_membership)
    session.commit()
    return db_user
