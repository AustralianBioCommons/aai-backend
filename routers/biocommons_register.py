import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from httpx import HTTPStatusError
from sqlmodel import Session
from starlette.responses import JSONResponse

from auth0.client import Auth0Client, get_auth0_client
from biocommons.bundles import BUNDLES, BiocommonsBundle
from biocommons.default import DEFAULT_PLATFORMS
from db.models import BiocommonsUser
from db.setup import get_db_session
from routers.errors import RegistrationRoute
from routers.utils import check_existing_user
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData
from schemas.biocommons_register import BiocommonsRegistrationRequest
from schemas.responses import (
    FieldError,
    RegistrationErrorResponse,
    RegistrationResponse,
)
logger = logging.getLogger(__name__)

# Bundle configuration mapping bundle names to their groups and included extra_platforms
# Note: Platforms listed here are auto-approved upon registration,
# while group memberships require manual approval
# Currently BPA Data Portal and Galaxy are auto-approved for all bundles

router = APIRouter(prefix="/biocommons", tags=["biocommons", "registration"], route_class=RegistrationRoute)


def create_user_in_db(user_data: Auth0UserData,
                      bundle: Optional[BiocommonsBundle],
                      session: Session,
                      auth0_client: Auth0Client,
                      commit: bool = False) -> BiocommonsUser:
    db_user = BiocommonsUser.from_auth0_data(data=user_data)
    session.add(db_user)
    session.flush()
    for platform in DEFAULT_PLATFORMS:
        db_user.add_platform_membership(
            platform=platform,
            db_session=session,
            auth0_client=auth0_client,
            auto_approve=True
        )

    if bundle is not None:
        logger.info(f"Adding group/platform memberships for bundle: {bundle}")
        bundle.create_memberships(
            user=db_user,
            auth0_client=auth0_client,
            db_session=session,
            commit=False,
        )

    session.flush()
    if commit:
        session.commit()
    return db_user


@router.post(
    "/register",
    responses={
        200: {"model": RegistrationResponse},
        400: {"model": RegistrationErrorResponse},
    },
)
async def register_biocommons_user(
    registration: BiocommonsRegistrationRequest,
    db_session: Session = Depends(get_db_session),
    auth0_client: Auth0Client = Depends(get_auth0_client),
):
    """Register a new BioCommons user."""

    # Create Auth0 user data
    user_data = BiocommonsRegisterData.from_biocommons_registration(registration)

    try:
        logger.info("Registering user with Auth0")
        auth0_user_data = auth0_client.create_user(user_data)

        logger.info("Adding user to DB")
        bundle = BUNDLES.get(registration.bundle)
        create_user_in_db(
            user_data=auth0_user_data,
            bundle=bundle,
            session=db_session,
            auth0_client=auth0_client
        )

        db_session.commit()

        logger.info(
            f"Successfully registered biocommons user: {auth0_user_data.user_id}"
        )
        return {
            "message": "User registered successfully",
            "user": auth0_user_data.model_dump(mode="json"),
        }

    except HTTPStatusError as e:
        logger.error(f"Auth0 registration failed: {e}")
        # Catch specific errors where possible and return a useful error message
        if e.response.status_code == 409:
            existing_field = check_existing_user(registration.username, registration.email, auth0_client)
            field_errors = []
            if existing_field == "username":
                field_errors.append(FieldError(field="username", message="Username is already taken"))
                response = RegistrationErrorResponse(
                    message="Username is already taken",
                    field_errors=field_errors
                )
            elif existing_field == "email":
                field_errors.append(FieldError(field="email", message="Email is already taken"))
                response = RegistrationErrorResponse(
                    message="Email is already taken",
                    field_errors=field_errors
                )
            elif existing_field == "both":
                field_errors.append(FieldError(field="username", message="Username is already taken"))
                field_errors.append(FieldError(field="email", message="Email is already taken"))
                response = RegistrationErrorResponse(
                    message="Username and email are already taken",
                    field_errors=field_errors
                )
            else:
                response = RegistrationErrorResponse(message="Username or email is already taken")
        else:
            response = RegistrationErrorResponse(message=f"Auth0 error: {str(e.response.text)}")
        return JSONResponse(status_code=400, content=response.model_dump(mode="json"))
    except Exception as e:
        logger.error(f"Unexpected error during registration: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
