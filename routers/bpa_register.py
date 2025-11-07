import logging

from fastapi import APIRouter, Depends, HTTPException
from httpx import HTTPStatusError
from sqlmodel import Session
from starlette.responses import JSONResponse

from auth0.client import Auth0Client, get_auth0_client
from db.models import BiocommonsUser, PlatformEnum
from db.setup import get_db_session
from routers.errors import RegistrationRoute
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData
from schemas.bpa import BPARegistrationRequest
from schemas.responses import RegistrationErrorResponse, RegistrationResponse

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/bpa",
    tags=["bpa", "registration"],
    # Overriding route class to handle registration errors
    route_class=RegistrationRoute
)


@router.post(
    "/register",
    responses={
        200: {"model": RegistrationResponse},
        400: {"model": RegistrationErrorResponse},
    },
)
async def register_bpa_user(
    registration: BPARegistrationRequest,
    db_session: Session = Depends(get_db_session),
    auth0_client: Auth0Client = Depends(get_auth0_client)
):
    """Register a new BPA user."""
    # Create Auth0 user data
    user_data = BiocommonsRegisterData.from_bpa_registration(
        registration=registration
    )

    try:
        logger.info("Registering user with Auth0")
        auth0_user_data = auth0_client.create_user(user_data)

        logger.info("Adding user to DB")
        _create_bpa_user_record(auth0_user_data, auth0_client=auth0_client, session=db_session)

        return {"message": "User registered successfully", "user": auth0_user_data.model_dump(mode="json")}

    # Return HTTP status errors as RegistrationErrorResponse
    except HTTPStatusError as e:
        # Catch specific errors where possible and return a useful error message
        if e.response.status_code == 409:
            response = RegistrationErrorResponse(message="Username or email already in use")
        else:
            response = RegistrationErrorResponse(message=f"Auth0 error: {str(e.response.text)}")
        return JSONResponse(status_code=400, content=response.model_dump(mode="json"))
    # Unknown errors should return 500
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to register user: {str(e)}"
        )


def _create_bpa_user_record(auth0_user_data: Auth0UserData, auth0_client: Auth0Client, session: Session) -> BiocommonsUser:
    db_user = BiocommonsUser.from_auth0_data(data=auth0_user_data)
    bpa_membership = db_user.add_platform_membership(
        platform=PlatformEnum.BPA_DATA_PORTAL,
        db_session=session,
        auth0_client=auth0_client,
        auto_approve=True
    )
    session.add(db_user)
    session.add(bpa_membership)
    session.commit()
    return db_user
