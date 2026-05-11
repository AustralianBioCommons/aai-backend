import logging

from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Depends, HTTPException
from httpx import HTTPStatusError
from sqlmodel import Session
from starlette.responses import JSONResponse, Response

from auth0.client import Auth0Client, get_auth0_client
from biocommons.bundles import BUNDLES
from config import Settings, get_settings
from db.models import BiocommonsUser, BiocommonsUserHistory
from db.setup import get_db_session
from db.types import PlatformEnum
from routers.errors import RegistrationRoute
from routers.utils import check_existing_user
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData
from schemas.responses import (
    FieldError,
    RegistrationErrorResponse,
    RegistrationResponse,
)
from schemas.sbp import SBPRegistrationRequest

logger = logging.getLogger("uvicorn.error")

router = APIRouter(
    prefix="/sbp",
    tags=["sbp", "registration"],
    # Overriding route class to handle registration errors
    route_class=RegistrationRoute
)

def validate_sbp_email_domain(email: str, settings: Settings) -> bool:
    try:
        validated_email = validate_email(email)
        domain = validated_email.domain.lower()
        allowed_domains_lower = [domain.lower() for domain in settings.sbp_allowed_email_domains]
        return domain in allowed_domains_lower
    except EmailNotValidError:
        return False


@router.post(
    "/register",
    responses={
        200: {"model": RegistrationResponse},
        400: {"model": RegistrationErrorResponse},
    },
)
async def register_sbp_user(
    registration: SBPRegistrationRequest,
    response: Response,
    db_session: Session = Depends(get_db_session),
    auth0_client: Auth0Client = Depends(get_auth0_client),
    settings: Settings = Depends(get_settings),
):
    """Register a new SBP user."""

    # Validate email domain
    if not validate_sbp_email_domain(registration.email, settings):
        logger.warning(f"SBP registration rejected for email domain: {registration.email}")
        allowed_domains_str = ", ".join(settings.sbp_allowed_email_domains)
        response = RegistrationErrorResponse(
            message=(
                "Email domain not approved for SBP registration. "
                f"Please use an email from an approved domain: {allowed_domains_str}."
            )
        )
        return JSONResponse(status_code=400, content=response.model_dump(mode="json"))

    # Create Auth0 user data
    user_data = BiocommonsRegisterData.from_sbp_registration(
        registration=registration
    )
    # Check if username has already been used previously
    username_used = BiocommonsUserHistory.is_username_used(user_data.username, session=db_session)
    if username_used:
        field_errors = [FieldError(field="username", message="Username is already taken")]
        error_response = RegistrationErrorResponse(
            message="Username is already taken",
            field_errors=field_errors
        )
        response.status_code = 400
        return error_response

    try:
        logger.info("Registering user with Auth0")
        auth0_user_data = auth0_client.create_user(user_data)

        logger.info("Adding user to DB")
        _create_sbp_user_record(
            auth0_user_data,
            auth0_client=auth0_client,
            session=db_session,
            request_reason=registration.request_reason,
        )
        db_session.commit()

        return {"message": "User registered successfully.", "user": auth0_user_data.model_dump(mode="json")}

    # Return HTTP status errors as RegistrationErrorResponse
    except HTTPStatusError as e:
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
    # Unknown errors should return 500
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to register user: {str(e)}"
        )


def _create_sbp_user_record(
    auth0_user_data: Auth0UserData,
    auth0_client: Auth0Client,
    session: Session,
    request_reason: str | None = None,
) -> BiocommonsUser:
    db_user = BiocommonsUser.from_auth0_data(data=auth0_user_data)
    session.add(db_user)
    session.flush()
    # Auto-approve SBP platform membership so the user can log into the platform immediately
    sbp_membership = db_user.add_platform_membership(
        platform=PlatformEnum.SBP,
        db_session=session,
        auth0_client=auth0_client,
        auto_approve=True,
    )
    session.add(sbp_membership)
    BUNDLES["sbp_workflow_execution"].create_memberships(
        user=db_user,
        auth0_client=auth0_client,
        db_session=session,
        commit=False,
        request_reason=request_reason,
    )
    return db_user
