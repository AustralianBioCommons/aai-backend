import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from httpx2 import HTTPStatusError
from sqlmodel import Session

from auth0.client import Auth0Client, get_auth0_client
from config import Settings, get_settings
from db.models import BiocommonsUser
from db.setup import get_db_session
from register.tokens import validate_recaptcha
from register.utils import (
    check_is_username_used,
    check_sbp_email_allowed,
    create_bundle_requests,
    create_platform_memberships,
    process_bundle_request_notifications,
)
from routers.errors import RegistrationRoute
from routers.utils import check_existing_user
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData
from schemas.biocommons_register import BiocommonsRegistrationRequest, BundleRequest
from schemas.responses import (
    FieldError,
    RegistrationErrorResponse,
    RegistrationResponse,
)

logger = logging.getLogger("uvicorn.error")

# Bundle configuration mapping bundle names to their groups and included extra_platforms
# Note: Platforms listed here are auto-approved upon registration,
# while group memberships require manual approval
# Currently BPA Data Portal and Galaxy are auto-approved for all bundles

router = APIRouter(prefix="/biocommons", tags=["biocommons", "registration"], route_class=RegistrationRoute)


def create_user_in_db(user_data: Auth0UserData,
                      bundles: Optional[list[BundleRequest]],
                      session: Session,
                      auth0_client: Auth0Client,
                      commit: bool = False,
                      sbp_enabled: bool = True) -> BiocommonsUser:
    db_user = BiocommonsUser.from_auth0_data(data=user_data)
    session.add(db_user)
    session.flush()
    # Add default platform memberships
    create_platform_memberships(db_user=db_user, auth0_client=auth0_client, session=session, sbp_enabled=sbp_enabled)
    # Create requests for selected bundles (if any)
    create_bundle_requests(bundles=bundles, db_user=db_user, session=session, auth0_client=auth0_client)
    session.flush()
    if commit:
        session.commit()
    return db_user


def _requests_sbp_bundle(registration: BiocommonsRegistrationRequest) -> bool:
    if registration.bundles is None:
        return False
    return any(bundle.bundle_id == "sbp_workflow_execution" for bundle in registration.bundles)

@router.post(
    "/register",
    responses={
        200: {"model": RegistrationResponse},
        400: {"model": RegistrationErrorResponse},
    },
)
async def register_biocommons_user(
    registration: BiocommonsRegistrationRequest,
    response: Response,
    db_session: Session = Depends(get_db_session),
    auth0_client: Auth0Client = Depends(get_auth0_client),
    settings: Settings = Depends(get_settings),
):
    """Register a new BioCommons user."""
    # Validate recaptcha
    if not registration.recaptcha_token:
        response.status_code = 400
        return RegistrationErrorResponse(message="Recaptcha token is required")
    recaptcha_check = validate_recaptcha(registration.recaptcha_token, settings)
    if not recaptcha_check:
        response.status_code = 400
        return RegistrationErrorResponse(message="Invalid recaptcha token, please try again")

    if _requests_sbp_bundle(registration) and not settings.sbp_enabled:
        response.status_code = 400
        return RegistrationErrorResponse(message="SBP workflow execution is currently unavailable.")

    # Pre-registration checks
    sbp_email_error = await check_sbp_email_allowed(email=registration.email, bundles=registration.bundles)
    if sbp_email_error is not None:
        response.status_code = 400
        return sbp_email_error

    # Create Auth0 user data
    user_data = BiocommonsRegisterData.from_biocommons_registration(registration)
    # Check if username has already been used previously
    duplicate_username_error = check_is_username_used(username=user_data.username, session=db_session)
    if duplicate_username_error:
        response.status_code = 400
        return duplicate_username_error

    try:
        logger.info("Registering user with Auth0")
        auth0_user_data = auth0_client.create_user(user_data)

        logger.info("Adding user to DB")
        db_user = create_user_in_db(
            user_data=auth0_user_data,
            bundles=registration.bundles,
            session=db_session,
            auth0_client=auth0_client,
            sbp_enabled=settings.sbp_enabled,
        )

        if registration.bundles is not None:
            process_bundle_request_notifications(
                bundles=registration.bundles,
                db_user=db_user,
                auth0_user_data=auth0_user_data,
                auth0_client=auth0_client,
                db_session=db_session,
                settings=settings,
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
                error_response = RegistrationErrorResponse(
                    message="Username is already taken",
                    field_errors=field_errors
                )
            elif existing_field == "email":
                field_errors.append(FieldError(field="email", message="Email is already taken"))
                error_response = RegistrationErrorResponse(
                    message="Email is already taken",
                    field_errors=field_errors
                )
            elif existing_field == "both":
                field_errors.append(FieldError(field="username", message="Username is already taken"))
                field_errors.append(FieldError(field="email", message="Email is already taken"))
                error_response = RegistrationErrorResponse(
                    message="Username and email are already taken",
                    field_errors=field_errors
                )
            else:
                error_response = RegistrationErrorResponse(message="Username or email is already taken")
        else:
            error_response = RegistrationErrorResponse(message=f"Auth0 error: {str(e.response.text)}")
        response.status_code = 400
        return error_response
    except Exception as e:
        logger.error(f"Unexpected error during registration: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
