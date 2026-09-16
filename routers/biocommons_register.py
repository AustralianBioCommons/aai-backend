import logging
from http import HTTPStatus
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException
from httpx2 import HTTPStatusError
from sqlmodel import Session
from starlette import status
from starlette.responses import Response

from auth.validator import verify_action_token
from auth0.client import Auth0Client, UpdateUserData, get_auth0_client
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
from schemas.auth0 import AafRegistrationActionToken
from schemas.biocommons import (
    Auth0UserData,
    BiocommonsAppMetadataUpdate,
    BiocommonsRegisterData,
    BiocommonsUserAccountType,
)
from schemas.biocommons_register import (
    AafRegistrationRequest,
    BiocommonsRegistrationRequest,
    BundleRequest,
)
from schemas.responses import (
    FieldError,
    RegistrationErrorResponse,
    RegistrationResponse,
)
from services.institutions import is_aaf_email

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


def _requests_sbp_bundle(bundles: list[BundleRequest] | None) -> bool:
    if bundles is None:
        return False
    return any(bundle.bundle_id == "sbp_workflow_execution" for bundle in bundles)

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

    if _requests_sbp_bundle(registration.bundles) and not settings.sbp_enabled:
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


def create_aaf_user_in_db(register_data: AafRegistrationRequest,
                          *,
                          auth0_token: AafRegistrationActionToken,
                          auth0_client: Auth0Client,
                          session: Session,
                          settings: Settings,
                          commit: bool = False):
    db_user = BiocommonsUser(
        id=auth0_token.user_id,
        email=auth0_token.email,
        username=register_data.username,
        # AAF users are considered email_verified by default
        email_verified=True,
        account_type=BiocommonsUserAccountType.AAF.value,
    )
    session.add(db_user)
    session.flush()
    # Add default platform memberships
    create_platform_memberships(db_user=db_user, auth0_client=auth0_client, session=session, sbp_enabled=settings.sbp_enabled)
    # Create requests for selected bundles (if any)
    create_bundle_requests(bundles=register_data.bundles, db_user=db_user, auth0_client=auth0_client, session=session)
    session.flush()
    if commit:
        session.commit()
    return db_user


def verify_registration_token(token: str, settings: Settings):
    """
    Verify the token sent through from the original Auth0 action - we use this to provide
    id, name + email so want to make sure it's verified
    """
    payload = verify_action_token(token, settings)
    if payload.get("purpose", None) != "aaf_registration":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token from Auth0 expired.")
    return AafRegistrationActionToken(**payload)


@router.post("/register-aaf")
async def register_aaf(
    register_data: AafRegistrationRequest,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    """
    Register an AAF user. Because we want to ensure we use the email and name provided by
    the AAF, using a signed token passed through from Auth0
    """
    if not register_data.recaptcha_token:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return RegistrationErrorResponse(message="Recaptcha token is required")
    recaptcha_check = validate_recaptcha(register_data.recaptcha_token, settings=settings)
    if not recaptcha_check:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return RegistrationErrorResponse(message="Invalid recaptcha token, please try again")

    validated_token = verify_registration_token(register_data.session_token, settings=settings)

    if _requests_sbp_bundle(register_data.bundles) and not settings.sbp_enabled:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return RegistrationErrorResponse(message="SBP workflow execution is currently unavailable.")

    is_aaf = is_aaf_email(validated_token.email, settings=settings)
    if not is_aaf:
        raise HTTPException(status_code=HTTPStatus.UNPROCESSABLE_CONTENT, detail=f"{validated_token.email} is not an AAF-associated email.")

    sbp_email_error = await check_sbp_email_allowed(email=validated_token.email, bundles=register_data.bundles)
    if sbp_email_error is not None:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return sbp_email_error

    duplicate_username_error = check_is_username_used(username=register_data.username, session=session)
    if duplicate_username_error:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return duplicate_username_error

    try:
        logger.info("Setting username in app_metadata")
        update_data = UpdateUserData(
            app_metadata=BiocommonsAppMetadataUpdate(
                username=register_data.username,
                account_type=BiocommonsUserAccountType.AAF,
                aaf_only=True,
            )
        )
        try:
            auth0_user_data = auth0_client.update_user(user_id=validated_token.user_id, update_data=update_data)
        except ValueError as e:
            logger.error(f"AAF registration failed: {e}")
            response.status_code = status.HTTP_400_BAD_REQUEST
            return RegistrationErrorResponse(message=f"AAF registration failed - couldn't update app_metadata: {e}")
        logger.info("Adding user to database...")
        db_user = create_aaf_user_in_db(
            register_data=register_data,
            auth0_token=validated_token,
            auth0_client=auth0_client,
            session=session,
            settings=settings,
            commit=False,
        )
        if register_data.bundles is not None:
            process_bundle_request_notifications(
                bundles=register_data.bundles,
                db_user=db_user,
                auth0_user_data=auth0_user_data,
                auth0_client=auth0_client,
                db_session=session,
                settings=settings
            )

        session.commit()
        logger.info("Successfully added user to database.")
        return {
            "message": "User registered successfully",
            "user": auth0_user_data
        }
    except HTTPStatusError as e:
        logger.error(f"AAF registration failed: {e}")
        # NOTE: don't think the checks of specific Auth0 issues are relevant here as we
        #   aren't registering in Auth0
        response.status_code = status.HTTP_400_BAD_REQUEST
        return RegistrationErrorResponse(message=f"AAF registration failed: {e.response.text}")
    except Exception as e:
        logger.error(f"Unexpected error during registration: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
