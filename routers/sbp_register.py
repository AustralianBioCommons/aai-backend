import logging

from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, Depends, HTTPException
from httpx import HTTPStatusError
from sqlmodel import Session
from starlette.responses import JSONResponse

from auth0.client import Auth0Client, get_auth0_client
from config import Settings, get_settings
from db.models import BiocommonsUser, Platform, PlatformEnum
from db.setup import get_db_session
from routers.errors import RegistrationRoute
from routers.utils import check_existing_user
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData
from schemas.responses import (
    FieldError,
    RegistrationErrorResponse,
    RegistrationResponse,
)
from schemas.sbp import SBPRegistrationRequest
from services.email_queue import enqueue_email

logger = logging.getLogger(__name__)

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


def compose_sbp_registration_email(registration: SBPRegistrationRequest, settings: Settings) -> tuple[str, str]:
    """Compose the approval email for SBP admins."""
    subject = "New Structural Biology Platform User Registration"

    body_html = f"""
        <p>A new user has registered for the Structural Biology Platform.</p>
        <p><strong>User:</strong> {registration.first_name} {registration.last_name} ({registration.email})</p>
        <p><strong>Username:</strong> {registration.username}</p>
        <p><strong>Registration Reason:</strong> {registration.reason}</p>
        <p>Please <a href='{settings.aai_portal_url}/requests'>log into the AAI Admin Portal</a> to review and approve access.</p>
    """

    return subject, body_html


def queue_sbp_admin_notifications(
    registration: SBPRegistrationRequest,
    db_session: Session,
    auth0_client: Auth0Client,
    settings: Settings,
) -> None:
    """Queue approval emails for SBP platform admins."""
    sbp_platform = Platform.get_by_id(PlatformEnum.SBP, db_session)
    if sbp_platform is None:
        logger.warning("SBP platform not found; skipping admin notification email")
        return

    admin_emails = sbp_platform.get_admins(auth0_client=auth0_client)
    if not admin_emails:
        logger.info("No SBP platform admins found; skipping notification email")
        return

    subject, body_html = compose_sbp_registration_email(registration, settings)
    for email in admin_emails:
        enqueue_email(
            db_session,
            to_address=email,
            subject=subject,
            body_html=body_html,
        )


@router.post(
    "/register",
    responses={
        200: {"model": RegistrationResponse},
        400: {"model": RegistrationErrorResponse},
    },
)
async def register_sbp_user(
    registration: SBPRegistrationRequest,
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

    try:
        logger.info("Registering user with Auth0")
        auth0_user_data = auth0_client.create_user(user_data)

        logger.info("Adding user to DB")
        _create_sbp_user_record(auth0_user_data, auth0_client=auth0_client, session=db_session)

        # Queue approval email for SBP platform admins
        queue_sbp_admin_notifications(
            registration=registration,
            db_session=db_session,
            auth0_client=auth0_client,
            settings=settings,
        )
        db_session.commit()

        return {"message": "User registered successfully. Approval pending.", "user": auth0_user_data.model_dump(mode="json")}

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


def _create_sbp_user_record(auth0_user_data: Auth0UserData, auth0_client: Auth0Client, session: Session) -> BiocommonsUser:
    db_user = BiocommonsUser.from_auth0_data(data=auth0_user_data)
    sbp_membership = db_user.add_platform_membership(
        platform=PlatformEnum.SBP,
        db_session=session,
        auth0_client=auth0_client,
        auto_approve=False
    )
    session.add(db_user)
    session.add(sbp_membership)
    session.flush()
    return db_user
