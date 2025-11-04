import logging

from email_validator import EmailNotValidError, validate_email
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from httpx import HTTPStatusError
from sqlmodel import Session
from starlette.responses import JSONResponse

from auth.ses import EmailService
from auth0.client import Auth0Client, get_auth0_client
from config import Settings, get_settings
from db.models import BiocommonsUser, PlatformEnum
from db.setup import get_db_session
from routers.errors import RegistrationRoute
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData
from schemas.responses import RegistrationErrorResponse, RegistrationResponse
from schemas.sbp import SBPRegistrationRequest

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


def send_approval_email(registration: SBPRegistrationRequest, settings: Settings):
    """Send email notification about new SBP registration."""
    email_service = EmailService()
    approver_email = "aai-dev@biocommons.org.au"
    subject = "New Structural Biology Platform User Registration"

    body_html = f"""
        <p>A new user has registered for the Structural Biology Platform.</p>
        <p><strong>User:</strong> {registration.first_name} {registration.last_name} ({registration.email})</p>
        <p><strong>Username:</strong> {registration.username}</p>
        <p><strong>Registration Reason:</strong> {registration.reason}</p>
        <p>Please <a href='{settings.aai_portal_url}/requests'>log into the AAI Admin Portal</a> to review and approve access.</p>
    """

    email_service.send_email(
        to_email=approver_email,
        subject=subject,
        body_html=body_html
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
    background_tasks: BackgroundTasks,
    db_session: Session = Depends(get_db_session),
    auth0_client: Auth0Client = Depends(get_auth0_client),
    settings: Settings = Depends(get_settings)
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

        # Send approval email in the background
        if settings.send_email:
            background_tasks.add_task(send_approval_email, registration, settings)
            logger.info("Approval email queued for sending")

        return {"message": "User registered successfully. Approval pending.", "user": auth0_user_data.model_dump(mode="json")}

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
    session.commit()
    return db_user
