import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from httpx import HTTPStatusError
from sqlmodel import Session
from starlette.responses import JSONResponse

from auth.ses import EmailService
from auth0.client import Auth0Client, get_auth0_client
from biocommons.bundles import BUNDLES
from biocommons.default import DEFAULT_PLATFORMS
from config import Settings, get_settings
from db.models import BiocommonsUser
from db.setup import get_db_session
from routers.errors import RegistrationRoute
from schemas.biocommons import BiocommonsRegisterData
from schemas.biocommons_register import BiocommonsRegistrationRequest
from schemas.responses import RegistrationErrorResponse, RegistrationResponse

logger = logging.getLogger(__name__)

# Bundle configuration mapping bundle names to their groups and included extra_platforms
# Note: Platforms listed here are auto-approved upon registration,
# while group memberships require manual approval
# Currently BPA Data Portal and Galaxy are auto-approved for all bundles

router = APIRouter(prefix="/biocommons", tags=["biocommons", "registration"], route_class=RegistrationRoute)


def send_approval_email(registration: BiocommonsRegistrationRequest, settings: Settings):
    """Send email notification about new biocommons registration."""
    email_service = EmailService()
    approver_email = "aai-dev@biocommons.org.au"
    subject = "New BioCommons User Registration"

    body_html = f"""
        <p>A new user has registered for the BioCommons platform.</p>
        <p><strong>User:</strong> {registration.first_name} {registration.last_name} ({registration.email})</p>
        <p><strong>Username:</strong> {registration.username}</p>
        <p><strong>Selected Bundle:</strong> {registration.bundle}</p>
        <p><strong>Requested Access:</strong> BPA Data Portal & Galaxy Australia</p>
        <p>Please <a href='{settings.aai_portal_url}/requests'>log into the AAI Admin Portal</a> to review and approve access.</p>
    """

    email_service.send(approver_email, subject, body_html)


@router.post(
    "/register",
    responses={
        200: {"model": RegistrationResponse},
        400: {"model": RegistrationErrorResponse},
    },
)
async def register_biocommons_user(
    registration: BiocommonsRegistrationRequest,
    background_tasks: BackgroundTasks,
    settings: Settings = Depends(get_settings),
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
        db_user = BiocommonsUser.from_auth0_data(data=auth0_user_data)
        db_session.add(db_user)
        db_session.flush()
        for platform in DEFAULT_PLATFORMS:
            db_user.add_platform_membership(
                platform=platform,
                db_session=db_session,
                auth0_client=auth0_client,
                auto_approve=True
            )

        if bundle := BUNDLES.get(registration.bundle):
            logger.info(f"Adding group/platform memberships for bundle: {bundle}")
            bundle.create_memberships(
                user=db_user,
                auth0_client=auth0_client,
                db_session=db_session
            )

            # Send approval email in the background
            if not bundle.group_auto_approve:
                if settings.send_email:
                    background_tasks.add_task(send_approval_email, registration, settings)
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
            response = RegistrationErrorResponse(message="Username or email already in use")
        else:
            response = RegistrationErrorResponse(message=f"Auth0 error: {str(e.response.text)}")
        return JSONResponse(status_code=400, content=response.model_dump(mode="json"))
    except Exception as e:
        logger.error(f"Unexpected error during registration: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
