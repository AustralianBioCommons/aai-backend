import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from httpx import HTTPStatusError
from pydantic import BaseModel
from sqlmodel import Session
from starlette.responses import JSONResponse

from auth.ses import EmailService
from auth0.client import Auth0Client, get_auth0_client
from config import Settings, get_settings
from db.models import BiocommonsGroup, BiocommonsUser, PlatformEnum
from db.setup import get_db_session
from db.types import GroupEnum
from routers.errors import RegistrationRoute
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData
from schemas.biocommons_register import BiocommonsRegistrationRequest, BundleType
from schemas.responses import RegistrationErrorResponse, RegistrationResponse

logger = logging.getLogger(__name__)


class BiocommonsBundle(BaseModel):
    id: BundleType
    group_id: GroupEnum
    group_auto_approve: bool
    # Platforms that are automatically approved upon registration
    platforms: list[PlatformEnum]

    def _add_group_membership(self, user: BiocommonsUser, session: Session):
        # Verify group exists
        BiocommonsGroup.get_by_id_or_404(group_id=self.group_id.value, session=session)
        group_membership = user.add_group_membership(
            group_id=self.group_id.value, db_session=session, auto_approve=self.group_auto_approve
        )
        session.add(group_membership)

    def _add_platform_memberships(self, user: BiocommonsUser, session: Session, auth0_client: Auth0Client):
        for platform in self.platforms:
            logger.info(f"Adding platform membership for {platform.value} to user {user.id}")
            platform_membership = user.add_platform_membership(
                platform=platform, db_session=session, auth0_client=auth0_client, auto_approve=True
            )
            session.add(platform_membership)

    def create_user_record(self, auth0_user_data: Auth0UserData, auth0_client: Auth0Client, db_session: Session):
        """
        Create a user record for the bundle user.
        """
        db_user = BiocommonsUser.from_auth0_data(data=auth0_user_data)
        db_session.add(db_user)
        db_session.flush()
        # Create group membership
        self._add_group_membership(user=db_user, session=db_session)
        # Add platform memberships based on bundle configuration
        self._add_platform_memberships(user=db_user, session=db_session, auth0_client=auth0_client)
        db_session.commit()
        return db_user


# Bundle configuration mapping bundle names to their groups and included platforms
# Note: Platforms listed here are auto-approved upon registration,
# while group memberships require manual approval
# Currently BPA Data Portal and Galaxy are auto-approved for all bundles
BUNDLES: dict[BundleType, BiocommonsBundle] = {
    "bpa_galaxy": BiocommonsBundle(
        id="bpa_galaxy",
        group_id=GroupEnum.BPA_GALAXY,
        group_auto_approve=True,
        platforms=[PlatformEnum.BPA_DATA_PORTAL, PlatformEnum.GALAXY],
    ),
    "tsi": BiocommonsBundle(
        id="tsi",
        group_id=GroupEnum.TSI,
        group_auto_approve=False,
        platforms=[PlatformEnum.BPA_DATA_PORTAL, PlatformEnum.GALAXY],
    ),
}

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
    bundle = BUNDLES[registration.bundle]

    try:
        logger.info("Registering user with Auth0")
        auth0_user_data = auth0_client.create_user(user_data)

        logger.info("Adding user to DB")
        bundle.create_user_record(
            auth0_user_data=auth0_user_data,
            auth0_client=auth0_client,
            db_session=db_session
        )

        # Send approval email in background
        if not bundle.group_auto_approve:
            if settings.send_email:
                background_tasks.add_task(send_approval_email, registration, settings)

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
