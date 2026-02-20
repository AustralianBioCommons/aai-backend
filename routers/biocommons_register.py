import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from httpx import HTTPStatusError
from sqlmodel import Session

from auth0.client import Auth0Client, get_auth0_client
from biocommons.bundles import BUNDLES, BiocommonsBundle
from biocommons.default import DEFAULT_PLATFORMS
from biocommons.emails import (
    compose_group_approval_email,
    get_group_admin_contacts,
    get_requester_identity,
)
from config import Settings, get_settings
from db.models import BiocommonsUser, GroupMembership
from db.setup import get_db_session
from register.tokens import validate_recaptcha
from routers.errors import RegistrationRoute
from routers.utils import check_existing_user
from schemas.biocommons import Auth0UserData, BiocommonsRegisterData
from schemas.biocommons_register import BiocommonsRegistrationRequest
from schemas.responses import (
    FieldError,
    RegistrationErrorResponse,
    RegistrationResponse,
)
from services.email_queue import enqueue_email

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
                      request_reason: Optional[str] = None,
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
            request_reason=request_reason,
        )

    session.flush()
    if commit:
        session.commit()
    return db_user


def _notify_bundle_group_admins(
    *,
    bundle: BiocommonsBundle,
    user: BiocommonsUser,
    auth0_client: Auth0Client,
    db_session: Session,
    settings: Settings,
) -> None:
    """
    Queue approval emails for bundle group admins when memberships require review.
    """
    if bundle.group_auto_approve:
        return

    membership = GroupMembership.get_by_user_id_and_group_id(
        user_id=user.id,
        group_id=bundle.group_id.value,
        session=db_session,
    )
    if membership is None:
        logger.warning(
            "Unable to find group membership for user %s and bundle %s",
            user.id,
            bundle.id,
        )
        return

    db_session.refresh(membership, attribute_names=["group", "user"])

    admin_contacts = get_group_admin_contacts(group=membership.group, auth0_client=auth0_client)
    if not admin_contacts:
        logger.info("No admins found for group %s; skipping notification", membership.group_id)
        return

    try:
        requester_email, requester_full_name = get_requester_identity(
            auth0_client=auth0_client,
            user_id=membership.user_id,
            fallback_email=membership.user.email,
        )
    except Exception as exc:
        logger.warning(
            "Failed to fetch Auth0 user data for %s; using fallback values: %s",
            membership.user_id,
            exc,
        )
        requester_email = membership.user.email
        requester_full_name = requester_email or "Unknown user"
    for email, admin_first_name in admin_contacts:
        subject, body_html = compose_group_approval_email(
            admin_first_name=admin_first_name,
            bundle_name=membership.group.name,
            requester_full_name=requester_full_name,
            requester_email=requester_email,
            request_reason=membership.request_reason,
            requester_user_id=membership.user_id,
            settings=settings,
        )
        enqueue_email(
            db_session,
            to_address=email,
            from_address=settings.default_email_sender,
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

    # Create Auth0 user data
    user_data = BiocommonsRegisterData.from_biocommons_registration(registration)

    try:
        logger.info("Registering user with Auth0")
        auth0_user_data = auth0_client.create_user(user_data)

        logger.info("Adding user to DB")
        bundle = BUNDLES.get(registration.bundle)
        db_user = create_user_in_db(
            user_data=auth0_user_data,
            bundle=bundle,
            session=db_session,
            auth0_client=auth0_client,
            request_reason=registration.request_reason,
        )

        if bundle is not None:
            _notify_bundle_group_admins(
                bundle=bundle,
                user=db_user,
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
