import logging
from typing import Optional

from sqlmodel import Session

from auth0.client import Auth0Client
from biocommons.bundles import BUNDLES, BiocommonsBundle
from biocommons.default import get_default_platforms
from biocommons.emails import (
    compose_bundle_request_confirmation_email,
    compose_group_approval_email,
    format_first_name,
    get_group_admin_contacts,
    get_requester_identity,
)
from config import Settings
from db.models import BiocommonsUser, BiocommonsUserHistory, GroupMembership
from schemas.biocommons import Auth0UserData
from schemas.biocommons_register import BundleRequest
from schemas.responses import FieldError, RegistrationErrorResponse
from services.email_queue import enqueue_email
from services.institutions import is_australian_research_institution_email

logger = logging.getLogger("uvicorn.error")


def check_is_username_used(username: str, session: Session) -> RegistrationErrorResponse | None:
    username_used = BiocommonsUserHistory.is_username_used(username, session=session)
    if username_used:
        field_errors = [FieldError(field="username", message="Username is already taken")]
        error_response = RegistrationErrorResponse(
            message="Username is already taken",
            field_errors=field_errors,
        )
        return error_response
    return None


def process_bundle_request_notifications(
        bundles: list[BundleRequest],
        db_user: BiocommonsUser,
        auth0_user_data: Auth0UserData,
        auth0_client: Auth0Client,
        db_session: Session,
        settings: Settings,):
    """
    Send any admin/requester notifications that are needed based on requested bundles
    Bundles that are auto-approved don't need notifications
    """
    for bundle_request in bundles:
        bundle = BUNDLES[bundle_request.bundle_id]
        if bundle.group_auto_approve:
            continue
        _notify_bundle_group_admins(
            bundle=bundle,
            user=db_user,
            auth0_client=auth0_client,
            db_session=db_session,
            settings=settings,
        )
        _notify_bundle_requester(
            bundle=bundle,
            user=db_user,
            auth0_user_data=auth0_user_data,
            db_session=db_session,
            settings=settings,
            request_reason=bundle_request.reason,
        )


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
            settings=settings,
        )
        enqueue_email(
            db_session,
            to_address=email,
            subject=subject,
            body_html=body_html,
            settings=settings,
        )


def _notify_bundle_requester(
    *,
    bundle: BiocommonsBundle,
    user: BiocommonsUser,
    auth0_user_data: Auth0UserData,
    db_session: Session,
    settings: Settings,
    request_reason: Optional[str],
) -> None:
    """
    Queue a confirmation email to the user after they request bundle access.
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

    db_session.refresh(membership, attribute_names=["group"])

    first_name = format_first_name(
        full_name=auth0_user_data.name,
        given_name=auth0_user_data.given_name,
        fallback="there",
    )
    subject, body_html = compose_bundle_request_confirmation_email(
        first_name=first_name,
        bundle_name=membership.group.name,
        request_reason=request_reason,
        settings=settings,
    )
    enqueue_email(
        db_session,
        to_address=str(auth0_user_data.email),
        subject=subject,
        body_html=body_html,
        settings=settings,
    )


async def check_sbp_email_allowed(email: str, bundles: list[BundleRequest] | None) -> RegistrationErrorResponse | None:
    """
    If user requests SBP access, check if the email domain is allowed.

    Return a RegistrationErrorResponse if SBP is requested and domain is not allowed, otherwise None.
    """
    if bundles is not None:
        has_sbp_bundle = any(bundle.bundle_id == "sbp_workflow_execution" for bundle in bundles)
        if has_sbp_bundle:
            is_institute = await is_australian_research_institution_email(email)
            if not is_institute:
                return RegistrationErrorResponse(
                    message="SBP workflow execution requires an Australian institutional email address.",
                    field_errors=[
                        FieldError(
                            field="email",
                            message="Please use an Australian institutional email address if applying for SBP workflow execution access.",
                        )
                    ],
                )
        else:
            return None
    return None


def create_platform_memberships(db_user: BiocommonsUser, auth0_client: Auth0Client, session: Session, sbp_enabled: bool = True) -> None:
    """
    Create default platform memberships (database record and Auth0 role) for a user
    """
    for platform in get_default_platforms(sbp_enabled=sbp_enabled):
        db_user.add_platform_membership(
            platform=platform,
            db_session=session,
            auth0_client=auth0_client,
            auto_approve=True
        )


def create_bundle_requests(bundles: list[BundleRequest] | None, db_user: BiocommonsUser, auth0_client: Auth0Client, session: Session) -> None:
    """
    Create bundle requests for a user, based on the bundles requested at registration
    """
    if bundles is not None:
        for bundle_request in bundles:
            bundle = BUNDLES[bundle_request.bundle_id]
            logger.info(f"Adding group/platform memberships for bundle: {bundle}")
            bundle.create_memberships(
                user=db_user,
                auth0_client=auth0_client,
                db_session=session,
                commit=False,
                request_reason=bundle_request.reason,
            )
