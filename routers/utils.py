import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Body, Query
from fastapi.params import Depends
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from auth0.client import Auth0Client, get_auth0_client
from biocommons.emails import compose_login_email_reminder
from config import Settings, get_settings
from db.models import BiocommonsUser
from db.setup import get_db_session
from register.tokens import validate_recaptcha
from schemas.biocommons import AppId
from schemas.responses import FieldError
from services.email_queue import enqueue_email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/utils", tags=["utils"])


def _check_username_exists(username: str, auth0_client: Auth0Client) -> bool:
    """Helper function to check if a username exists in Auth0."""
    try:
        q = f'username:"{username}"'
        res = auth0_client.get_users(q=q)

        users = res if isinstance(res, list) else getattr(res, "users", [])
        target = username.lower()

        return any(
            getattr(u, "username", "").lower() == target
            for u in users
            if getattr(u, "username", None)
        )
    except Exception as e:
        logger.warning(f"Error checking username existence: {e}")
        return False


def _check_email_exists(email: str, auth0_client: Auth0Client) -> bool:
    """Helper function to check if an email exists in Auth0."""
    try:
        email_results = auth0_client.search_users_by_email(email)
        return len(email_results) > 0
    except Exception as e:
        logger.warning(f"Error checking email existence: {e}")
        return False


def check_existing_user(username: str, email: str, auth0_client: Auth0Client) -> Literal["both", "email", "username"] | None:
    """Check if username or email already exists in Auth0.

    Returns:
        - "username" if username exists
        - "email" if email exists
        - "both" if both exist
        - None if neither exists
    """
    username_exists = _check_username_exists(username, auth0_client)
    email_exists = _check_email_exists(email, auth0_client)

    if username_exists and email_exists:
        return "both"
    elif username_exists:
        return "username"
    elif email_exists:
        return "email"
    return None


class RegistrationInfo(BaseModel):
    app: AppId = "biocommons"


class AvailabilityResponse(BaseModel):
    """Response for checking username/email availability"""
    available: bool
    field_errors: list[FieldError] = []


class UsernameLookupRequest(BaseModel):
    username: Annotated[str, Field(min_length=3, max_length=128)]
    recaptcha_token: Annotated[str, Field(min_length=1)]


class UsernameLookupResponse(BaseModel):
    found: bool
    masked_email: str | None = None
    message: str


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not local or not domain:
        return "***@***"

    def _mask_segment(value: str, keep_start: int, keep_end: int) -> str:
        if len(value) <= keep_start + keep_end:
            return value[0] + "*" * max(len(value) - 1, 1)
        start = value[:keep_start]
        end = value[-keep_end:] if keep_end else ""
        hidden = "*" * max(len(value) - keep_start - keep_end, 2)
        return f"{start}{hidden}{end}"

    masked_local = _mask_segment(local, keep_start=2, keep_end=1)
    domain_parts = domain.split(".")
    masked_parts: list[str] = []
    for idx, part in enumerate(domain_parts):
        if not part:
            continue
        is_tld = idx == len(domain_parts) - 1
        if is_tld:
            masked_parts.append(_mask_segment(part, keep_start=1, keep_end=0))
        else:
            masked_parts.append(_mask_segment(part, keep_start=2, keep_end=1))

    masked_domain = ".".join(masked_parts) if masked_parts else "***"
    return f"{masked_local}@{masked_domain}"


def _find_user_by_username(
    *,
    username: str,
    auth0_client: Auth0Client,
) -> tuple[str, str] | None:
    q = f'username:"{username}"'
    users = auth0_client.get_users(q=q)
    target = username.lower()
    for candidate in users:
        if not candidate.username or not candidate.email:
            continue
        if candidate.username.lower() == target:
            return candidate.username, str(candidate.email)
    return None


@router.get("/register/check-username-availability", response_model=AvailabilityResponse)
async def check_username_availability(
    username: Annotated[str, Query(min_length=3, max_length=128)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
):
    """
    Check if a username is available for registration.

    Returns availability status with field errors if already taken.
    """
    exists = _check_username_exists(username, auth0_client)
    if exists:
        return AvailabilityResponse(
            available=False,
            field_errors=[FieldError(field="username", message="Username is already taken")]
        )
    return AvailabilityResponse(available=True)


@router.get("/register/check-email-availability", response_model=AvailabilityResponse)
async def check_email_availability(
    email: Annotated[str, Query()],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
):
    """
    Check if an email is available for registration.

    Returns availability status with field errors if already registered.
    """
    exists = _check_email_exists(email, auth0_client)
    if exists:
        return AvailabilityResponse(
            available=False,
            field_errors=[FieldError(field="email", message="Email is already taken")]
        )
    return AvailabilityResponse(available=True)


@router.get("/register/registration-info")
async def get_registration_info(
        user_email: str,
        client: Annotated[Auth0Client, Depends(get_auth0_client)]):
    """
    Return the app a user used to register, if available in app_metadata.
    """
    results = client.search_users_by_email(email=user_email)
    for user in results:
        current_email = str(user.email).lower()
        if current_email == user_email.lower():
            if user.app_metadata.registration_from is None:
                return RegistrationInfo(app="biocommons")
            return RegistrationInfo(app=user.app_metadata.registration_from)
    return RegistrationInfo(app="biocommons")


@router.post(
    "/login/recover-email",
    response_model=UsernameLookupResponse,
)
async def recover_login_email(
    payload: Annotated[UsernameLookupRequest, Body()],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
    db_session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    """
    Recover login email by username and send a reminder email to the account email address.
    """
    recaptcha_check = validate_recaptcha(payload.recaptcha_token, settings)
    if not recaptcha_check:
        return UsernameLookupResponse(
            found=False,
            message="Invalid recaptcha token, please try again",
        )

    found = _find_user_by_username(username=payload.username, auth0_client=auth0_client)
    if found is None:
        return UsernameLookupResponse(
            found=False,
            message="No account found for that username.",
        )

    canonical_username, email = found
    subject, body_html = compose_login_email_reminder(
        username=canonical_username,
        email=email,
    )
    enqueue_email(
        db_session,
        to_address=email,
        from_address=settings.default_email_sender,
        subject=subject,
        body_html=body_html,
    )
    db_session.commit()

    db_user = db_session.exec(
        select(BiocommonsUser).where(BiocommonsUser.username == canonical_username)
    ).one_or_none()
    if db_user is not None and db_user.email.lower() != email.lower():
        logger.warning(
            "Username %s has mismatched DB/Auth0 emails (db=%s, auth0=%s)",
            canonical_username,
            db_user.email,
            email,
        )

    return UsernameLookupResponse(
        found=True,
        masked_email=_mask_email(email),
        message="If the username exists, a reminder email has been sent.",
    )
