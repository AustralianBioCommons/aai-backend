import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from fastapi.params import Depends
from pydantic import BaseModel

from auth0.client import Auth0Client, get_auth0_client
from schemas.biocommons import AppId
from schemas.responses import FieldError

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
