import logging
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Annotated
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from httpx2 import HTTPStatusError
from pydantic import BaseModel
from sqlmodel import Session
from starlette import status
from starlette.responses import RedirectResponse, Response

from auth.validator import create_action_token, verify_action_token
from auth0.client import Auth0Client, UpdateUserData, get_auth0_client
from config import Settings, get_settings
from db.models import BiocommonsUser
from db.setup import get_db_session
from dependencies.auth import require_action_token
from register.tokens import validate_recaptcha
from register.utils import (
    check_is_username_used,
    check_sbp_email_allowed,
    create_bundle_requests,
    create_platform_memberships,
    process_bundle_request_notifications,
)
from schemas.auth0 import AafRegistrationActionToken, Auth0ActionToken
from schemas.biocommons import (
    Auth0Identity,
    Auth0UserData,
    BiocommonsAppMetadataUpdate,
    BiocommonsUserAccountType,
)
from schemas.biocommons_register import AafRegistrationRequest
from schemas.responses import RegistrationErrorResponse
from services.institutions import is_aaf_email

router = APIRouter(
    prefix="/aaf", tags=["aaf"]
)
logger = logging.getLogger("uvicorn.error")


class AccountLinkResponse(BaseModel):
    link: bool
    aaf_only: bool = False
    blocked: bool = False
    primary_id: str
    aaf_identity: Auth0Identity | None = None


class SignedAccountLinkResponse(AccountLinkResponse):
    """
    Set the fields we need a signed action token to return
    to Auth0
    """
    sub: str
    iss: str
    state: str


def link_aaf_account(db_user_id: str, aaf_user_id: str, auth0_client: Auth0Client, session: Session) -> Auth0Identity:
    """
    Update app_metadata and DB record for AAF account linking.

    NOTE: we can't do the actual linking here, it needs to be done
    on the Auth0 side. See: https://support.auth0.com/center/s/article/Unable-to-process-redirect-callback
    """
    def _get_aaf_identity(aaf_user: Auth0UserData) -> Auth0Identity | None:
        for identity in aaf_user.identities:
            if identity.connection == "AAF":
                return identity
        return None

    aaf_user_info = auth0_client.get_user(user_id=aaf_user_id)
    aaf_identity = _get_aaf_identity(aaf_user_info)
    if aaf_identity is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Couldn't get AAF provider information")

    db_user = BiocommonsUser.get_by_id_or_404(db_user_id, session=session)
    if db_user.account_type == BiocommonsUserAccountType.AAF and db_user.other_user_id == aaf_user_id:
        logger.info("AAF account already linked, skipping re-link")
        return aaf_identity

    logger.info("Updating DB record and account metadata")
    now = datetime.now(tz=timezone.utc)
    try:
        auth0_client.update_user(
            db_user_id,
            update_data=UpdateUserData(
                app_metadata=BiocommonsAppMetadataUpdate(
                    account_type=BiocommonsUserAccountType.AAF,
                    linking_completed=True,
                    linking_completed_at=now
                )
            )
        )
    except ValueError as exc:
        logger.error(f"Failed to update account metadata in Auth0: {exc}")
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail="Failed to link account with Auth0") from exc
    logger.info("Updating DB record")
    db_user.link_aaf_account(aaf_user_id=aaf_user_id, session=session, updated_by=db_user, commit=True)
    return aaf_identity


def mark_user_aaf_only(user_email: str, aaf_user_id: str, auth0_client: Auth0Client):
    update_data = UpdateUserData(
        app_metadata=BiocommonsAppMetadataUpdate(
            aaf_only=True,
            checked_email=user_email,
            linking_completed=True,
            linking_completed_at=datetime.now(tz=timezone.utc),
        )
    )
    auth0_client.update_user(user_id=aaf_user_id, update_data=update_data)


def return_signed_response(
    state: str,
    response: AccountLinkResponse,
    action_token: Auth0ActionToken,
    settings: Settings,
):
    """
    Auth0 Actions need to receive the response as a signed JWT
    token, sign the AccountLinkResponse we want to return
    and redirect to the continue endpoint
    """
    signed_payload = SignedAccountLinkResponse(
        **response.model_dump(),
        sub=action_token.sub or action_token.user_id,
        iss=action_token.iss or settings.auth0_domain,
        state=state,
    )
    signed_token = create_action_token(
        payload=signed_payload.model_dump(mode="json", exclude_none=True),
        settings=settings,
    )
    auth0_base_url = get_auth0_continue_base_url(action_token, settings)
    redirect_url = httpx.URL(
        f"{auth0_base_url}/continue",
        params={"state": state, "session_token": signed_token},
    )
    return RedirectResponse(url=redirect_url)


def get_auth0_continue_base_url(action_token: Auth0ActionToken, settings: Settings) -> str:
    """
    Get domain to continue action from action token's issuer, if possible - want
    to ensure we continue on the same domain
    """
    if action_token.iss:
        issuer = action_token.iss.rstrip("/")
        parsed_issuer = urlparse(issuer)
        if parsed_issuer.scheme and parsed_issuer.netloc:
            return f"{parsed_issuer.scheme}://{parsed_issuer.netloc}"
        return f"https://{issuer}"
    return settings.auth0_custom_domain or f"https://{settings.auth0_domain}"


@router.get("/check-link")
def check_aaf_account_link(
    state: str,
    token: Annotated[Auth0ActionToken, Depends(require_action_token(purpose="aaf_link"))],
    session: Annotated[Session, Depends(get_db_session)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    email = token.email
    aaf_user_id = token.user_id
    auth0_matches = auth0_client.search_users_by_email(
        email,
        connection=settings.auth0_db_connection
    )
    # No existing account: no need to link
    if not auth0_matches:
        mark_user_aaf_only(email, aaf_user_id, auth0_client)
        resp = AccountLinkResponse(link=False, aaf_only=True, primary_id=aaf_user_id)
        return return_signed_response(
            state=state,
            response=resp,
            action_token=token,
            settings=settings,
        )

    existing_account = None
    for user in auth0_matches:
        if user.email.lower() == email.lower():
            existing_account = user
            break
    # No exact match: no existing account
    if not existing_account:
        mark_user_aaf_only(email, aaf_user_id, auth0_client)
        resp = AccountLinkResponse(link=False, aaf_only=True, primary_id=aaf_user_id)
        return return_signed_response(
            state=state,
            response=resp,
            action_token=token,
            settings=settings,
        )

    if existing_account.blocked:
        resp = AccountLinkResponse(link=True, aaf_only=False, primary_id=existing_account.user_id, blocked=True)
        return return_signed_response(
            state=state,
            response=resp,
            action_token=token,
            settings=settings,
        )

    aaf_identity = link_aaf_account(
        db_user_id=existing_account.user_id,
        aaf_user_id=aaf_user_id,
        auth0_client=auth0_client,
        session=session,
    )
    resp = AccountLinkResponse(link=True, aaf_only=False, primary_id=existing_account.user_id, aaf_identity=aaf_identity)
    return return_signed_response(
        state=state,
        response=resp,
        action_token=token,
        settings=settings,
    )


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


def _requests_sbp_bundle(registration: AafRegistrationRequest) -> bool:
    if registration.bundles is None:
        return False
    return any(bundle.bundle_id == "sbp_workflow_execution" for bundle in registration.bundles)


@router.post("/register")
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

    if _requests_sbp_bundle(register_data) and not settings.sbp_enabled:
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
        update_data = UpdateUserData(app_metadata=BiocommonsAppMetadataUpdate(username=register_data.username))
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
