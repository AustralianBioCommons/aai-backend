import logging
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Annotated

import httpx2
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session
from starlette.responses import RedirectResponse

from auth.validator import create_action_token
from auth0.client import Auth0Client, UpdateUserData, get_auth0_client
from config import Settings, get_settings
from db.models import BiocommonsUser
from db.setup import get_db_session
from dependencies.auth import require_action_token
from schemas.auth0 import Auth0ActionToken
from schemas.biocommons import (
    Auth0UserData,
    BiocommonsAppMetadataUpdate,
    BiocommonsUserAccountType,
)

router = APIRouter(
    prefix="/aaf", tags=["aaf"]
)
logger = logging.getLogger("uvicorn.error")


class AccountLinkResponse(BaseModel):
    link: bool
    aaf_only: bool = False
    primary_id: str


def link_aaf_account(db_user_id: str, aaf_user_id: str, auth0_client: Auth0Client, session: Session):
    def _get_aaf_identity(aaf_user: Auth0UserData):
        for identity in aaf_user.identities:
            if identity.connection == "AAF":
                return identity
        return None
    db_user = BiocommonsUser.get_by_id_or_404(db_user_id, session=session)
    if db_user.account_type == BiocommonsUserAccountType.AAF and db_user.other_user_id == aaf_user_id:
        logger.info("AAF account already linked, skipping re-link")
        return db_user

    aaf_user_info = auth0_client.get_user(user_id=aaf_user_id)
    aaf_identity = _get_aaf_identity(aaf_user_info)
    if aaf_identity is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Couldn't get AAF provider information")

    logger.info("Linking AAF account to existing database account")
    now = datetime.now(tz=timezone.utc)
    try:
        auth0_client.link_identity(primary_user_id=db_user_id, secondary_user_id=aaf_user_id,
                                   secondary_provider=aaf_identity.provider,
                                   secondary_connection_name=aaf_identity.connection)
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
        logger.error(f"Failed to link AAF account in Auth0: {exc}")
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail="Failed to link account with Auth0") from exc
    logger.info("Updating DB record")
    db_user.link_aaf_account(aaf_user_id=aaf_user_id, session=session, updated_by=db_user, commit=True)
    return db_user


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
    settings: Settings,
):
    """
    Auth0 Actions need to receive the response as a signed JWT
    token, sign the AccountLinkResponse we want to return
    and redirect to the continue endpoint
    """
    token = create_action_token(
        payload=response.model_dump(mode="json"),
        settings=settings,
    )
    auth0_base_url = settings.auth0_custom_domain or f"https://{settings.auth0_domain}"
    redirect_url = httpx2.URL(
        f"{auth0_base_url}/continue",
        params={"state": state, "session_token": token},
    )
    return RedirectResponse(url=redirect_url)



@router.get("/check-link", response_model=AccountLinkResponse)
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
        resp = AccountLinkResponse(link=False, aaf_only=True, primary_id=token.user_id)
        return return_signed_response(state=state, response=resp, settings=settings)

    existing_account = None
    for user in auth0_matches:
        if user.email.lower() == email.lower():
            existing_account = user
            break
    # No exact match: no existing account
    if not existing_account:
        mark_user_aaf_only(email, aaf_user_id, auth0_client)
        resp = AccountLinkResponse(link=False, aaf_only=True, primary_id=email)
        return return_signed_response(state=state, response=resp, settings=settings)

    if existing_account.blocked:
        raise HTTPException(status_code=403, detail="Existing account is blocked.")

    link_aaf_account(
        db_user_id=existing_account.user_id,
        aaf_user_id=aaf_user_id,
        auth0_client=auth0_client,
        session=session,
    )
    resp = AccountLinkResponse(link=True, aaf_only=False, primary_id=existing_account.user_id)
    return return_signed_response(state=state, response=resp, settings=settings)
