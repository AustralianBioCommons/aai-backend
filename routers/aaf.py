import logging
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Annotated
from urllib.parse import urlparse

import httpx2
from fastapi import APIRouter, Depends, HTTPException
from pydantic import AwareDatetime, BaseModel
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session
from starlette import status
from starlette.responses import RedirectResponse

from auth.user_permissions import get_db_user_or_404, get_session_user
from auth.validator import create_action_token
from auth0.client import Auth0Client, UpdateUserData, get_auth0_client
from config import Settings, get_settings
from db.models import AccountMigrationRequest, BiocommonsUser
from db.setup import get_db_session
from dependencies.auth import require_action_token
from dependencies.utils import request_time
from schemas.aaf_migration import (
    MigrateToAafRequest,
    MigrationDirection,
    MigrationStatus,
)
from schemas.auth0 import AafMigrationActionToken, Auth0ActionToken
from schemas.biocommons import (
    Auth0Identity,
    Auth0UserData,
    BiocommonsAppMetadataUpdate,
    BiocommonsUserAccountType,
)
from schemas.user import SessionUser

router = APIRouter(
    prefix="/aaf", tags=["aaf"]
)
logger = logging.getLogger("uvicorn.error")


MIGRATION_EXPIRY_MINUTES = 10


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


def link_aaf_account(
    db_user_id: str,
    aaf_user_id: str,
    auth0_client: Auth0Client,
    session: Session,
    *,
    new_email: str | None = None,
    connection: str | None = None,
    commit: bool = True,
) -> Auth0Identity:
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
    if new_email is not None:
        try:
            db_user.update_email(new_email=new_email, verified=True, session=session, updated_by=db_user)
            session.flush()
        except IntegrityError as exc:
            session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email is already in use by another user.",
            ) from exc
    now = datetime.now(tz=timezone.utc)
    try:
        auth0_client.update_user(
            db_user_id,
            update_data=UpdateUserData(
                app_metadata=BiocommonsAppMetadataUpdate(
                    account_type=BiocommonsUserAccountType.AAF,
                    linking_completed=True,
                    linking_completed_at=now
                ),
                email=new_email,
                email_verified=True if new_email is not None else None,
                connection=connection,
            )
        )
    except ValueError as exc:
        session.rollback()
        logger.error(f"Failed to update account metadata in Auth0: {exc}")
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail="Failed to link account with Auth0") from exc
    logger.info("Updating DB record")
    db_user.link_aaf_account(aaf_user_id=aaf_user_id, session=session, updated_by=db_user)
    if commit:
        session.commit()
    return aaf_identity


def mark_user_aaf_only(user_email: str, aaf_user_id: str, auth0_client: Auth0Client):
    update_data = UpdateUserData(
        app_metadata=BiocommonsAppMetadataUpdate(
            account_type=BiocommonsUserAccountType.AAF,
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
    redirect_url = httpx2.URL(
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
    """
    Used when linking an AAF account to an existing account
    """
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


class MigrateToAafResponse(BaseModel):
    migration_id: str
    expires_at: AwareDatetime


@router.post("/migrate/auth0-to-aaf")
def migrate_auth0_to_aaf(
    migrate_data: MigrateToAafRequest,
    user: Annotated[SessionUser, Depends(get_session_user)],
    db_user: Annotated[BiocommonsUser, Depends(get_db_user_or_404)],
    session: Annotated[Session, Depends(get_db_session)],
    now: Annotated[AwareDatetime, Depends(request_time)]
):
    """
    Called when an existing user wants to change their email address from
    non-institutional (recorded in Auth0 database) to institutional
    (log in via AAF).

    Returns a migration_id used to link the AAF login back to the
    original account
    """
    if db_user.account_type != BiocommonsUserAccountType.AUTH0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account cannot be migrated to AAF - not an Auth0 account."
        )
    user_id = user.access_token.sub
    conflicting_user = BiocommonsUser.get_by_email(
        email=migrate_data.new_email,
        session=session,
        case_insensitive=True,
        include_deleted=True,
        exclude_user_id=user_id,
    )
    if conflicting_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already in use by another user.",
        )
    existing_request = AccountMigrationRequest.get_pending_by_user_id(user_id=user_id, session=session)
    if existing_request is not None:
        logger.warning(f"Found existing pending migration for user {user_id}, replacing")
        session.delete(existing_request)
        session.flush()
    migration_request = AccountMigrationRequest(
        user_id=user.access_token.sub,
        new_email=migrate_data.new_email,
        direction=MigrationDirection.AUTH0_TO_AAF,
        expires_at=now + timedelta(minutes=MIGRATION_EXPIRY_MINUTES),
        status=MigrationStatus.PENDING,
    )
    session.add(migration_request)
    # Get migration request data before commit, which expires the object
    response = MigrateToAafResponse(
        migration_id=migration_request.id,
        expires_at=migration_request.expires_at,
    )
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A pending migration request already exists for this user. Please try again.",
        ) from exc
    return response


@router.get("/migrate/auth0-to-aaf/complete")
def complete_auth0_to_aaf_migration(
    state: str,
    token: Annotated[
        AafMigrationActionToken,
        Depends(require_action_token(purpose="aaf_migration", token_model=AafMigrationActionToken)),
    ],
    session: Annotated[Session, Depends(get_db_session)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
    settings: Annotated[Settings, Depends(get_settings)],
    now: Annotated[AwareDatetime, Depends(request_time)],
):
    """
    Called to complete migration from Auth0 to AAF, after AAF login.

    Redirects to the /continue endpoint to complete login.
    """
    migration_request = AccountMigrationRequest.get_by_id_or_404(session=session, id=token.migration_id, with_for_update=True)
    if (
        migration_request.direction != MigrationDirection.AUTH0_TO_AAF
        or migration_request.status != MigrationStatus.PENDING
    ):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Migration request is not pending for Auth0 to AAF")
    if migration_request.is_expired(now=now):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Migration request has expired, please try again")
    if token.email.lower() != migration_request.new_email.lower():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="AAF email does not match the migration request")

    db_user = BiocommonsUser.get_by_id_or_404(migration_request.user_id, session=session)
    if db_user.account_type != BiocommonsUserAccountType.AUTH0:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account cannot be migrated to AAF - not an Auth0 account.")
    conflicting_user = BiocommonsUser.get_by_email(
        email=migration_request.new_email,
        session=session,
        case_insensitive=True,
        include_deleted=True,
        exclude_user_id=db_user.id,
    )
    if conflicting_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already in use by another user.",
        )
    existing_account = auth0_client.get_user(user_id=db_user.id)
    if existing_account.blocked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account cannot be migrated to AAF - blocked in Auth0.",
        )
    aaf_identity = link_aaf_account(
        db_user_id=db_user.id,
        aaf_user_id=token.user_id,
        auth0_client=auth0_client,
        session=session,
        new_email=migration_request.new_email,
        connection=settings.auth0_db_connection,
        commit=False,
    )
    migration_request.status = MigrationStatus.COMPLETED
    session.add(migration_request)
    response = AccountLinkResponse(link=True, primary_id=db_user.id, aaf_identity=aaf_identity)
    session.commit()
    return return_signed_response(
        state=state,
        response=response,
        action_token=token,
        settings=settings,
    )
