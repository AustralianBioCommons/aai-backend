import hashlib
import hmac
import http
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict

from botocore.exceptions import ClientError
from fastapi import APIRouter, Body, Depends, HTTPException, Response, status
from httpx import AsyncClient, HTTPStatusError
from loguru import logger
from pydantic import AliasPath, BaseModel, Field
from pydantic import BaseModel as PydanticBaseModel
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select
from starlette.responses import RedirectResponse

from auth.management import get_management_token
from auth.ses import EmailService, get_email_service
from auth.user_permissions import get_db_user, get_session_user, user_is_general_admin
from auth.validator import verify_action_token
from auth0.client import Auth0Client, UpdateUserData, get_auth0_client
from auth0.user_info import UserInfo, get_auth0_user_info
from biocommons.emails import (
    compose_email_change_otp_email,
    compose_group_approval_email,
)
from biocommons.groups import GroupId
from config import Settings, get_settings
from db.models import (
    BiocommonsGroup,
    BiocommonsUser,
    EmailChangeOtp,
    GroupMembership,
    Platform,
    PlatformMembership,
)
from db.setup import get_db_session
from db.types import ApprovalStatusEnum
from schemas.biocommons import (
    Auth0UserData,
    BiocommonsAppMetadata,
    BiocommonsEmail,
    BiocommonsFirstName,
    BiocommonsLastName,
    BiocommonsUsername,
    PasswordChangeRequest,
    UserProfileData,
)
from schemas.responses import FieldError, FieldErrorResponse
from schemas.user import SessionUser
from services.email_queue import enqueue_email

router = APIRouter(
    prefix="/me", tags=["user"], responses={401: {"description": "Unauthorized"}}
)


class PlatformMembershipData(PydanticBaseModel):
    platform_id: str
    approval_status: str


class GroupMembershipData(PydanticBaseModel):
    """
    Data model for group membership, when returned from the API.
    Should be created automatically from GroupMembership when
    setting a response_model on a route.
    """
    group_id: str
    approval_status: str
    # Get group_name from the nested group object
    group_name: str = Field(validation_alias=AliasPath("group", "name"))


class CombinedMembershipData(PydanticBaseModel):
    platforms: list[PlatformMembershipData]
    groups: list[GroupMembershipData]


class PlatformAdminData(PydanticBaseModel):
    """
    Data model for platform admin response.
    """
    id: str
    name: str


class GroupAdminData(PydanticBaseModel):
    """
    Data model for group admin response.
    """
    id: str = Field(validation_alias="group_id")
    name: str
    short_name: str


class EmailChangeRequest(BaseModel):
    email: BiocommonsEmail


class EmailChangeContinueRequest(BaseModel):
    otp: Annotated[str, Field(min_length=1)]


OTP_EXPIRATION_MINUTES = 10
OTP_WINDOW_SECONDS = 60
MAX_WINDOW_ATTEMPTS = 10
MAX_TOTAL_ATTEMPTS = 10
OTP_LENGTH = 6
def _generate_otp_code() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))


def _hash_otp(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _ensure_datetime_is_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


async def get_user_data(
    user: SessionUser, settings: Annotated[Settings, Depends(get_settings)]
) -> Auth0UserData:
    """Fetch and return user data from Auth0."""
    url = f"https://{settings.auth0_domain}/api/v2/users/{user.access_token.sub}"
    token = get_management_token(settings=settings)
    headers = {"Authorization": f"Bearer {token}"}

    try:
        async with AsyncClient() as client:
            response = await client.get(url, headers=headers)
            if response.status_code != 200:
                raise HTTPException(
                    status_code=403,
                    detail="Failed to fetch user data",
                )
            return Auth0UserData(**response.json())
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=403, detail=f"Failed to fetch user data: {str(e)}"
        )


async def update_user_metadata(
    user_id: str, token: str, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Utility function to update user metadata in Auth0."""
    url = f"https://{get_settings().auth0_domain}/api/v2/users/{user_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    try:
        async with AsyncClient() as client:
            response = await client.patch(
                url, headers=headers, json={"app_metadata": metadata}
            )
            if response.status_code != 200:
                raise HTTPException(
                    status_code=403,
                    detail="Failed to update user metadata",
                )
            return response.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=403,
            detail=f"Failed to update user metadata: {str(e)}",
        )


@router.get("/profile", response_model=UserProfileData)
async def get_profile(
    user_info: Annotated[UserInfo, Depends(get_auth0_user_info)],
    db_user: Annotated[BiocommonsUser, Depends(get_db_user)],
):
    return UserProfileData.from_db_user(db_user, auth0_user_info=user_info)


@router.get("/platforms",
            response_model=list[PlatformMembershipData],)
async def get_platforms(
        user: Annotated[SessionUser, Depends(get_session_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    return PlatformMembership.get_by_user_id(user_id=user.access_token.sub, session=db_session)


@router.get(
    "/platforms/approved",
    response_model=list[PlatformMembershipData],
)
async def get_approved_platforms(
        user: Annotated[SessionUser, Depends(get_session_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    """Get approved platforms for the current user."""
    return PlatformMembership.get_by_user_id(user_id=user.access_token.sub,
                                              approval_status=ApprovalStatusEnum.APPROVED,
                                              session=db_session)


@router.get(
    "/platforms/pending",
    response_model=list[PlatformMembershipData],
)
async def get_pending_platforms(
        user: Annotated[SessionUser, Depends(get_session_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    """Get pending platforms for the current user."""
    return PlatformMembership.get_by_user_id(user_id=user.access_token.sub,
                                              approval_status=ApprovalStatusEnum.PENDING,
                                              session=db_session)


@router.get(
    "/platforms/admin-roles",
    response_model=list[PlatformAdminData],
    description="Get platforms for which the current user has admin privileges.",
)
async def get_admin_platforms(
    user: Annotated[SessionUser, Depends(get_session_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
):
    """Get platforms for which the current user has admin privileges."""
    user_roles = user.access_token.biocommons_roles
    return Platform.get_for_admin_roles(role_names=user_roles, session=db_session)


@router.get("/groups",
            response_model=list[GroupMembershipData],)
async def get_groups(
        user: Annotated[SessionUser, Depends(get_session_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    return GroupMembership.get_by_user_id(user_id=user.access_token.sub, session=db_session)


@router.get("/groups/approved",
            response_model=list[GroupMembershipData],)
async def get_approved_groups(
        user: Annotated[SessionUser, Depends(get_session_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    return GroupMembership.get_by_user_id(user_id=user.access_token.sub,
                                         approval_status=ApprovalStatusEnum.APPROVED,
                                         session=db_session)


@router.get("/groups/pending",
            response_model=list[GroupMembershipData],)
async def get_pending_groups(
        user: Annotated[SessionUser, Depends(get_session_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    return GroupMembership.get_by_user_id(user_id=user.access_token.sub,
                                          approval_status=ApprovalStatusEnum.PENDING,
                                          session=db_session)


@router.get(
    "/groups/admin-roles",
    response_model=list[GroupAdminData],
    description="Get groups for which the current user has admin privileges.",
)
async def get_admin_groups(
    user: Annotated[SessionUser, Depends(get_session_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
):
    """Get groups for which the current user has admin privileges."""
    user_roles = user.access_token.biocommons_roles
    return BiocommonsGroup.get_for_admin_roles(role_names=user_roles, session=db_session)


class GroupAccessRequestData(BaseModel):
    group_id: GroupId


@router.post("/groups/request")
def request_group_access(
        request_data: GroupAccessRequestData,
        user: Annotated[SessionUser, Depends(get_session_user)],
        db_user: Annotated[BiocommonsUser, Depends(get_db_user)],
        auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
        db_session: Annotated[Session, Depends(get_db_session)],
        settings: Annotated[Settings, Depends(get_settings)],
):
    """
    Request access to a group. Users can re-request access if their last
    request was rejected; otherwise the request is rejected if a membership
    already exists.
    """
    group_id = request_data.group_id
    existing_membership = GroupMembership.get_by_user_id_and_group_id(
        user_id=user.access_token.sub,
        group_id=group_id,
        session=db_session,
    )
    membership: GroupMembership
    if existing_membership is not None:
        if existing_membership.approval_status == ApprovalStatusEnum.REVOKED:
            group_name = group_id
            if existing_membership.group is None:
                db_session.refresh(existing_membership, attribute_names=["group"])
            if existing_membership.group is not None:
                group_name = existing_membership.group.name
            raise HTTPException(
                status_code=http.HTTPStatus.CONFLICT,
                detail=(
                    "Your account has been revoked access to "
                    f"{group_name}, please contact support to access."
                ),
            )
        if existing_membership.approval_status != ApprovalStatusEnum.REJECTED:
            raise HTTPException(
                status_code=http.HTTPStatus.CONFLICT,
                detail=f"User {user.access_token.sub} already has a membership for {group_id}",
            )
        membership = existing_membership
        membership.approval_status = ApprovalStatusEnum.PENDING
        membership.rejection_reason = None
        membership.updated_by = None
        membership.updated_at = datetime.now(timezone.utc)
        membership.save(session=db_session, commit=False)
        logger.info("Re-requested group membership for %s(%s)", group_id, user.access_token.sub)
    else:
        group = BiocommonsGroup.get_by_id(group_id, db_session)
        membership = GroupMembership(
            group=group,
            user=db_user,
            approval_status=ApprovalStatusEnum.PENDING,
            updated_by=None
        )
        membership.save(session=db_session, commit=False)
        logger.info("Requested group membership for %s(%s)", group_id, user.access_token.sub)
    logger.info("Queueing emails to group admins for approval")
    admin_emails = membership.group.get_admins(auth0_client=auth0_client)
    for email in admin_emails:
        subject, body_html = compose_group_approval_email(request=membership, settings=settings)
        enqueue_email(
            db_session,
            to_address=email,
            from_address=settings.default_email_sender,
            subject=subject,
            body_html=body_html,
        )
    db_session.commit()
    return {"message": f"Group membership for {group_id} requested successfully."}


@router.get("/is-general-admin")
async def check_is_general_admin(
    user: Annotated[SessionUser, Depends(get_session_user)],
    db_user: Annotated[BiocommonsUser, Depends(get_db_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    """Check if the current user has general admin privileges."""
    try:
        validated = user_is_general_admin(user, settings, db_user=db_user, db_session=db_session)
        if validated:
            return True
    except HTTPException:
        return False


@router.get("/all/pending",
            response_model=CombinedMembershipData)
async def get_all_pending(
    user: Annotated[SessionUser, Depends(get_session_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
):
    """Get all pending platforms and groups."""
    platforms = PlatformMembership.get_by_user_id(user_id=user.access_token.sub,
                                                  approval_status=ApprovalStatusEnum.PENDING,
                                                  session=db_session)
    groups = GroupMembership.get_by_user_id(user_id=user.access_token.sub,
                                             approval_status=ApprovalStatusEnum.PENDING,
                                             session=db_session)
    return {"platforms": platforms, "groups": groups}


@router.post(
    "/profile/username/update",
    responses={
        200: {"model": Auth0UserData},
        400: {"model": FieldErrorResponse},
    },
)
async def update_username(
    username: Annotated[BiocommonsUsername, Body(embed=True)],
    user: Annotated[SessionUser, Depends(get_session_user)],
    db_user: Annotated[BiocommonsUser, Depends(get_db_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
    settings: Annotated[Settings, Depends(get_settings)],
    response: Response,
):
    """Update the username of the current user."""
    # Check if username already exists in local database
    existing_user = db_session.exec(
        select(BiocommonsUser)
        .where(
            BiocommonsUser.username == username,
            BiocommonsUser.id != user.access_token.sub,
        )
    ).first()

    if existing_user:
        response.status_code = 400
        field_errors = [FieldError(field="username", message="Username is already taken")]
        return FieldErrorResponse(
            message="Username is already taken",
            field_errors=field_errors
        )

    # Update in Auth0 (need to include connection when updating username)
    update_data = UpdateUserData(username=username, connection=settings.auth0_db_connection)
    try:
        resp = auth0_client.update_user(user_id=user.access_token.sub, update_data=update_data)
    except HTTPStatusError as e:
        logger.error(f"Error updating username: {e}")
        response.status_code = 400
        if e.response.status_code == 409:
            # Username already exists in Auth0
            field_errors = [FieldError(field="username", message="Username is already taken")]
            return FieldErrorResponse(
                message="Username is already taken",
                field_errors=field_errors
            )
        if e.response.status_code == 400:
            error_details = e.response.json()
            return FieldErrorResponse(
                message=error_details.get("message", "Invalid username")
            )
        if e.response.status_code in (401, 403):
            return FieldErrorResponse(
                message="You do not have permission to update your username. Please try logging in again."
            )
        return FieldErrorResponse(message="Unknown error.")

    # Update database
    db_user.username = username
    db_session.add(db_user)
    try:
        db_session.commit()
    except IntegrityError:
        db_session.rollback()
        logger.error(f"Database integrity error: username {username} already exists in database")
        response.status_code = 400
        field_errors = [FieldError(field="username", message="Username is already taken")]
        return FieldErrorResponse(
            message="Username is already taken",
            field_errors=field_errors
        )
    return resp


class NameUpdateRequest(BaseModel):
    """Request model for updating user's name."""
    first_name: BiocommonsFirstName
    last_name: BiocommonsLastName


@router.post("/profile/name/update",
             response_model=Auth0UserData)
async def update_name(
    payload: Annotated[NameUpdateRequest, Body()],
    user: Annotated[SessionUser, Depends(get_session_user)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
):
    """Update the first name and last name for the current user."""
    update_data = UpdateUserData()
    update_data.given_name = payload.first_name
    update_data.family_name = payload.last_name
    update_data.name = f"{payload.first_name} {payload.last_name}"

    # Update picture with Auth0 avatar using initials (ASCII only)
    first_initial = next((c.lower() for c in payload.first_name if c.isascii() and c.isalpha()), None)
    last_initial = next((c.lower() for c in payload.last_name if c.isascii() and c.isalpha()), None)

    if first_initial and last_initial:
        initials = f"{first_initial}{last_initial}"
        update_data.picture = f"https://ui-avatars.com/api/?name={initials}&background=random"

    try:
        return auth0_client.update_user(user_id=user.access_token.sub, update_data=update_data)
    except HTTPStatusError as e:
        logger.error(f"Error updating name: {e}")
        if e.response.status_code in (401, 403):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to update your name. Please try logging in again."
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update name."
        )


@router.post("/profile/email/update")
async def update_email(
    payload: Annotated[EmailChangeRequest, Body()],
    user: Annotated[SessionUser, Depends(get_session_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
    email_service: Annotated[EmailService, Depends(get_email_service)],
):
    """Start an email change by sending an OTP to the requested address."""
    conflicting_user = db_session.exec(
        select(BiocommonsUser)
        .where(
            BiocommonsUser.email == payload.email,
            BiocommonsUser.id != user.access_token.sub,
        )
    ).one_or_none()
    if conflicting_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already in use by another user.",
        )
    now = datetime.now(timezone.utc)
    # Clear existing OTPs
    db_session.exec(
        update(EmailChangeOtp)
        .where(
            EmailChangeOtp.user_id == user.access_token.sub,
            EmailChangeOtp.is_active.is_(True),
        )
    .values(is_active=False)
    )

    db_session.commit()

    code = _generate_otp_code()
    otp_entry = EmailChangeOtp(
        user_id=user.access_token.sub,
        target_email=payload.email,
        otp_hash=_hash_otp(code),
        created_at=now,
        expires_at=now + timedelta(minutes=OTP_EXPIRATION_MINUTES),
        window_start=now,
    )
    db_session.add(otp_entry)
    db_session.commit()

    try:
        subject, body_html = compose_email_change_otp_email(
            code=code,
            target_email=payload.email,
            expiration_minutes=OTP_EXPIRATION_MINUTES,
        )
        email_service.send(
            to_address=payload.email,
            subject=subject,
            body_html=body_html,
        )
    except ClientError as exc:
        message = exc.response.get("Error", {}).get("Message") or str(exc)
        logger.error("Failed to send OTP email via SES: {}", message)
        raise
    return {"message": "OTP sent to the requested email address."}


@router.post("/profile/email/continue",
             response_model=Auth0UserData)
async def continue_email_update(
    payload: Annotated[EmailChangeContinueRequest, Body()],
    user: Annotated[SessionUser, Depends(get_session_user)],
    db_user: Annotated[BiocommonsUser, Depends(get_db_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    """Complete an email change by validating the OTP and updating Auth0."""
    now = datetime.now(timezone.utc)
    otp_entry = db_session.exec(
        select(EmailChangeOtp)
        .where(
            EmailChangeOtp.user_id == user.access_token.sub,
            EmailChangeOtp.is_active.is_(True),
        )
        .order_by(EmailChangeOtp.created_at.desc())
    ).first()
    if otp_entry is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending email change request exists.",
        )

    expires_at = _ensure_datetime_is_aware(otp_entry.expires_at)
    if expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending email change request exists.",
        )

    if otp_entry.total_attempts >= MAX_TOTAL_ATTEMPTS:
        otp_entry.is_active = False
        db_session.add(otp_entry)
        db_session.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many verification attempts. Try again later.",
        )
    provided_hash = _hash_otp(payload.otp)
    if not hmac.compare_digest(otp_entry.otp_hash, provided_hash):
        otp_entry.total_attempts += 1
        if otp_entry.total_attempts >= MAX_TOTAL_ATTEMPTS:
            otp_entry.is_active = False
        db_session.add(otp_entry)
        db_session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP.",
        )

    conflicting_user = db_session.exec(
        select(BiocommonsUser)
        .where(
            BiocommonsUser.email == otp_entry.target_email,
            BiocommonsUser.id != user.access_token.sub,
        )
    ).one_or_none()
    if conflicting_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already in use by another user.",
        )

    otp_entry.is_active = False
    otp_entry.total_attempts += 1
    db_session.add(otp_entry)
    db_session.commit()

    old_email = db_user.email
    update_data = UpdateUserData(
        email=otp_entry.target_email,
        email_verified=True,
        connection=settings.auth0_db_connection,
    )
    resp = auth0_client.update_user(user_id=user.access_token.sub, update_data=update_data)

    management_token = get_management_token(settings=settings)
    auth0_full_user = auth0_client.get_user(user_id=user.access_token.sub)
    metadata = (
        auth0_full_user.app_metadata.model_dump(mode="json", exclude_none=True)
        if auth0_full_user.app_metadata
        else {}
    )
    old_emails = metadata.get("old_emails", [])
    old_emails.append(
        {
            "old_email": old_email,
            "until_datetime": now.isoformat(),
        }
    )
    metadata["old_emails"] = old_emails
    await update_user_metadata(user_id=user.access_token.sub, token=management_token, metadata=metadata)

    db_user.email = resp.email
    db_user.email_verified = resp.email_verified
    db_session.add(db_user)
    db_session.commit()
    return resp


@router.post(
    "/profile/password/update",
    responses={
        200: {"model": dict},
        400: {"model": FieldErrorResponse},
    },
)
async def change_password(
    payload: PasswordChangeRequest,
    session_user: Annotated[SessionUser, Depends(get_session_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
    response: Response,
):
    """Allow a logged-in user to change their password."""
    connection = settings.auth0_db_connection
    auth0_user = await get_user_data(session_user, settings)

    if not any(identity.connection == connection for identity in auth0_user.identities):
        response.status_code = 400
        return FieldErrorResponse(
            message="Password changes are not supported for this account."
        )

    current_password_ok = auth0_client.check_user_password(auth0_user.username, password=payload.current_password, settings=settings)
    if not current_password_ok:
        response.status_code = 400
        field_errors = [FieldError(field="currentPassword", message="Current password is incorrect")]
        return FieldErrorResponse(
            message="Current password is incorrect",
            field_errors=field_errors
        )

    try:
        update_data = UpdateUserData(password=payload.new_password, connection=connection)
        auth0_client.update_user(user_id=auth0_user.user_id, update_data=update_data)
        return {"message": "Password updated successfully"}
    except HTTPStatusError as e:
        logger.error(f"Error updating password: {e}")
        response.status_code = 400
        return FieldErrorResponse(
            message="Failed to update password"
        )


class MigratePasswordRequest(BaseModel):
    """
    POST data when triggering password change as part of legacy user migration.
    """
    session_token: str
    client_id: str

@router.post(
    "/migration/update-password",
)
def migrate_password(data: MigratePasswordRequest,
                     settings: Annotated[Settings, Depends(get_settings)],
                     auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],):
    """
    Trigger password change as part of legacy user migration. Requires
    a signed session token generated by Auth0
    """
    # Will raise if token is invalid
    payload = verify_action_token(data.session_token, settings=settings)
    try:
        user_id = payload["sub"]
        email = payload["email"]
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Invalid session token: {e}")
    logger.info(f"Initiating password change for user {user_id}")
    auth0_client.trigger_password_change(user_email=email, client_id=data.client_id, settings=settings)
    return {"message": "Password change initiated successfully"}


@router.get("/migration/password-changed")
def finish_migrate_password(state: str,
                            session_token: str,
                            settings: Annotated[Settings, Depends(get_settings)],
                            auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],):
    """
    Complete the migration process. This should be called by Auth0 when a user
    starts the actual password change, and clears their user_needs_migration flag.
    """
    # Will raise if token is invalid
    payload = verify_action_token(session_token, settings=settings)
    try:
        user_id = payload["sub"]
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Invalid session token: {e}")
    # NOTE: due to the way the update user endpoint works (app_metadata is merged, not replaced),
    #  this should not overwrite existing app_metadata
    updated_metadata = BiocommonsAppMetadata(user_needs_migration=False)
    logger.info(f"Updating app_metadata for user: {user_id}")
    auth0_client.update_user(user_id=user_id, update_data=UpdateUserData(app_metadata=updated_metadata))
    logger.info("Returning to Auth0")
    return RedirectResponse(url=f"{settings.auth0_custom_domain}/continue?state={state}")
