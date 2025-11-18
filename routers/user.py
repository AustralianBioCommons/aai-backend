from typing import Annotated, Any, Dict

from fastapi import APIRouter, Body, Depends, HTTPException, status
from httpx import AsyncClient
from pydantic import AliasPath, Field
from pydantic import BaseModel as PydanticBaseModel
from sqlmodel import Session

from auth.management import get_management_token
from auth.user_permissions import get_db_user, get_session_user, user_is_general_admin
from auth0.client import Auth0Client, UpdateUserData, get_auth0_client
from auth0.user_info import UserInfo, get_auth0_user_info
from config import Settings, get_settings
from db.models import (
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
    Platform,
    PlatformMembership,
)
from db.setup import get_db_session
from db.types import ApprovalStatusEnum
from schemas.biocommons import (
    Auth0UserData,
    BiocommonsUsername,
    PasswordChangeRequest,
    UserProfileData,
)
from schemas.user import SessionUser

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


class GroupAdminData(PydanticBaseModel):
    """
    Data model for group admin response.
    """
    id: str = Field(validation_alias="group_id")
    name: str
    short_name: str


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


@router.post("/profile/username/update",
             response_model=Auth0UserData)
async def update_username(
    username: Annotated[BiocommonsUsername, Body(embed=True)],
    user: Annotated[SessionUser, Depends(get_session_user)],
    db_user: Annotated[BiocommonsUser, Depends(get_db_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    """Update the username of the current user."""
    # Update in Auth0 (need to include connection when updating username)
    update_data = UpdateUserData(username=username, connection=settings.auth0_db_connection)
    resp = auth0_client.update_user(user_id=user.access_token.sub, update_data=update_data)
    db_user.username = username
    db_session.add(db_user)
    db_session.commit()
    return resp


@router.post("/profile/password/update",)
async def change_password(
    payload: PasswordChangeRequest,
    session_user: Annotated[SessionUser, Depends(get_session_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    auth0_client: Annotated[Auth0Client, Depends(get_auth0_client)],
):
    """Allow a logged-in user to change their password."""
    connection = settings.auth0_db_connection
    auth0_user = await get_user_data(session_user, settings)

    if not any(identity.connection == connection for identity in auth0_user.identities):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password changes are not supported for this account.",
        )

    current_password_ok = auth0_client.check_user_password(auth0_user.username, password=payload.current_password, settings=settings)
    if not current_password_ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )
    update_data = UpdateUserData(password=payload.new_password, connection=connection)
    auth0_client.update_user(user_id=auth0_user.user_id, update_data=update_data)
    return True
