from typing import Annotated, Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from httpx import AsyncClient
from pydantic import BaseModel as PydanticBaseModel
from sqlalchemy import Sequence
from sqlmodel import Session, select

from auth.management import get_management_token
from auth.validator import get_current_user
from config import Settings, get_settings
from db.models import GroupMembership, PlatformMembership
from db.setup import get_db_session
from db.types import ApprovalStatusEnum
from schemas.biocommons import Auth0UserData
from schemas.user import SessionUser

router = APIRouter(
    prefix="/me", tags=["user"], responses={401: {"description": "Unauthorized"}}
)


class PlatformMembershipData(PydanticBaseModel):
    platform_id: str
    approval_status: str


class GroupMembershipData(PydanticBaseModel):
    group_id: str
    approval_status: str


class CombinedMembershipData(PydanticBaseModel):
    platforms: list[PlatformMembershipData]
    groups: list[GroupMembershipData]


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


def _get_user_platforms(user_id: str,
                        approval_status: ApprovalStatusEnum | None = None) -> Sequence[PlatformMembership]:
    """Utility function to get platforms for a user."""
    query = (select(PlatformMembership)
             .where(PlatformMembership.user_id == user_id))
    if approval_status is not None:
        query = query.where(PlatformMembership.approval_status == approval_status)
    return query


def _get_user_groups(user_id: str,
                     approval_status: ApprovalStatusEnum | None = None) -> Sequence[GroupMembership]:
    """Utility function to get groups for a user."""
    query = (select(GroupMembership)
             .where(GroupMembership.user_id == user_id))
    if approval_status is not None:
        query = query.where(GroupMembership.approval_status == approval_status)
    return query


@router.get("/platforms",
            response_model=list[PlatformMembershipData],)
async def get_platforms(
        user: Annotated[SessionUser, Depends(get_current_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    query = _get_user_platforms(user_id=user.access_token.sub)
    return db_session.exec(query).all()


@router.get(
    "/platforms/approved",
    response_model=list[PlatformMembershipData],
)
async def get_approved_platforms(
        user: Annotated[SessionUser, Depends(get_current_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    """Get approved platforms for the current user."""
    query = _get_user_platforms(user_id=user.access_token.sub,
                                approval_status=ApprovalStatusEnum.APPROVED)
    return db_session.exec(query).all()


@router.get(
    "/platforms/pending",
    response_model=list[PlatformMembershipData],
)
async def get_pending_platforms(
        user: Annotated[SessionUser, Depends(get_current_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    """Get pending platforms for the current user."""
    query = _get_user_platforms(user_id=user.access_token.sub,
                                approval_status=ApprovalStatusEnum.PENDING)
    return db_session.exec(query).all()


@router.get("/groups",
            response_model=list[GroupMembershipData],)
async def get_groups(
        user: Annotated[SessionUser, Depends(get_current_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    query = _get_user_groups(user_id=user.access_token.sub)
    return db_session.exec(query).all()


@router.get("/groups/approved",
            response_model=list[GroupMembershipData],)
async def get_approved_groups(
        user: Annotated[SessionUser, Depends(get_current_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    query = _get_user_groups(user_id=user.access_token.sub,
                             approval_status=ApprovalStatusEnum.APPROVED)
    return db_session.exec(query).all()


@router.get("/groups/pending",
            response_model=list[GroupMembershipData],)
async def get_pending_groups(
        user: Annotated[SessionUser, Depends(get_current_user)],
        db_session: Annotated[Session, Depends(get_db_session)],
):
    query = _get_user_groups(user_id=user.access_token.sub,
                             approval_status=ApprovalStatusEnum.PENDING)
    return db_session.exec(query).all()


@router.get("/is-admin")
async def check_is_admin(
    user: Annotated[SessionUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
):
    """Check if the current user has admin privileges."""
    return {"is_admin": user.is_admin(settings)}


@router.get("/all/pending",
            response_model=CombinedMembershipData)
async def get_all_pending(
    user: Annotated[SessionUser, Depends(get_current_user)],
    db_session: Annotated[Session, Depends(get_db_session)],
):
    """Get all pending platforms and groups."""
    platforms_query = _get_user_platforms(user_id=user.access_token.sub,
                                    approval_status=ApprovalStatusEnum.PENDING)
    groups_query = _get_user_groups(user_id=user.access_token.sub,
                              approval_status=ApprovalStatusEnum.PENDING)
    platforms = db_session.exec(platforms_query).all()
    groups = db_session.exec(groups_query).all()
    return {"platforms": platforms, "groups": groups}
