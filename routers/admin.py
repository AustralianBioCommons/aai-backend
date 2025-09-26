import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.params import Query
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import alias, false, func, or_
from sqlmodel import Session, select

from auth.validator import get_current_user, user_is_admin
from auth0.client import Auth0Client, get_auth0_client
from db.models import (
    Auth0Role,
    BiocommonsGroup,
    BiocommonsUser,
    GroupMembership,
    Platform,
    PlatformEnum,
    PlatformMembership,
)
from db.setup import get_db_session
from db.types import ApprovalStatusEnum, GroupEnum
from schemas.biocommons import Auth0UserDataWithMemberships
from schemas.user import SessionUser

logger = logging.getLogger('uvicorn.error')


UserIdParam = Path(..., pattern=r"^auth0\\|[a-zA-Z0-9]+$")
ServiceIdParam = Path(..., pattern=r"^[-a-zA-Z0-9_]+$")
ResourceIdParam = Path(..., pattern=r"^[-a-zA-Z0-9_]+$")


PLATFORM_MAPPING = {
    "galaxy": {"enum": PlatformEnum.GALAXY, "name": "Galaxy Australia"},
    "bpa_data_portal": {"enum": PlatformEnum.BPA_DATA_PORTAL, "name": "Bioplatforms Australia Data Portal"},
    "sbp": {"enum": PlatformEnum.SBP, "name": "Structural Biology Platform"},
}

GROUP_MAPPING = {
    "tsi": {"enum": GroupEnum.TSI, "name": "Threatened Species Initiative Bundle"},
    "bpa_galaxy": {"enum": GroupEnum.BPA_GALAXY, "name": "Bioplatforms Australia Data Portal & Galaxy Australia Bundle"},
}


class BiocommonsUserResponse(BaseModel):
    """
    Response schema for BiocommonsUser from the database
    """
    id: str = Field(description="Auth0 user ID")
    email: str = Field(description="User email address")
    username: str = Field(description="User username")
    email_verified: bool = Field(description="User email verification status")
    created_at: datetime = Field(description="User creation timestamp")


class PaginationParams(BaseModel):
    """
    Query parameters for paginated endpoints. Page starts at 1.
    """
    page: int = Query(1, ge=1)
    per_page: int = Query(100, ge=1, le=100)

    @property
    def start_index(self):
        return (self.page - 1) * self.per_page


def get_pagination_params(page: int = 1, per_page: int = 100):
    try:
        return PaginationParams(page=page, per_page=per_page)
    except ValidationError:
        raise HTTPException(
            status_code=422,
            detail="Invalid page params: page should be >= 1, per_page should be >= 1 and <= 100"
        )


router = APIRouter(prefix="/admin", tags=["admin"],
                   dependencies=[Depends(user_is_admin)])


@router.get("/filters")
def get_filter_options():
    """
    Get available filter options for users endpoint.

    Returns a list of all available filter options with their short IDs and display names.
    Uses the same IDs as defined in PLATFORM_MAPPING and GROUP_MAPPING.
    """
    options = []

    for platform_id, platform_data in PLATFORM_MAPPING.items():
        options.append({
            "id": platform_id,
            "name": platform_data["name"]
        })

    for group_id, group_data in GROUP_MAPPING.items():
        options.append({
            "id": group_id,
            "name": group_data["name"]
        })

    return options


@router.get("/users",
            response_model=list[BiocommonsUserResponse])
def get_users(admin_user: Annotated[SessionUser, Depends(get_current_user)],
              db_session: Annotated[Session, Depends(get_db_session)],
              pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
              filter_by: str = Query(None, description="Filter users by group ('tsi', 'bpa_galaxy') or platform ('galaxy', 'bpa_data_portal')"),
              search: str = Query(None, description="Search users by username or email")):
    """
    Get all users from the database with pagination and optional filtering.

    Args:
        filter_by: Optional filter parameter. Can be:
            - Group bundle names: 'tsi', 'bpa_galaxy'
            - Platform names: 'galaxy', 'bpa_data_portal'
        search: Optional search parameter for username or email
    """
    admin_roles = admin_user.access_token.biocommons_roles
    # Base query with platform access filtering built-in
    allowed_platforms_subquery = (
        select(Platform.id)
        .join(Platform.admin_roles)
        .where(Auth0Role.name.in_(admin_roles))
    ).alias("allowed_platforms")
    # Need an alias or SQLAlchemy complains about duplicate column names
    pm = alias(PlatformMembership, name="pm")
    base_query = (
        select(BiocommonsUser)
        .join(pm, BiocommonsUser.id == pm.c.user_id)
        .where(pm.c.platform_id.in_(allowed_platforms_subquery))
        .distinct()
    )

    if filter_by:
        if filter_by in GROUP_MAPPING:
            full_group_id = GROUP_MAPPING[filter_by]["enum"].value

            group_statement = select(BiocommonsGroup).where(BiocommonsGroup.group_id == full_group_id)
            group = db_session.exec(group_statement).first()
            if not group:
                raise HTTPException(status_code=404, detail=f"Group '{filter_by}' not found")

            base_query = base_query.join(GroupMembership, BiocommonsUser.id == GroupMembership.user_id).where(GroupMembership.group_id == full_group_id)

        elif filter_by in PLATFORM_MAPPING:
            platform_enum_value = PLATFORM_MAPPING[filter_by]["enum"]
            base_query = base_query.join(PlatformMembership, BiocommonsUser.id == PlatformMembership.user_id).where(PlatformMembership.platform_id == platform_enum_value)

        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid filter_by value '{filter_by}'"
            )

    if search:
        s = search.strip().lower()

        if "@" in s:
            base_query = base_query.where(
                or_(
                    func.lower(BiocommonsUser.email) == s,
                    func.lower(BiocommonsUser.email).ilike(f"%{s}%")
                )
            )
        else:
            base_query = base_query.where(
                or_(
                    func.lower(BiocommonsUser.username).ilike(f"%{s}%"),
                    func.lower(BiocommonsUser.email).ilike(f"%{s}%")
                )
            )

    user_query = base_query.offset(pagination.start_index).limit(pagination.per_page)
    users = db_session.exec(user_query).all()
    return users


# NOTE: This must appear before /users/{user_id} so it takes precedence
@router.get(
    "/users/approved",
    response_model=list[BiocommonsUserResponse])
def get_approved_users(db_session: Annotated[Session, Depends(get_db_session)],
                       pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    platform_approved_query = (
        select(BiocommonsUser)
        .join(PlatformMembership, BiocommonsUser.id == PlatformMembership.user_id)
        .where(PlatformMembership.approval_status == ApprovalStatusEnum.APPROVED)
        .distinct()
    )
    user_query = platform_approved_query.offset(pagination.start_index).limit(pagination.per_page)
    users = db_session.exec(user_query).all()
    return users


@router.get("/users/pending",
            response_model=list[BiocommonsUserResponse])
def get_pending_users(db_session: Annotated[Session, Depends(get_db_session)],
                      pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    platform_pending_query = (
        select(BiocommonsUser)
        .join(PlatformMembership, BiocommonsUser.id == PlatformMembership.user_id)
        .where(PlatformMembership.approval_status == ApprovalStatusEnum.PENDING)
        .distinct()
    )
    user_query = platform_pending_query.offset(pagination.start_index).limit(pagination.per_page)
    users = db_session.exec(user_query).all()
    return users


@router.get("/users/revoked")
def get_revoked_users(db_session: Annotated[Session, Depends(get_db_session)],
                      pagination: Annotated[PaginationParams, Depends(get_pagination_params)]):
    platform_revoked_query = (
        select(BiocommonsUser)
        .join(PlatformMembership, BiocommonsUser.id == PlatformMembership.user_id)
        .where(PlatformMembership.approval_status == ApprovalStatusEnum.REVOKED)
        .distinct()
    )
    user_query = platform_revoked_query.offset(pagination.start_index).limit(pagination.per_page)
    users = db_session.exec(user_query).all()
    return users


@router.get("/users/unverified", response_model=list[BiocommonsUserResponse])
def get_unverified_users(
    db_session: Annotated[Session, Depends(get_db_session)],
    pagination: Annotated[PaginationParams, Depends(get_pagination_params)],
):
    """
    Return users whose email is not verified, using Auth0 search for efficiency.
    """
    query = (
        select(BiocommonsUser)
        .where(BiocommonsUser.email_verified == false())
        .offset(pagination.start_index)
        .limit(pagination.per_page)
    )
    users = db_session.exec(query).all()
    return users


@router.get("/users/{user_id}",
            response_model=BiocommonsUserResponse)
def get_user(user_id: Annotated[str, UserIdParam],
             db_session: Annotated[Session, Depends(get_db_session)]):
    user = db_session.get_one(BiocommonsUser, user_id)
    return user


@router.get("/users/{user_id}/details",
            response_model=Auth0UserDataWithMemberships)
def get_user_details(user_id: Annotated[str, UserIdParam],
                     client: Annotated[Auth0Client, Depends(get_auth0_client)],
                     db_session: Annotated[Session, Depends(get_db_session)]):
    """
    Get user data from Auth0, along with group and platform membership information
    from our user DB.
    """
    user = client.get_user(user_id)
    from db.models import BiocommonsUser
    db_user = db_session.get_one(BiocommonsUser, user_id)
    details = Auth0UserDataWithMemberships.from_auth0_data(
        auth0_data=user,
        db_data=db_user,
    )
    return details


@router.post("/users/{user_id}/verification-email/resend")
def resend_verification_email(user_id: Annotated[str, UserIdParam],
                              client: Annotated[Auth0Client, Depends(get_auth0_client)]):
    client.resend_verification_email(user_id)
    return {"message": "Verification email resent."}
